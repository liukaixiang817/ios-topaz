#!/usr/bin/env python3
"""Run real resident EFI/XNU with one or two kernel cores in generic ARM64 QEMU.

Firmware retains CPU0; explicit kernel CPU1, CPU7, or CPU7+6 trials validate
memory/PSCI/SGI/16KiB handoff and RAM logs, not SDM845 peripherals or iOS GUI.
An old-kernel refusal run is a diagnostic and can never admit a phone image.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import zlib


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--qemu',required=True,type=Path)
    ap.add_argument('--code',required=True,type=Path)
    ap.add_argument('--vars',required=True,type=Path)
    ap.add_argument('--driver-manifest',required=True,type=Path)
    ap.add_argument('--kernel',required=True,type=Path)
    ap.add_argument('--payload',required=True,type=Path)
    ap.add_argument('--output',required=True,type=Path)
    ap.add_argument('--seconds',type=int,default=120)
    ap.add_argument('--legacy-core-refusal',action='store_true')
    ap.add_argument('--fault-ufs-host-disable',action='store_true',
                    help='disable the actual isolated UFS HCE after native READ10; require reset refusal')
    ap.add_argument('--fault-owned-sync',action='store_true',help='actual blkdebug final backend flush returns EIO')
    ap.add_argument('--fault-owned-write-delay',action='store_true',help='actual blkdebug holds WRITE beyond native DMA deadline')
    ap.add_argument('--mtools',type=Path,help='local mtools bin for an actual GPT/FAT disk-payload test')
    a=ap.parse_args();root=Path(__file__).resolve().parents[1]
    if not 15<=a.seconds<=600:ap.error('deadline must be 15..600 seconds')
    manifest=json.loads(a.driver_manifest.read_text());app=a.driver_manifest.parent/manifest['artifact']
    drain=manifest.get('RAM_native_drain_test')
    owned_ufs=manifest.get('isolated_QEMU_owned_UFS_test',False)
    virtual_ufs=manifest.get('isolated_QEMU_readonly_UFS_test',False) or owned_ufs
    response_short=manifest.get('controlled_owned_response_short_injection',False)
    guard_omitted=manifest.get('controlled_durable_guard_omitted',False)
    if virtual_ufs and (drain not in (('success','stale-cookie') if owned_ufs else ('success',)) or manifest.get('kernel_CPU_affinity')!=7 or
                        manifest.get('kernel_CPU_count')!=2):
        raise ValueError('native virtual UFS requires the two-core native drain fixture')
    if (a.fault_owned_sync or a.fault_owned_write_delay or response_short or guard_omitted) and not owned_ufs:
        raise ValueError('owned I/O faults require isolated writable synthetic fixture')
    if sum(map(bool,(a.fault_owned_sync,a.fault_owned_write_delay,response_short,a.fault_ufs_host_disable,drain=='stale-cookie',guard_omitted)))>1:
        raise ValueError('one independently attributable fault per run')
    if owned_ufs and (manifest.get('RAM_host_idle_recovery_seconds') is not None or
                      manifest.get('raw_reset_requires_durable_SAFE') is not True):
        raise ValueError('owned writes require prior raw reset and RAM lease protection')
    if a.fault_ufs_host_disable and not virtual_ufs:
        raise ValueError('controller fault is confined to the isolated virtual UFS fixture')
    if drain not in (None,'success','stale-cookie','peer-refused') or (drain and a.legacy_core_refusal):
        raise ValueError('unsupported native RAM drain test configuration')
    target=manifest.get('kernel_CPU_affinity')
    count=manifest.get('kernel_CPU_count',1)
    if (not manifest.get('QEMU_variant') or target not in (1,7) or count not in (1,2,4) or
        (count>1 and target!=7) or (drain=='peer-refused' and count not in (2,4)) or
        manifest.get('sha256')!=sha(app) or manifest.get('payload_sha256')!=sha(a.payload) or
        manifest.get('kernel_sha256')!=sha(a.kernel)):
        raise ValueError('QEMU inputs do not match the built test driver')
    for name,digest in manifest['inputs'].items():
        if sha(root/name)!=digest:raise ValueError('QEMU driver source changed: '+name)
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    esp=out/'esp/EFI/BOOT';esp.mkdir(parents=True)
    shutil.copyfile(app,esp/'BOOTAA64.EFI');shutil.copyfile(a.payload,out/'esp/PAYLOAD.BIN')
    shutil.copyfile(a.vars,out/'vars.fd')
    disk_fixture=None
    disk='fat:ro:'+str(out/'esp')
    if manifest.get('disk_payload_read_only'):
        if not a.mtools:ap.error('disk payload requires the actual GPT/FAT fixture')
        import polaris_efi_disk_fixture
        chain=manifest.get('chain_app');child=None
        if chain:
            child=Path(chain['artifact_path'])
            if sha(child)!=chain['sha256']:raise ValueError('selected chain app changed')
        disk_fixture=polaris_efi_disk_fixture.create(out/'fixture.raw',app,a.payload,
            manifest['disk_guid'],manifest['disk_start_lba'],manifest['disk_blocks'],
            manifest['disk_payload_path'],a.mtools,child)
        disk=str(out/'fixture.raw')
    cmd=[str(a.qemu.resolve()),'-M','virt,gic-version=3,virtualization=off','-cpu','cortex-a55',
         '-smp',str(target+1),'-m','8G','-display','none','-monitor','none','-nic','none',
         '-serial','file:'+str(out/'serial.log'),'-qmp','stdio','-no-reboot',
         '-drive','if=pflash,format=raw,readonly=on,file='+str(a.code.resolve()),
         '-drive','if=pflash,format=raw,file='+str(out/'vars.fd'),
         '-drive','if=none,id=esp,format=raw,readonly=on,file='+disk,
         '-device','virtio-blk-pci,drive=esp','-device','virtio-gpu-pci']
    ufs_fixture=None;ufs_before=None;fault=None;test_socket_dir=None;owned_variant=None
    if virtual_ufs:
        # Exclusively a newly created bounded file. No caller-supplied disk,
        # phone device, userdata, firmware file or writable backend is accepted.
        head=bytes(range(256))*4096
        import adt
        payload=a.payload.read_bytes();at,n=struct.unpack_from('<QQ',payload,32)
        tree,_=adt.parse(payload[at:at+n]);nodes=[x for x in tree.children if x.name=='polaris-qemu-ufs']
        ufs_fixture=out/'isolated-new-UFS-lun0.raw'
        if owned_ufs:
            import polaris_owned_qemu_fixture as owned_fixture
            import polaris_uefi_cpu_tree as cpu_tree
            cpu_tree.validate(payload[at:at+n],7,True,2)
            owned_variant=owned_fixture.variant(tree)
            owned_fixture.create(root,ufs_fixture,tree)
            with ufs_fixture.open('rb') as f:head=f.read(1<<20)
        else:
            with ufs_fixture.open('xb') as f:f.write(head);f.truncate(64<<20)
        if len(nodes)!=1 or nodes[0].prop('head-crc32')!=struct.pack('<I',zlib.crc32(head)):
            raise ValueError('native read fixture CRC does not match the bound tree')
        ufs_before=sha(ufs_fixture)
        cmd+=['-device','ufs,id=isolated-native-ufs']
        if a.fault_owned_sync or a.fault_owned_write_delay:
            # Never present an arbitrary caller-supplied file/device as writable.
            # Installed QAPI validates these options before any guest starts.
            # NONE activates at blkdebug open. WRITE_AIO/FLUSH_TO_DISK events
            # belong to upper format drivers and did not fire in a raw graph.
            # iotype confines this active rule to the intended actual request.
            rule={'event':'none',
                  'iotype':'flush' if a.fault_owned_sync else 'write',
                  'errno':5 if a.fault_owned_sync else 0,'once':True,'immediately':False}
            if a.fault_owned_write_delay:rule['delay-ns']=120_000_000_000
            backend={'driver':'blkdebug','node-name':'isolated-lun0','image':{
                'driver':'raw','file':{'driver':'file','filename':str(ufs_fixture)}},'inject-error':[rule]}
            (out/'backend-fault-config.json').write_text(json.dumps(backend,indent=2)+'\n')
            cmd+=['-blockdev',json.dumps(backend)]
        elif owned_ufs:
            cmd+=['-blockdev',json.dumps({'driver':'raw','node-name':'isolated-lun0',
                'file':{'driver':'file','filename':str(ufs_fixture)}})]
        else:
            cmd+=['-drive','if=none,id=isolated-lun0,format=raw,readonly='+('off' if owned_ufs else 'on')+',file='+str(ufs_fixture)]
        cmd+=['-device','ufs-lu,id=isolated-native-lun0,drive=isolated-lun0,lun=0']
        if a.fault_ufs_host_disable:
            test_socket_dir=tempfile.TemporaryDirectory(prefix='polaris-ufs-')
            socket_path=str(Path(test_socket_dir.name)/'qtest.sock')
            cmd+=['-qtest','unix:'+socket_path+',server=on,wait=off',
                  '-qtest-log',str(out/'qtest-fault.log')]
    start=time.monotonic();error=None
    with (out/'qemu.log').open('wb') as err:
        p=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=err)
        try:
            if 'QMP' not in json.loads(p.stdout.readline()):raise ValueError('QMP greeting absent')
            def q(command,args=None):
                request={'execute':command}
                if args is not None:request['arguments']=args
                p.stdin.write(json.dumps(request).encode()+b'\n');p.stdin.flush()
                while True:
                    response=json.loads(p.stdout.readline())
                    if 'event' in response:continue
                    if 'error' in response:raise RuntimeError(response['error'])
                    return response['return']
            q('qmp_capabilities')
            while time.monotonic()-start<a.seconds:
                text=(out/'serial.log').read_text(errors='replace') if (out/'serial.log').exists() else ''
                if (a.fault_ufs_host_disable and fault is None and
                        ('POLARIS OWNED TEST: actual WRITE10 and READ10 MATCH' if owned_ufs else
                         'POLARIS QEMU UFS: PASS native PCI/link/descriptor/completion/read') in text):
                    # Actual emulated hardware state changes, not kernel counters
                    # or an ACK substituted for a native completion result.
                    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
                        sock.settimeout(3);sock.connect(socket_path)
                        stream=sock.makefile('rwb',buffering=0)
                        def hardware(command):
                            stream.write(command.encode()+b'\n')
                            while True:
                                line=stream.readline().decode().strip()
                                if not line:raise RuntimeError('qtest hardware connection closed')
                                if line.startswith('IRQ'):continue
                                if not line.startswith('OK'):raise RuntimeError('qtest hardware request failed')
                                return line
                        before=hardware('readl 0x10100034')
                        if int(before.split()[1],0)!=1:raise ValueError('actual UFS HCE was not enabled')
                        ack=hardware('writel 0x10100034 0')
                        after=hardware('readl 0x10100034')
                        if int(after.split()[1],0)!=0:raise ValueError('actual HCE disable not observed')
                        fault=dict(kind='actual_UFS_HCE_disable_after_native_read',before=before,
                                   write_response=ack,after=after,seconds=time.monotonic()-start)
                        (out/'hardware-fault.json').write_text(json.dumps(fault,indent=2)+'\n')
                test_done=(('QEMU_OWNED_DURABLE_SAFE=1' in text or 'QEMU_OWNED_REFUSED=1' in text or
                            'QEMU_OWNED_RESET_PROTECTION_FAILED=1' in text or 'QEMU_OWNED_GUARD_ABSENT_REFUSED=1' in text) if owned_ufs else
                           ('QEMU_RAM_DRAINED=1' in text or 'QEMU_RAM_DRAIN_STALE_REFUSED=1' in text or
                            'QEMU_RAM_DRAIN_FAILED=1' in text or 'QEMU_RAM_PEER_OFF_REFUSED=1' in text) if drain else
                           ('SMP STRESS all4 PASS' in text and 'QEMU_INPUT_BRIDGE=1' in text))
                if count>1:
                    test_done=test_done and f'POLARIS SMP CHECK: PASS selected={count} callbacks={count*16} remote=' in text
                if ('panic(cpu ' in text or test_done or
                    'XNU_ADMISSION=0x8' in text or p.poll() is not None):break
                time.sleep(.2)
            if owned_ufs:
                # Record guest-caused accounting BEFORE host stop can add its
                # own flush. An observer flush must never prove guest durability.
                (out/'actual-blockstats.json').write_text(json.dumps(q('query-blockstats',{'query-nodes':True}),indent=2)+'\n')
                (out/'actual-backend-stats.json').write_text(json.dumps(q('query-blockstats'),indent=2)+'\n')
            if not a.fault_owned_write_delay:
                q('stop')
            # QMP stop itself flushes/drains block backends. In the unknown-DMA
            # experiment it would wait for (and complete) the deliberately held
            # request, destroying the pending-hardware observation. After sticky
            # FAILED, read the live immutable queue/status instead, then kill
            # only this synthetic model. No guest reset permission is granted.
            if virtual_ufs:
                if not owned_ufs:
                    (out/'actual-blockstats.json').write_text(json.dumps(q('query-blockstats',{'query-nodes':True}),indent=2)+'\n')
                    (out/'actual-backend-stats.json').write_text(json.dumps(q('query-blockstats'),indent=2)+'\n')
                (out/'actual-pci.json').write_text(json.dumps(q('query-pci'),indent=2)+'\n')
                (out/'actual-UFS-registers.txt').write_text(q('human-monitor-command',
                    {'command-line':'xp/40wx 0x10100000'}))
            (out/'registers.txt').write_text(q('human-monitor-command',{'command-line':'info registers -a'}))
            spec=importlib.util.spec_from_file_location('efi_build',root/'tools/build-polaris-uefi-xnu.py')
            builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
            raw=a.payload.read_bytes();va=struct.unpack_from('<Q',raw,16)[0];base=struct.unpack_from('<Q',raw,56)[0]
            syms=builder.symbols(a.kernel.read_bytes())
            q('pmemsave',{'val':base+syms['_sweet_log_ring']-va,'size':4<<20,'filename':str(out/'kernel-ring.bin')})
            if drain:
                q('pmemsave',{'val':base+syms['_polaris_uefi_shutdown']-va,'size':256,
                              'filename':str(out/'native-shutdown-mailbox.bin')})
            if owned_ufs:
                # Read actual stopped-guest native queue storage. These are
                # kernel Mach-O symbols, never supplied/modelled host counters.
                listing=subprocess.check_output(['/usr/bin/nm','-a',str(a.kernel)],text=True)
                addresses={line.split()[2]:int(line.split()[0],16) for line in listing.splitlines()
                           if len(line.split())==3 and line.split()[0]!='U'}
                queue={}
                for name,size in [('polaris_ufs_inflight',1),('polaris_ufs_sealed',1),
                                  ('polaris_ufs_submitted',8),('polaris_ufs_completed',8),
                                  ('polaris_owned_failed',1),('polaris_owned_active',1),
                                  ('polaris_owned_final_sync',1)]:
                    address=addresses['_'+name]-va
                    if not 0<=address<=manifest['RAM_bytes']-size:raise ValueError('native queue symbol outside owned RAM')
                    saved=out/(name+'.bin')
                    q('pmemsave',{'val':base+address,'size':size,'filename':str(saved)})
                    queue[name]=int.from_bytes(saved.read_bytes(),'little')
                (out/'actual-native-UFS-queue.json').write_text(json.dumps(queue,indent=2)+'\n')
            if a.fault_owned_write_delay:
                # Intentional teardown of a refused MODEL with unknown DMA.
                # This is not a guest shutdown/reset or a physical recovery.
                p.kill();p.wait(timeout=5)
            else:
                q('quit');p.wait(timeout=5)
        except Exception as e:error=str(e)
        finally:
            if p.poll() is None:p.kill();p.wait()
            if test_socket_dir:test_socket_dir.cleanup()
    text=(out/'serial.log').read_text(errors='replace') if (out/'serial.log').exists() else ''
    ring=(out/'kernel-ring.bin').read_bytes().split(b'\0')[0].decode(errors='replace') if (out/'kernel-ring.bin').exists() else ''
    (out/'kernel-ring.txt').write_text(ring)
    checks=dict(firmware_EL1='EFI_EL=0x0000000000000004' in text,
                firmware_CPU0='EFI_MPIDR=0x0000000080000000' in text,
                bank_owned='XNU_BANK_OWNERSHIP=0x0000000000000001' in text,
                payload_valid='QEMU_PAYLOAD_VALID=0x0000000000000001' in text,
                PSCI_target_matches=f'KERNEL_PSCI_TARGET=0x{target:016x}' in text,
                PSCI_success='KERNEL_PSCI_STATUS=0x0000000000000000' in text,
                live_RAM_log='SWEET: starting device-tree platform expert' in ring and 'SWEET: starting device-tree platform expert' in text)
    if a.legacy_core_refusal:
        checks['expected_legacy_guard']='invalid topology cpu=0 mpidr=0x1 count=1' in ring
    else:
        checks.update(boot_variable_snapshot='EFI_BOOT_OPTIONS_CAPTURE=0x0000000000000001' in text,
                      explicit_kernel_core_count=(f'POLARIS UEFI: one kernel CPU, logical0 physical{target:#x}; firmware CPU0 reserved' in ring if count==1 else
                          f'POLARIS UEFI: resident kernel CPUs={count} boot logical0 physical{target:#x}; firmware CPU0 reserved' in ring),
                      four_process_VM_stress='SMP STRESS all4 PASS' in ring,
                      each_child_passed=ring.count('SMP STRESS child PASS')==4,
                      bounded_input_handshake='QEMU_INPUT_BRIDGE=1' in text and 'POLARIS UEFI INPUT: seq=2 down=0' in ring,
                      no_panic='panic(cpu ' not in ring and 'panic(cpu ' not in text,
                      no_stress_failure='SMP STRESS FAIL' not in ring)
        if count>1:
            checks.update(both_kernel_CPUs_online=f'SWEET CPU: {count}/{count} CPUs initialized, SGI1 verified' in ring,
                          real_cross_core_callbacks=f'POLARIS SMP CHECK: PASS selected={count} callbacks={count*16} remote=' in ring)
    if count==4 and not a.legacy_core_refusal:
        checks['four_core_affinities_and_xcalls']=checks.get('both_kernel_CPUs_online') is True and checks.get('real_cross_core_callbacks') is True
    if manifest.get('CPU_OSM_readonly_inventory'):
        checks['native_OSM_probe_refused_before_virtual_MMIO']='POLARIS OSM RO: REFUSED platform; no MMIO' in ring and 'POLARIS OSM RO: bank' not in ring and 'POLARIS OSM REQUEST:' not in ring
    if manifest.get('CPU_OSM_stock_performance'):
        checks['native_stock_OSM_refused_before_virtual_RW']='POLARIS OSM PERF: REFUSED platform/mode; no RW mapping' in ring and 'POLARIS OSM PERF: armed' not in ring and 'POLARIS OSM RO: bank' not in ring
    if manifest.get('TSENS_readonly_inventory'):
        checks['native_TSENS_refused_before_virtual_MMIO']=('POLARIS TSENS RO: REFUSED platform/mode; no MMIO' in ring and 'POLARIS TSENS RO: armed' not in ring and 'POLARIS TSENS RAW:' not in ring)
        checks['native_TSENS_wire_core']=('POLARIS TSENS WIRE VM: PASS; actual native bounded core, synthetic reads only' in ring)
        checks['explicit_TSENS_readonly_payload']=([t for t in a.payload.read_bytes()[0x48:0x2a8].split(b'\0',1)[0].split() if t.startswith(b'polaristsens=')]==[b'polaristsens=1'])
        checks['native_future_display_deadline_probe']=('POLARIS PFB PRECISION VM: PASS; actual native callback, future deadlines only' in ring)
    if manifest.get('GPU_stock_request'):
        checks['native_GPU_stock_refused_before_virtual_MMIO']='POLARIS GPU STOCK: REFUSED platform/mode before GPU MMIO' in ring and 'POLARIS GPU STOCK: armed=' not in ring and 'POLARIS GPU STOCK SAMPLE:' not in ring
    if b'polarisgpuwctest=1' in a.payload.read_bytes()[0x48:0x2a8].split(b'\0',1)[0].split():
        checks['native_framebuffer_workloop_probe']=('POLARIS PFB VM: PASS callbacks=4 taken=3 empty=1 pokes=3 latest=201 error=0; actual native workloop, no panel/GPU' in ring)
    if manifest.get('physical_buttons'):
        checks['native_three_key_consumer']=('QEMU_PHYSICAL_KEY_CONSUMER=1' in text and
            'POLARIS KEYS: seq=7 changed=4 pressed=0' in ring and
            all(f'POLARIS KEYS: seq={n} changed={changed:x} pressed={pressed:x}' in ring
                for n,changed,pressed in [(2,1,1),(3,2,3),(4,4,7),(5,1,6),(6,2,4)]) and
            not any(f'POLARIS KEYS: stopped error={e};' in ring for e in (1,2,3)))
        checks['explicit_three_key_payload']=([t for t in a.payload.read_bytes()[0x48:0x2a8].split(b'\0',1)[0].split() if t.startswith(b'polarisbuttons=')]==[b'polarisbuttons=1'])
    if manifest.get('framebuffer_arrival_wake'):
        checks['explicit_framebuffer_wake_payload']=([t for t in a.payload.read_bytes()[0x48:0x2a8].split(b'\0',1)[0].split() if t.startswith(b'polarisfbwake=')]==[b'polarisfbwake=1'])
        checks['arrival_wake_native_probe_required']=checks.get('native_framebuffer_workloop_probe') is True
    if manifest.get('disk_payload_read_only'):
        checks.update(unique_GPT_filesystem='DISK_ESP_MATCHES=0x0000000000000001' in text,
                      disk_payload_exact_read=f'DISK_READ_BYTES=0x{manifest["payload_bytes"]:016x}' in text,
                      disk_files_closed_before_kernel='DISK_FILES_CLOSED=0x0000000000000002' in text,
                      disk_read_success='DISK_READ_STATUS=0x0000000000000000' in text)
    if manifest.get('chain_app'):
        checks.update(selected_disk_app_started='CHAIN_APP_START=0x0000000000000001' in text,
                      chain_file_handles_closed='CHAIN_FILES_CLOSED=0x0000000000000002' in text,
                      chain_loaded_success='CHAIN_LOAD_IMAGE=0x0000000000000000' in text,
                      selected_app_did_not_return='CHAIN_APP_RETURN=' not in text)
    mailbox=None
    if drain:
        saved=out/'native-shutdown-mailbox.bin';box=saved.read_bytes() if saved.exists() else b''
        if len(box)==256:
            request=struct.unpack_from('<QII',box)
            status=struct.unpack_from('<QIIIIQQI',box,128)
            mailbox=dict(request_cookie=request[0],request_sequence=request[1],request_mode=request[2],
                         cookie=status[0],sequence=status[1],mode=status[2],phase=status[3],
                         error=status[4],write_epoch=status[5],flushed_epoch=status[6],capabilities=status[7])
        checks['native_mailbox_captured']=mailbox is not None
        checks['native_request_after_VM_and_input']=('QEMU_OWNED_DRAIN_REQUESTED=1' if owned_ufs else 'QEMU_RAM_DRAIN_REQUESTED=1') in text
        if owned_ufs:
            refused=a.fault_ufs_host_disable or a.fault_owned_sync or a.fault_owned_write_delay or response_short or drain=='stale-cookie' or guard_omitted
            if response_short or a.fault_owned_write_delay or guard_omitted:
                checks.pop('native_request_after_VM_and_input') # Failed during WRITE before a shutdown request.
            checks.update(raw_and_lease_disabled_before_reset_permission='QEMU_OWNED_RAW_AND_LEASE_DISABLED=1' in text,
                          live_firmware_guard_observed_by_kernel='POLARIS OWNED GUARD: runtime generated=50470002 observed before PCI/MMIO' in ring,
                          owner_verified_through_native_UFS='POLARIS OWNED: actual UFS metadata verified inode=13 generation=305419896' in ring,
                          protected_base_descriptor_refused='POLARIS OWNED: protected-base WRITE refused before descriptor; submissions unchanged' in ring,
                          actual_owned_WRITE_submitted='POLARIS OWNED NATIVE: doorbell op=2a bytes=4096' in ring,
                          no_false_RAM_drained='QEMU_RAM_DRAINED=1' not in text,
                          no_reset_protection_failure='QEMU_OWNED_RESET_PROTECTION_FAILED=1' not in text)
            if guard_omitted:
                for key in ('owner_verified_through_native_UFS','protected_base_descriptor_refused','actual_owned_WRITE_submitted','live_firmware_guard_observed_by_kernel'):
                    checks.pop(key)
                checks.update(native_refused_before_PCI_MMIO='POLARIS QEMU UFS: REFUSED identity before any PCI/MMIO access' in ring,
                              no_PCI_or_owned_data_claim='POLARIS QEMU UFS: actual PCI' not in ring and 'POLARIS OWNED NATIVE: doorbell' not in ring,
                              firmware_no_guard_reset_refused='QEMU_OWNED_GUARD_ABSENT_REFUSED=1' in text,
                              no_write_or_SAFE_cookie=bool(mailbox and mailbox['cookie']==mailbox['phase']==mailbox['write_epoch']==mailbox['flushed_epoch']==mailbox['capabilities']==0))
            elif refused:
                checks.update(firmware_refused_both_reset_modes='QEMU_OWNED_REFUSED=1' in text,
                              no_durable_SAFE='QEMU_OWNED_DURABLE_SAFE=1' not in text and bool(mailbox and mailbox['phase']==6 and mailbox['error'] and mailbox['capabilities']==0 and mailbox['flushed_epoch']==0),
                              no_peer_OFF_claim='actual PSCI AFFINITY_OFF' not in ring)
                if a.fault_ufs_host_disable:checks['actual_HCE_loss_observed']=fault is not None
                if a.fault_owned_sync:
                    checks['real_native_final_SYNC_refused']=('POLARIS OWNED SYNC: native sealed final SYNCHRONIZE CACHE10 begin epoch=1' in ring and 'POLARIS OWNED SYNC: REFUSED error=' in ring and 'SWEET UFS: command 0x35 failed:' in ring)
                if response_short:
                    checks['controlled_completed_response_residual_refused']=('POLARIS OWNED FAULT: injected short UPIU after actual WRITE completion' in ring and 'POLARIS UFS: unexpected response flags/tag/residual' in ring)
                if a.fault_owned_write_delay:
                    checks['actual_native_WRITE_timeout']='SWEET UFS: command 0x2a timed out' in ring
                    regs=(out/'actual-UFS-registers.txt').read_text()
                    # UTRLDBR is offset0x58; independent hardware dump must retain bit0.
                    values=[]
                    for line in regs.splitlines():
                        if ':' in line:values += [int(v,16) for v in line.split(':',1)[1].split()]
                    checks['actual_doorbell_still_pending']=len(values)>22 and values[22]&1==1
                    checks['no_completed_write_or_readback_claim']='POLARIS OWNED TEST: actual WRITE10 and READ10 MATCH' not in ring
                if drain=='stale-cookie':checks['native_stale_cookie_refused']='POLARIS UEFI DRAIN: refused noncanonical/replayed request' in ring
            else:
                checks.update(actual_owned_READ_back='POLARIS OWNED TEST: actual WRITE10 and READ10 MATCH epoch=1' in ring,
                              real_native_final_SYNC_completed='POLARIS OWNED SYNC: actual completion epoch=1 flushed=1' in ring,
                              native_zero_mounts_busy='POLARIS UEFI DRAIN: actual VFS mounts=0 busy=0; owned file final UFS synchronization required' in ring,
                              native_peer_actual_OFF='POLARIS UEFI CPU DRAIN: logical1 physical0x6 actual PSCI AFFINITY_OFF' in ring,
                              firmware_observed_durable_SAFE='QEMU_OWNED_DURABLE_SAFE=1' in text,
                              exact_safe_mailbox=bool(mailbox and mailbox['cookie']==mailbox['request_cookie'] and mailbox['cookie'] and mailbox['sequence']==mailbox['request_sequence']==1 and mailbox['mode']==mailbox['request_mode']==2 and mailbox['phase']==5 and mailbox['error']==0 and mailbox['write_epoch']==mailbox['flushed_epoch']==1 and mailbox['capabilities']==0x1f))
        elif drain=='success' and a.fault_ufs_host_disable:
            checks.update(actual_hardware_fault_applied=fault is not None,
                          native_shutdown_entered='POLARIS UEFI DRAIN: accepted seq=1 mode=2' in ring,
                          real_zero_mounts_and_buffers='POLARIS UEFI DRAIN: actual VFS mounts=0 busy=0' in ring,
                          native_controller_seal_refused='POLARIS UEFI DRAIN: native UFS seal refused' in ring,
                          firmware_reset_both_modes_refused='QEMU_RAM_RESET_REFUSED=1' in text,
                          no_drain_or_SAFE_granted=bool(mailbox and mailbox['cookie']==mailbox['request_cookie'] and
                              mailbox['sequence']==mailbox['request_sequence']==1 and mailbox['mode']==2 and
                              mailbox['phase']==6 and mailbox['error'] and mailbox['capabilities']==0x80000000),
                          no_peer_stop_or_drained_claim='actual PSCI AFFINITY_OFF' not in ring and 'QEMU_RAM_DRAINED=1' not in text)
        elif drain=='success':
            checks.update(native_reboot_sync_path='POLARIS UEFI DRAIN: accepted seq=1 mode=2; calling reboot_kernel sync path' in ring,
                          real_zero_mounts_and_buffers='POLARIS UEFI DRAIN: actual VFS mounts=0 busy=0; RAM only, no UFS durability proof' in ring,
                          firmware_observed_RAM_drained='QEMU_RAM_DRAINED=1' in text,
                          separate_RAM_result=bool(mailbox and mailbox['cookie']==mailbox['request_cookie'] and
                              mailbox['cookie'] and mailbox['sequence']==mailbox['request_sequence']==1 and
                              mailbox['mode']==mailbox['request_mode']==2 and mailbox['phase']==3 and
                              mailbox['error']==mailbox['write_epoch']==mailbox['flushed_epoch']==0 and
                              mailbox['capabilities']==0x80000003))
            if count>1:
                checks['native_peer_affinity_OFF']=all(
                    f'POLARIS UEFI CPU DRAIN: logical{logical} physical{target-logical:#x} actual PSCI AFFINITY_OFF; coordinator logical0 physical{target:#x}' in ring
                    for logical in range(1,count))
        elif drain=='peer-refused':
            checks.update(native_shutdown_entered='POLARIS UEFI DRAIN: accepted seq=1 mode=2' in ring,
                          real_zero_mounts_and_buffers='POLARIS UEFI DRAIN: actual VFS mounts=0 busy=0' in ring,
                          native_peer_OFF_refused='POLARIS UEFI DRAIN: selected CPU quiesce refused' in ring,
                          actual_peer_still_ON='POLARIS UEFI CPU DRAIN: CPU_OFF returned/refused, actual affinity=0; no reset permission' in ring,
                          firmware_reset_refused='QEMU_RAM_PEER_OFF_REFUSED=1' in text,
                          no_safe_permission=bool(mailbox and mailbox['cookie']==mailbox['request_cookie'] and
                              mailbox['sequence']==mailbox['request_sequence']==1 and mailbox['mode']==2 and
                              mailbox['phase']==6 and mailbox['error'] and mailbox['capabilities']==0x80000000),
                          no_OFF_or_drained_claim='actual PSCI AFFINITY_OFF' not in ring and 'QEMU_RAM_DRAINED=1' not in text)
        else:
            checks.update(native_stale_request_rejected='POLARIS UEFI DRAIN: refused noncanonical/replayed request' in ring,
                          no_shutdown_entered='POLARIS UEFI DRAIN: accepted' not in ring,
                          firmware_observed_sticky_refusal='QEMU_RAM_DRAIN_STALE_REFUSED=1' in text,
                          no_drain_or_durable_permission=bool(mailbox and mailbox['cookie'] and
                              mailbox['cookie']!=mailbox['request_cookie'] and mailbox['phase']==6 and
                              mailbox['error'] and mailbox['sequence']==mailbox['mode']==0 and
                              mailbox['capabilities']==0x80000000))
    if virtual_ufs and not owned_ufs:
        checks.update(actual_native_UFS_read='POLARIS QEMU UFS: PASS native PCI/link/descriptor/completion/read; write gate unchanged' in ring,
                      actual_fixture_CRC=f'CRC32={zlib.crc32(bytes(range(256))*4096):08x} expected={zlib.crc32(bytes(range(256))*4096):08x} MATCH' in ring,
                      no_native_UFS_failure='POLARIS QEMU UFS: FAILED' not in ring,
                      isolated_backend_unchanged=sha(ufs_fixture)==ufs_before)
        if not a.fault_ufs_host_disable:
            checks['actual_native_UFS_sealed']='POLARIS UFS SEAL: owned idle native queue submitted=' in ring
    reopened=None
    if owned_ufs:
        reopened=owned_fixture.reopen_check(root,ufs_fixture,not (a.fault_owned_write_delay or guard_omitted),owned_variant)
        (out/'backend-reopen-proof.json').write_text(json.dumps(reopened,indent=2)+'\n')
        checks.update(full_backend_reopened_and_matched=reopened['all_LUN_bytes_match_expected'],
                      protected_base_byte_identical=reopened['protected_base_unchanged'],
                      no_unexpected_LUN_block_changes=reopened['changed_blocks']==reopened['expected_changed_blocks'],
                      original_fixture_source_unchanged=reopened['original_source_unchanged'])
        if owned_variant=='tail4' and not guard_omitted:
            checks['exact_filesystem_tail_bound']='POLARIS OWNED BOUNDS: GPT=32768 ext4=32764 unowned_tail=4' in ring
        stats=json.loads((out/'actual-backend-stats.json').read_text()) if (out/'actual-backend-stats.json').exists() else []
        stats=[s for s in stats if s.get('node-name')=='isolated-lun0' or s.get('device')=='isolated-lun0' or
               s.get('qdev','').startswith('/machine/peripheral/isolated-native-lun0/')]
        checks['exact_owned_backend_stats_captured']=len(stats)==1
        queue=json.loads((out/'actual-native-UFS-queue.json').read_text()) if (out/'actual-native-UFS-queue.json').exists() else {}
        if guard_omitted:
            checks['actual_native_queue_never_submitted']=bool(queue and queue['polaris_ufs_inflight']==0 and
                queue['polaris_ufs_submitted']==queue['polaris_ufs_completed']==0 and not queue['polaris_owned_active'])
        elif a.fault_owned_write_delay:
            checks['native_unknown_DMA_retained']=bool(queue and queue['polaris_ufs_inflight']==1 and
                queue['polaris_owned_failed']==1 and queue['polaris_ufs_submitted']==queue['polaris_ufs_completed']+1)
        else:
            checks['native_queue_actual_completions_balanced']=bool(queue and queue['polaris_ufs_inflight']==0 and
                queue['polaris_ufs_submitted']==queue['polaris_ufs_completed'] and queue['polaris_ufs_completed']>0)
        def stat_values(value,key):
            if isinstance(value,dict):
                if key in value:yield value[key]
                for child in value.values():yield from stat_values(child,key)
            elif isinstance(value,list):
                for child in value:yield from stat_values(child,key)
        if a.fault_owned_sync:
            checks['actual_backend_failed_flush_recorded']=any(v>0 for v in stat_values(stats,'failed_flush_operations'))
        elif not (a.fault_ufs_host_disable or a.fault_owned_write_delay or response_short or drain=='stale-cookie' or guard_omitted):
            checks['actual_backend_flush_completed']=any(v>0 for v in stat_values(stats,'flush_operations'))
    record=dict(passed=all(checks.values()) and error is None,checks=checks,error=error,
                diagnostic_legacy_only=a.legacy_core_refusal,release_handoff_admitted=not virtual_ufs and not a.legacy_core_refusal and drain!='peer-refused' and all(checks.values()) and error is None,
                full_iOS_boot_proven=False,physical_USB_proven=False,SDM845_emulated=False,
                RAM_native_drain_test=drain,native_shutdown_mailbox=mailbox,
                CPU_OSM_readonly_inventory=bool(manifest.get("CPU_OSM_readonly_inventory")),
                CPU_OSM_stock_performance=bool(manifest.get("CPU_OSM_stock_performance")),
                GPU_stock_request=manifest.get("GPU_stock_request",0),
                framebuffer_arrival_wake=manifest.get('framebuffer_arrival_wake',False),
                physical_buttons=manifest.get('physical_buttons',False),
                TSENS_readonly_inventory=manifest.get('TSENS_readonly_inventory',False),
                persistent_root_or_UFS_durability_proven=False,
                isolated_QEMU_readonly_UFS_test=virtual_ufs and not owned_ufs,
                isolated_QEMU_owned_UFS_test=owned_ufs,owned_backend_reopen=reopened,
                controlled_response_short_injection=response_short,
                controlled_durable_guard_omitted=guard_omitted,
                actual_backend_SYNC_EIO=a.fault_owned_sync,actual_backend_WRITE_delay=a.fault_owned_write_delay,
                snapshot_while_guest_running=a.fault_owned_write_delay,
                owned_backend_accounting_before_host_stop=bool(owned_ufs and (out/'actual-backend-stats.json').exists()),
                actual_native_queue=queue if owned_ufs else None,runner_sha256=sha(Path(__file__)),
                owned_fixture_helper_sha256=sha(root/'tools/polaris_owned_qemu_fixture.py') if owned_ufs else None,
                UFS_hardware_fault=fault,
                isolated_UFS_backend_sha256=sha(ufs_fixture) if ufs_fixture else None,
                kernel_CPU_affinity=target,
                kernel_CPU_count=count,
                app_sha256=sha(app),payload_sha256=sha(a.payload),kernel_sha256=sha(a.kernel),
                inputs=manifest['inputs'],seconds=time.monotonic()-start,command=cmd,
                code_sha256=sha(a.code),vars_template_sha256=sha(a.vars))
    record['disk_fixture']=disk_fixture
    (out/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({k:record[k] for k in ['passed','checks','diagnostic_legacy_only','seconds','error']},indent=2))
    return 0 if record['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
