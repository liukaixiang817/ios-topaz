#!/usr/bin/env python3
"""Build a RAM-only resident EFI/XNU driver, never install or boot it.

QEMU mode is explicitly separate: virt has different RAM/CPU affinities and
cannot validate the Qualcomm peripheral implementation or physical DDR map.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import uuid
import zlib


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def symbols(raw):
    if len(raw)<32 or raw[:4]!=b'\xcf\xfa\xed\xfe':raise ValueError('requires kernel Mach-O')
    count,commands=struct.unpack_from('<II',raw,16)
    if count>4096 or commands>len(raw)-32:raise ValueError('invalid Mach-O commands')
    at=32;wanted={}
    for _ in range(count):
        kind,size=struct.unpack_from('<II',raw,at)
        if size<8 or size>32+commands-at:raise ValueError('invalid Mach-O command size')
        if kind==2:
            off,n,strings,bytes_=struct.unpack_from('<4I',raw,at+8)
            if n>(len(raw)-off)//16 or strings>len(raw) or bytes_>len(raw)-strings:raise ValueError('invalid symbol table')
            for i in range(n):
                name,typ,section,desc,value=struct.unpack_from('<IBBHQ',raw,off+16*i)
                if name>=bytes_ or typ&0xe0:continue
                end=raw.find(b'\0',strings+name,strings+bytes_)
                if end<0:raise ValueError('unterminated kernel symbol')
                text=raw[strings+name:end]
                if text in (b'_sweet_log_ring',b'_sweet_log_total',b'_polaris_uefi_input',b'_polaris_uefi_shutdown'):
                    if text.decode() in wanted:raise ValueError('duplicate log symbol')
                    wanted[text.decode()]=value
        at+=size
    if not {'_sweet_log_ring','_sweet_log_total'}<=set(wanted):raise ValueError('kernel RAM console symbols absent')
    return wanted


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--zig',required=True,type=Path)
    ap.add_argument('--kernel',required=True,type=Path)
    ap.add_argument('--payload',required=True,type=Path)
    ap.add_argument('--output',required=True,type=Path)
    ap.add_argument('--test-qemu',action='store_true')
    ap.add_argument('--test-qemu-ufs',action='store_true',
                    help='isolated read-only native virtual UFS; never a physical admission proof')
    ap.add_argument('--test-qemu-owned',action='store_true',
                    help='write only a newly copied synthetic owned-file UFS fixture; never phone admission')
    ap.add_argument('--test-owned-response-short',action='store_true',
                    help='QEMU-only software response-residual injection after real WRITE completion')
    ap.add_argument('--physical-owned-marker',action='store_true',
                    help='separately admitted physical8MiB marker; original root stays RAM COW')
    ap.add_argument('--test-omit-durable-guard',action='store_true',
                    help='QEMU-only old-loader mismatch: native owned writes must be refused before MMIO')
    ap.add_argument('--kernel-core',type=int,choices=(1,7),default=1,
                    help='boot XNU core: existing small CPU1 or opt-in big CPU7; firmware retains CPU0')
    ap.add_argument('--kernel-cpus',type=int,choices=(1,2),default=1,
                    help='one kernel core or opt-in CPU7+CPU6 pair; firmware CPU0 stays reserved')
    ap.add_argument('--test-ram-drain',choices=['success','stale-cookie','peer-refused'],
                    help='QEMU-only real BSD RAM drain experiment; never UFS durability proof')
    ap.add_argument('--ram-shutdown-bridge',action='store_true',
                    help='expose native RAM-only shutdown mailbox over resident USB')
    ap.add_argument('--efi-application',action='store_true',help='selected application, never ReadyToBoot interception')
    ap.add_argument('--disk-guid',type=uuid.UUID,help='exact GPT partition UUID for read-only disk payload')
    ap.add_argument('--disk-start-lba',type=int)
    ap.add_argument('--disk-blocks',type=int)
    ap.add_argument('--disk-version',default='V0061')
    ap.add_argument('--chain-app-manifest',type=Path,help='RAM test wrapper for the exact already-built selected disk app')
    a=ap.parse_args();r=Path(__file__).resolve().parents[1]
    target=a.kernel_core if a.test_qemu else a.kernel_core<<8
    if a.physical_owned_marker and (a.test_qemu or a.kernel_core!=7 or a.kernel_cpus!=2 or
                                    not a.ram_shutdown_bridge or a.chain_app_manifest):
        ap.error('physical marker requires physical CPU7+6 and its selected native shutdown bridge')
    if a.test_qemu_ufs and (not a.test_qemu or a.kernel_core!=7 or a.kernel_cpus!=2):
        ap.error('isolated virtual UFS requires explicit QEMU CPU7+6')
    if a.test_qemu_owned and (not a.test_qemu_ufs or a.test_ram_drain not in ('success','stale-cookie') or
                              a.disk_guid or a.chain_app_manifest or a.efi_application):
        ap.error('owned virtual fixture requires isolated QEMU UFS and native drain without disk/chain mode')
    if a.test_owned_response_short and not a.test_qemu_owned:
        ap.error('controlled response injection requires isolated owned-file mode')
    if a.test_omit_durable_guard and (not a.test_qemu_owned or a.test_owned_response_short):
        ap.error('guard-omission injection requires the isolated owned QEMU test alone')
    if a.kernel_cpus==2 and a.kernel_core!=7:ap.error('two-core trial requires the CPU7+CPU6 pair')
    if a.test_ram_drain=='peer-refused' and a.kernel_cpus!=2:
        ap.error('peer refusal injection requires the explicit two-core QEMU test')
    if a.test_ram_drain and (not a.test_qemu or a.chain_app_manifest):
        ap.error('RAM drain experiment requires QEMU without a chain wrapper')
    if a.ram_shutdown_bridge and a.chain_app_manifest:
        ap.error('RAM shutdown bridge belongs to the selected loader, not its chain wrapper')
    if a.disk_guid is not None:
        if (a.disk_start_lba is None or a.disk_blocks is None or not 0<a.disk_start_lba<2**64 or
            not 0<a.disk_blocks<2**64-a.disk_start_lba):ap.error('disk identity requires valid start and block count')
        if len(a.disk_version)!=5 or a.disk_version[0]!='V' or not a.disk_version[1:].isascii() or not a.disk_version[1:].isdigit():
            ap.error('disk version must be V plus four ASCII digits')
    elif a.efi_application or a.disk_start_lba is not None or a.disk_blocks is not None:
        ap.error('selected application requires a complete disk identity')
    if a.chain_app_manifest and (not a.disk_guid or a.efi_application):ap.error('chain wrapper requires disk identity and no --efi-application')
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    raw=a.payload.read_bytes();k=a.kernel.read_bytes()
    sys.path.insert(0,str(r/'tools'));import mkpayload
    tokens=raw[0x48:0x2a8].split(b'\0',1)[0].split()
    if any(t.startswith(b'polarisdurableguard=') for t in tokens):
        raise ValueError('durable guard must be produced by live resident firmware')
    if (a.physical_owned_marker or a.test_qemu_owned) and len(raw[0x48:0x2a8].split(b'\0',1)[0])+32>=608:
        raise ValueError('reserve space for runtime durable guard in final boot args')
    if [t for t in tokens if t.startswith(b'polarisownedmarker=')]!=([b'polarisownedmarker=1'] if a.physical_owned_marker else []):
        raise ValueError('physical marker must be uniquely bound to explicit firmware durable mode')
    if a.physical_owned_marker:
        for key,value in [('polarisfileroot','1'),('rootrw','1'),('polarisramcow','1'),('polarisrammb','512'),('ufsrw','0')]:
            if [t for t in tokens if t.startswith((key+'=').encode())]!=[(key+'='+value).encode()]:
                raise ValueError('physical marker requires unchanged512MiB RAM COW root and closed generic write gate')
    ufs_tokens=[t for t in tokens if t.startswith(b'polarisqemuufs=')]
    if ufs_tokens!=([b'polarisqemuufs=1'] if a.test_qemu_ufs else []):
        raise ValueError('virtual UFS must be explicitly and uniquely bound to a QEMU-only test')
    for key,enabled in [('polarisqemuowned',a.test_qemu_owned),('polarisownedfault',a.test_owned_response_short)]:
        if [t for t in tokens if t.startswith((key+'=').encode())]!=([(key+'=1').encode()] if enabled else []):
            raise ValueError('owned-file opt-in/injection must be uniquely bound to its isolated QEMU test')
    off_tokens=[t for t in tokens if t.startswith(b'polarisofftest=')]
    if off_tokens!=([b'polarisofftest=1'] if a.test_ram_drain=='peer-refused' else []):
        raise ValueError('peer refusal injection must be uniquely bound to its QEMU-only test')
    cpu_tokens=[t for t in tokens if t.startswith(b'polarisbootcpu=')]
    if cpu_tokens!=[f'polarisbootcpu={target}'.encode()]:
        raise ValueError('payload must uniquely declare the exact selected kernel core')
    if [t for t in tokens if t.startswith(b'cpus=')]!=[f'cpus={a.kernel_cpus}'.encode()]:
        raise ValueError('payload must uniquely declare the selected kernel CPU count')
    # Bind firmware PSCI target to the kernel's actual tree, not just a token.
    import polaris_uefi_cpu_tree
    if len(raw)<72:raise ValueError('payload header truncated')
    tree_at,tree_bytes=struct.unpack_from('<QQ',raw,32)
    if tree_at>len(raw) or not 8<=tree_bytes<=len(raw)-tree_at:
        raise ValueError('CPU tree source outside payload')
    tree=polaris_uefi_cpu_tree.validate(raw[tree_at:tree_at+tree_bytes],a.kernel_core,a.test_qemu,a.kernel_cpus)
    if any(n.name=='polaris-qemu-ufs' for n in tree.children)!=a.test_qemu_ufs:
        raise ValueError('virtual UFS opt-in does not match the actual tree')
    if any(n.name=='polaris-qemu-owned-file' for n in tree.children)!=a.test_qemu_owned:
        raise ValueError('owned-file opt-in does not match the actual tree')
    if any(n.name=='polaris-owned-marker' for n in tree.children)!=a.physical_owned_marker:
        raise ValueError('physical marker opt-in does not match the actual tree')
    kernel=bytearray(k);m=mkpayload.parse_macho(kernel);mkpayload.apply_chained_fixups(kernel,m)
    va=struct.unpack_from('<Q',raw,16)[0]
    if va!=m['segs'][0]['vmaddr']&~0x1ffffff:raise ValueError('payload virtual base mismatch')
    n=struct.unpack_from('<I',raw,12)[0]
    if n>64 or len(raw)<0x2a8+32*n:raise ValueError('invalid payload segment table')
    segs=[struct.unpack_from('<4Q',raw,0x2a8+32*i) for i in range(n)]
    for s in m['segs']:
        if not s['vmsize']:continue
        matches=[row for row in segs if row[:2]==(s['vmaddr'],s['vmsize'])]
        if len(matches)!=1:raise ValueError('payload kernel segment mismatch')
        _,_,off,size=matches[0]
        if off>len(raw) or size>len(raw)-off or size!=s['filesize'] or raw[off:off+size]!=kernel[s['fileoff']:s['fileoff']+size]:
            raise ValueError('payload does not contain this rebased kernel')
    syms=symbols(k);log=syms['_sweet_log_ring']-va;total=syms['_sweet_log_total']-va
    end=struct.unpack_from('<Q',raw,48)[0]-va
    if not 0<=log<=end-(4<<20) or not 0<=total<=end-8:raise ValueError('log symbols outside kernel ownership')
    input_offset=syms.get('_polaris_uefi_input',va)-va;input_present='_polaris_uefi_input' in syms
    if input_present and (input_offset%128 or not 0<=input_offset<=end-256):raise ValueError('invalid input mailbox address')
    if not a.test_qemu and not input_present:raise ValueError('physical trial requires the bounded input kernel')
    shutdown_offset=syms.get('_polaris_uefi_shutdown',va)-va
    shutdown_bridge=a.ram_shutdown_bridge or bool(a.test_ram_drain)
    if shutdown_bridge:
        tokens=raw[0x48:0x2a8].split(b'\0',1)[0].split()
        if tokens.count(b'polarisquiesce=1')!=1 or any(
                t.startswith(b'polarisquiesce=') and t!=b'polarisquiesce=1' for t in tokens):
            raise ValueError('RAM drain experiment requires explicit unique kernel opt-in')
        if ('_polaris_uefi_shutdown' not in syms or shutdown_offset%128 or
                not 0<=shutdown_offset<=end-256 or not input_present or
                abs(shutdown_offset-input_offset)<256):
            raise ValueError('invalid independent shutdown mailbox symbol')
    # Run the exact C copy-plan admission function before emitting an EFI image.
    lib=out/'payload-validator.dylib';flags=['-DPOLARIS_EFI_TEST_QEMU=1'] if a.test_qemu else []
    subprocess.run(['/usr/bin/clang','-shared','-fPIC',*flags,str(r/'shim/polaris/payload.c'),'-o',str(lib)],check=True)
    class Plan(ctypes.Structure):_fields_=[(x,ctypes.c_uint64) for x in ['adt','args','top','entry']]
    fn=ctypes.CDLL(str(lib)).polaris_payload_check
    fn.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_uint64,ctypes.POINTER(Plan)];fn.restype=ctypes.c_char_p
    buf=ctypes.create_string_buffer(raw);plan=Plan();error=fn(buf,len(raw),0x100000000,ctypes.byref(plan))
    if error:raise ValueError(error.decode())
    config=out/'uefi-xnu-config.h'
    config.write_text(f'''#define EFI_XNU_PAYLOAD_BYTES {len(raw)}u
#define EFI_XNU_PAYLOAD_CRC32 0x{zlib.crc32(raw):08x}u
#define EFI_XNU_LOG_OFFSET 0x{log:x}ULL
#define EFI_XNU_LOG_TOTAL_OFFSET 0x{total:x}ULL
#define EFI_XNU_LOG_SIZE (4u*1024u*1024u)
#define EFI_XNU_INPUT_AVAILABLE {int(input_present)}
#define EFI_XNU_INPUT_OFFSET 0x{input_offset:x}ULL
#define EFI_XNU_CPU {target}u
#define EFI_XNU_BOOT_CPU_TOKEN "polarisbootcpu={target}"
#define EFI_XNU_CPUS_TOKEN "cpus={a.kernel_cpus}"
''')
    if shutdown_bridge:
        with config.open('a') as f:
            f.write('#define EFI_XNU_SHUTDOWN_BRIDGE 1\n')
            f.write(f'#define EFI_XNU_SHUTDOWN_OFFSET 0x{shutdown_offset:x}ULL\n')
            if a.test_ram_drain:
                mode={'success':1,'stale-cookie':2,'peer-refused':3}[a.test_ram_drain]
                f.write(f'#define EFI_XNU_RAM_DRAIN_TEST {mode}\n')
            if a.test_qemu_owned:f.write('#define EFI_XNU_OWNED_TEST 1\n')
            if a.test_omit_durable_guard:f.write('#define EFI_XNU_TEST_OMIT_OWNED_GUARD 1\n')
            if a.physical_owned_marker:f.write('#define EFI_XNU_PHYSICAL_MARKER 1\n')
    disk_path=None
    if a.disk_guid:
        disk_path='\\EFI\\Polaris\\'+a.disk_version+'\\PAYLOAD.BIN'
        with config.open('a') as f:
            f.write('#define EFI_XNU_DISK_GUID {'+','.join(str(b) for b in a.disk_guid.bytes_le)+'}\n')
            f.write(f'#define EFI_XNU_DISK_START {a.disk_start_lba}ULL\n#define EFI_XNU_DISK_BLOCKS {a.disk_blocks}ULL\n')
            f.write('#define EFI_XNU_DISK_PATH {'+','.join(str(ord(c)) for c in disk_path)+',0}\n')
    chain=None
    if a.chain_app_manifest:
        child=json.loads(a.chain_app_manifest.read_text());child_file=a.chain_app_manifest.parent/child['artifact']
        if (child.get('selected_application') is not True or child.get('QEMU_variant')!=a.test_qemu or
            child.get('disk_guid')!=str(a.disk_guid) or child.get('disk_start_lba')!=a.disk_start_lba or
            child.get('disk_blocks')!=a.disk_blocks or child.get('disk_payload_path')!=disk_path or
            child.get('kernel_CPU_affinity')!=target or child.get('kernel_CPU_count',1)!=a.kernel_cpus or
            child.get('kernel_sha256')!=sha(a.kernel) or child.get('payload_sha256')!=sha(a.payload) or
            child.get('sha256')!=sha(child_file) or not 0<child_file.stat().st_size<2<<20):
            raise ValueError('chain requires matching selected application and exact disk/payload/kernel')
        image_bytes=child_file.read_bytes();pe=struct.unpack_from('<I',image_bytes,60)[0]
        if image_bytes[pe:pe+6]!=b'PE\0\0\x64\xaa' or struct.unpack_from('<H',image_bytes,pe+24+68)[0]!=10:
            raise ValueError('chain target must be AArch64 EFI_APPLICATION')
        chain=dict(manifest_sha256=sha(a.chain_app_manifest),artifact_path=str(child_file.resolve()),
                   sha256=sha(child_file),bytes=len(image_bytes),historical_inputs=child['inputs'])
        name='\\EFI\\Polaris\\'+a.disk_version+'\\PolarisIos.efi'
        with config.open('a') as f:
            f.write(f'#define EFI_XNU_CHAIN_BYTES {len(image_bytes)}u\n#define EFI_XNU_CHAIN_CRC32 0x{zlib.crc32(image_bytes):08x}u\n')
            f.write('#define EFI_XNU_CHAIN_PATH {'+','.join(str(ord(c)) for c in name)+',0}\n')
        flags.append('-DPOLARIS_EFI_CHAIN_APP=1')
    if a.efi_application:flags.append('-DPOLARIS_EFI_APPLICATION=1')
    sources=['uefi-xnu.c','uefi-xnu-ap.S','uefi-xnu-crc.c','payload.c','uefi-usb.c','uefi-usb-command.c','uefi-usb-control.c']
    inputs=['shim/polaris/'+n for n in sources]+['shim/polaris/uefi.h','shim/polaris/uefi-xnu.h','shim/polaris/uefi-usb.h','shim/polaris/uefi-memory.h','shim/polaris/uefi-reset.h','shim/polaris/uefi-file.h','shim/polaris/uefi-boot-options.h','shim/polaris/uefi-ram-lease.h','shim/polaris/payload.h','tools/build-polaris-uefi-xnu.py','tools/polaris-uefi-input.h']
    inputs+=['tools/polaris_uefi_cpu_tree.py','tools/adt.py']
    inputs.append('shim/polaris/runtime-marker.h')
    if shutdown_bridge:inputs.append('shim/polaris/runtime-quiesce.h')
    objects=[]
    for source in sources:
        obj=out/(Path(source).stem+'.obj');objects.append(str(obj))
        cmd=['/usr/bin/clang','--target=aarch64-unknown-windows','-ffreestanding','-fno-builtin','-fno-stack-protector','-fshort-wchar','-mgeneral-regs-only','-O2','-Wall','-Wextra','-Werror',*flags,'-I'+str(out),'-c',str(r/'shim/polaris'/source),'-o',str(obj)]
        p=subprocess.run(cmd,capture_output=True);(out/(source+'.log')).write_bytes(p.stdout+p.stderr)
        if p.returncode:raise RuntimeError('EFI module compile failed: '+source)
    application=a.test_qemu or a.efi_application
    image=out/('PolarisXnuTest.efi' if a.test_qemu else 'PolarisIos.efi' if application else 'PolarisChainDxe.efi' if chain else 'PolarisXnuDxe.efi')
    env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(out/'zig-global'),ZIG_LOCAL_CACHE_DIR=str(out/'zig-local'))
    p=subprocess.run([str(a.zig.resolve()),'build-exe',*objects,'-target','aarch64-uefi','--subsystem','efi_application' if application else 'efi_boot_service_driver','-O','ReleaseSmall','-femit-bin='+str(image)],env=env,capture_output=True)
    (out/'link.log').write_bytes(p.stdout+p.stderr)
    if p.returncode:raise RuntimeError('EFI link failed')
    manifest=dict(artifact=image.name,sha256=sha(image),bytes=image.stat().st_size,
                  kernel_sha256=sha(a.kernel),payload_sha256=sha(a.payload),payload_bytes=len(raw),
                  payload_crc32=zlib.crc32(raw),payload_C_admission=True,rebased_kernel_bytes_match=True,
                  RAM_only_XNU_loader=not a.physical_owned_marker,kernel_handoff=True,storage_write_api=False,NVRAM_write_api=False,
                  original_root_writes_volatile=True,physical_small_file_write_test=a.physical_owned_marker,
                  reset_commands=True,reset_commands_hardware_tested=False,ready_to_boot_driver=not application,
                  RAM_host_idle_recovery_seconds=None if (a.test_qemu_owned or a.physical_owned_marker) else 1800,
                  selected_application=a.efi_application,disk_payload_read_only=bool(a.disk_guid),
                  disk_guid=str(a.disk_guid) if a.disk_guid else None,disk_start_lba=a.disk_start_lba,
                  disk_blocks=a.disk_blocks,disk_payload_path=disk_path,
                  chain_app=chain,
                  bounded_input=input_present,input_offset=input_offset,
                  RAM_native_drain_test=a.test_ram_drain,RAM_native_shutdown_bridge=shutdown_bridge,
                  shutdown_offset=shutdown_offset if shutdown_bridge else None,
                  persistent_root_or_UFS_durability_proven=False,
                  QEMU_variant=a.test_qemu,phone_compatible=not a.test_qemu,
                  isolated_QEMU_readonly_UFS_test=a.test_qemu_ufs and not a.test_qemu_owned,
                  isolated_QEMU_owned_UFS_test=a.test_qemu_owned,
                  controlled_owned_response_short_injection=a.test_owned_response_short,
                  raw_reset_requires_durable_SAFE=a.test_qemu_owned or a.physical_owned_marker,
                  physical_owned_marker_test=a.physical_owned_marker,
                  controlled_durable_guard_omitted=a.test_omit_durable_guard,
                  durable_guard_generated_after_reset_disabled=a.test_qemu_owned or a.physical_owned_marker,
                  kernel_CPU_affinity=target,
                  kernel_CPU_count=a.kernel_cpus,
                  RAM_base=0x130000000 if a.test_qemu else 0x180000000,RAM_bytes=0xfc8a0000,
                  firmware_core_reserved=0,firmware_services_exited=False,
                  device_execution_tested=False,inputs={p:sha(r/p) for p in inputs})
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({k:manifest[k] for k in ['artifact','sha256','bytes','QEMU_variant','device_execution_tested']}))


if __name__=='__main__':main()
