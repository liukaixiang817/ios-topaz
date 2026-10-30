#!/usr/bin/env python3
"""Actual whole EFI-XNU terminal exchange; SOFTWARE PMIC/RAM USB sink only."""
import argparse,hashlib,importlib.util,json,re,shutil,struct,subprocess,time
from pathlib import Path
from polaris_wled_runtime_journal import journal,exit_footer,exit_receipt


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for n in ('driver-manifest','kernel','payload','output'):ap.add_argument('--'+n,type=Path,required=True)
    a=ap.parse_args();root=Path(__file__).resolve().parents[1];m=json.loads(a.driver_manifest.read_text());app=a.driver_manifest.parent/m['artifact']
    case=m.get('controlled_WLED_native_exit')
    if (case not in ('delayed-footer','lost-receipt-recovery') or m.get('QEMU_variant') is not True or
        m.get('WLED_native_runtime_test') is not True or m.get('WLED_native_runtime_physical') is not False or
        m.get('WLED_native_SOFTWARE_PMIC') is not True or m.get('WLED_atomic_exit_footer_max')!=212 or
        m.get('WLED_atomic_exit_receipt_bytes')!=60 or m.get('controlled_WLED_native_fault') or
        m.get('controlled_WLED_native_lifecycle') or m.get('controlled_WLED_native_start_refusal') or
        (sha(app),sha(a.kernel),sha(a.payload))!=(m['sha256'],m['kernel_sha256'],m['payload_sha256'])):
        raise ValueError('exact independent terminal fixture required')
    for n,digest in m['inputs'].items():
        p=(root/n).resolve()
        if root not in p.parents or sha(p)!=digest:raise ValueError('changed fixture input '+n)
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);esp=out/'esp/EFI/BOOT';esp.mkdir(parents=True)
    shutil.copyfile(app,esp/'BOOTAA64.EFI');shutil.copyfile(a.payload,out/'esp/PAYLOAD.BIN');shutil.copyfile('/opt/homebrew/share/qemu/edk2-arm-vars.fd',out/'vars.fd')
    cmd=['/opt/homebrew/bin/qemu-system-aarch64','-M','virt,gic-version=3,virtualization=off','-cpu','cortex-a55','-smp','8','-m','8G','-display','none','-monitor','none','-nic','none','-serial','file:'+str(out/'serial.log'),'-qmp','stdio','-no-reboot','-drive','if=pflash,format=raw,readonly=on,file=/opt/homebrew/share/qemu/edk2-aarch64-code.fd','-drive','if=pflash,format=raw,file='+str(out/'vars.fd'),'-drive','if=none,id=esp,format=raw,readonly=on,file=fat:ro:'+str(out/'esp'),'-device','virtio-blk-pci,drive=esp','-device','virtio-gpu-pci']
    began=time.monotonic();error=None;checks={};values={};attempts=[]
    with (out/'qemu.log').open('wb') as log:
        p=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log)
        try:
            if 'QMP' not in json.loads(p.stdout.readline()):raise ValueError('no QMP')
            def q(command,args=None):
                request={'execute':command}
                if args is not None:request['arguments']=args
                p.stdin.write(json.dumps(request).encode()+b'\n');p.stdin.flush()
                while True:
                    reply=json.loads(p.stdout.readline())
                    if 'event' in reply:continue
                    if 'error' in reply:raise ValueError(reply['error'])
                    return reply['return']
            q('qmp_capabilities');text=''
            while time.monotonic()-began<110:
                text=(out/'serial.log').read_text(errors='replace') if (out/'serial.log').exists() else ''
                if 'WLED_EXIT_MODEL_HOLD' in text or 'panic(cpu ' in text or p.poll() is not None:break
                time.sleep(.1)
            q('stop');values={k:int(v,16) for k,v in re.findall(r'([A-Z_0-9]+)=0x([0-9a-f]{16})',text)}
            # All source-native diagnostic pointers must lie in the actual loaded EFI allocation.
            image_base=values['EFI_IMAGE_BASE'];image_bytes=values['EFI_IMAGE_BYTES']
            def dump(name,address,size):
                if not 0<size<=4096 or not image_base<=address<=image_base+image_bytes-size:
                    raise ValueError('terminal evidence outside exact loaded image')
                q('pmemsave',{'val':address,'size':size,'filename':str(out/name)});return (out/name).read_bytes()
            spec=importlib.util.spec_from_file_location('builder',root/'tools/build-polaris-uefi-xnu.py');b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
            payload=a.payload.read_bytes();va,base=struct.unpack_from('<Q',payload,16)[0],struct.unpack_from('<Q',payload,56)[0];symbols=b.symbols(a.kernel.read_bytes())
            for name,symbol,size in [('shutdown.bin','_polaris_uefi_shutdown',256),('wled-mailbox.bin','_polaris_uefi_wled',256)]:
                q('pmemsave',{'val':base+symbols[symbol]-va,'size':size,'filename':str(out/name)})
            native=(out/'shutdown.bin').read_bytes();nc,ns,mode,phase,err,epoch,flushed,caps=struct.unpack_from('<QIIIIQQI',native,128)
            attempt_count=2 if case=='lost-receipt-recovery' else 1
            previous=None
            for at in range(attempt_count):
                pages=[]
                for n in range(3):
                    key=f'WLED_EXIT_P{at}{n}'
                    pages.append(dump(f'prefix-{at}-{n}.bin',values[key+'_ADDRESS'],values[key+'_BYTES']))
                prefix=journal(pages)
                if previous is not None and any(prefix[k]!=previous[k] for k in ('records','total','prefix_crc','cookie','issued','completed','request','ack','flags','fault_or','rt_or')):raise ValueError('recovery prefix omitted prior failed-delivery observations')
                footer=dump(f'footer-{at}.bin',values[f'WLED_EXIT_FOOTER{at}_ADDRESS'],values[f'WLED_EXIT_FOOTER{at}_BYTES'])
                reply=dump(f'reply-{at}.bin',values[f'WLED_EXIT_REPLY{at}_ADDRESS'],64)
                if reply[:4]!=b'OKAY':raise ValueError('actual reply not OKAY')
                sealed=exit_footer(footer,prefix,native_cookie=nc,native_sequence=ns,recover=bool(at))
                final=exit_receipt(reply[4:],sealed);attempts.append(dict(prefix=prefix,final=final,footer_sha256=sha(out/f'footer-{at}.bin'),reply_sha256=sha(out/f'reply-{at}.bin')));previous=final
            # Read the actual native ring, not only firmware's serial mirror.
            total_address=base+symbols['_sweet_log_total']-va
            q('pmemsave',{'val':total_address,'size':8,'filename':str(out/'kernel-total.bin')})
            total=struct.unpack('<Q',(out/'kernel-total.bin').read_bytes())[0]
            if not 0<total<=4<<20:raise ValueError('unbounded actual native log')
            q('pmemsave',{'val':base+symbols['_sweet_log_ring']-va,'size':total,'filename':str(out/'kernel-ring.bin')})
            ring=(out/'kernel-ring.bin').read_bytes().decode(errors='replace');(out/'kernel-ring.txt').write_text(ring)
            checks=dict(actual_EL1=values.get('XNU_ADMISSION')==0,actual_payload=values.get('QEMU_PAYLOAD_VALID')==1,
                actual_native_started='Darwin Kernel Version' in ring,
                native_workloop_three_actual_RAM_copies='POLARIS WLED NATIVE VM: PASS cycles=3 copies=3 seq=6 error=0;' in ring,
                actual_native_RAM_drain=bool(nc) and (ns,mode,phase,err,epoch,flushed,caps)==(1,2,3,0,0,0,0x80000003),
                actual_final_archive=previous['total']==(82 if attempt_count==2 else 80),
                no_additional_PMIC_WRITE=values.get('WLED_EXIT_FINAL_ISSUED')==values.get('WLED_EXIT_FINAL_COMPLETED')==12,
                original_errors_zero=values.get('WLED_EXIT_FINAL_ERROR')==0,
                footer_actual_delay_over_original_freshness=values.get('WLED_EXIT_DELAY_US',0)>=250000,
                actual_reset_observer_only_after_final_pair=values.get('WLED_EXIT_RESET_OBSERVED')==1,
                reset_arm_actual_guest_delay=values.get('RESET_ARM_ENDED_US',0)-values.get('RESET_ARM_BEGAN_US',0)>=250000,
                reset_checked_after_new_pair=previous['records'][-1]['ended_us']<=values.get('RESET_FINAL_CHECK_US',0)<=previous['records'][-1]['ended_us']+200000,
                bounded_attempts=values.get('WLED_EXIT_ATTEMPTS')==attempt_count,
                expected_first_delivery=values.get('WLED_EXIT_FIRST_RESULT')==int(attempt_count==1),
                failed_delivery_no_reset=attempt_count==1 or values.get('WLED_EXIT_FAILED_NO_RESET')==1,
                explicit_readonly_recovery=attempt_count==1 or values.get('WLED_EXIT_RECOVERY_RESULT')==1,
                complete_literal_raw_prefix_footer_receipt=True,no_panic='panic(cpu ' not in text and 'panic(cpu ' not in ring
            )
            if not all(checks.values()):raise ValueError('actual native exit checks failed: '+','.join(k for k,v in checks.items() if not v))
        except Exception as e:error=str(e)
        finally:
            p.terminate()
            try:p.wait(timeout=3)
            except subprocess.TimeoutExpired:p.kill();p.wait()
    result=dict(passed=error is None and bool(checks) and all(checks.values()),checks=checks,error=error,seconds=time.monotonic()-began,
        controlled_exit=case,attempts=attempts,raw_fields=values,inputs=m['inputs'],driver_manifest_sha256=sha(a.driver_manifest),
        driver_sha256=sha(app),runner_sha256=sha(Path(__file__)),SOFTWARE_PMIC=True,RAM_USB_sink=True,physical_USB_or_PMIC_emulation=False,physical_admission=False,actual_guest_reset_proven=False)
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:result[k] for k in ('passed','error','seconds')}))
    if not result['passed']:raise SystemExit(1)


if __name__=='__main__':main()
