#!/usr/bin/env python3
"""Actual pre-XNU power-cycle adapter, software PMIC only; never phone admission alone."""
import argparse,hashlib,importlib.util,json,re,shutil,struct,subprocess,time
from pathlib import Path

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('driver-manifest','kernel','payload','output'):ap.add_argument('--'+name,required=True,type=Path)
    ap.add_argument('--qemu',type=Path,default=Path('/opt/homebrew/bin/qemu-system-aarch64'))
    ap.add_argument('--code',type=Path,default=Path('/opt/homebrew/share/qemu/edk2-aarch64-code.fd'))
    ap.add_argument('--vars',type=Path,default=Path('/opt/homebrew/share/qemu/edk2-arm-vars.fd'))
    a=ap.parse_args();root=Path(__file__).resolve().parents[1];m=json.loads(a.driver_manifest.read_text());app=a.driver_manifest.parent/m['artifact']
    if (m.get('QEMU_variant') is not True or m.get('WLED_power_cycle_only') is not True or m.get('WLED_readonly_inventory_only') is not False or
        m.get('kernel_CPU_ON_compiled_out') is not True or m.get('kernel_handoff') is not False or
        m.get('storage_write_api') is not False or m.get('NVRAM_write_api') is not False or m.get('PMIC_write_api') is not True or
        m.get('physical_buttons') is not True or m.get('kernel_CPU_affinity')!=7 or m.get('kernel_CPU_count')!=4 or
        m.get('sha256')!=sha(app) or m.get('payload_sha256')!=sha(a.payload) or m.get('kernel_sha256')!=sha(a.kernel)):
        raise ValueError('explicit source-bound QEMU-only pre-XNU inventory required')
    for name,digest in m['inputs'].items():
        if sha(root/name)!=digest:raise ValueError('inventory source changed: '+name)
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);esp=out/'esp/EFI/BOOT';esp.mkdir(parents=True)
    shutil.copyfile(app,esp/'BOOTAA64.EFI');shutil.copyfile(a.payload,out/'esp/PAYLOAD.BIN');shutil.copyfile(a.vars,out/'vars.fd')
    cmd=[str(a.qemu),'-M','virt,gic-version=3,virtualization=off','-cpu','cortex-a55','-smp','8','-m','8G',
         '-display','none','-monitor','none','-nic','none','-serial','file:'+str(out/'serial.log'),'-qmp','stdio','-no-reboot',
         '-drive','if=pflash,format=raw,readonly=on,file='+str(a.code),'-drive','if=pflash,format=raw,file='+str(out/'vars.fd'),
         '-drive','if=none,id=esp,format=raw,readonly=on,file=fat:ro:'+str(out/'esp'),
         '-device','virtio-blk-pci,drive=esp','-device','virtio-gpu-pci']
    began=time.monotonic();error=None;values={};actual={};text='';checks={}
    with (out/'qemu.log').open('wb') as log:
        p=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log)
        try:
            if 'QMP' not in json.loads(p.stdout.readline()):raise ValueError('no QMP greeting')
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
            while time.monotonic()-began<60:
                text=(out/'serial.log').read_text(errors='replace') if (out/'serial.log').exists() else ''
                if 'WLED_POWER_MODEL_HOLD: NO_CPU_ON' in text or p.poll() is not None:break
                time.sleep(.2)
            q('stop')
            values={k:int(v,16) for k,v in re.findall(r'([A-Z_0-9]+)=0x([0-9a-f]{16})',text)}
            address=values.get('WLED_AP_STAGE_ADDRESS',0)
            if not address or address&7:raise ValueError('actual AP stage address absent')
            spec=importlib.util.spec_from_file_location('loader',root/'tools/build-polaris-uefi-xnu.py');loader=importlib.util.module_from_spec(spec);spec.loader.exec_module(loader)
            symbols=loader.symbols(a.kernel.read_bytes());raw=a.payload.read_bytes();va=struct.unpack_from('<Q',raw,16)[0];base=struct.unpack_from('<Q',raw,56)[0]
            for name,pa in [('actual_AP_stage',address),('actual_kernel_log_total',base+symbols['_sweet_log_total']-va)]:
                line=q('human-monitor-command',{'command-line':f'xp /1gx {pa:#x}'});actual[name]=line
                # HMP xp prints bare hexadecimal addresses, unlike its values.
                match=re.fullmatch(r'\s*(?:0x)?([0-9a-f]+):\s*(0x[0-9a-f]+)\s*',line)
                if not match or int(match[1],16)!=pa or int(match[2],16)!=0:
                    raise ValueError('kernel/AP executed or snapshot unreadable: '+name)
            injected=m.get('controlled_WLED_write_timeout') is True
            oem=m.get('WLED_OEM_status_policy') is True
            status_injected=m.get('controlled_WLED_status_after_issue',0)
            if type(status_injected) is not int or not 0<=status_injected<=0xffff or (status_injected and (not oem or injected)):
                raise ValueError('incompatible status fault scope')
            refused=injected or bool(status_injected)
            expected_error=65 if status_injected else 36 if injected else 0
            checks={'firmware_EL1_admission':values.get('XNU_ADMISSION')==0,'exact_payload_valid':values.get('QEMU_PAYLOAD_VALID')==1,
                    'kernel_prepared_not_executed':'KERNEL_PREPARED_ENTRY=' in text and values.get('WLED_KERNEL_AP_STAGE')==0,
                    'no_PSCI_CPU_ON':'KERNEL_PSCI_STATUS=' not in text,
                    'mock_backend_explicit':values.get('WLED_POWER_MOCK_BACKEND')==1,
                    'preflight_succeeded':values.get('WLED_POWER_PREPARE_ERROR')==0,
                    'expected_final_error':values.get('WLED_POWER_FINAL_ERROR')==expected_error,
                    'expected_final_uncertainty':values.get('WLED_POWER_FINAL_UNCERTAIN')==int(refused),
                    'writes_issued_exactly':values.get('WLED_POWER_WRITES_ISSUED')==(1 if refused else 4),
                    'writes_completed_exactly':values.get('WLED_POWER_WRITES_COMPLETED')==(1 if status_injected else 0 if injected else 4),
                    'reset_gate':values.get('WLED_POWER_FINAL_RESET_ALLOWED')==int(not refused),
                    'off_readback_and_reset':refused or (values.get('WLED_POWER_OFF_MODULE')==0 and values.get('WLED_POWER_OFF_IRQ')==0 and values.get('WLED_POWER_OFF_RESET_REFUSED')==1),
                    'on_readback_after_two_seconds':refused or (values.get('WLED_POWER_RESTORED_MODULE')==0x80 and values.get('WLED_POWER_RESTORED_IRQ')==2 and values.get('WLED_POWER_RESTORED_US',0)-values.get('WLED_POWER_OFF_US',0)>=2000000),
                    'actual_AP_context_stage_zero':bool(actual.get('actual_AP_stage')),
                    'actual_kernel_log_total_zero':bool(actual.get('actual_kernel_log_total')),
                    'no_native_startup_log':'Darwin Kernel Version' not in text and 'POLARIS SMP CHECK:' not in text,
                    'no_panic':'panic(cpu ' not in text}
            if oem:
                words={int(k[len('WLED_POWER_W'):-len('_WORD')],16):v for k,v in values.items()
                       if re.fullmatch(r'WLED_POWER_W[0-9A-F]{2}_WORD',k)}
                checks.update(OEM_policy_explicit=values.get('WLED_POWER_OEM_STATUS_POLICY')==1,
                              retained_status_history=bool(words) and len(words)==values.get('WLED_POWER_WITNESS_COUNT'))
                if status_injected:
                    checks['serious_word_retained']=any((v&255)&(status_injected&255) or
                        ((v>>8)&255)&(status_injected>>8) for v in words.values())
                else:
                    checks['ILIM_history_not_discarded']=values.get('WLED_POWER_WITNESS_FAULT_OR')==1 and values.get('WLED_POWER_WITNESS_RT_OR')==1
        except Exception as e:error=str(e)
        finally:
            if p.poll() is None:p.terminate()
            try:p.wait(timeout=5)
            except subprocess.TimeoutExpired:p.kill();p.wait()
    result={'passed':bool(checks) and all(checks.values()) and error is None,'checks':checks,'error':error,'seconds':time.monotonic()-began,
            'driver_sha256':sha(app),'driver_manifest_sha256':sha(a.driver_manifest),'kernel_sha256':sha(a.kernel),'payload_sha256':sha(a.payload),
            'inputs':m['inputs'],'runner_sha256':sha(Path(__file__)),'raw_fields':values,'actual_guest_memory':actual,'controlled_write_timeout':m['controlled_WLED_write_timeout'],
            'WLED_power_cycle_only':True,'release_handoff_admitted':False,'actual_phone_or_PMIC_emulated':False,
            'WLED_OEM_status_policy':m.get('WLED_OEM_status_policy',False),
            'controlled_status_after_issue':m.get('controlled_WLED_status_after_issue',0),
            'kernel_CPU_started':False,'physical_PMIC_power_control_tested':False,'command':cmd}
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2));raise SystemExit(not result['passed'])
if __name__=='__main__':main()
