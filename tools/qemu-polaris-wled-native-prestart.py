#!/usr/bin/env python3
"""Actual EFI native-runtime pre-CPU refusal, RAM receipt only.

SOFTWARE PMIC/virt machine. No physical image admission or hardware emulation.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import time
from polaris_wled_runtime_journal import zero_write_receipt


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for n in ('driver-manifest','payload','kernel','output'):ap.add_argument('--'+n,type=Path,required=True)
    a=ap.parse_args();root=Path(__file__).resolve().parents[1]
    m=json.loads(a.driver_manifest.read_text());app=a.driver_manifest.parent/m['artifact']
    kind=m.get('controlled_WLED_native_start_refusal')
    if (kind not in ('owner','configuration','before-runtime') or m.get('QEMU_variant') is not True or
        m.get('WLED_native_runtime_test') is not True or m.get('WLED_native_runtime_physical') is not False or
        m.get('WLED_native_SOFTWARE_PMIC') is not True or m.get('controlled_WLED_native_fault') or
        m.get('controlled_WLED_native_lifecycle') or m.get('WLED_native_zero_write_receipt_bytes')!=40 or
        m.get('kernel_sha256')!=sha(a.kernel) or m.get('payload_sha256')!=sha(a.payload) or
        m.get('sha256')!=sha(app)):
        raise ValueError('not the independent current-source prestart fixture')
    for name,digest in m['inputs'].items():
        p=(root/name).resolve()
        if root not in p.parents or sha(p)!=digest:raise ValueError('changed exact EFI input')
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    esp=out/'esp/EFI/BOOT';esp.mkdir(parents=True);shutil.copyfile(app,esp/'BOOTAA64.EFI')
    shutil.copyfile(a.payload,out/'esp/PAYLOAD.BIN')
    shutil.copyfile('/opt/homebrew/share/qemu/edk2-arm-vars.fd',out/'vars.fd')
    cmd=['/opt/homebrew/bin/qemu-system-aarch64','-M','virt,gic-version=3,virtualization=off',
         '-cpu','cortex-a55','-smp','8','-m','8G','-display','none','-monitor','none','-nic','none',
         '-serial','file:'+str(out/'serial.log'),'-qmp','stdio','-no-reboot',
         '-drive','if=pflash,format=raw,readonly=on,file=/opt/homebrew/share/qemu/edk2-aarch64-code.fd',
         '-drive','if=pflash,format=raw,file='+str(out/'vars.fd'),
         '-drive','if=none,id=esp,format=raw,readonly=on,file=fat:ro:'+str(out/'esp'),
         '-device','virtio-blk-pci,drive=esp','-device','virtio-gpu-pci']
    began=time.monotonic();checks={};raw={};error=None;decoded=None
    with (out/'qemu.log').open('wb') as log:
        p=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log)
        try:
            if 'QMP' not in json.loads(p.stdout.readline()):raise ValueError('QMP greeting missing')
            def q(command,args=None):
                request={'execute':command}
                if args is not None:request['arguments']=args
                p.stdin.write(json.dumps(request).encode()+b'\n');p.stdin.flush()
                while True:
                    response=json.loads(p.stdout.readline())
                    if 'event' in response:continue
                    if 'error' in response:raise ValueError(response['error'])
                    return response['return']
            q('qmp_capabilities')
            while time.monotonic()-began<45:
                text=(out/'serial.log').read_text(errors='replace') if (out/'serial.log').exists() else ''
                if 'WLED_NATIVE_ZERO_MODEL_HOLD' in text or p.poll() is not None:break
                time.sleep(.1)
            q('stop');raw={k:int(v,16) for k,v in re.findall(r'([A-Z_0-9]+)=0x([0-9a-f]{16})',text)}
            address=raw.get('WLED_NATIVE_ZERO_RECEIPT_ADDRESS',0)
            if not address or raw.get('WLED_NATIVE_ZERO_RECEIPT_BYTES')!=40:raise ValueError('actual receipt absent')
            q('pmemsave',{'val':address,'size':40,'filename':str(out/'actual-zero-write-receipt.bin')})
            decoded=zero_write_receipt((out/'actual-zero-write-receipt.bin').read_bytes())
            spec=importlib.util.spec_from_file_location('builder',root/'tools/build-polaris-uefi-xnu.py')
            b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
            payload=a.payload.read_bytes();va,base=struct.unpack_from('<Q',payload,16)[0],struct.unpack_from('<Q',payload,56)[0]
            symbols=b.symbols(a.kernel.read_bytes());memory={}
            for name,at in (('AP_stage',raw.get('WLED_NATIVE_ZERO_AP_ADDRESS',0)),
                            ('kernel_log_total',base+symbols['_sweet_log_total']-va)):
                if not at or at&7:raise ValueError('unaligned actual no-CPU witness')
                reply=q('human-monitor-command',{'command-line':f'xp /1gx {at:#x}'})
                match=re.fullmatch(r'\s*(?:0x)?([0-9a-f]+):\s*(0x[0-9a-f]+)\s*',reply)
                if not match or int(match[1],16)!=at:raise ValueError('unreadable actual no-CPU witness')
                memory[name]=int(match[2],16)
            (out/'actual-memory.json').write_text(json.dumps(memory,indent=2)+'\n')
            checks=dict(actual_EL1=raw.get('XNU_ADMISSION')==0,actual_payload=raw.get('QEMU_PAYLOAD_VALID')==1,
                mode1_refused=raw.get('WLED_NATIVE_ZERO_MODE1_REFUSED')==1,
                mode2_ready=raw.get('WLED_NATIVE_ZERO_MODE2_READY')==1,
                one_shot=raw.get('WLED_NATIVE_ZERO_ONCE_REFUSED')==1,
                fresh=raw.get('WLED_NATIVE_ZERO_FRESH')==1,
                no_CPU_issued=raw.get('WLED_NATIVE_ZERO_CPU_ISSUED')==0,
                actual_AP_stage_zero=memory['AP_stage']==raw.get('WLED_NATIVE_ZERO_AP_STAGE')==0,
                actual_kernel_log_zero=memory['kernel_log_total']==0,
                zero_WRITE=raw.get('WLED_NATIVE_ZERO_ISSUED')==raw.get('WLED_NATIVE_ZERO_COMPLETED')==raw.get('WLED_NATIVE_ZERO_UNCERTAIN')==0,
                actual_error_retained=decoded['error']==raw.get('WLED_NATIVE_ZERO_ERROR')=={'owner':32,'configuration':66,'before-runtime':0}[kind],
                no_native_start_or_PSCI='Darwin Kernel Version' not in text and 'KERNEL_PSCI_STATUS=' not in text,
                no_panic='panic(cpu ' not in text,actual_receipt_decoded=True)
            if not all(checks.values()):raise ValueError('actual EFI prestart checks failed')
        except Exception as e:error=str(e)
        finally:
            p.terminate()
            try:p.wait(timeout=3)
            except subprocess.TimeoutExpired:p.kill();p.wait()
    result=dict(passed=error is None and bool(checks) and all(checks.values()),error=error,checks=checks,
        controlled_refusal=kind,seconds=time.monotonic()-began,raw_fields=raw,receipt=decoded,
        SOFTWARE_PMIC=True,physical_or_USB_emulation=False,physical_admission=False,
        native_drain_proven=False,inputs=m['inputs'],driver_manifest_sha256=sha(a.driver_manifest),
        driver_sha256=sha(app),runner_sha256=sha(Path(__file__)))
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:result[k] for k in ('passed','error','seconds')}))
    if not result['passed']:raise SystemExit(1)


if __name__=='__main__':main()
