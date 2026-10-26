#!/usr/bin/env python3
"""Run the real probe under EDK2/QEMU. This is NOT a Qualcomm board emulator."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import time


def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--image',required=True,type=Path)
    ap.add_argument('--output',required=True,type=Path)
    ap.add_argument('--virtualization',choices=['on','off'],default='off')
    ap.add_argument('--expect-hold',action='store_true')
    ap.add_argument('--expect-usb-unavailable',action='store_true',help='USB-enabled driver must safely hold when QCOM protocol is absent')
    ap.add_argument('--usb-mock',action='store_true',help='test actual EFI driver through a fake QCOM protocol; no USB controller emulation')
    ap.add_argument('--qemu',default='/opt/homebrew/bin/qemu-system-aarch64')
    ap.add_argument('--code',type=Path,default=Path('/opt/homebrew/share/qemu/edk2-aarch64-code.fd'))
    ap.add_argument('--vars',type=Path,default=Path('/opt/homebrew/share/qemu/edk2-arm-vars.fd'))
    a=ap.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    esp=out/'esp/EFI/BOOT';esp.mkdir(parents=True)
    shutil.copyfile(a.image,esp/'BOOTAA64.EFI')
    varsfile=out/'vars.fd';shutil.copyfile(a.vars,varsfile)
    serial=out/'serial.log';stderr=out/'qemu.log'
    cmd=[a.qemu,'-machine','virt,gic-version=3,virtualization='+a.virtualization,'-cpu','cortex-a55',
         '-accel','tcg','-smp','1','-m','8G','-display','none','-monitor','none','-nic','none',
         '-serial','file:'+str(serial),'-no-reboot',
         '-drive','if=pflash,format=raw,readonly=on,file='+str(a.code.resolve()),
         '-drive','if=pflash,format=raw,file='+str(varsfile),
         '-drive','if=none,id=esp,format=raw,readonly=on,file=fat:ro:'+str(out/'esp'),
         '-device','virtio-blk-pci,drive=esp','-device','virtio-gpu-pci']
    began=time.monotonic();seen=False
    with stderr.open('wb') as log:
        p=subprocess.Popen(cmd,stdout=log,stderr=subprocess.STDOUT)
        try:
            while time.monotonic()-began<55:
                text=serial.read_text(errors='replace') if serial.exists() else ''
                marker=('POLARIS EFI HOLD: inventory only; no operating system started' if a.expect_hold else
                        'POLARIS EFI PROBE PASS: NO_DISK_WRITE NO_NVRAM_WRITE NO_XNU_JUMP')
                if a.expect_usb_unavailable:marker='USB_DIAG_RESULT=0x800000000000000e'
                if a.usb_mock:marker='USB_MOCK_PASS'
                if marker in text:
                    seen=True;break
                if 'USB_MOCK_FAIL' in text:break
                if p.poll() is not None:break
                time.sleep(.2)
        finally:
            if p.poll() is None:p.terminate()
            try:p.wait(timeout=5)
            except subprocess.TimeoutExpired:p.kill();p.wait()
    text=serial.read_text(errors='replace') if serial.exists() else ''
    fields={k:int(v,16) for k,v in re.findall(r'([A-Z_0-9]+)=0x([0-9a-f]{16})',text)}
    checks=dict(probe_returned_success=seen,expected_EL=fields.get('CURRENT_EL')==(8 if a.virtualization=='on' else 4),
                supports_16KiB=((fields.get('MMFR0',0)>>20)&15)==1,
                loaded_image=fields.get('LOADED_IMAGE_STATUS')==0,
                filesystem=fields.get('FS_STATUS')==0,
                memory_map=fields.get('MAP_STATUS')==0 and fields.get('MAP_DESCRIPTORS',0)>0,
                QCOM_USB_protocol_matches_case=fields.get('QCOM_USB_STATUS')==(0 if a.usb_mock else 0x800000000000000e))
    if a.expect_hold:
        checks['watchdog_disabled']=fields.get('WATCHDOG_DISABLE')==0
        checks['probe_completed_before_hold']=fields.get('PROBE_RESULT')==0
    if a.expect_usb_unavailable:checks['USB_absence_held_safely']=fields.get('USB_DIAG_RESULT')==0x800000000000000e
    if a.usb_mock:
        checks['USB_mock_log_map_screenshot_uploads']=fields.get('USB_MOCK_UPLOADS')==3
        checks['USB_mock_write_commands_rejected']=fields.get('USB_MOCK_WRITE_REJECTIONS')==2
        checks['USB_mock_cancelled_transfer_recovered']=fields.get('USB_MOCK_CANCEL_RECOVERY')==1
    record=dict(passed=all(checks.values()),checks=checks,fields=fields,seconds=time.monotonic()-began,
                image_sha256=digest(a.image),code_sha256=digest(a.code),initial_vars_sha256=digest(a.vars),
                qemu_version=subprocess.check_output([a.qemu,'--version'],text=True).splitlines()[0],
                CPU='cortex-a55',CPUs=1,RAM='8GiB',GIC=3,kernel_page_support='16KiB',
                board='QEMU virt; not SDM845',virtualization=a.virtualization,actual_phone_UEFI_tested=False,
                phone_device_access=False,phone_storage_writes=False,
                inventory_hold=a.expect_hold,kernel_handoff_tested=False,
                QCOM_protocol_mock=a.usb_mock,actual_USB_transport_tested=False,
                emulation_limits=['Qualcomm UFS','Qualcomm USB','RPMh/PMIC','phone physical memory map','Mindows firmware'],
                command=cmd)
    (out/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2));raise SystemExit(0 if record['passed'] else 1)


if __name__=='__main__':main()
