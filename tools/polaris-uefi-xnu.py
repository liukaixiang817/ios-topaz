#!/usr/bin/env python3
"""Control one explicitly bound RAM-only Polaris EFI/XNU trial.

No partition, filesystem, firmware-variable or generic fastboot commands.
Capture is a single log/screen snapshot, not the paused continuous observer.
The reboot acknowledgement means accepted, not proof of the resulting mode.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import time

from polaris_uefi_usb_transport import KernelProtocol, LibusbTransport


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()


def binding(boot, image, driver):
    if (boot.get('state')!='temporary_UEFI_XNU_boot_command_succeeded' or
        boot.get('image_sha256')!=image.get('sha256') or not boot.get('sent_utc') or
        not image.get('RAM_only_XNU_loader') or image.get('storage_write_api') is not False or
        image.get('NVRAM_write_api') is not False or
        image.get('driver_sha256')!=driver.get('sha256') or
        not driver.get('RAM_only_XNU_loader') or driver.get('QEMU_variant') is not False or
        driver.get('storage_write_api') is not False or driver.get('NVRAM_write_api') is not False):
        raise ValueError('not bound to a sent, physical, RAM-only EFI/XNU image')


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('action',choices=['state','capture','boot','reboot-normal','reboot-fastboot'])
    ap.add_argument('--libusb',required=True,type=Path)
    ap.add_argument('--boot-record',required=True,type=Path)
    ap.add_argument('--image-manifest',required=True,type=Path)
    ap.add_argument('--driver-manifest',required=True,type=Path)
    ap.add_argument('--payload',type=Path)
    ap.add_argument('--output',required=True,type=Path)
    ap.add_argument('--wait-seconds',type=int,default=0)
    a=ap.parse_args()
    if not 0<=a.wait_seconds<=600:ap.error('target discovery wait must be 0..600 seconds')
    if (a.action=='boot')!=(a.payload is not None):ap.error('--payload is required only for boot')
    boot=json.loads(a.boot_record.read_text());image=json.loads(a.image_manifest.read_text())
    driver=json.loads(a.driver_manifest.read_text());binding(boot,image,driver)
    raw=a.payload.read_bytes() if a.payload else None
    if raw is not None and (len(raw)!=driver.get('payload_bytes') or
                           hashlib.sha256(raw).hexdigest()!=driver.get('payload_sha256')):
        raise ValueError('payload changed since driver build; no device access attempted')
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    record=dict(started_utc=now(),sent_utc=boot['sent_utc'],image_sha256=image['sha256'],
                driver_sha256=driver['sha256'],action=a.action,continuous_observer=False,
                storage_writes=False,NVRAM_writes=False,errors=[],captures={},
                host_reader_sha256=sha(Path(__file__)),
                host_transport_sha256=sha(Path(__file__).with_name('polaris_uefi_usb_transport.py')))
    def save():
        target=out/'result.json';target.write_text(json.dumps(record,indent=2)+'\n');target.chmod(0o600)
    native=None;save()
    try:
        native=LibusbTransport(a.libusb);record['libusb_sha256']=sha(native.library)
        began=time.monotonic()
        while not native.open_target():
            if time.monotonic()-began>=a.wait_seconds:raise RuntimeError('synthetic UEFI endpoint not discovered')
            time.sleep(1)
        record['discovery_seconds']=time.monotonic()-began
        protocol=KernelProtocol(native);record['product']=protocol.product()
        record['state_before']=protocol.state();save()
        if a.action=='boot':
            protocol.stage_payload(raw,driver);record['payload_validated']=True;save()
            protocol.boot();record['kernel_command_acknowledged']=True;save()
            record['state_after']=protocol.state()
        elif a.action.startswith('reboot-'):
            protocol.reboot(a.action=='reboot-fastboot')
            record['reset_command_acknowledged']=True
            record['resulting_boot_mode_verified']=False
        elif a.action=='capture':
            # Reuse only offline parsers; this reader never starts the old observer.
            spec=importlib.util.spec_from_file_location('capture_format',Path(__file__).with_name('polaris-uefi-usb-read.py'))
            formats=importlib.util.module_from_spec(spec);spec.loader.exec_module(formats)
            for kind,name in [('logs','kernel.log'),('screenshot','screen.ppm')]:
                protocol.stage(kind);data=protocol.upload();target=out/name
                target.write_bytes(data);target.chmod(0o600)
                info=dict(bytes=len(data),sha256=sha(target))
                if kind=='screenshot':
                    w,h,offset=formats.ppm_info(data);info.update(width=w,height=h)
                    try:
                        from PIL import Image
                    except ImportError:info['PNG']='Pillow unavailable; PPM retained'
                    else:
                        Image.frombytes('RGB',(w,h),data[offset:]).save(out/'screen.png')
                        with Image.open(out/'screen.png') as check:
                            if check.convert('RGB').tobytes()!=data[offset:]:raise ValueError('PNG pixel mismatch')
                        (out/'screen.png').chmod(0o600);info['PNG']='screen.png'
                record['captures'][kind]=info;save()
            record['state_after']=protocol.state()
        record['passed']=True
    except Exception as error:
        record['errors'].append(str(error));record['passed']=False
    finally:
        if native:native.close()
        record['completed_utc']=now();save()
    print(json.dumps({k:record[k] for k in ['action','passed','errors']},ensure_ascii=False))
    return 0 if record['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
