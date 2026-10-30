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
    if any(x.get(k) for x in (image,driver) for k in
           ('WLED_native_runtime_physical','WLED_native_runtime_test','PMIC_write_api')):
        raise ValueError('WLED native runtime requires its independent controller and final receipt')
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
    ap.add_argument('action',choices=['state','capture','boot-options','boot','tap','swipe','reboot-normal','reboot-fastboot',
                                      'shutdown-normal','shutdown-fastboot'])
    ap.add_argument('--libusb',required=True,type=Path)
    ap.add_argument('--boot-record',required=True,type=Path)
    ap.add_argument('--image-manifest',required=True,type=Path)
    ap.add_argument('--driver-manifest',required=True,type=Path)
    ap.add_argument('--payload',type=Path)
    ap.add_argument('--output',required=True,type=Path)
    ap.add_argument('--wait-seconds',type=int,default=0)
    ap.add_argument('--shutdown-seconds',type=int,default=180)
    ap.add_argument('--x',type=int);ap.add_argument('--y',type=int)
    ap.add_argument('--to-x',type=int);ap.add_argument('--to-y',type=int)
    ap.add_argument('--duration-ms',type=int,default=400)
    a=ap.parse_args()
    if not 0<=a.wait_seconds<=600:ap.error('target discovery wait must be 0..600 seconds')
    if not 1<=a.shutdown_seconds<=300:ap.error('native drain deadline must be 1..300 seconds')
    if (a.action=='boot')!=(a.payload is not None):ap.error('--payload is required only for boot')
    if a.action in ['tap','swipe']:
        if a.x is None or a.y is None or not 0<=a.x<1080 or not 0<=a.y<2160:ap.error('contact coordinates required in panel bounds')
        if a.action=='swipe' and (a.to_x is None or a.to_y is None or not 0<=a.to_x<1080 or not 0<=a.to_y<2160 or not 100<=a.duration_ms<=1500):ap.error('swipe destination/duration invalid')
    boot=json.loads(a.boot_record.read_text());image=json.loads(a.image_manifest.read_text())
    driver=json.loads(a.driver_manifest.read_text());binding(boot,image,driver)
    if a.action.startswith('shutdown-') and driver.get('RAM_native_shutdown_bridge') is not True:
        raise ValueError('native shutdown requires the explicitly built RAM-only bridge')
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
        elif a.action.startswith('shutdown-'):
            token=protocol.request_shutdown(a.action=='shutdown-fastboot')
            record['native_shutdown_token']=list(token);record['shutdown_samples']=[];save()
            start=time.monotonic()
            while True:
                status=protocol.shutdown_status()
                if not record['shutdown_samples'] or status!=record['shutdown_samples'][-1]['status']:
                    record['shutdown_samples'].append(dict(utc=now(),status=status));save()
                if status['error'] or status['phase']==6:raise RuntimeError('kernel refused native RAM shutdown; no reset sent')
                if status['phase']==3:break
                if time.monotonic()-start>=a.shutdown_seconds:raise RuntimeError('native RAM shutdown not completed; no reset sent')
                time.sleep(.25)
            # Preserve kernel evidence before the reset removes the RAM log.
            protocol.stage('logs');data=protocol.upload();p=out/'shutdown-kernel.log';p.write_bytes(data);p.chmod(0o600)
            record['native_shutdown_log_sha256']=sha(p);save()
            record['native_RAM_drained_status']=protocol.reboot_drained()
            record['persistent_UFS_durability_proven']=False
            record['reset_command_acknowledged']=True
            record['resulting_boot_mode_verified']=False # Must query real expected FASTBOOT separately.
        elif a.action in ['tap','swipe']:
            record['input_before']=protocol.input_status();save()
            if a.action=='tap':protocol.tap(a.x,a.y)
            else:protocol.swipe(a.x,a.y,a.to_x,a.to_y,a.duration_ms)
            record['input_after']=protocol.input_status()
            record['kernel_consumed_contact_sequence']=True
            record['UI_response_verified']=False
        elif a.action=='boot-options':
            from polaris_uefi_boot_options import parse_snapshot
            protocol.stage('boot-options');data=protocol.upload()
            target=out/'boot-options.bin';target.write_bytes(data);target.chmod(0o600)
            parsed=parse_snapshot(data);(out/'boot-options.json').write_text(json.dumps(parsed,indent=2)+'\n')
            for row in parsed['records']:
                if row['status']=='0x0000000000000000':
                    start=row['data_offset'];p=out/(row['name']+'.bin');p.write_bytes(data[start:start+row['bytes']]);p.chmod(0o600)
            record['boot_options_complete']=parsed['complete'];record['boot_options_sha256']=sha(target)
            if not parsed['complete']:raise ValueError('boot-variable backup incomplete; no changes permitted')
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
