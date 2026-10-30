#!/usr/bin/env python3
"""One source-bound pre-XNU WLED read hold. No OS, touch or PMIC-write command."""
import argparse
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path

from polaris_uefi_usb_transport import KernelProtocol, LibusbTransport


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def binding(boot, image, driver):
    if (boot.get('state') != 'temporary_WLED_inventory_boot_command_succeeded' or
            boot.get('image_sha256') != image.get('sha256') or not boot.get('sent_utc') or
            image.get('driver_sha256') != driver.get('sha256')):
        raise ValueError('not the bound physical WLED inventory session')
    for item in (image, driver):
        for key, value in dict(WLED_readonly_inventory_only=True,
                               kernel_CPU_ON_compiled_out=True, kernel_handoff=False,
                               PMIC_write_api=False, storage_write_api=False,
                               NVRAM_write_api=False).items():
            if type(item.get(key)) is not type(value) or item[key] != value:
                raise ValueError('not an isolated readonly WLED hold: ' + key)
    if driver.get('QEMU_variant') is not False:
        raise ValueError('mock WLED image is not a phone image')
    watch = driver.get('WLED_readonly_fault_watch',False)
    if type(watch) is not bool or image.get('WLED_readonly_fault_watch',False) is not watch or boot.get('WLED_readonly_fault_watch',False) is not watch:
        raise ValueError('fault-watch boot/image/driver scope mismatch')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('action', choices=('state', 'inventory', 'capture', 'reboot-fastboot'))
    for n in ('libusb', 'boot-record', 'image-manifest', 'driver-manifest', 'output'):
        ap.add_argument('--' + n, type=Path, required=True)
    ap.add_argument('--payload', type=Path)
    a = ap.parse_args()
    boot, image, driver = (json.loads(p.read_text()) for p in (a.boot_record, a.image_manifest, a.driver_manifest))
    binding(boot, image, driver)
    raw = a.payload.read_bytes() if a.payload else None
    if ((a.action == 'inventory') != (raw is not None) or (raw is not None and
            (len(raw) != driver.get('payload_bytes') or hashlib.sha256(raw).hexdigest() != driver.get('payload_sha256')))):
        raise ValueError('inventory needs the exact source-bound RAM payload')
    a.output.mkdir(parents=True, exist_ok=False)
    record = dict(action=a.action, started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  sent_utc=boot['sent_utc'], image_sha256=image['sha256'],
                  driver_sha256=driver['sha256'], reader_sha256=sha(Path(__file__)),
                  PMIC_writes=False, storage_writes=False, NVRAM_writes=False,
                  WLED_readonly_fault_watch=driver.get('WLED_readonly_fault_watch',False),
                  kernel_CPU_ON_compiled_out=True, errors=[])
    native = None
    try:
        native = LibusbTransport(a.libusb)
        if not native.open_target():
            raise RuntimeError('bound UEFI endpoint not available')
        protocol = KernelProtocol(native); record['product'] = protocol.product()
        record['state_before'] = protocol.state()
        if a.action == 'inventory':
            protocol.stage_payload(raw, driver); protocol.boot()
            record['inventory_request_acknowledged'] = True
            record['state_after'] = protocol.state()
            if record['state_after'] != 'prepared':
                raise RuntimeError('pre-XNU inventory did not remain in hold')
        elif a.action == 'reboot-fastboot':
            if record['state_before'] not in ('waiting-payload', 'prepared', 'validated', 'admission-refused'):
                raise ValueError('refusing reset outside pre-XNU hold')
            protocol.reboot(True); record['reset_command_acknowledged'] = True
            record['actual_FASTBOOT_verified'] = False
        elif a.action == 'capture':
            spec = importlib.util.spec_from_file_location('wled_records', Path(__file__).with_name('polaris-wled-observations.py'))
            module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
            protocol.stage('logs'); data = protocol.upload()
            p = a.output / 'firmware.log'; p.write_bytes(data); p.chmod(0o600)
            record['firmware_log_sha256'] = sha(p)
            record['inventory'] = module.parse(data.decode(errors='replace'))
            if driver.get('WLED_readonly_fault_watch'):
                spec = importlib.util.spec_from_file_location('watch_records', Path(__file__).with_name('polaris-wled-watch-observations.py'))
                module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
                record['fault_watch'] = module.parse(data.decode(errors='replace'))
            record['state_after'] = protocol.state()
            if record['state_after'] != 'prepared':
                raise ValueError('inventory capture is not pre-XNU hold')
        record['passed'] = True
    except Exception as e:
        record['passed'] = False; record['errors'].append(str(e))
    finally:
        if native:
            native.close()
        record['completed_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        p = a.output / 'result.json'; p.write_text(json.dumps(record, indent=2) + '\n'); p.chmod(0o600)
    print(json.dumps({k: record[k] for k in ('action', 'passed', 'errors')}))
    return 0 if record['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
