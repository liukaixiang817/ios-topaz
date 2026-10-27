#!/usr/bin/env python3
"""Directed USB control of one SHA-bound small-marker RAM trial.

No raw reboot, generic fastboot, storage command, replacement kernel or input
injection interface. Only the admitted kernel can issue its bounded marker
write. Durable SAFE is necessary for reset; actual mode/readback remain separate.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import time

from polaris_marker_admission import admit_manifest, evidence, require, sha
from polaris_owned_marker_protocol import OwnedMarkerProtocol
from polaris_uefi_usb_transport import LibusbTransport


def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('action', choices=('state', 'capture', 'boot', 'shutdown-fastboot'))
    for name in ('libusb', 'boot-record', 'image-manifest', 'driver-manifest', 'output'):
        ap.add_argument('--' + name, type=Path, required=True)
    ap.add_argument('--payload', type=Path)
    ap.add_argument('--wait-seconds', type=int, default=0)
    ap.add_argument('--shutdown-seconds', type=int, default=180)
    a = ap.parse_args(); root = Path(__file__).resolve().parents[1]
    require(0 <= a.wait_seconds <= 600 and 1 <= a.shutdown_seconds <= 300, 'bounded deadlines required')
    require((a.action == 'boot') == (a.payload is not None), 'payload only for one explicit boot')
    driver = json.loads(a.driver_manifest.read_text()); admit_manifest(driver)
    image = json.loads(a.image_manifest.read_text()); boot = json.loads(a.boot_record.read_text())
    require(image.get('physical_owned_marker_trial') is True and image.get('writes_only_new_owned_marker') is True and
            image.get('RAM_only_XNU_loader') is False and image.get('raw_reset_requires_durable_SAFE') is True and
            image.get('RAM_host_idle_recovery_seconds', 1800) is None and
            image.get('original_root_writes_volatile') is True and image.get('NVRAM_write_api') is False and
            image.get('storage_write_api') is False and image.get('marker_bytes') == 8 << 20 and
            image.get('marker_write_bytes') == 4096 and image.get('driver_sha256') == driver.get('sha256') and
            boot.get('state') == 'temporary_UEFI_XNU_boot_command_succeeded' and boot.get('sent_utc') and
            boot.get('image_sha256') == image.get('sha256'), 'not a bound sent physical marker trial')
    require(sha(a.image_manifest.parent / image['artifact']) == image['sha256'] and
            sha(a.driver_manifest.parent / driver['artifact']) == driver['sha256'], 'image or driver changed')
    require(image.get('admission_sha256') == sha(root / 'tools/polaris_marker_admission.py') and
            image.get('packager_sha256') == sha(root / 'tools/polaris-uefi-marker-image.py'), 'admission or packager source changed')
    for record in image['evidence'].values(): evidence(root, record)
    raw = a.payload.read_bytes() if a.payload else None
    if raw is not None:
        require(hashlib.sha256(raw).hexdigest() == driver['payload_sha256'], 'payload changed')
    out = a.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    result = dict(action=a.action, started_utc=now(), sent_utc=boot['sent_utc'], image_sha256=image['sha256'],
                  marker_only=True, original_root_writes_volatile=True, raw_reset_api=False,
                  potential_owned_marker_write=a.action == 'boot', NVRAM_writes=False,
                  continuous_observer=False, full_iOS_persistence_proven=False, errors=[],
                  controller_sha256=sha(Path(__file__)),
                  protocol_sha256=sha(root / 'tools/polaris_owned_marker_protocol.py'),
                  transport_sha256=sha(root / 'tools/polaris_uefi_usb_transport.py'))
    def save():
        p = out / 'result.json'; p.write_text(json.dumps(result, indent=2) + '\n'); p.chmod(0o600)
    native = None; save()
    try:
        native = LibusbTransport(a.libusb); began = time.monotonic()
        while not native.open_target():
            if time.monotonic() - began >= a.wait_seconds: raise RuntimeError('marker UEFI endpoint not discovered')
            time.sleep(1)
        protocol = OwnedMarkerProtocol(native, driver); result['product'] = protocol.product()
        result['state_before'] = protocol.state(); save()
        if a.action == 'boot':
            protocol.stage_payload(raw, driver); protocol.boot()
            result['kernel_command_acknowledged'] = True
            result['kernel_or_write_success_proven'] = False
        elif a.action == 'capture':
            result['files'] = {}
            for stage, name in [('logs', 'kernel.log'), ('screenshot', 'screen.ppm')]:
                protocol.stage(stage); data = protocol.upload(); p = out / name
                p.write_bytes(data); p.chmod(0o600); result['files'][name] = dict(bytes=len(data), sha256=sha(p)); save()
            result['native_status'] = protocol.shutdown_status()
        elif a.action == 'shutdown-fastboot':
            result['native_shutdown_token'] = list(protocol.request_shutdown(True)); save()
            began = time.monotonic(); result['samples'] = []
            while True:
                status = protocol.shutdown_status()
                if not result['samples'] or status != result['samples'][-1]['status']:
                    result['samples'].append(dict(utc=now(), status=status)); save()
                if status['error'] or status['phase'] == 6: raise RuntimeError('native marker FAILED; no reset sent')
                if status['phase'] == 5: break
                if time.monotonic() - began >= a.shutdown_seconds: raise RuntimeError('native SAFE not reached; no reset sent')
                time.sleep(.25)
            protocol.stage('logs'); p = out / 'shutdown-kernel.log'; p.write_bytes(protocol.upload()); p.chmod(0o600)
            result['shutdown_log_sha256'] = sha(p); save()
            result['native_SAFE'] = protocol.reboot_safe()
            result['reset_acknowledged'] = True; result['actual_FASTBOOT_verified'] = False
            result['physical_persistence_readback_proven'] = False
        else:
            result['native_status'] = protocol.shutdown_status()
        result['passed'] = True
    except Exception as error:
        result['passed'] = False; result['errors'].append(str(error))
    finally:
        if native: native.close()
        result['completed_utc'] = now(); save()
    print(json.dumps({k: result[k] for k in ('action', 'passed', 'errors')}))
    return 0 if result['passed'] else 1


if __name__ == '__main__': raise SystemExit(main())
