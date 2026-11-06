#!/usr/bin/env python3
"""One reviewed native Wi-Fi RAM trial; default offline, no reset/flash/retry.

After the OEM boot ACK, the persistent CPU0 loop owns its resources and USB
service is not assumed. An ACK proves command acceptance only, not iOS or Wi-Fi.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import time

from polaris_fastboot_identity import expected_polaris_fastboot
from polaris_uefi_usb_transport import KernelProtocol, LibusbTransport

ROOT = Path(__file__).resolve().parents[1]
# Admission precedes USB: NV has a 120s producer limit and the independent
# CE/HTT producers each have 30s. Allow these existing device limits plus entry
# overhead; this host wait neither renews a device lease nor retries a call.
INITIAL_SERVICE_WAIT_SECONDS = 210


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate(review_path):
    review = json.loads(review_path.read_text())
    require(review['scope'] == 'one_native_WiFi_RO_RAMCOW_trial' and
            review['temporary_trial_review_complete'] is True and
            review['physical_networking_verified'] is False and
            review['may_write_userdata'] is False, 'wrong trial review scope')
    require(review['boot_helper_sha256'] == sha(Path(__file__)), 'boot helper changed')
    require(set(review['gates']) == {'1', '2', '3', '4', '5'} and
            all(x['trial_review_passed'] is True for x in review['gates'].values()),
            'incomplete trial review')
    for name, digest in review['files'].items():
        path = (ROOT/name).resolve()
        require(path.is_relative_to(ROOT) and sha(path) == digest, 'frozen input changed: '+name)
    case = (ROOT/review['case']).resolve()
    require(case.is_relative_to(ROOT/'research'), 'private candidate path')
    image_manifest = case/'image-0001/manifest.json'
    driver_manifest = case/'driver-0001/manifest.json'
    image = json.loads(image_manifest.read_text())
    driver = json.loads(driver_manifest.read_text())
    root = json.loads((case/'fresh-20F66-readonly-root-review.json').read_text())
    require(root['passed'] is True and len(root['checks']) == 40 and
            all(root['checks'].values()) and root['may_write_userdata'] is False,
            'current readonly root review incomplete')
    require(image['sha256'] == review['image_sha256'] and
            image['driver_manifest_sha256'] == sha(driver_manifest) and
            image['driver_sha256'] == driver['sha256'] and
            image['payload_sha256'] == driver['payload_sha256'], 'candidate bindings')
    require(image['scope'] == 'native_WiFi_retained_CPU0_RO_RAMCOW' and
            image['post_start_USB_service'] is False and
            image['immutable_root_RAMCOW_only'] is True and
            image['may_write_userdata'] is False and driver['QEMU_variant'] is False,
            'candidate is outside reviewed scope')
    for directory, manifest in ((case/'image-0001', image), (case/'driver-0001', driver)):
        require(Path(manifest['artifact']).name == manifest['artifact'], 'artifact path')
        require(sha(directory/manifest['artifact']) == manifest['sha256'], 'artifact changed')
    payload = case/'payload-0001/payload.bin'
    require(sha(payload) == driver['payload_sha256'], 'payload changed')
    spec = importlib.util.spec_from_file_location('nonce', ROOT/'tools/polaris-wifi-nonce-candidate.py')
    nonce = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(nonce)
    nonce.verify(driver_manifest, sha(driver_manifest))
    return review, case, image, driver, nonce


def run_trial(args, review, case, image, driver, nonce):
    """Transport for a separately validated scope; no admission policy here."""
    output = args.output.resolve()
    require(output.is_relative_to(ROOT/'research') and not output.exists(), 'new private output required')
    serial = args.serial_file.read_text().strip()
    require(re.fullmatch(r'[A-Za-z0-9._-]{1,128}', serial), 'invalid private device selection')
    require(sha(args.fastboot) == review['fastboot_sha256'] and
            sha(args.libusb) == review['libusb_sha256'], 'host transport changed')
    if not args.boot_once:
        print('Frozen native Wi-Fi trial inputs verified; no device command or nonce consumption')
        return
    output.mkdir(parents=True)
    record = dict(state='prepared', utc=now(), image_sha256=image['sha256'],
                  driver_sha256=driver['sha256'], review_sha256=sha(args.review),
                  phone_partition_writes=False, physical_networking_verified=False,
                  post_start_USB_observer=False)
    if review.get('XNU_execution_forbidden') is True:
        record.update(scope=review['scope'], XNU_execution_forbidden=True,
                      userdata_access_api=False)

    def save():
        record['updated_utc'] = now()
        (output/'boot.json').write_text(json.dumps(record, indent=2)+'\n')

    transport = None
    protocol = None
    try:
        save()
        fastboot = [str(args.fastboot.resolve()), '-s', serial]
        result = subprocess.run(fastboot+['getvar', 'product'], capture_output=True, text=True, timeout=8)
        text = (result.stdout+result.stderr).replace(serial, '<redacted>')
        record['product_check'] = dict(exit_code=result.returncode, output=text)
        require(expected_polaris_fastboot(result.returncode, text), 'expected Polaris FASTBOOT absent')
        # Consume durably before the first possible image transfer. Any failure
        # or lost ACK burns this pool; this helper offers no resume/replay path.
        record['nonce'] = nonce.consume(case/'driver-0001/manifest.json', sha(case/'driver-0001/manifest.json'))
        record.update(state='temporary_boot_attempted', sent_utc=now())
        save()
        result = subprocess.run(fastboot+['boot', str(case/'image-0001'/image['artifact'])],
                                capture_output=True, text=True, timeout=120)
        text = (result.stdout+result.stderr).replace(serial, '<redacted>')
        (output/'fastboot.log').write_text(text)
        require(result.returncode == 0 and 'OKAY' in text, 'temporary boot ACK absent; no replay')
        record.update(state='temporary_boot_ACK', fastboot_exit_code=result.returncode)
        save()

        class ProgressTransport(LibusbTransport):
            def write_data(self, data):
                result = super().write_data(data)
                record['payload_host_bytes'] = record.get('payload_host_bytes', 0)+len(data)
                if record['payload_host_bytes'] % (1 << 20) == 0:
                    save()
                return result

        transport = ProgressTransport(args.libusb)
        deadline = time.monotonic()+INITIAL_SERVICE_WAIT_SECONDS
        while not transport.open_target():
            require(time.monotonic() < deadline, 'new UEFI service unavailable; no reset/retry')
            time.sleep(.2)
        protocol = KernelProtocol(transport)
        record['UEFI_product'] = protocol.product()
        record.update(state='staging_RAM_payload', payload_stage_started_utc=now())
        save()
        protocol.stage_payload((case/'payload-0001/payload.bin').read_bytes(), driver)
        record.update(state='RAM_payload_validated', payload_stage=protocol.payload_stage)
        save()
        if driver.get('UEFI_watchdog_status_before_native_required') is True:
            require(driver.get('RAM_idle_reboot_enabled') is False, 'idle reboot must be disabled')
            protocol.stage('logs')
            logs = protocol.upload()
            (output/'pre-native-idle-watchdog.log').write_bytes(logs)
            statuses = re.findall(rb'UEFI_WATCHDOG_DISABLE_STATUS=0x([0-9a-fA-F]{16})', logs)
            idle = re.findall(rb'RAM_IDLE_AUTO_RESET_SECONDS=0x([0-9a-fA-F]{16})', logs)
            record['pre_native_idle_status'] = dict(log_sha256=hashlib.sha256(logs).hexdigest(),
                watchdog_status=[int(x,16) for x in statuses], idle_recovery_seconds=[int(x,16) for x in idle])
            save()
            require(statuses and all(int(x,16)==0 for x in statuses) and
                    idle and all(int(x,16)==0 for x in idle), 'watchdog/idle hold not confirmed; native start refused')
        record.update(state='native_start_attempted', native_start_utc=now())
        save()
        protocol.boot(ack_seconds=90)
        record.update(state='native_start_ACK', native_command_ACK=True,
                      kernel_boot_proven=False, physical_scan_proven=False)
        save()
        print('One new image and exact RAM payload accepted; native start ACK received. Phone boot/scan not yet proven.')
    except Exception as error:
        record.update(state='stopped_no_retry', error=(type(error).__name__+': '+str(error)).replace(serial, '<redacted>'))
        save()
        raise RuntimeError(record['error']) from None
    finally:
        if protocol and hasattr(protocol, 'payload_stage'):
            record['payload_stage'] = protocol.payload_stage
        if transport:
            record['last_transfer'] = getattr(transport, 'last_transfer', None)
        save()
        if transport:
            transport.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('review', 'serial-file', 'fastboot', 'libusb', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--boot-once', action='store_true')
    args = parser.parse_args()
    run_trial(args, *validate(args.review))


if __name__ == '__main__':
    main()
