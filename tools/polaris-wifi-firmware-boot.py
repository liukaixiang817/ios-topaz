#!/usr/bin/env python3
"""One terminal RAM firmware diagnostic, with XNU execution forbidden.

This scope never starts the application-processor kernel or its UFS reader.
The ordinary iOS/native-runtime helper retains its independent 40-check root
admission. Both scopes share only the one-use RAM transport after validation.
"""
import argparse
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('polaris_native_boot', ROOT/'tools/polaris-wifi-native-boot.py')
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
sha, require = native.sha, native.require


def validate(review_path):
    review = json.loads(review_path.read_text())
    require(review.get('scope') == 'one_native_WiFi_firmware_diagnostic_RAM_trial' and
            review.get('temporary_trial_review_complete') is True and
            review.get('physical_networking_verified') is False and
            review.get('may_write_userdata') is False and
            review.get('XNU_execution_forbidden') is True, 'wrong firmware-only review scope')
    require(review['boot_helper_sha256'] == sha(Path(__file__)) and
            review['transport_helper_sha256'] == sha(ROOT/'tools/polaris-wifi-native-boot.py'),
            'firmware diagnostic helper changed')
    require(set(review['gates']) == {'1', '2', '3', '4', '5'} and
            all(x['trial_review_passed'] is True for x in review['gates'].values()),
            'incomplete firmware diagnostic review')
    for name, digest in review['files'].items():
        path = (ROOT/name).resolve()
        require(path.is_relative_to(ROOT) and sha(path) == digest, 'frozen input changed: '+name)
    case = (ROOT/review['case']).resolve()
    require(case.is_relative_to(ROOT/'research'), 'private firmware diagnostic path')
    image_manifest, driver_manifest = case/'image-0001/manifest.json', case/'driver-0001/manifest.json'
    image, driver = json.loads(image_manifest.read_text()), json.loads(driver_manifest.read_text())
    require(image['scope'] == 'native_WiFi_firmware_diagnostic_RAM_only' and
            image.get('wifi_firmware_diagnostic_only') is True and
            driver.get('wifi_firmware_diagnostic_only') is True,
            'candidate is not the separate firmware diagnostic')
    for data in (image, driver):
        require(data.get('kernel_handoff') is False and
                data.get('XNU_execution_forbidden') is True and
                data.get('userdata_access_api') is False, 'kernel/storage access is not closed')
    require(image['post_start_USB_service'] is False and
            image['may_write_userdata'] is False and image['immutable_root_RAMCOW_only'] is False and
            driver['QEMU_variant'] is False and driver['storage_write_api'] is False and
            driver['NVRAM_write_api'] is False and driver.get('disk_payload_path') is None and
            driver['wifi_native_auth_metadata_checkpoint_phase'] in
            ('assigned', 'returned', 'copied', 'copy-ready', 'first-copy'), 'firmware diagnostic scope changed')
    require(image['sha256'] == review['image_sha256'] and
            image['driver_manifest_sha256'] == sha(driver_manifest) and
            image['driver_sha256'] == driver['sha256'] and
            image['payload_sha256'] == driver['payload_sha256'], 'firmware candidate bindings')
    for directory, manifest in ((case/'image-0001', image), (case/'driver-0001', driver)):
        require(Path(manifest['artifact']).name == manifest['artifact'], 'artifact path')
        require(sha(directory/manifest['artifact']) == manifest['sha256'], 'artifact changed')
    require(sha(case/'payload-0001/payload.bin') == driver['payload_sha256'], 'inert RAM payload changed')
    config_path = case/'driver-0001/uefi-xnu-config.h'
    require(review['files'].get(str(config_path.relative_to(ROOT))) == sha(config_path),
            'diagnostic compiler configuration not frozen')
    config = config_path.read_text().splitlines()
    mode = {'assigned': 1, 'returned': 2, 'copied': 3, 'copy-ready': 4, 'first-copy': 5}[driver['wifi_native_auth_metadata_checkpoint_phase']]
    require(config.count('#define EFI_XNU_WIFI_FIRMWARE_DIAGNOSTIC_ONLY 1') == 1 and
            config.count(f'#define EFI_XNU_WIFI_AUTH_METADATA_CHECKPOINT {mode}') == 1 and
            not any(x.startswith('#define EFI_XNU_DISK_GUID') for x in config),
            'diagnostic compiler mode changed')
    for name, digest in driver['inputs'].items():
        path = (ROOT/name).resolve()
        require(path.is_relative_to(ROOT) and review['files'].get(name) == digest and sha(path) == digest,
                'driver input changed or not frozen: '+name)
    proof_path = case/'firmware-only-control-proof.json'
    require(str(proof_path.relative_to(ROOT)) in review['files'], 'firmware code proof not frozen')
    proof = json.loads(proof_path.read_text())
    require(proof.get('passed') is True and
            proof.get('source_sha256') == sha(ROOT/'shim/polaris/uefi-xnu.c') and
            proof.get('builder_sha256') == sha(ROOT/'tools/build-polaris-uefi-xnu.py') and
            proof.get('default_loader_code_and_data_unchanged') is True and
            proof.get('default_MachO_byte_identical') is True and
            proof.get('default_COFF_timestamp_only_difference') is True and
            proof.get('terminal_guard_actual_function_tested') is True and
            proof.get('terminal_guard_case_count') == 1300 and
            proof.get('normal_root_validator_AST_identical') is True and
            proof.get('shared_transport_AST_identical_except_diagnostic_record_fields') is True and
            proof.get('diagnostic_has_no_kernel_handoff_references') is True,
            'actual firmware-only code qualification missing')
    require(set(proof['qualified_objects']) == {'driver-0001/uefi-xnu.obj', 'actual-loader-macho.obj'},
            'both actual diagnostic object formats required')
    for name, digest in proof['qualified_objects'].items():
        path = (case/name).resolve()
        require(path.is_relative_to(case) and sha(path) == digest and
                str(path.relative_to(ROOT)) in review['files'], 'qualified object changed or not frozen')
    nonce = importlib.util.spec_from_file_location('nonce', ROOT/'tools/polaris-wifi-nonce-candidate.py')
    module = importlib.util.module_from_spec(nonce)
    nonce.loader.exec_module(module)
    module.verify(driver_manifest, sha(driver_manifest))
    return review, case, image, driver, module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('review', 'serial-file', 'fastboot', 'libusb', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--boot-once', action='store_true')
    args = parser.parse_args()
    native.run_trial(args, *validate(args.review))


if __name__ == '__main__':
    main()
