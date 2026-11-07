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
            ('assigned', 'returned', 'copied', 'copy-ready', 'first-copy', 'first-rmb', 'copy-prefix', 'idle-hold', 'copy-page', 'native-ready'), 'firmware diagnostic scope changed')
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
    mode = {'assigned': 1, 'returned': 2, 'copied': 3, 'copy-ready': 4, 'first-copy': 5, 'first-rmb': 6, 'copy-prefix': 7, 'idle-hold': 8, 'copy-page': 9, 'native-ready': 10}[driver['wifi_native_auth_metadata_checkpoint_phase']]
    fault_hold=driver.get('wifi_native_fault_hold',False)
    fault_config=[x for x in config if x.startswith('#define EFI_XNU_WIFI_NATIVE_FAULT_HOLD')]
    require(type(fault_hold) is bool and (not fault_hold or mode==10) and
            fault_config==(['#define EFI_XNU_WIFI_NATIVE_FAULT_HOLD 1'] if fault_hold else []),
            'native fault hold compiler scope not frozen')
    marker=driver.get('wifi_native_bootloader_marker',False)
    rmtfs_diagnostics=driver.get('wifi_native_rmtfs_diagnostics',False)
    rmtfs_envelope=driver.get('wifi_rmtfs_auth_envelope',False)
    copy_boundary=driver.get('wifi_native_copy_boundary_trace',False)
    boundary_config=[x for x in config if x.startswith('#define EFI_XNU_WIFI_NATIVE_COPY_BOUNDARY_TRACE')]
    require(type(copy_boundary) is bool and (not copy_boundary or fault_hold) and
            image.get('wifi_native_copy_boundary_trace',False) is copy_boundary and
            boundary_config==(['#define EFI_XNU_WIFI_NATIVE_COPY_BOUNDARY_TRACE 1'] if copy_boundary else []),
            'copy boundary trace compiler/image scope mismatch')
    envelope_config=[x for x in config if x.startswith('#define EFI_XNU_WIFI_RMTFS_AUTH_ENVELOPE')]
    require(type(rmtfs_envelope) is bool and (not rmtfs_envelope or fault_hold) and
            image.get('wifi_rmtfs_auth_envelope',False) is rmtfs_envelope and
            envelope_config==(['#define EFI_XNU_WIFI_RMTFS_AUTH_ENVELOPE 1'] if rmtfs_envelope else []),
            'RMTFS auth envelope compiler/image scope mismatch')
    for data in (driver,image):
        require(data.get('rmtfs_transaction_whole_ticks',1920000)==(19200000 if rmtfs_envelope else 1920000) and
                data.get('rmtfs_issued_step_ticks',1920000)==1920000,
                'RMTFS auth whole/issued-step policy mismatch')
    rmtfs_config=[x for x in config if x.startswith('#define EFI_XNU_WIFI_NATIVE_RMTFS_DIAGNOSTICS')]
    require(type(rmtfs_diagnostics) is bool and (not rmtfs_diagnostics or fault_hold) and
            image.get('wifi_native_rmtfs_diagnostics',False) is rmtfs_diagnostics and
            rmtfs_config==(['#define EFI_XNU_WIFI_NATIVE_RMTFS_DIAGNOSTICS 1'] if rmtfs_diagnostics else []),
            'RMTFS terminal diagnostic scope/compiler/image binding mismatch')
    vendor_extents=driver.get('wifi_vendor_segment_extents',False)
    vendor_config=[x for x in config if x.startswith('#define EFI_XNU_WIFI_VENDOR_SEGMENT_EXTENTS')]
    require(type(vendor_extents) is bool and (not vendor_extents or fault_hold) and
            image.get('wifi_vendor_segment_extents',False) is vendor_extents and
            vendor_config==(['#define EFI_XNU_WIFI_VENDOR_SEGMENT_EXTENTS 1'] if vendor_extents else []),
            'vendor segment extent compiler/image scope mismatch')
    for record in (driver,image):
        require(record.get('modem_copy_gap_pages_written',True) is (not vendor_extents) and
                record.get('modem_copy_page_tail_written',True) is (not vendor_extents) and
                record.get('modem_copy_untouched_page_record')==(2 if vendor_extents else None),
                'vendor segment extent record semantics mismatch')
    invalidate=driver.get('wifi_native_progress_invalidate',False)
    invalidate_config=[x for x in config if x.startswith('#define EFI_XNU_WIFI_NATIVE_PROGRESS_INVALIDATE')]
    require(type(invalidate) is bool and (not invalidate or fault_hold) and
            image.get('wifi_native_progress_invalidate',False) is invalidate and
            driver.get('native_progress_cache_operation','CVAC')==image.get('native_progress_cache_operation','CVAC')==('CIVAC' if invalidate else 'CVAC') and
            invalidate_config==(['#define EFI_XNU_WIFI_NATIVE_PROGRESS_INVALIDATE 1'] if invalidate else []),
            'own progress CIVAC compiler/image scope mismatch')
    fast_sha=driver.get('wifi_scalar_sha256_fast',False)
    fast_config=[x for x in config if x.startswith('#define POLARIS_WIFI_SCALAR_SHA256_FAST')]
    require(type(fast_sha) is bool and (not fast_sha or fault_hold) and
            image.get('wifi_scalar_sha256_fast',False) is fast_sha and
            driver.get('scalar_sha256_uses_SIMD',False) is False and image.get('scalar_sha256_uses_SIMD',False) is False and
            fast_config==(['#define POLARIS_WIFI_SCALAR_SHA256_FAST 1'] if fast_sha else []),
            'fast scalar SHA256 compiler/image scope mismatch')
    trace_first=driver.get('wifi_native_copy_trace_first',0)
    trace_config=[x for x in config if x.startswith('#define EFI_XNU_WIFI_NATIVE_COPY_TRACE_FIRST')]
    require(type(trace_first) is int and 0<=trace_first<=30464 and (not trace_first or fault_hold) and
            image.get('wifi_native_copy_trace_first',0)==trace_first and
            trace_config==(['#define EFI_XNU_WIFI_NATIVE_COPY_TRACE_FIRST '+str(trace_first)] if trace_first else []),
            'fine copy trace compiler/image scope mismatch')
    watchdog=driver.get('wifi_native_watchdog_readonly',False)
    watchdog_config=[x for x in config if x.startswith('#define EFI_XNU_WIFI_NATIVE_WATCHDOG_READONLY')]
    require(type(watchdog) is bool and (not watchdog or (marker and fault_hold)) and
            watchdog_config==(['#define EFI_XNU_WIFI_NATIVE_WATCHDOG_READONLY 1'] if watchdog else []) and
            image.get('wifi_native_watchdog_readonly',False) is watchdog and
            driver.get('native_apps_watchdog_register_writes',False) is False and
            image.get('native_apps_watchdog_register_writes',False) is False,
            'native watchdog inventory scope/compiler/image binding mismatch')
    marker_config=[x for x in config if x.startswith('#define EFI_XNU_WIFI_NATIVE_BOOTLOADER_MARKER')]
    require(type(marker) is bool and (not marker or fault_hold) and
            marker_config==(['#define EFI_XNU_WIFI_NATIVE_BOOTLOADER_MARKER 1'] if marker else []),
            'pre-native bootloader marker compiler scope not frozen')
    require(driver.get('pre_native_volatile_boot_reason_writes',False) is marker and
            image.get('wifi_native_bootloader_marker',False) is marker and
            image.get('pre_native_volatile_boot_reason_writes',False) is marker,
            'pre-native marker image/driver binding mismatch')
    require(config.count('#define EFI_XNU_WIFI_FIRMWARE_DIAGNOSTIC_ONLY 1') == 1 and
            config.count(f'#define EFI_XNU_WIFI_AUTH_METADATA_CHECKPOINT {mode}') == 1 and
            not any(x.startswith('#define EFI_XNU_DISK_GUID') for x in config),
            'diagnostic compiler mode changed')
    events = driver.get('wifi_native_first_rmb_events')
    if mode == 6:
        require(type(events) is int and 1 <= events <= 6 and
                config.count(f'#define EFI_XNU_WIFI_FIRST_RMB_EVENTS {events}') == 1,
                'first RMB completion count not frozen')
    else:
        require(events is None and not any(x.startswith('#define EFI_XNU_WIFI_FIRST_RMB_EVENTS') for x in config),
                'unexpected first RMB completion count')
    require(driver.get('RAM_idle_reboot_enabled') is False and
            driver.get('UEFI_watchdog_status_before_native_required') is True, 'idle/watchdog policy missing')
    segments = driver.get('wifi_native_copy_segments')
    if mode == 7:
        require(type(segments) is int and 1 <= segments <= 28 and
                config.count(f'#define EFI_XNU_WIFI_COPY_SEGMENTS {segments}') == 1,
                'copy prefix count not frozen')
    else:
        require(segments is None and not any(x.startswith('#define EFI_XNU_WIFI_COPY_SEGMENTS') for x in config),
                'unexpected copy prefix count')
    page = driver.get('wifi_native_copy_page_before')
    if mode == 9:
        require(type(page) is int and 1 <= page < 30720 and
                config.count(f'#define EFI_XNU_WIFI_COPY_PAGE_BEFORE {page}') == 1,
                'copy page not frozen')
    else:
        require(page is None and not any(x.startswith('#define EFI_XNU_WIFI_COPY_PAGE_BEFORE') for x in config),
                'unexpected copy page')
    probe = driver.get('wifi_native_copy_page_probe', False)
    probe_config = [x for x in config if x.startswith('#define EFI_XNU_WIFI_COPY_PAGE_PROBE')]
    require(type(probe) is bool and (not probe or mode == 9) and
            probe_config == (['#define EFI_XNU_WIFI_COPY_PAGE_PROBE 1'] if probe else []),
            'copy page translation probe not frozen')
    after_write = driver.get('wifi_native_copy_page_after_write', False)
    after_config = [x for x in config if x.startswith('#define EFI_XNU_WIFI_COPY_PAGE_AFTER_WRITE')]
    require(type(after_write) is bool and (not after_write or (mode == 9 and not probe)) and
            after_config == (['#define EFI_XNU_WIFI_COPY_PAGE_AFTER_WRITE 1'] if after_write else []),
            'copy page after-write hold not frozen')
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
            proof.get('idle_reboot_disabled_default') is True and
            proof.get('watchdog_disable_status_recorded') is True and
            proof.get('idle_policy_actual_function_tested') is True and
            proof.get('terminal_guard_actual_function_tested') is True and
            proof.get('terminal_guard_case_count') == 11549 and
            proof.get('normal_root_validator_AST_identical') is True and
            proof.get('shared_transport_one_use_order_with_pre_start_idle_status') is True and
            proof.get('diagnostic_has_no_kernel_handoff_references') is True,
            'actual firmware-only code qualification missing')
    if mode == 10:
        require(proof.get('native_ready_recheck_tested') is True and
                proof.get('native_ready_recheck_cases') == 108 and
                proof.get('native_ready_GOP_saved_state_tested') is True and
                proof.get('non_ready_objects_identical') is True,
                'continuous native-ready qualification missing')
    if fault_hold:
        require(driver.get('wifi_native_fault_stack_bytes')==16384 and
                driver.get('wifi_native_fault_exception_return') is False and
                driver.get('wifi_native_fault_foreign_calls') is False and
                proof.get('native_fault_actual_EL1_exception_cases')==3 and
                proof.get('native_fault_non_EL1_refused') is True and
                proof.get('native_fault_default_OFF_objects_identical') is True and
                proof.get('native_fault_terminal_handler_qualified') is True,
                'native terminal fault evidence qualification missing')
        if marker:
            require(proof.get('pre_native_marker_actual_policy_tested') is True and
                    proof.get('pre_native_marker_host_order_tested') is True and
                    proof.get('pre_native_marker_USB_ACK_after_readback_tested') is True,
                    'pre-native marker qualification missing')
        if vendor_extents:
            require(proof.get('vendor_extents_actual_word_and_plan_bounds_tested') is True and
                    proof.get('vendor_extents_full_copy_auth_canaries_tested') is True and
                    proof.get('vendor_extents_default_OFF_objects_identical') is True and
                    proof.get('vendor_extents_own_vendor_source_compared') is True,
                    'vendor segment extent qualification missing')
        if rmtfs_diagnostics:
            require(proof.get('rmtfs_terminal_actual_rows_tested') is True and
                    proof.get('rmtfs_terminal_default_OFF_objects_identical') is True,
                    'RMTFS terminal diagnostic qualification missing')
        if rmtfs_envelope:
            require(proof.get('rmtfs_auth_envelope_actual_guarded_CPU_delay_tested') is True and
                    proof.get('rmtfs_auth_envelope_per_step_100ms_and_whole_1s_refusal_tested') is True and
                    proof.get('rmtfs_auth_envelope_default_OFF_objects_identical') is True,
                    'RMTFS auth envelope qualification missing')
        if copy_boundary:
            require(proof.get('copy_boundary_actual_policy_and_failures_tested') is True and
                    proof.get('copy_boundary_full_auth_software_peer_tested') is True and
                    proof.get('copy_boundary_default_OFF_objects_identical') is True,
                    'copy boundary trace qualification missing')
        if invalidate:
            require(proof.get('own_progress_CIVAC_actual_EL1_QEMU') is True and
                    proof.get('own_progress_CIVAC_actual_EL2_refused_QEMU') is True and
                    proof.get('own_progress_CIVAC_default_OFF_objects_identical') is True and
                    proof.get('own_progress_CIVAC_remote_cache_operation_changed') is False,
                    'own progress CIVAC qualification missing')
        if fast_sha:
            require(proof.get('scalar_SHA256_actual_header_vectors_tested') is True and
                    proof.get('scalar_SHA256_admitted_read_bounds_tested') is True and
                    proof.get('scalar_SHA256_default_OFF_objects_identical') is True and
                    proof.get('scalar_SHA256_actual_objects_general_regs_only') is True,
                    'fast scalar SHA256 qualification missing')
        if trace_first:
            require(proof.get('relocated_copy_trace_actual_policy_tested') is True and
                    proof.get('relocated_copy_trace_default_objects_identical') is True and
                    proof.get('relocated_copy_trace_first')==trace_first,
                    'relocated fine copy trace qualification missing')
        if watchdog:
            require(proof.get('native_watchdog_actual_policy_tested') is True and
                    proof.get('native_watchdog_actual_callbacks_qualified') is True and
                    proof.get('native_watchdog_default_OFF_objects_identical') is True and
                    proof.get('native_progress_published_before_optional_watchdog') is True,
                    'native watchdog readonly qualification missing')
        qualified=proof.get('native_fault_qualified_objects',{})
        require(set(qualified)=={'driver-0001/uefi-wifi-native-fault.obj','actual-native-fault-macho.obj'},
                'both actual native fault vector objects required')
        for name,digest in qualified.items():
            path=(case/name).resolve()
            require(path.is_relative_to(case) and sha(path)==digest and
                    str(path.relative_to(ROOT)) in review['files'],
                    'native fault vector object changed or not frozen')
    if mode == 9:
        require(proof.get('page_hook_context_and_GOP_tested') is True and
                proof.get('non_page_objects_identical') is True,
                'page checkpoint qualification missing')
        if not after_write:
            require(proof.get('page_hook_before_translation_tested') is True,
                    'before-page checkpoint qualification missing')
    if probe:
        require(proof.get('page_translation_probe_tested') is True and
                proof.get('page_translation_probe_target_access') is False and
                proof.get('probe_disabled_page_objects_identical') is True,
                'page translation probe qualification missing')
    if after_write:
        require(proof.get('page_after_write_hold_tested') is True and
                proof.get('selected_page_cache_issued') is False and
                proof.get('after_write_OFF_objects_identical') is True,
                'page after-write qualification missing')
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
