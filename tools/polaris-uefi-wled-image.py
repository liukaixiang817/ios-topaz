#!/usr/bin/env python3
"""Package a source-bound, pre-XNU WLED READ inventory RAM hold only.

This is deliberately separate from iOS admission. It cannot authorize a
kernel handoff, a PMIC writer, a persistent installation or a power result.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

MODEL_CHECKS = {'firmware_EL1_admission', 'exact_payload_valid',
                'kernel_prepared_not_executed', 'no_PSCI_CPU_ON',
                'mock_backend_explicit', 'expected_observer_result',
                'expected_completed_read_count', 'inventory_holds_on_both_results',
                'actual_AP_context_stage_zero', 'actual_kernel_log_total_zero',
                'no_native_startup_log', 'no_panic'}
WATCH_CHECKS = {'watch_result_matches_scope','watch_uses_elapsed_arch_clock','watch_keeps_all_fault_words'}

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def admit(driver, models, fault_watch=False):
    if driver.get('WLED_OEM_status_policy',False) is not False or driver.get('controlled_WLED_status_after_issue',0)!=0:
        raise ValueError('OEM writer status policy is not readonly inventory')
    if type(fault_watch) is not bool or driver.get('WLED_readonly_fault_watch',False) is not fault_watch:
        raise ValueError('explicit readonly fault-watch scope mismatch')
    required = dict(WLED_readonly_inventory_only=True,
                    kernel_CPU_ON_compiled_out=True, kernel_handoff=False,
                    PMIC_write_api=False, storage_write_api=False,
                    NVRAM_write_api=False, physical_buttons=True,
                    probe_only=True, holds_before_OS_start=True,
                    kernel_CPU_affinity=0x700, kernel_CPU_count=4)
    for key, expected in required.items():
        if type(driver.get(key)) is not type(expected) or driver[key] != expected:
            raise ValueError('not the restricted readonly WLED hold: ' + key)
    if (driver.get('QEMU_variant') is not False or
            driver.get('phone_compatible') is not True or
            driver.get('controlled_WLED_read_refusal') is not False or
            driver.get('controlled_WLED_fault_pulse',False) is not False or
            driver.get('physical_owned_marker_test') is not False or
            driver.get('selected_application') is not False or
            driver.get('disk_payload_read_only') is not False or
            driver.get('chain_app') is not None or
            driver.get('ready_to_boot_driver') is not True or
            driver.get('payload_C_admission') is not True or
            driver.get('rebased_kernel_bytes_match') is not True or
            driver.get('RAM_host_idle_recovery_seconds') != 1800):
        raise ValueError('foreign or writable WLED hold mode')
    if not driver.get('inputs') or len(models) != 2:
        raise ValueError('both source-bound positive and read-refusal EFI cases required')
    seen = set()
    for model in models:
        if (model.get('passed') is not True or
                model.get('WLED_readonly_inventory_only') is not True or
                model.get('release_handoff_admitted') is not False or
                model.get('actual_phone_or_PMIC_emulated') is not False or
                model.get('kernel_CPU_started') is not False or
                model.get('PMIC_power_control_tested') is not False or
                model.get('inputs') != driver['inputs'] or
                model.get('kernel_sha256') != driver.get('kernel_sha256')):
            raise ValueError('stale or incorrectly promoted WLED model evidence')
        checks = model.get('checks', {})
        if set(checks) != MODEL_CHECKS | (WATCH_CHECKS if fault_watch else set()) or any(v is not True for v in checks.values()):
            raise ValueError('actual EFI hold/AP-zero/read-refusal checks incomplete')
        refused = model.get('controlled_read_refusal')
        if type(refused) is not bool or refused in seen:
            raise ValueError('distinct positive and read-refusal cases required')
        seen.add(refused)
        raw = model.get('raw_fields', {})
        if (model.get('WLED_readonly_fault_watch',False) is not fault_watch or
                model.get('controlled_fault_pulse',False) is not fault_watch):
            raise ValueError('missing explicit synthetic fault witness binding')
        if (raw.get('WLED_MOCK_BACKEND') != 1 or raw.get('WLED_KERNEL_AP_STAGE') != 0 or
                raw.get('WLED_READ_COMMANDS') != (4 if refused else 32) or
                raw.get('WLED_SNAPSHOT_FORMAT') != 2 or
                raw.get('WLED_READONLY_RESULT') != (6 if refused else 7 if fault_watch else 0) or
                set(model.get('actual_guest_memory', {})) != {'actual_AP_stage', 'actual_kernel_log_total'}):
            raise ValueError('missing actual guest hold/read-refusal observations')
        if fault_watch and (raw.get('WH_SAMPLES')!=(0 if refused else 32) or
                raw.get('WH_COMPLETE')!=int(not refused) or raw.get('WH_ERROR')!=(1 if refused else 0) or
                raw.get('WH_SOURCE_REFUSAL')!=(6 if refused else 7) or raw.get('WH_READS')!=(0 if refused else 128)):
            raise ValueError('missing bounded watch/refusal observations')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('original', 'driver-manifest', 'success', 'read-refused', 'output'):
        ap.add_argument('--' + name, type=Path, required=True)
    ap.add_argument('--expected-original-sha256', required=True)
    ap.add_argument('--fault-watch',action='store_true',help='explicit no-writer fault timeline; separate evidence required')
    a = ap.parse_args()
    root = Path(__file__).resolve().parents[1]
    if a.output.exists():
        raise ValueError('refusing to overwrite a WLED image directory')
    driver = json.loads(a.driver_manifest.read_text())
    cases = [json.loads(p.read_text()) for p in (a.success, a.read_refused)]
    admit(driver, cases,a.fault_watch)
    for name, digest in driver['inputs'].items():
        p = (root / name).resolve()
        if root not in p.parents or sha(p) != digest:
            raise ValueError('WLED source changed: ' + name)
    app = a.driver_manifest.parent / driver['artifact']
    if app.resolve().parent != a.driver_manifest.parent.resolve() or sha(app) != driver['sha256']:
        raise ValueError('physical WLED driver changed')
    for path, model in zip((a.success, a.read_refused), cases):
        m = json.loads((path.parent.parent / (path.parent.name.replace('-run-', '-driver-')) / 'manifest.json').read_text())
        binary = path.parent.parent / (path.parent.name.replace('-run-', '-driver-')) / m['artifact']
        if (model['driver_manifest_sha256'] != sha(binary.parent / 'manifest.json') or
                model['driver_sha256'] != sha(binary) or m['QEMU_variant'] is not True or
                m['inputs'] != driver['inputs'] or
                m['payload_sha256'] != model['payload_sha256'] or
                m['kernel_CPU_ON_compiled_out'] is not True or
                m['kernel_handoff'] is not False):
            raise ValueError('model executable/source binding changed')
    if sha(a.original) != a.expected_original_sha256:
        raise ValueError('original Mindows UEFI changed')
    spec = importlib.util.spec_from_file_location('firmware', root / 'tools/polaris-uefi-firmware.py')
    fw = importlib.util.module_from_spec(spec); spec.loader.exec_module(fw)
    image, record = fw.package(a.original.read_bytes(), app.read_bytes())
    a.output.mkdir(parents=True)
    target = a.output / 'polaris-original-uefi-wled-readonly.img'
    target.write_bytes(image)
    record.update(artifact=target.name, sha256=sha(target), bytes=len(image),
                  original_sha256=a.expected_original_sha256,
                  driver_sha256=driver['sha256'], driver_manifest_sha256=sha(a.driver_manifest),
                  model_result_sha256=[sha(p) for p in (a.success, a.read_refused)],
                  WLED_readonly_inventory_only=True, kernel_CPU_ON_compiled_out=True,
                  WLED_readonly_fault_watch=a.fault_watch,
                  kernel_handoff=False, PMIC_write_api=False,
                  storage_write_api=False, NVRAM_write_api=False,
                  actual_backlight_control_proven=False, installer=False,
                  packager_sha256=sha(Path(__file__)))
    (a.output / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
    print('Original UEFI files preserved; readonly WLED hold packaged, no kernel handoff or power proof')


if __name__ == '__main__':
    main()
