#!/usr/bin/env python3
"""Verify the NEW parent link, cached failure gates and complete raw publication.

No phone, firmware API, PSCI or hardware access is executed by these checks.
The original PEs are input DATA for the sanitizer peer only.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--driver', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    driver, out = args.driver.resolve(), args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((driver/'manifest.json').read_text())
    sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    assert sha(driver/manifest['artifact']) == manifest['sha256']
    assert len(manifest['inputs']) == 80
    for name, digest in manifest['inputs'].items():
        assert sha(ROOT/name) == digest, name
    for key in ['wifi_CPU0_power_transaction', 'wifi_CPU0_power_default_OFF',
                'wifi_CPU0_power_unknown_blocks_native_PON_receipt',
                'wifi_CPU0_power_UNKNOWN_no_USB_Console_Stall_or_firmware_return',
                'wifi_CPU0_power_exact_local_restore_before_known_Delete',
                'wifi_CPU0_power_new_host_admission_required']:
        assert manifest[key] is True, key
    assert manifest['wifi_CPU0_power_candidate_ready'] is False
    assert manifest['wifi_CPU0_power_hardware_ownership_independently_qualified'] is False
    assert manifest['wifi_CPU0_RPMh_private_direct_provider_RAM_body_only'] is False
    assert manifest['wifi_CPU0_RPMh_private_vote_commandset_MMIO_SMC_MSS_NVserve_calls'] is None
    assert manifest['original_GCD_new_scope_RAM_log_capacity'] == 8388608
    assert manifest['wifi_CPU0_resources_firmware_RAM_log_capacity'] == 8388608
    records = []

    def run(name, command):
        result = subprocess.run([str(x) for x in command], cwd=ROOT, capture_output=True,
                                text=True, timeout=100)
        (out/(name+'.log')).write_text(result.stdout+result.stderr)
        records.append(dict(name=name, command=[str(x) for x in command], exit=result.returncode))
        if result.returncode:
            raise RuntimeError(f'{name}: inspect {out/(name+".log")}')
        return result.stdout

    common = ['/usr/bin/clang', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function']
    inc = ['-I'+str(driver), '-I'+str(ROOT/'tools'), '-I'+str(ROOT/'shim/polaris')]
    run('affected-path-ASAN-UBSAN-build', [*common, '-std=c11', '-D_POSIX_C_SOURCE=200112L',
        '-DEFI_XNU_GCD_MMIO_QUERY_AVAILABLE=1', '-O1', '-g', '-fsanitize=address,undefined',
        *inc, ROOT/'tools/polaris-wifi-power-path-test.c', '-o', out/'peer'])
    files = [ROOT/manifest[key] for key in ['original_GCD_original_PE',
             'wifi_CPU0_NPA_source_PE', 'wifi_CPU0_RPMh_source_PE', 'wifi_CPU0_power_source_PE']]
    peer = json.loads(run('affected-path-ASAN-UBSAN-run', [out/'peer', *files]))
    assert peer['checks'] == 15 and peer['parent_cached_gate_checked'] is True
    assert peer['whole_raw_report_bytes'] == 2924839
    assert peer['real_firmware_or_MMIO_execution'] is False
    # Compile the actual parent main, not a replacement wrapper. Both targets
    # include its literal &wln_cpu_on_issued and non-returning quarantine leaf.
    native = ['-DEFI_XNU_WLED_NATIVE_RUNTIME_PHYSICAL=1']
    for target, suffix in [('aarch64-unknown-windows', 'obj'), ('arm64-apple-macos14', 'o')]:
        run('actual-parent-main-'+suffix, [*common, '--target='+target, '-ffreestanding',
            '-fno-builtin', '-fno-stack-protector', '-fshort-wchar', '-mgeneral-regs-only',
            '-O2', '-Wframe-larger-than=1024', *native, *inc,
            '-c', ROOT/'shim/polaris/uefi-xnu.c', '-o', out/('parent-main.'+suffix)])
    preprocessed = run('actual-parent-main-preprocessed', [*common,
        '--target=aarch64-unknown-windows', '-ffreestanding', *native, *inc,
        '-E', '-P', ROOT/'shim/polaris/uefi-xnu.c'])
    (out/'physical-main.preprocessed.c').write_text(preprocessed)
    assert ',&wln_cpu_on_issued' in preprocessed
    assert 'power_unknown_hold' in preprocessed and 'pwrpt_preboot' in preprocessed
    assert 'WIFI_POWER_PATH_RAW_V1_BEGIN' in preprocessed
    proof = dict(passed=True, scope='NEW complete physical-body parent link and 15 SOFTWARE path/report/gate cases; NO hardware execution',
        checks=records, software=peer, parent_registered=True, whole_EFI_linked=True,
        actual_main_CO_FF_and_MachO=True, actual_main_max_frame=1024,
        literal_native_flag_is_source_address=True, complete_client_and_path_hex_bytes=2924839,
        firmware_log_capacity=8388608, log_snapshot_uses_sizeof_actual_buffer=True,
        held_or_UNKNOWN_is_nonreturning_local_masked_hold=True,
        UNKNOWN_has_no_USB_response_or_automatic_reset=True,
        QEMU_terminal_models_are_separate=True, driver_sha256=manifest['sha256'],
        driver_manifest_sha256=sha(driver/'manifest.json'), current_compiled_inputs=manifest['inputs'],
        extra_source_inputs={n: sha(ROOT/n) for n in ['tools/polaris-wifi-power-parent-check.py', 'tools/polaris-wifi-power-path-test.c']},
        physical_hardware_ownership_established=False, new_host_profile=False,
        original_firmware_or_PSCI_AT_MMIO_executed=False, phone_USB=False,
        new_native_CI=False, old_manifest_or_frozen_controller_modified=False,
        may_vote=False, may_start_MSS=False, may_serve_NV_to_remote=False, scan_join_data=False)
    (out/'proof.json').write_text(json.dumps(proof, indent=2)+'\n')
    print(json.dumps(dict(passed=True, checks=len(records), software_cases=peer['checks'],
        linked_driver=manifest['sha256'], linked_bytes=manifest['bytes'], compiled_inputs=80,
        proof_sha256=sha(out/'proof.json'), physical_candidate_ready=False)))


if __name__ == '__main__':
    main()
