#!/usr/bin/env python3
"""Verify the focused capture-only parent; original EFI files are input data."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--driver', type=Path, required=True)
    ap.add_argument('--normal-bindings', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    a = ap.parse_args()
    driver, normal, out = a.driver.resolve(), a.normal_bindings.resolve(), a.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    d = json.loads((driver/'manifest.json').read_text())
    assert len(d['inputs']) == 80 and sha(driver/d['artifact']) == d['sha256']
    for name, value in d['inputs'].items():
        assert sha(ROOT/name) == value, name
    assert d['wifi_CPU0_power_CmdDb_capture_only'] is True
    assert d['wifi_CPU0_power_CPUcritical_and_RSC_reachable'] is False
    for field in ('CmdDb_original_Query_calls_max', 'guarded_PSCI_calls_max', 'steps_max', 'transaction_events_max'):
        assert type(d['wifi_CPU0_power_'+field]) is int and d['wifi_CPU0_power_'+field] == 0
    assert d['wifi_CPU0_power_CmdDb_planned_stop_error'] == 13
    records = []

    def run(name, command, expected=0):
        r = subprocess.run([str(x) for x in command], cwd=ROOT, capture_output=True,
                           text=True, timeout=100)
        (out/(name+'.log')).write_text(r.stdout+r.stderr)
        records.append(dict(name=name, command=[str(x) for x in command], exit=r.returncode))
        if (expected == 0 and r.returncode) or (expected != 0 and not r.returncode):
            raise RuntimeError(name+': '+str(out/(name+'.log')))
        return r.stdout

    common = ['/usr/bin/clang', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function']
    sources = [('normal', normal, 'polaris-wifi-power-path-test.c', 17),
               ('capture', driver, 'polaris-wifi-cmddb-capture-test.c', 7)]
    peers = {}
    original = [ROOT/d[k] for k in ('original_GCD_original_PE', 'wifi_CPU0_NPA_source_PE',
                                   'wifi_CPU0_RPMh_source_PE', 'wifi_CPU0_power_source_PE')]
    for name, config, source, count in sources:
        run(name+'-ASAN-UBSAN-build', [*common, '-std=c11', '-D_POSIX_C_SOURCE=200112L',
            '-DEFI_XNU_GCD_MMIO_QUERY_AVAILABLE=1', '-O1', '-g', '-fsanitize=address,undefined',
            '-I'+str(config), '-I'+str(ROOT/'tools'), '-I'+str(ROOT/'shim/polaris'),
            ROOT/'tools'/source, '-o', out/name])
        peers[name] = json.loads(run(name+'-ASAN-UBSAN-run', [out/name, *original]))
        assert peers[name]['checks'] == count
    inc = ['-I'+str(driver), '-I'+str(ROOT/'tools'), '-I'+str(ROOT/'shim/polaris')]
    native = ['-DEFI_XNU_WLED_NATIVE_RUNTIME_PHYSICAL=1']
    for target, suffix in [('aarch64-unknown-windows', 'obj'), ('arm64-apple-macos14', 'o')]:
        run('actual-parent-'+suffix, [*common, '--target='+target, '-O2', '-ffreestanding',
            '-fno-builtin', '-fno-stack-protector', '-fshort-wchar', '-mgeneral-regs-only',
            '-Wframe-larger-than=1024', *native, *inc, '-c', ROOT/'shim/polaris/uefi-xnu.c',
            '-o', out/('parent.'+suffix)])
    pp = run('actual-parent-preprocessed', [*common, '--target=aarch64-unknown-windows',
        '-ffreestanding', *native, *inc, '-E', '-P', ROOT/'shim/polaris/uefi-xnu.c'])
    body = pp.split('static inline int pwrpt_body(', 1)[1].split('static struct pwrpt_result', 1)[0]
    for forbidden in ('pwrpc_begin(', 'pwrmd_collect(', 'pwra_acquire(', 'pwrsc_begin(', 'pwrsc_step('):
        assert forbidden not in body, forbidden
    assert 'pwcd_actual_query' not in pp and 'ops->query(' not in pp
    assert '.query=0' in pp and ',&wln_cpu_on_issued' in pp and 'power_unknown_hold' in pp
    assert 'CMDDB_CAPTURE_ONLY_PLANNED_STOP_NO_QUERY_API_NO_CPU_CRITICAL_NO_RSC' in pp
    assert 'WIFI_POWER_PATH_RAW_V1_BEGIN' in pp
    proof = dict(passed=True, scope='focused complete namespace capture and known retirement; NO original Query/CPU-critical/RSC execution',
        checks=records, software_peers=peers, linked_driver_SHA256=d['sha256'], linked_bytes=d['bytes'],
        compiled_inputs=d['inputs'], actual_parent_CO_FF_and_MachO=True, max_frame=1024,
        actual_preprocessed_parent_SHA256=hashlib.sha256(pp.encode()).hexdigest(),
        capture_Query_adapter_absent=True, capture_critical_and_RSC_body_absent=True,
        complete_raw_abi_preserved=True, unknown_still_blocks_native_PON_receipt=True,
        physical_firmware_executed=False, physical_root_cause_isolated=False,
        new_native_CI=False, phone_USB=False, scan_join_data=False,
        extra_sources={name:sha(ROOT/name) for name in ('tools/polaris-wifi-cmddb-capture-check.py',
            'tools/polaris-wifi-cmddb-capture-test.c', 'tools/polaris-wifi-power-path-test.c')})
    (out/'proof.json').write_text(json.dumps(proof, indent=2)+'\n')
    print(json.dumps(dict(passed=True, checks=len(records), software_cases=24,
        proof_SHA256=sha(out/'proof.json'), physical_candidate_ready=False)))


if __name__ == '__main__':
    main()
