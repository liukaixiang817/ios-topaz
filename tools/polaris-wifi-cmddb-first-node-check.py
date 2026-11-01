#!/usr/bin/env python3
"""Verify first raw Core node planned-stop parent; no complete namespace or database load."""
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
    ap.add_argument('--bounded-bindings', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    a = ap.parse_args()
    driver, normal, bounded, out = [p.resolve() for p in (a.driver, a.normal_bindings, a.bounded_bindings, a.out)]
    out.mkdir(parents=True, exist_ok=False)
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    d = json.loads((driver/'manifest.json').read_text())
    assert len(d['inputs']) == 82 and sha(driver/d['artifact']) == d['sha256']
    for name, value in d['inputs'].items():
        assert sha(ROOT/name) == value, name
    assert d['wifi_CPU0_power_CmdDb_bounded_GCD'] is True
    assert d['wifi_CPU0_power_CmdDb_first_node_stop'] is True
    assert d['wifi_CPU0_power_CmdDb_effective_node_budget'] == 1
    assert d['wifi_CPU0_power_CmdDb_namespace_complete_possible'] is False
    assert d['wifi_CPU0_power_CmdDb_database_target_bytes_max'] == 0
    assert d['wifi_CPU0_power_CmdDb_GCD_namespace_target_guard_count'] == 0
    assert d['wifi_CPU0_power_CmdDb_planned_stop_error'] == 14
    assert d['wifi_CPU0_power_CmdDb_first_node_no_UNKNOWN_clearing'] is True
    assert d['wifi_CPU0_power_CmdDb_GCD_namespace_no_EFI_status_fabrication'] is True
    assert d['wifi_CPU0_power_CmdDb_GCD_namespace_no_API_fallback'] is True
    assert d['wifi_CPU0_power_raw_format'] == 'RAW_V2'
    assert d['wifi_CPU0_power_raw_bytes'] == 1656240
    assert d['wifi_CPU0_power_CmdDb_GCD_namespace_raw_bytes'] == 183064
    assert d['wifi_CPU0_power_CmdDb_GCD_namespace_target_guard_bytes'] == 832
    for field in ('CmdDb_original_Query_calls_max', 'CmdDb_original_GCD_API_calls_max',
                  'CmdDb_GCD_namespace_lock_or_TPL_calls_max', 'guarded_PSCI_calls_max',
                  'steps_max', 'transaction_events_max'):
        assert type(d['wifi_CPU0_power_'+field]) is int and d['wifi_CPU0_power_'+field] == 0
    records, dependencies = [], set()

    def run(name, command):
        r = subprocess.run([str(x) for x in command], cwd=ROOT, capture_output=True, text=True, timeout=100)
        (out/(name+'.log')).write_text(r.stdout+r.stderr)
        records.append(dict(name=name, command=[str(x) for x in command], exit=r.returncode))
        if r.returncode:
            raise RuntimeError(name+': inspect '+str(out/(name+'.log')))
        return r.stdout

    def deps(file):
        for word in file.read_text().replace('\\\n', ' ').split()[1:]:
            p = Path(word).resolve()
            if p.is_file() and p.is_relative_to(ROOT):
                dependencies.add(str(p.relative_to(ROOT)))

    common = ['/usr/bin/clang', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function']
    original = [ROOT/d[k] for k in ('original_GCD_original_PE', 'wifi_CPU0_NPA_source_PE',
        'wifi_CPU0_RPMh_source_PE', 'wifi_CPU0_power_source_PE')]
    peers = {}
    for name, config, source, count in [('normal', normal, 'power-path', 17),
            ('old-bounded', bounded, 'cmddb-bounded', 37), ('first-node', driver, 'cmddb-first-node', 37)]:
        dep = out/(name+'.d')
        run(name+'-ASAN-UBSAN-build', [*common, '-std=c11', '-D_POSIX_C_SOURCE=200112L',
            '-DEFI_XNU_GCD_MMIO_QUERY_AVAILABLE=1', '-O1', '-g', '-fsanitize=address,undefined',
            '-MD', '-MF', dep, '-I'+str(config), '-I'+str(ROOT/'tools'), '-I'+str(ROOT/'shim/polaris'),
            ROOT/('tools/polaris-wifi-'+source+'-test.c'), '-o', out/name])
        deps(dep)
        peers[name] = json.loads(run(name+'-ASAN-UBSAN-run', [out/name, *original]))
        assert peers[name]['checks'] == count
    assert peers['first-node']['path_raw_bytes'] == d['wifi_CPU0_power_raw_bytes']
    assert peers['first-node']['physical_firmware_executed'] is False
    inc = ['-I'+str(driver), '-I'+str(ROOT/'tools'), '-I'+str(ROOT/'shim/polaris')]
    for target, suffix in [('aarch64-unknown-windows', 'obj'), ('arm64-apple-macos14', 'o')]:
        dep = out/('parent-'+suffix+'.d')
        run('actual-parent-'+suffix, [*common, '--target='+target, '-O2', '-ffreestanding',
            '-fno-builtin', '-fno-stack-protector', '-fshort-wchar', '-mgeneral-regs-only',
            '-Wframe-larger-than=1024', '-DEFI_XNU_WLED_NATIVE_RUNTIME_PHYSICAL=1',
            '-MD', '-MF', dep, *inc, '-c', ROOT/'shim/polaris/uefi-xnu.c', '-o', out/('parent.'+suffix)])
        deps(dep)
    pp = run('actual-parent-preprocessed', [*common, '--target=aarch64-unknown-windows',
        '-ffreestanding', '-DEFI_XNU_WLED_NATIVE_RUNTIME_PHYSICAL=1', *inc, '-E', '-P', ROOT/'shim/polaris/uefi-xnu.c'])
    body = pp.split('static inline int pwcd_database_read(', 1)[1].split('static inline int pwcd_query_matches(', 1)[0]
    for forbidden in ('g->io.query(', 'pwcd_enter(', 'pwcd_leave(', 'get_descriptor,', 'pgns_target_guard(', 'PWCD_LOAD', 'r->database_raw['):
        assert forbidden not in body, forbidden
    for required in ('pgns_collect(', 'pgns_first_node_stopped(', 'PWCD_FIRST_NODE_STOP'):
        assert required in body, required
    assert 'pwcd_actual_query' not in pp and 'ops->query(' not in pp
    assert 'WIFI_POWER_PATH_RAW_V2_BEGIN' in pp and 'WIFI_POWER_PATH_RAW_V1_BEGIN' not in pp
    assert 'FIRST_CORE_NODE_PLANNED_STOP_PARTIAL_NAMESPACE_NO_DATABASE_LOAD' in pp
    assert 'power_unknown_hold' in pp and ',&wln_cpu_on_issued' in pp
    power = pp.split('static inline int pwrpt_body(', 1)[1].split('static struct pwrpt_result', 1)[0]
    for forbidden in ('pwrpc_begin(', 'pwrmd_collect(', 'pwra_acquire(', 'pwrsc_begin(', 'pwrsc_step('):
        assert forbidden not in power
    dependencies.add('tools/polaris-wifi-cmddb-first-node-check.py')
    proof = dict(passed=True, checks=records, software_cases=sum(p['checks'] for p in peers.values()),
        peers=peers, linked_driver_SHA256=d['sha256'], linked_bytes=d['bytes'], compiled_inputs=d['inputs'],
        sources={n:sha(ROOT/n) for n in sorted(dependencies)},
        actual_parent_COFF_and_MachO=True, max_frame=1024,
        actual_preprocessed_parent_SHA256=hashlib.sha256(pp.encode()).hexdigest(),
        no_original_GCD_Query_in_CmdDb_body=True, no_original_CmdDb_Query=True,
        no_database_target_load_in_actual_preprocessed_body=True, full_namespace_or_stable_proven=False,
        UNKNOWN_never_cleared_or_reclassified=True,
        complete_RAW_V2_retained=True, original_EFI_status_not_fabricated=True,
        critical_and_RSC_body_compiled_out=True, bounded_subrecords_explicit_parent_gate=True,
        scope='same known private client -> original Core source/head/released-lock/template -> one fully owned/AT-checked RAW node -> both source checkpoints -> planned PARTIAL stop BEFORE node-field interpretation or database target load -> known-client retirement; SOFTWARE peers only',
        phone_USB=False, original_firmware_executed=False, physical_root_cause_isolated=False,
        new_native_CI=False, new_host_profile_ready=False, physical_candidate_ready=False, scan_join_data=False)
    (out/'proof.json').write_text(json.dumps(proof, indent=2)+'\n')
    print(json.dumps(dict(passed=True, checks=len(records), software_cases=proof['software_cases'],
        raw_bytes=d['wifi_CPU0_power_raw_bytes'], proof_SHA256=sha(out/'proof.json'), physical_candidate_ready=False)))


if __name__ == '__main__':
    main()
