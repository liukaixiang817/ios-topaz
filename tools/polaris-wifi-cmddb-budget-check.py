#!/usr/bin/env python3
"""Verify separate completed RO work admission and the full private capture."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('driver', 'normal-bindings', 'bounded-bindings', 'first-bindings', 'hash-proof', 'out'):
        ap.add_argument('--'+name, type=Path, required=True)
    a = ap.parse_args()
    driver, normal, bounded, first, hash_proof, out = [p.resolve() for p in
        (a.driver, a.normal_bindings, a.bounded_bindings, a.first_bindings, a.hash_proof, a.out)]
    out.mkdir(parents=True, exist_ok=False)
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    d = json.loads((driver/'manifest.json').read_text())
    assert len(d['inputs']) == 83 and sha(driver/d['artifact']) == d['sha256']
    for name, value in d['inputs'].items():
        assert sha(ROOT/name) == value, name
    assert d['wifi_CPU0_power_CmdDb_bounded_GCD'] is True
    assert d['wifi_CPU0_power_CmdDb_capture_only'] is True
    assert not d.get('wifi_CPU0_power_CmdDb_first_node_stop')
    assert d['wifi_CPU0_power_CmdDb_GCD_namespace_target_guard_count'] == 66
    for name in ('work_admission', 'work_admission_default_OFF', 'work_admission_independent_RO_ticket',
                 'work_admission_before_private_Create', 'work_admission_no_deadline_renewal',
                 'work_admission_estimate_not_hardware_authority'):
        assert d['wifi_CPU0_power_CmdDb_'+name] is True
    for name, value in dict(work_admission_samples=3, work_admission_checkpoints=80,
            work_admission_reserve_ticks=480000, work_admission_plan_ticks=2400000,
            work_admission_original_GetMap_calls_max=2, work_admission_original_GCD_Query_calls=0,
            work_admission_Core_hash_checkpoints=5, work_admission_original_fresh_ticks=3840000,
            work_admission_raw_bytes=31552).items():
        assert type(d['wifi_CPU0_power_CmdDb_'+name]) is int and d['wifi_CPU0_power_CmdDb_'+name] == value
    h = json.loads(hash_proof.read_text())
    assert h['passed'] and h['peer']['checks'] == 3007
    for name, value in h['source_files'].items():
        assert sha(ROOT/name) == value, name
    records, dependencies, peers = [], set(), {}

    def run(name, command):
        r = subprocess.run([str(x) for x in command], cwd=ROOT, capture_output=True, text=True, timeout=120)
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
    for name, config, source, count in [('normal', normal, 'power-path', 17),
            ('old-bounded', bounded, 'cmddb-bounded', 37), ('old-first', first, 'cmddb-first-node', 37),
            ('budget-full', driver, 'cmddb-budget', 24)]:
        dep = out/(name+'.d')
        run(name+'-ASAN-UBSAN-build', [*common, '-std=c11', '-D_POSIX_C_SOURCE=200112L',
            '-DEFI_XNU_GCD_MMIO_QUERY_AVAILABLE=1', '-O1', '-g', '-fsanitize=address,undefined',
            '-MD', '-MF', dep, '-I'+str(config), '-I'+str(ROOT/'tools'), '-I'+str(ROOT/'shim/polaris'),
            ROOT/('tools/polaris-wifi-'+source+'-test.c'), '-o', out/name])
        deps(dep)
        peers[name] = json.loads(run(name+'-ASAN-UBSAN-run', [out/name, *original]))
        assert peers[name]['checks'] == count
    assert peers['budget-full']['budget_raw_bytes'] == d['wifi_CPU0_power_CmdDb_work_admission_raw_bytes']
    assert peers['budget-full']['complete_same_context_DB_after_budget'] is True
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
    preboot = pp.split('static inline void pwrpt_preboot(', 1)[1].split('static inline void pwrpt_raw_hex(', 1)[0]
    assert preboot.index('pwbd_run(final,stage,&pwbd_record)') < preboot.index('pwrcl_run_body(')
    assert '||!pwbd_record.admitted)return;' in preboot
    assert 'return pwbd_parent_unsafe()||pwrpt_unsafe(&pwrpt_record)||pwrcl_unsafe();' in pp
    assert 'power_unknown_hold' in pp and ',&wln_cpu_on_issued' in pp
    for required in ('WIFI_CMDDB_WORK_ADMISSION_RAW_V1_BEGIN', 'WIFI_POWER_PATH_RAW_V2_BEGIN',
                     'INDEPENDENT_COMPLETED_RO_CONTEXT_BEFORE_PRIVATE_CLIENT', 'pgns_target_guard('):
        assert required in pp, required
    admission = pp.split('static inline int pwbd_run(', 1)[1].split('static inline int pwbd_parent_unsafe(', 1)[0]
    for forbidden in ('pgcd_finish(', 'pgcd_query_page(', 'pwrcl_run_body(', '->spent=0', '->result=0', 'memset('):
        assert forbidden not in admission, forbidden
    for required in ('pgcd_open(c)', 'pgcd_map_read(c,1)', 'pgcd_snapshot(c,1)',
                     'pgci_verify(', 'r->core.phase=3;c->finished=1', 'r->retired=1'):
        assert required in admission, required
    body = pp.split('static inline int pwcd_database_read(', 1)[1].split('static inline int pwcd_query_matches(', 1)[0]
    assert 'g->io.query(' not in body and 'pgns_collect(' in body and 'pgns_target_guard(' in body
    assert 'pwcd_actual_query' not in pp and 'ops->query(' not in pp
    power = pp.split('static inline int pwrpt_body(', 1)[1].split('static struct pwrpt_result', 1)[0]
    for forbidden in ('pwrpc_begin(', 'pwrmd_collect(', 'pwra_acquire(', 'pwrsc_begin(', 'pwrsc_step('):
        assert forbidden not in power, forbidden
    off = run('default-OFF-preprocessed', [*common, '--target=aarch64-unknown-windows', '-ffreestanding',
        '-DEFI_XNU_WLED_NATIVE_RUNTIME_PHYSICAL=1',
        '-I'+str(bounded), '-I'+str(ROOT/'tools'), '-I'+str(ROOT/'shim/polaris'), '-E', '-P', ROOT/'shim/polaris/uefi-xnu.c'])
    qemu = run('QEMU-preprocessed', [*common, '--target=aarch64-unknown-windows', '-ffreestanding',
        '-DPOLARIS_EFI_TEST_QEMU=1', '-DEFI_XNU_WLED_NATIVE_RUNTIME_TEST=1',
        '-DEFI_XNU_WLED_NATIVE_EXIT_TEST=1', *inc, '-E', '-P', ROOT/'shim/polaris/uefi-xnu.c'])
    for forbidden in ('static struct pwbd_result pwbd_record', 'static inline int pwbd_run('):
        assert forbidden not in off and forbidden not in qemu, forbidden
    dependencies.add('tools/polaris-wifi-cmddb-budget-check.py')
    proof = dict(passed=True, checks=records, software_cases=sum(p['checks'] for p in peers.values()), peers=peers,
        compiled_inputs=d['inputs'], sources={n:sha(ROOT/n) for n in sorted(dependencies)},
        driver_SHA256=d['sha256'], driver_bytes=d['bytes'], max_frame=1024,
        actual_COFF_MachO_parent=True, actual_pp_SHA256=hashlib.sha256(pp.encode()).hexdigest(),
        scalar_hash_proof=str(hash_proof.relative_to(ROOT)), scalar_hash_proof_SHA256=sha(hash_proof),
        independent_RO_phase_retired_before_actual_private_Create=True, private_final_tickets_never_rebased=True,
        estimate_is_not_future_timing_proof=True, original_private_200ms_unchanged=True,
        UNKNOWN_and_raw_parent_gate=True, no_original_GCD_Query_or_CmdDb_Query=True,
        no_critical_PSCI_or_RSC=True, default_OFF_QEMU_compiled_out=True,
        phone_USB=False, phone_timing_proven=False, physical_candidate_ready=False, scan_join_data=False)
    (out/'proof.json').write_text(json.dumps(proof, indent=2)+'\n')
    print(json.dumps(dict(passed=True, checks=len(records), software_cases=proof['software_cases'],
        work_raw_bytes=d['wifi_CPU0_power_CmdDb_work_admission_raw_bytes'], proof_SHA256=sha(out/'proof.json'), physical_candidate_ready=False)))


if __name__ == '__main__':
    main()
