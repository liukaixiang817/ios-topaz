#!/usr/bin/env python3
"""Verify four independently completed RO preparations, their parent and affected readers."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('driver', 'normal-bindings', 'bounded-bindings', 'first-bindings', 'budget-bindings', 'hash-proof', 'out'):
        ap.add_argument('--'+name, type=Path, required=True)
    a = ap.parse_args()
    driver, normal, bounded, first, budget, hp, out = [p.resolve() for p in
        (a.driver, a.normal_bindings, a.bounded_bindings, a.first_bindings, a.budget_bindings, a.hash_proof, a.out)]
    out.mkdir(parents=True, exist_ok=False)
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    d = json.loads((driver/'manifest.json').read_text())
    assert len(d['inputs']) == 85 and sha(driver/d['artifact']) == d['sha256']
    for name, value in d['inputs'].items():
        assert sha(ROOT/name) == value, name
    prefix = 'wifi_CPU0_power_CmdDb_'
    assert d['wifi_CPU0_power_execution_kind'] == 'STAGED_CMDDB_RO_PREPARATION'
    assert d['wifi_CPU0_power_raw_format'] == 'STAGED_RO_RAW_V1' and d['wifi_CPU0_power_raw_bytes'] == 1660544
    for name in ('staged_RO_prepare', 'staged_RO_default_OFF', 'staged_RO_independent_resident_spent_once_tickets',
                 'staged_RO_before_any_private_client', 'staged_RO_NO_deadline_reset_or_rebase',
                 'staged_RO_final_native_flag_source_literal', 'staged_RO_no_continuous_hardware_lease_claim',
                 'staged_RO_all_loaded_headers_before_after', 'staged_RO_cross_phase_namespace_map_source_equal',
                 'staged_RO_original_ARC_decoder_reused', 'bounded_GCD', 'capture_only'):
        assert d[prefix+name] is True
    for name, value in dict(staged_RO_phases=4, staged_RO_bytes_per_phase=65536,
            staged_RO_phase_raw_bytes=349456, staged_RO_original_fresh_ticks=3840000,
            staged_RO_original_GetMap_calls_max=8, staged_RO_original_LocateProtocol_calls_max=4,
            staged_RO_full_namespace_passes=8, staged_RO_full_database_copies=2,
            GCD_namespace_target_guard_count=68, original_Query_calls_max=0, original_GCD_API_calls_max=0).items():
        assert type(d[prefix+name]) is int and d[prefix+name] == value
    for name in ('wifi_CPU0_RPMh_client_or_vote', 'wifi_CPU0_RPMh_MMIO_or_SMC', 'wifi_CPU0_RPMh_private_client',
                 'wifi_CPU0_RPMh_private_physical_body', 'wifi_CPU0_power_CPUcritical_and_RSC_reachable'):
        assert d[name] is False
    for name in ('wifi_CPU0_RPMh_private_API_calls_max', 'wifi_CPU0_power_guarded_PSCI_calls_max',
                 'wifi_CPU0_power_client_raw_bytes', 'wifi_CPU0_power_access_raw_bytes', 'wifi_CPU0_power_CPU_raw_bytes'):
        assert type(d[name]) is int and d[name] == 0
    assert not d.get(prefix+'first_node_stop') and not d.get(prefix+'work_admission')
    h = json.loads(hp.read_text())
    assert h['passed'] and h['peer']['checks'] == 3007
    for name, value in h['source_files'].items():
        assert sha(ROOT/name) == value, name
    records, dependencies, peers = [], set(), {}

    def run(name, command):
        command = [str(x) for x in command]
        r = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=120)
        (out/(name+'.log')).write_text(r.stdout+r.stderr)
        records.append(dict(name=name, command=command, exit=r.returncode))
        (out/'progress.json').write_text(json.dumps(records, indent=2)+'\n')
        if r.returncode:
            raise RuntimeError(name+': inspect '+str(out/(name+'.log')))
        return r.stdout

    def deps(file):
        for word in file.read_text().replace('\\\n', ' ').split()[1:]:
            p = Path(word).resolve()
            if p.is_file() and p.is_relative_to(ROOT):
                dependencies.add(str(p.relative_to(ROOT)))

    common = ['/usr/bin/clang', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function']
    original = [ROOT/d[k] for k in ('original_GCD_original_PE', 'wifi_CPU0_NPA_source_PE', 'wifi_CPU0_RPMh_source_PE', 'wifi_CPU0_power_source_PE')]
    for name, config, source, count in [('normal', normal, 'power-path', 17),
            ('old-bounded', bounded, 'cmddb-bounded', 37), ('old-first', first, 'cmddb-first-node', 37),
            ('old-budget', budget, 'cmddb-budget', 24), ('staged', driver, 'cmddb-staged', 50)]:
        dep = out/(name+'.d')
        run(name+'-ASAN-UBSAN-build', [*common, '-std=c11', '-D_POSIX_C_SOURCE=200112L',
            '-DEFI_XNU_GCD_MMIO_QUERY_AVAILABLE=1', '-O1', '-g', '-fsanitize=address,undefined',
            '-MD', '-MF', dep, '-I'+str(config), '-I'+str(ROOT/'tools'), '-I'+str(ROOT/'shim/polaris'),
            ROOT/('tools/polaris-wifi-'+source+'-test.c'), '-o', out/name])
        deps(dep)
        peers[name] = json.loads(run(name+'-ASAN-UBSAN-run', [out/name, *original]))
        assert peers[name]['checks'] == count
    assert peers['staged']['staged_raw_bytes'] == d['wifi_CPU0_power_raw_bytes']
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
    assert 'pwsp_run(&staged,enumeration,stage,final,native_cpu_on,&pwsp_record)' in preboot
    for forbidden in ('pwrcl_run_body(', 'pwbd_run(', 'pwrcl_actual_create', 'pwrcl_actual_drop'):
        assert forbidden not in preboot, forbidden
    assert '||pwsp_unsafe(&pwsp_record)' in pp and ',&wln_cpu_on_issued' in pp
    report = pp.split('static inline void pwrpt_report(', 1)[1].split('static inline int pacgq', 1)[0]
    for required in ('WIFI_CMDDB_STAGED_RO_RAW_V1_BEGIN', 'sizeof(pwsp_record)', 'NO_PRIVATE_CLIENT_NO_QUERY_NO_CRITICAL_PSCI_NO_RSC'):
        assert required in report, required
    for forbidden in ('WIFI_POWER_CLIENT_RAW', 'WIFI_POWER_PATH_RAW', 'ZERO_VOTE'):
        assert forbidden not in report, forbidden
    staged = pp.split('static inline int pwsp_unsafe(', 1)[1].split('static inline int pwrpt_body(', 1)[0]
    for forbidden in ('pgcd_finish(', 'pgcd_query_page(', 'pwrcl_run_body(', 'pwrpc_begin(',
                      'pwra_acquire(', 'pwrsc_step(', '->spent=0', '->result=0', 'memset(', 'client_held=1'):
        assert forbidden not in staged, forbidden
    for required in ('pgcd_open(g)', 'pgcd_map_read(g,1)', 'pgcd_snapshot(g,1)',
                     'pgns_collect_ro(', 'pgns_target_guard_ro(', 'pgns_ro_owner_close(',
                     'pwcd_select_bytes(', 'r->phase=3;g->finished=1;s->retired=1'):
        assert required in staged, required
    close = staged.split('static inline int pwsp_close(', 1)[1].split('static inline int pwsp_piece(', 1)[0]
    assert close.index('pgcd_map_read(g,1)') < close.index('pgns_target_guard_ro(') < close.index('pwsp_source_snapshot(s,1)') < close.index('pgns_ro_owner_close(') < close.index('g->finished=1')
    hold = pp.split('static void power_unknown_hold(', 1)[1].split('_Static_assert', 1)[0]
    for forbidden in ('OutputString', 'Stall(', 'UsbFn', 'reset(', 'pwrcl_actual_drop'):
        assert forbidden not in hold, forbidden
    assert 'daifset,#15' in hold and 'wfe' in hold and 'ram_hex' in hold
    off = run('default-OFF-preprocessed', [*common, '--target=aarch64-unknown-windows', '-ffreestanding',
        '-DEFI_XNU_WLED_NATIVE_RUNTIME_PHYSICAL=1', '-I'+str(bounded), '-I'+str(ROOT/'tools'), '-I'+str(ROOT/'shim/polaris'), '-E', '-P', ROOT/'shim/polaris/uefi-xnu.c'])
    qemu = run('QEMU-preprocessed', [*common, '--target=aarch64-unknown-windows', '-ffreestanding',
        '-DPOLARIS_EFI_TEST_QEMU=1', '-DEFI_XNU_WLED_NATIVE_RUNTIME_TEST=1',
        '-DEFI_XNU_WLED_NATIVE_EXIT_TEST=1', *inc, '-E', '-P', ROOT/'shim/polaris/uefi-xnu.c'])
    for forbidden in ('static struct pwsp_result pwsp_record', 'static inline int pwsp_run(', 'WIFI_CMDDB_STAGED_RO_RAW'):
        assert forbidden not in off and forbidden not in qemu, forbidden
    dependencies.add('tools/polaris-wifi-cmddb-staged-check.py')
    proof = dict(passed=True, checks=records, software_cases=sum(p['checks'] for p in peers.values()), peers=peers,
        compiled_inputs=d['inputs'], sources={n:sha(ROOT/n) for n in sorted(dependencies)},
        driver_SHA256=d['sha256'], driver_bytes=d['bytes'], max_frame=1024,
        actual_COFF_MachO_parent=True, actual_pp_SHA256=hashlib.sha256(pp.encode()).hexdigest(),
        scalar_hash_proof=str(hp.relative_to(ROOT)), scalar_hash_proof_SHA256=sha(hp),
        four_independently_completed_RO_contexts=True, per_page_immediate_source_and_AT_guard=True,
        original_200ms_each_ticket=True, final_private_tickets_never_reset_rebased=True,
        two_full_DB_copies_and_existing_ARC_decoder=True, no_client_Query_PSCI_RSC=True,
        UNKNOWN_and_full_raw_parent_gate=True, default_OFF_QEMU_compiled_out=True,
        phone_USB=False, phone_timing_proven=False, physical_candidate_ready=False, scan_join_data=False)
    (out/'proof.json').write_text(json.dumps(proof, indent=2)+'\n')
    print(json.dumps(dict(passed=True, checks=len(records), software_cases=proof['software_cases'],
        staged_raw_bytes=d['wifi_CPU0_power_raw_bytes'], proof_SHA256=sha(out/'proof.json'), physical_candidate_ready=False)))


if __name__ == '__main__':
    main()
