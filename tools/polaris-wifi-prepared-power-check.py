#!/usr/bin/env python3
"""Verify full prepared/current/private power composition without changing old scopes."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('driver', 'normal-bindings', 'bounded-bindings', 'first-bindings', 'budget-bindings', 'staged-bindings', 'hash-proof', 'out'):
        ap.add_argument('--'+name, type=Path, required=True)
    ap.add_argument('--firmware-log-mib',type=int,choices=(10,12),default=12)
    ap.add_argument('--reuse-software-proof',type=Path)
    a = ap.parse_args()
    driver, normal, bounded, first, budget, staged, hp, out = [p.resolve() for p in
        (a.driver, a.normal_bindings, a.bounded_bindings, a.first_bindings, a.budget_bindings, a.staged_bindings, a.hash_proof, a.out)]
    out.mkdir(parents=True, exist_ok=True)
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    d = json.loads((driver/'manifest.json').read_text())
    assert len(d['inputs']) == 86 and sha(driver/d['artifact']) == d['sha256']
    for name, value in d['inputs'].items():
        assert sha(ROOT/name) == value, name
    assert d['wifi_CPU0_power_execution_kind'] == 'STAGED_RO_THEN_CURRENT_PRIVATE_BOUNDED_POWER'
    assert d['wifi_CPU0_power_prepared_transaction'] is True and d['wifi_CPU0_power_prepared_default_OFF'] is True
    for key, value in dict(raw_bytes=1892336, staged_RO_raw_bytes=1660544, client_raw_bytes=227104,
            prepared_binding_raw_bytes=233520, access_raw_bytes=401800, CPU_raw_bytes=10048,
            guarded_PSCI_calls_max=14, steps_max=256, transaction_events_max=1024,
            prepared_current_header_entry_aux_ranges=7, prepared_current_selected_byte_passes=3,
            prepared_current_complete_namespace_passes=2, prepared_current_original_Query_calls=0,
            prepared_masked_FULL_DB_bytes_per_snapshot=131072, prepared_masked_FULL_DB_snapshots=2,
            prepared_original_private_deadline_ticks=3840000,
            CmdDb_GCD_namespace_target_guard_count=120).items():
        assert type(d['wifi_CPU0_power_'+key]) is int and d['wifi_CPU0_power_'+key] == value
    assert d['wifi_CPU0_power_raw_format'] == 'PREPARED_POWER_RAW_V1'
    for key in ('prepared_binding_admission_and_close_arch_retained_separately',
            'prepared_masked_fresh_NS_WB_PAR_restore_each_page', 'prepared_NO_fake_API_observation_or_client',
            'prepared_no_old_RO_ticket_reuse','prepared_final_ticket_unopened_before_Clock',
            'prepared_both_raw_scopes_exported_complete','CPUcritical_and_RSC_reachable'):
        assert d['wifi_CPU0_power_'+key] is True
    assert d['wifi_CPU0_power_CmdDb_capture_only'] is False
    assert d['wifi_CPU0_RPMh_private_client'] is True and d['wifi_CPU0_RPMh_private_API_calls_max'] == 2
    assert d['original_GCD_new_scope_RAM_log_capacity'] == a.firmware_log_mib << 20
    assert d['wifi_CPU0_resources_firmware_RAM_log_capacity'] == a.firmware_log_mib << 20
    assert d['wifi_CPU0_power_CmdDb_original_Query_calls_max'] == 0
    h = json.loads(hp.read_text())
    assert h['passed'] and h['peer']['checks'] == 3007
    for name, value in h['source_files'].items():
        assert sha(ROOT/name) == value, name
    records, dependencies, peers = [], set(), {}
    previous = {}
    if (out/'progress.json').exists():
        assert (out/'cached-unchanged-dependencies.json').exists()
        for name,value in json.loads((out/'cached-unchanged-dependencies.json').read_text()).items():
            assert sha(ROOT/name)==value,name
        previous={x['name']:x for x in json.loads((out/'progress.json').read_text())}


    def run(name, command):
        command = [str(x) for x in command]
        if name in previous:
            old=previous[name];assert old['exit']==0 and old['command']==command
            records.append(old);return (out/(name+'.log')).read_text()
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
            ('old-budget', budget, 'cmddb-budget', 24), ('old-staged', staged, 'cmddb-staged', 50),
            ('prepared-bind', staged, 'cmddb-prepared', 17), ('prepared-power', staged, 'prepared-power', 20)]:
        dep = out/(name+'.d')
        if a.reuse_software_proof:
            prior=json.loads(a.reuse_software_proof.read_text());assert prior['passed'] is True
            build=next(x for x in prior['checks'] if x['name']==name+'-ASAN-UBSAN-build')
            executed=next(x for x in prior['checks'] if x['name']==name+'-ASAN-UBSAN-run')
            assert build['exit']==executed['exit']==0
            olddep=Path(build['command'][build['command'].index('-MF')+1])
            for word in olddep.read_text().replace('\\\n',' ').split()[1:]:
                source=Path(word).resolve()
                if source.is_file() and source.is_relative_to(ROOT):
                    relative=str(source.relative_to(ROOT));assert sha(source)==prior['sources'][relative],relative
            deps(olddep);records.extend([dict(build,reused_unchanged_software=True),dict(executed,reused_unchanged_software=True)])
            peers[name]=prior['peers'][name];assert peers[name]['checks']==count
            continue
        run(name+'-ASAN-UBSAN-build', [*common, '-std=c11', '-D_POSIX_C_SOURCE=200112L',
            '-DEFI_XNU_GCD_MMIO_QUERY_AVAILABLE=1', '-O1', '-g', '-fsanitize=address,undefined',
            '-MD', '-MF', dep, '-I'+str(config), '-I'+str(ROOT/'tools'), '-I'+str(ROOT/'shim/polaris'),
            ROOT/('tools/polaris-wifi-'+source+'-test.c'), '-o', out/name])
        deps(dep)
        peers[name] = json.loads(run(name+'-ASAN-UBSAN-run', [out/name, *original]))
        assert peers[name]['checks'] == count
    assert peers['prepared-power']['new_full_body_bytes'] == d['wifi_CPU0_power_raw_bytes']
    assert peers['prepared-bind']['prepared_binding_raw_bytes'] == d['wifi_CPU0_power_prepared_binding_raw_bytes']
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
    preboot = pp.split('static inline void pwrpt_preboot(',1)[1].split('static inline void pwrpt_raw_hex(',1)[0]
    assert preboot.index('pwsp_run(') < preboot.index('pwrcl_run_body(')
    assert '.preparation=&pwsp_record' in preboot and '.query=0' in preboot
    assert '||pwsp_unsafe(&pwsp_record)' in pp and ',&wln_cpu_on_issued' in pp
    body=pp.split('static inline int pwrpt_body(',1)[1].split('static struct pwrpt_result',1)[0]
    assert 'pwcp_collect(' in body and 'pwcd_collect(' not in body
    for required in ('pwrpb_capture(', 'pwrpc_begin(', 'pwra_acquire_prepared(', 'pwrsc_begin(',
                     'pwrsc_step(', 'pwra_retire(', 'pwrpc_end(', 'pwcp_finish('):
        assert required in body,required
    assert body.index('pwra_retire(') < body.index('pwrpc_end(') < body.index('pwrmd_collect(&io->device,p,work,g,&r->RAM[2]') < body.index('pwcp_finish(')
    report=pp.split('static inline void pwrpt_report(',1)[1].split('static inline int pacgq',1)[0]
    for label in ('WIFI_CMDDB_STAGED_RO_RAW_V1_BEGIN','WIFI_POWER_CLIENT_RAW_V1_BEGIN','WIFI_PREPARED_POWER_RAW_V1_BEGIN'):
        assert label in report,label
    assert 'WIFI_POWER_PATH_RAW' not in report and 'ZERO_VOTE' not in report
    current=pp.split('static inline int pwcp_unsafe(',1)[1].split('enum pwra_error',1)[0]
    for forbidden in ('pgcd_open(', 'pgcd_finish(', 'pgcd_query_page(', '->spent=0', '->result=0', 'memset(', 'client_held=1'):
        assert forbidden not in current,forbidden
    assert 'pgns_collect(' in current and 'pgns_target_guard(' in current and 'pwcd_select_bytes(' in current
    masked=pp.split('static inline int pwra_cmddb_prepared(',1)[1].split('static inline int pwra_cmddb(',1)[0]
    for required in ('for(unsigned k=0;k<(0x20000u/4096u);k++)', 's->raw[offset]!=prepared->database[1][offset]', 't->saved!=t->restored', 'pgns_descriptor('):
        assert required in masked,required
    assert 'g->io.query(' not in masked and 'ops->query(' not in masked
    hold = pp.split('static void power_unknown_hold(', 1)[1].split('_Static_assert', 1)[0]
    for forbidden in ('OutputString', 'Stall(', 'UsbFn', 'reset(', 'pwrcl_actual_drop'):
        assert forbidden not in hold, forbidden
    assert 'daifset,#15' in hold and 'wfe' in hold and 'ram_hex' in hold
    off = run('default-OFF-preprocessed', [*common, '--target=aarch64-unknown-windows', '-ffreestanding',
        '-DEFI_XNU_WLED_NATIVE_RUNTIME_PHYSICAL=1', '-I'+str(bounded), '-I'+str(ROOT/'tools'), '-I'+str(ROOT/'shim/polaris'), '-E', '-P', ROOT/'shim/polaris/uefi-xnu.c'])
    qemu = run('QEMU-preprocessed', [*common, '--target=aarch64-unknown-windows', '-ffreestanding',
        '-DPOLARIS_EFI_TEST_QEMU=1', '-DEFI_XNU_WLED_NATIVE_RUNTIME_TEST=1',
        '-DEFI_XNU_WLED_NATIVE_EXIT_TEST=1', *inc, '-E', '-P', ROOT/'shim/polaris/uefi-xnu.c'])
    for forbidden in ('static struct pwcp_result', 'static inline int pwcp_collect(', 'WIFI_PREPARED_POWER_RAW'):
        assert forbidden not in off and forbidden not in qemu, forbidden
    dependencies.add('tools/polaris-wifi-prepared-power-check.py')
    proof = dict(passed=True, checks=records, software_cases=sum(p['checks'] for p in peers.values()), peers=peers,
        compiled_inputs=d['inputs'], sources={n:sha(ROOT/n) for n in sorted(dependencies)},
        driver_SHA256=d['sha256'], driver_bytes=d['bytes'], max_frame=1024,
        actual_COFF_MachO_parent=True, actual_pp_SHA256=hashlib.sha256(pp.encode()).hexdigest(),
        scalar_hash_proof=str(hp.relative_to(ROOT)), scalar_hash_proof_SHA256=sha(hp),
        four_independently_completed_RO_contexts=True, per_page_immediate_source_and_AT_guard=True,
        original_200ms_each_ticket=True, final_private_tickets_never_reset_rebased=True,
        two_full_DB_copies_and_existing_ARC_decoder=True, same_private_current_CPU_RSC_restore_Delete=True,
        full_masked_DB_comparison_preserved=True, CmdDb_Query_calls=0,
        UNKNOWN_and_full_raw_parent_gate=True, default_OFF_QEMU_compiled_out=True,
        phone_USB=False, phone_timing_proven=False, physical_candidate_ready=False, scan_join_data=False)
    (out/'proof.json').write_text(json.dumps(proof, indent=2)+'\n')
    print(json.dumps(dict(passed=True, checks=len(records), software_cases=proof['software_cases'],
        complete_body_bytes=d['wifi_CPU0_power_raw_bytes'], proof_SHA256=sha(out/'proof.json'), physical_candidate_ready=False)))


if __name__ == '__main__':
    main()
