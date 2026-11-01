#!/usr/bin/env python3
"""Verify the distinct bounded READ/complete-restore parent, entirely offline."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('driver', 'legacy-proof', 'bindings', 'off-bindings', 'out'):
        ap.add_argument('--' + name, type=Path, required=True)
    ap.add_argument('--reuse-read-proof', type=Path,
        help='Reuse only the unchanged READ core after exact compiler-dependency hashes match')
    a = ap.parse_args()
    driver, prior, bindings, off, out = [p.resolve() for p in
        (a.driver, a.legacy_proof, a.bindings, a.off_bindings, a.out)]
    out.mkdir(parents=True, exist_ok=False)
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    d = json.loads((driver / 'manifest.json').read_text())
    old = json.loads(prior.read_text())
    assert old['passed'] and old['software_cases'] == 204
    for name, value in old['sources'].items():
        assert sha(ROOT / name) == value, name
    assert len(d['inputs']) == 88 and sha(driver / d['artifact']) == d['sha256']
    for name, value in d['inputs'].items():
        assert sha(ROOT / name) == value, name
    assert d['wifi_CPU0_power_execution_kind'] == 'STAGED_RO_CURRENT_PRIVATE_THREE_READ_RESTORE_NO_RESOURCE_WRITE'
    assert d['wifi_CPU0_power_raw_format'] == 'CURRENT_ARC_READ_RAW_V2'
    for name, value in dict(raw_bytes=1941984, access_raw_bytes=401936,
            current_ARC_read_raw_bytes=49488, current_ARC_read_requests_max=3,
            current_ARC_commands_per_read=1, current_ARC_resource_WRITE_commands_max=0,
            current_ARC_original_Read_API_calls=0, current_ARC_read_MSGID=0x108,
            current_ARC_read_shared_event_limit=1024, current_ARC_read_shared_step_limit=256,
            current_ARC_read_shared_deadline_ticks=960000,
            prepared_original_private_deadline_ticks=3840000).items():
        assert type(d['wifi_CPU0_power_' + name]) is int and d['wifi_CPU0_power_' + name] == value
    for name, value in dict(current_ARC_read=True, current_ARC_read_default_OFF=True,
            current_ARC_read_capture_only=True, current_ARC_resource_WRITE_reachable=False,
            current_ARC_read_single_outstanding=True, current_ARC_read_CMD_DATA_writes=False,
            current_ARC_read_RAW_not_qualified_vote=True,
            current_ARC_read_full_RW_prefix_before_CPU_restore=True,
            current_ARC_read_checked_IO_prefix_crossbound=True,
            current_ARC_read_same_source_client_200ms=True,
            current_ARC_read_entire_partial_raw_preserved=True,
            current_ARC_retired_single_command_latch=True,
            current_ARC_original_FREE_and_request_NULL_required=True,
            current_ARC_trigger_low_readback_before_staging=True,
            current_ARC_three_new_rising_edges=True,
            current_ARC_restore_enable_after_final_ACK=True,
            current_ARC_normal_ON_pending_known_refusal=True,
            current_ARC_CPU_refusal_requires_all_guard_returns_and_full_close=True,
            current_ARC_CPU_refusal_never_masks_or_stores=True,
            current_ARC_unsupported_or_unknown_CPU_state_quarantines=True,
            current_ARC_read_qualified_response_semantics_proven=False).items():
        assert d['wifi_CPU0_power_' + name] is value
    assert type(d['wifi_CPU0_power_current_ARC_high_trigger_restore_stores_max']) is int
    assert d['wifi_CPU0_power_current_ARC_high_trigger_restore_stores_max'] == 0
    records, sources, peers = [], {}, {}

    def run(name, command):
        command = [str(x) for x in command]
        p = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=120)
        (out / (name + '.log')).write_text(p.stdout + p.stderr)
        records.append(dict(name=name, command=command, exit=p.returncode))
        (out / 'progress.json').write_text(json.dumps(records, indent=2) + '\n')
        if p.returncode:
            raise RuntimeError(name + ': inspect ' + str(out / (name + '.log')))
        return p.stdout

    def deps(path):
        for word in path.read_text().replace('\\\n', ' ').split()[1:]:
            p = Path(word).resolve()
            if p.is_file() and p.is_relative_to(ROOT):
                name = str(p.relative_to(ROOT))
                sources[name] = sha(p)

    common = ['/usr/bin/clang', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function']
    originals = [ROOT / d[k] for k in ('original_GCD_original_PE', 'wifi_CPU0_NPA_source_PE',
        'wifi_CPU0_RPMh_source_PE', 'wifi_CPU0_power_source_PE')]
    for name, source, count, arguments in (
            ('read-core', 'polaris-wifi-rsc-read-test.c', 1077, []),
            ('read-parent', 'polaris-wifi-current-read-test.c', 30, originals)):
        if name == 'read-core' and a.reuse_read_proof:
            prior_path = a.reuse_read_proof.resolve()
            prior_read = json.loads(prior_path.read_text())
            assert prior_read['passed'] and prior_read['peers'][name]['checks'] == count
            build = next(x for x in prior_read['checks'] if x['name'] == name + '-ASAN-UBSAN-build')
            executed = next(x for x in prior_read['checks'] if x['name'] == name + '-run')
            assert build['exit'] == executed['exit'] == 0
            dep = Path(build['command'][build['command'].index('-MF') + 1])
            for word in dep.read_text().replace('\\\n', ' ').split()[1:]:
                source = Path(word).resolve()
                if source.is_file() and source.is_relative_to(ROOT):
                    relative = str(source.relative_to(ROOT))
                    assert sha(source) == prior_read['sources'][relative], relative
            deps(dep)
            records.extend([dict(build, reused_unchanged_software=True),
                dict(executed, reused_unchanged_software=True)])
            peers[name] = prior_read['peers'][name]
            continue
        dep = out / (name + '.d')
        run(name + '-ASAN-UBSAN-build', [*common, '-std=c11', '-D_POSIX_C_SOURCE=200112L',
            '-DEFI_XNU_GCD_MMIO_QUERY_AVAILABLE=1', '-O1', '-g', '-fsanitize=address,undefined',
            '-MD', '-MF', dep, '-I' + str(bindings), '-I' + str(ROOT / 'tools'),
            '-I' + str(ROOT / 'shim/polaris'), ROOT / 'tools' / source, '-o', out / name])
        deps(dep)
        peers[name] = json.loads(run(name + '-run', [out / name, *arguments]))
        assert peers[name]['passed'] and peers[name]['checks'] == count
    assert peers['read-parent']['body_bytes'] == d['wifi_CPU0_power_raw_bytes']
    inc = ['-I' + str(driver), '-I' + str(ROOT / 'tools'), '-I' + str(ROOT / 'shim/polaris')]
    for target, suffix in [('aarch64-unknown-windows', 'obj'), ('arm64-apple-macos14', 'o')]:
        dep = out / ('parent-' + suffix + '.d')
        run('actual-parent-' + suffix, [*common, '--target=' + target, '-O2', '-ffreestanding',
            '-fno-builtin', '-fno-stack-protector', '-fshort-wchar', '-mgeneral-regs-only',
            '-Wframe-larger-than=1024', '-DEFI_XNU_WLED_NATIVE_RUNTIME_PHYSICAL=1',
            '-MD', '-MF', dep, *inc, '-c', ROOT / 'shim/polaris/uefi-xnu.c', '-o', out / ('parent.' + suffix)])
        deps(dep)
    pp = run('actual-parent-preprocessed', [*common, '--target=aarch64-unknown-windows', '-ffreestanding',
        '-DEFI_XNU_WLED_NATIVE_RUNTIME_PHYSICAL=1', *inc, '-E', '-P', ROOT / 'shim/polaris/uefi-xnu.c'])
    body = pp.split('static inline int pwrpt_body(', 1)[1].split('static struct pwrpt_result pwrpt_record', 1)[0]
    for required in ('pwra_acquire_read(', 'pwrr_begin(', 'pwrr_step(', 'pwrr_retired(',
            'pwra_retire(', 'pwrpc_end_checked(', 'PWRPT_READ_ONLY', 'goto power_retired'):
        assert required in body, required
    for forbidden in ('pwrsc_begin(', 'pwrsc_step(', 'pwra_bind_write(', 'pwrr_plan('):
        assert forbidden not in body, forbidden
    assert '&wln_cpu_on_issued' in pp
    assert 'WIFI_CURRENT_ARC_READ_RAW_V2_BEGIN' in pp and 'WIFI_PREPARED_POWER_RAW_V1_BEGIN' not in pp
    hold = pp.split('static void power_unknown_hold(', 1)[1].split('_Static_assert', 1)[0]
    for forbidden in ('OutputString', 'Stall(', 'UsbFn', 'reset(', 'pwrcl_actual_drop'):
        assert forbidden not in hold
    assert 'daifset,#15' in hold and 'wfe' in hold and 'ram_hex' in hold
    for name, extra, includes in (
            ('default-OFF', ['-DEFI_XNU_WLED_NATIVE_RUNTIME_PHYSICAL=1'], ['-I' + str(off), *inc[1:]]),
            ('QEMU', ['-DPOLARIS_EFI_TEST_QEMU=1', '-DEFI_XNU_WLED_NATIVE_RUNTIME_TEST=1'], inc)):
        text = run(name + '-preprocessed', [*common, '--target=aarch64-unknown-windows',
            '-ffreestanding', *extra, *includes, '-E', '-P', ROOT / 'shim/polaris/uefi-xnu.c'])
        for forbidden in ('static inline int pwrr_begin(', 'WIFI_CURRENT_ARC_READ_RAW_V2_BEGIN'):
            assert forbidden not in text, (name, forbidden)
    sources['tools/polaris-wifi-current-read-check.py'] = sha(Path(__file__))
    total = old['software_cases'] + sum(x['checks'] for x in peers.values())
    proof = dict(passed=True, checks=records, peers=peers, software_cases=total,
        affected_legacy_proof=str(prior.relative_to(ROOT)), affected_legacy_proof_SHA256=sha(prior),
        sources=sources, compiled_inputs=d['inputs'], driver_SHA256=d['sha256'], driver_bytes=d['bytes'],
        actual_COFF_MachO_parent=True, max_frame=1024, actual_pp_SHA256=hashlib.sha256(pp.encode()).hexdigest(),
        original_200ms_not_reset_rebased=True, single_same_qualified_private_context=True,
        READ_resource_WRITE_compiled_unreachable=True, raw_response_not_saved_vote=True,
        complete_TCS_RW_source_CPU_namespace_restore_required=True, all_partial_raw_preserved=True,
        read_and_checked_IO_prefixes_crossbound=True, full_masked_DB_comparisons_preserved=True,
        UNKNOWN_nonreturn_parent_gate_preserved=True, default_OFF_QEMU_compiled_out=True,
        phone_USB=False, actual_MMIO_or_READ=False, ARC_response_semantics_qualified=False,
        physical_candidate_ready=False, scan_join_data=False)
    (out / 'proof.json').write_text(json.dumps(proof, indent=2) + '\n')
    print(json.dumps(dict(passed=True, checks=len(records), software_cases=total,
        proof_SHA256=sha(out / 'proof.json'), physical_candidate_ready=False)))


if __name__ == '__main__':
    main()
