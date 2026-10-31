#!/usr/bin/env python3
"""Check CmdDb -> bounded ARC transaction components with software peers only."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bindings', type=Path, required=True)
    p.add_argument('--original-pe', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    out, bindings = a.out.resolve(), a.bindings.resolve()
    out.mkdir(parents=True, exist_ok=True)
    spec = importlib.util.spec_from_file_location('own_cmddb', ROOT/'tools/polaris-wifi-cmddb-identity.py')
    identity = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(identity)
    header, bound = identity.binding(a.original_pe.resolve())
    (out/'uefi-wifi-cmddb-binding.h').write_text(header)
    core = ROOT/json.loads((bindings/'manifest.json').read_text())['original_GCD_original_PE']
    results = []

    def run(name, cmd):
        result = subprocess.run([str(x) for x in cmd], cwd=ROOT, capture_output=True, text=True, timeout=60)
        (out/(name+'.log')).write_text(result.stdout+result.stderr)
        results.append(dict(name=name, command=[str(x) for x in cmd], exit=result.returncode))
        if result.returncode:
            raise RuntimeError(f'{name}: {out/(name+".log")}')
        return result.stdout

    inc = ['-I'+str(ROOT/'tools'), '-I'+str(ROOT/'shim/polaris'), '-I'+str(bindings), '-I'+str(out)]
    common = ['/usr/bin/clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function']
    with tempfile.TemporaryDirectory(prefix='polaris-power-check-') as temporary:
        temporary = Path(temporary)
        peers = {}
        for label, source in [('RSC', 'polaris-wifi-rsc-transaction-test.c'),
                              ('CmdDb', 'polaris-wifi-cmddb-test.c'),
                              ('pipeline', 'polaris-wifi-power-integration-test.c')]:
            binary = temporary/label
            run(label+'-ASAN-UBSAN-build', [*common, '-D_POSIX_C_SOURCE=200112L', '-DEFI_XNU_GCD_MMIO_QUERY_AVAILABLE=1',
                '-O1', '-g', '-fsanitize=address,undefined', *inc, ROOT/'tools'/source, '-o', binary])
            args = [] if label == 'RSC' else [core, a.original_pe.resolve()]
            peers[label] = json.loads(run(label+'-software-run', [binary, *args]))
        assert peers['RSC']['checks'] == 36 and peers['CmdDb']['checks'] == 35 and peers['pipeline']['checks'] == 1
        assert peers['RSC']['hardware_MMIO_executed'] is False and peers['pipeline']['physical_lease_established'] is False
        wrapper = out/'freestanding-components.c'
        wrapper.write_text('#include <stdint.h>\nvoid text(const char *);void report(const char *,uint64_t);\n'
            '#include "uefi-xnu-config.h"\n#include "uefi-gcd-mmio-readonly.h"\n#include "uefi-audio-i2c-cache.h"\n'
            '#define EFI_XNU_WIFI_CMDDB_QUERY_AVAILABLE 1\n#include "uefi-wifi-cmddb-query.h"\n'
            '#include "polaris-wifi-rsc-transaction.h"\n'
            'int query_component(struct pwcd_io *io,const struct paic_result *e,struct pgcd_context *g,struct pwcd_result *r,struct pwrph_work *w){\n'
            ' io->query=pwcd_actual_query;return pwcd_collect(io,e,g,r,w);}\n'
            'int power_component(const struct pwrsc_io *io,struct pwrsc_transaction *r,unsigned mask,const uint32_t *saved,const uint32_t *desired){\n'
            ' return pwrsc_begin(io,r,mask,saved,desired);}\n'
            'int power_component_step(const struct pwrsc_io *io,struct pwrsc_transaction *r){return pwrsc_step(io,r);}\n')
        for target, suffix in [('aarch64-unknown-windows', 'obj'), ('arm64-apple-macos14', 'o')]:
            run('freestanding-components-'+suffix, [*common, '--target='+target, '-O2', '-ffreestanding', '-fno-builtin',
                '-fno-stack-protector', '-mgeneral-regs-only', '-Wframe-larger-than=1024', *inc,
                '-c', wrapper, '-o', out/('components.'+suffix)])
    names = ['tools/polaris-wifi-rsc-transaction.h', 'tools/polaris-wifi-rsc-transaction-test.c',
        'tools/polaris-wifi-power-integration-test.c', 'tools/polaris-wifi-power-check.py',
        'tools/polaris-wifi-cmddb-test.c', 'shim/polaris/uefi-wifi-cmddb-query.h',
        'tools/polaris-wifi-cmddb-identity.py', 'tools/polaris-wifi-cmddb-identity.h', 'tools/polaris-uefi-gcd-test.c']
    sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    proof = dict(passed=True, scope='software actual public-ABI query -> ARC index -> bounded transaction -> saved vote/register restore; no original code or MMIO execution',
        peers=peers, software_cases=72, checks=results, source_sha256=bound['source_whole_sha256'],
        sources={name:sha(ROOT/name) for name in names}, RSC_raw_bytes=49464, RSC_event_bytes=48,
        new_RSC_backend_not_original_firmware_patch_or_fallback=True, original_blocking_submit_not_called=True,
        RSC_total_budget_ticks=960000, counter_frequency=19200000, maximum_steps=256, raw_history_capacity=1024,
        old_200ms_freshness_not_changed=True, partial_UNKNOWN_never_ACK_or_retry_or_cleanup=True,
        raise_order=['CX', 'MX', 'MSS'], restore_order=['MSS', 'MX', 'CX'], never_lower_below_saved_during_raise=True,
        IRQ_enable_type_untouched=True, fixed_TCS1_not_assumed=True, saved_live_vote_input_is_SOFTWARE_fixture=True,
        physical_lease_established=False, live_cache_or_TCS_captured=False, physical_MMIO_adapter_implemented=False,
        parent_registered=False, new_driver_linked=False, host_admission_ready=False,
        phone_USB=False, new_native_CI=False, whole_EFI_models_rerun=False,
        may_vote=False, may_start_MSS=False, may_serve_NV_to_remote=False, scan_join_data=False)
    (out/'proof.json').write_text(json.dumps(proof, indent=2)+'\n')
    print(json.dumps(dict(passed=True, software_cases=72, checks=len(results),
        proof_sha256=sha(out/'proof.json'), physical_lease=False, phone_USB=False)))


if __name__ == '__main__':
    main()
