#!/usr/bin/env python3
"""Qualify the finite original-Core RAM reader; never executes original EFI."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--bindings', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    a = ap.parse_args()
    bindings, out = a.bindings.resolve(), a.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    old = json.loads((bindings/'manifest.json').read_text())
    originals = [ROOT/old[k] for k in ('original_GCD_original_PE',
        'wifi_CPU0_NPA_source_PE', 'wifi_CPU0_RPMh_source_PE', 'wifi_CPU0_power_source_PE')]
    spec = importlib.util.spec_from_file_location('own_namespace', ROOT/'tools/polaris-wifi-gcd-namespace-identity.py')
    identity = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(identity)
    header, source = identity.binding(originals[0])
    (out/'uefi-wifi-gcd-namespace-binding.h').write_text(header)
    (out/'binding.json').write_text(json.dumps(source, indent=2)+'\n')
    checks, dependencies = [], set()
    inc = ['-I'+str(out), '-I'+str(bindings), '-I'+str(ROOT/'tools'), '-I'+str(ROOT/'shim/polaris')]
    common = ['/usr/bin/clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function']

    def run(name, cmd):
        r = subprocess.run([str(x) for x in cmd], cwd=ROOT, capture_output=True, text=True, timeout=100)
        (out/(name+'.log')).write_text(r.stdout+r.stderr)
        checks.append(dict(name=name, exit=r.returncode, command=[str(x) for x in cmd]))
        if r.returncode:
            raise RuntimeError(name+': inspect '+str(out/(name+'.log')))
        return r.stdout

    def deps(file):
        for word in file.read_text().replace('\\\n', ' ').split()[1:]:
            p = Path(word).resolve()
            if p.is_file() and p.is_relative_to(ROOT):
                dependencies.add(str(p.relative_to(ROOT)))

    dep = out/'peer.d'
    run('ASAN-UBSAN-build', [*common, '-D_POSIX_C_SOURCE=200112L',
        '-DEFI_XNU_GCD_MMIO_QUERY_AVAILABLE=1', '-O1', '-g', '-fsanitize=address,undefined',
        '-MD', '-MF', dep, *inc, ROOT/'tools/polaris-wifi-gcd-namespace-test.c', '-o', out/'peer'])
    deps(dep)
    peer = json.loads(run('ASAN-UBSAN-cases', [out/'peer', *originals]))
    assert peer['passed'] is True and peer['checks'] == 27 and peer['physical_firmware_executed'] is False
    wrapper = out/'reader.c'
    wrapper.write_text('''#include <stdint.h>
void text(const char *);void report(const char *,uint64_t);
#include "uefi-xnu-config.h"
#include "uefi-gcd-mmio-readonly.h"
#include "uefi-audio-i2c-cache.h"
#define EFI_XNU_WIFI_GCD_NAMESPACE_RO_AVAILABLE 1
#include "uefi-wifi-gcd-namespace.h"
int reader(const struct paic_io *m,struct pwrcl_result *p,const struct pwrph_work *w,
 struct pgcd_context *g,struct pgns_result *r)
{const struct pgns_io io={m,0,pgns_actual_translate};return pgns_collect(&io,p,w,g,r);}
''' + f'_Static_assert(sizeof(struct pgns_result)=={peer["raw_bytes"]},"complete namespace raw ABI");\n')
    for target, suffix in [('aarch64-unknown-windows', 'obj'), ('arm64-apple-macos14', 'o')]:
        dep = out/('reader-'+suffix+'.d')
        run('actual-reader-'+suffix, [*common, '--target='+target, '-O2', '-ffreestanding',
            '-fno-builtin', '-fno-stack-protector', '-mgeneral-regs-only', '-Wframe-larger-than=1024',
            '-MD', '-MF', dep, *inc, '-c', wrapper, '-o', out/('reader.'+suffix)])
        deps(dep)
    for name, defines in [('default-OFF', ''), ('QEMU-compiledout',
            '#define EFI_XNU_WIFI_GCD_NAMESPACE_RO_AVAILABLE 1\n#define POLARIS_EFI_TEST_QEMU 1\n')]:
        file = out/(name+'.c')
        file.write_text(defines+'#include "uefi-wifi-gcd-namespace.h"\nint closed(void){return 0;}\n')
        pp = run(name, [*common, '--target=aarch64-unknown-windows', '-ffreestanding', *inc, '-E', '-P', file])
        assert 'pgns_collect' not in pp and 'pgns_result' not in pp
    dependencies.add('tools/polaris-wifi-gcd-namespace-check.py')
    dependencies.add('tools/polaris-wifi-gcd-namespace-identity.py')
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    proof = dict(passed=True, checks=checks, software_cases=peer['checks'], peer=peer,
        binding=source, raw_bytes=peer['raw_bytes'], original_images_are_data_only=True,
        actual_component_COFF_MachO=True, max_frame=1024,
        sources={n:sha(ROOT/n) for n in sorted(dependencies)},
        physical_namespace_captured=False, physical_root_cause_isolated=False,
        parent_or_builder_registered=False, host_profile_ready=False, physical_candidate_ready=False,
        phone_USB=False, new_native_CI=False, new_wholeEFI_models=False, scan_join_data=False,
        scope='source-bound finite512-node two-pass Core RAM namespace, partial/AT retained; no original GCD API or locks/TPL calls; captured descriptor is not a live read grant')
    (out/'proof.json').write_text(json.dumps(proof, indent=2)+'\n')
    print(json.dumps(dict(passed=True, checks=len(checks), software_cases=peer['checks'],
        raw_bytes=peer['raw_bytes'], proof_SHA256=sha(out/'proof.json'), physical_candidate_ready=False)))


if __name__ == '__main__':
    main()
