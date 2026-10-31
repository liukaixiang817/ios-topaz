#!/usr/bin/env python3
"""Exercise the original-ABI CmdDb adapter; no phone, firmware or power execution."""
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
    p.add_argument('--bindings', type=Path, required=True,
                   help='Existing original-Core/RPMh digest headers; never modified or admitted as a new candidate')
    p.add_argument('--original-pe', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    out, bindings = a.out.resolve(), a.bindings.resolve()
    out.mkdir(parents=True, exist_ok=True)
    spec = importlib.util.spec_from_file_location('own_cmddb', ROOT/'tools/polaris-wifi-cmddb-identity.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    header, binding = module.binding(a.original_pe.resolve())
    (out/'uefi-wifi-cmddb-binding.h').write_text(header)
    (out/'binding.json').write_text(json.dumps(binding, indent=2)+'\n')
    core = ROOT/json.loads((bindings/'manifest.json').read_text())['original_GCD_original_PE']
    records = []

    def run(name, cmd, expected=0):
        result = subprocess.run([str(x) for x in cmd], cwd=ROOT, capture_output=True, text=True, timeout=60)
        (out/(name+'.log')).write_text(result.stdout+result.stderr)
        records.append(dict(name=name, exit=result.returncode, expected=expected, command=[str(x) for x in cmd]))
        if (expected == 0 and result.returncode) or (expected != 0 and result.returncode == 0):
            raise RuntimeError(f'{name}: inspect {out/(name+".log")}')
        return result.stdout

    inc = ['-I'+str(ROOT/'tools'), '-I'+str(ROOT/'shim/polaris'), '-I'+str(bindings), '-I'+str(out)]
    with tempfile.TemporaryDirectory(prefix='polaris-cmddb-check-') as temporary:
        temporary = Path(temporary)
        common = ['/usr/bin/clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function']
        run('software-build', [*common, '-D_POSIX_C_SOURCE=200112L', '-DEFI_XNU_GCD_MMIO_QUERY_AVAILABLE=1',
            '-O1', '-g', '-fsanitize=address,undefined', *inc, ROOT/'tools/polaris-wifi-cmddb-test.c', '-o', temporary/'test'])
        host = json.loads(run('software-API-and-faults', [temporary/'test', core, a.original_pe.resolve()]))
        assert host['checks'] == 35 and host['raw_bytes'] == 345248
        assert host['original_firmware_executed'] is False and host['power_votes'] == 0
        wrapper = out/'physical-adapter.c'
        wrapper.write_text('#include <stdint.h>\nvoid text(const char *);void report(const char *,uint64_t);\n'
            '#include "uefi-xnu-config.h"\n#include "uefi-gcd-mmio-readonly.h"\n#include "uefi-audio-i2c-cache.h"\n'
            '#define EFI_XNU_WIFI_CMDDB_QUERY_AVAILABLE 1\n#include "uefi-wifi-cmddb-query.h"\n'
            'int physical_adapter(struct pwcd_io *io,const struct paic_result *e,struct pgcd_context *g,struct pwcd_result *r,struct pwrph_work *w){\n'
            ' io->query=pwcd_actual_query;return pwcd_collect(io,e,g,r,w);}\n')
        for target, suffix in [('aarch64-unknown-windows', 'obj'), ('arm64-apple-macos14', 'o')]:
            run('physical-body-'+suffix, [*common, '--target='+target, '-O2', '-ffreestanding', '-fno-builtin',
                '-fno-stack-protector', '-mgeneral-regs-only', '-Wframe-larger-than=1024', *inc,
                '-c', wrapper, '-o', out/('physical-adapter.'+suffix)])
        # A hosted fixture must never silently enter either firmware body.
        run('reject-software-fixture-in-firmware', [*common, '--target=aarch64-unknown-windows',
            '-ffreestanding', '-DPOLARIS_CMDDB_SOFTWARE_TEST=1', *inc, '-fsyntax-only', wrapper], expected=1)
        off = temporary/'default-off.c'
        off.write_text('#include "uefi-wifi-cmddb-query.h"\nint default_off(void){return EFI_XNU_WIFI_CMDDB_QUERY_AVAILABLE;}\n')
        run('default-OFF', [*common, '--target=aarch64-unknown-windows', '-ffreestanding', *inc,
            '-c', off, '-o', out/'default-off.obj'])
    sources = ['shim/polaris/uefi-wifi-cmddb-query.h', 'tools/polaris-wifi-cmddb-identity.py',
        'tools/polaris-wifi-cmddb-identity.h', 'tools/polaris-wifi-cmddb-test.c', 'tools/polaris-wifi-cmddb-check.py',
        'tools/polaris-uefi-gcd-test.c']
    sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    proof = dict(passed=True, scope='real source-bound adapter with software public ABI/This/u32-status/u64-EFI peer and fault delivery; original bytes are data only',
        host=host, checks=records, source_whole_sha256=binding['source_whole_sha256'],
        sources={name:sha(ROOT/name) for name in sources}, binding_sha256=sha(out/'uefi-wifi-cmddb-binding.h'),
        raw_bytes=345248, exact_own_SMEM_physical_bounds_preserved=True,
        current_CMDdb_captured=False, current_ARC_indices_observed=False,
        standalone_inventory_boot_created=False, builder_registered=False, parent_integrated=False,
        new_driver_linked=False, new_host_admission_ready=False, new_native_CI=False, phone_USB=False,
        may_vote=False, may_start_MSS=False, may_serve_NV_to_remote=False, scan_join_data=False)
    (out/'proof.json').write_text(json.dumps(proof, indent=2)+'\n')
    print(json.dumps(dict(passed=True, software_cases=host['checks'], checks=len(records),
        proof_sha256=sha(out/'proof.json'), physical_firmware_executed=False)))


if __name__ == '__main__':
    main()
