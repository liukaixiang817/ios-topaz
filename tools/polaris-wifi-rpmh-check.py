#!/usr/bin/env python3
"""Check the new original-RPMh init/DRV/TCS RAM collector; no USB/firmware execution."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--driver', required=True, type=Path, help='New compiled RPMh-ON driver directory')
    p.add_argument('--out', required=True, type=Path)
    a = p.parse_args()
    driver, out = a.driver.resolve(), a.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((driver/'manifest.json').read_text())
    assert manifest['wifi_CPU0_RPMh_RAM_readonly'] is True
    assert manifest['wifi_CPU0_RPMh_client_or_vote'] is False
    assert manifest['wifi_CPU0_RPMh_provider_API_calls'] == 0
    assert manifest['original_GCD_new_scope_RAM_log_capacity'] == 1572864
    sha = lambda x: hashlib.sha256(x.read_bytes()).hexdigest()
    for name, expected in manifest['inputs'].items():
        assert sha(ROOT/name) == expected, name
    core = ROOT/manifest['original_GCD_original_PE']
    npa = ROOT/manifest['wifi_CPU0_NPA_source_PE']
    rpmh = ROOT/manifest['wifi_CPU0_RPMh_source_PE']
    results = []
    def run(name, cmd):
        r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=60)
        (out/(name+'.log')).write_text(r.stdout+r.stderr)
        results.append(dict(name=name, command=[str(x) for x in cmd], exit=r.returncode))
        if r.returncode:
            raise RuntimeError(f'{name} failed: {out/(name+".log")}')
        return r.stdout
    inc = ['-I'+str(ROOT/'tools'), '-I'+str(ROOT/'shim/polaris'), '-I'+str(driver)]
    with tempfile.TemporaryDirectory(prefix='polaris-npa-check-') as tmp:
        tmp = Path(tmp)
        run('ASAN-UBSAN-build', ['/usr/bin/clang', '-std=c11', '-D_POSIX_C_SOURCE=200112L',
            '-DEFI_XNU_GCD_MMIO_QUERY_AVAILABLE=1', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
            '-Wno-unused-function', '-fsanitize=address,undefined', *inc,
            str(ROOT/'tools/polaris-wifi-rpmh-test.c'), '-o', str(tmp/'test')])
        host = json.loads(run('ASAN-UBSAN-run', [str(tmp/'test'), str(core), str(npa), str(rpmh)]))
        assert host['checks'] == 29 and host['raw_bytes'] == 19264 and host['snapshot_bytes'] == 4000
        wrapper = out/'actual-coordinator.c'
        wrapper.write_text('#include <stdint.h>\nvoid text(const char *);void report(const char *,uint64_t);\n'
            '#include "uefi-xnu-config.h"\n#include "uefi-audio-clock-gcd-query.h"\n'
            'void actual_coordinator(struct efi_system *s,const struct efi_loaded *self) {\n'
            ' (void)pgcd_bind_resident(self);struct pgcd_context *g=pgcd_prepare(s,2);\n'
            ' pacgq_collect_preboot(s,2,g);\n}\n'
            'void actual_report(void (*append)(const char *)){pacgq_report_preboot(append);}\n')
        for target, suffix in [('aarch64-unknown-windows', 'obj'), ('arm64-apple-macos14', 'o')]:
            run('actual-coordinator-'+suffix, ['/usr/bin/clang', '--target='+target,
                '-std=c11', '-O2', '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
                '-mgeneral-regs-only', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
                '-Wframe-larger-than=1024', *inc, '-c', str(wrapper), '-o', str(out/('actual-coordinator.'+suffix))])
    files = ['tools/polaris-wifi-rpmh-test.c', 'tools/polaris-wifi-rpmh-check.py', 'tools/polaris-wifi-npa-test.c']
    proof = dict(passed=True, scope='29 software source/init/DRV/TCS/lifetime including executable combined NPA-to-RPMh and spent-context refusals checks plus actual AArch64 coordinator objects and complete EFI link; NO physical RPMh/firmware execution',
        host=host, driver_sha256=manifest['sha256'], driver_bytes=manifest['bytes'],
        driver_manifest_sha256=sha(driver/'manifest.json'), full_compiled_inputs_match_current=True,
        new_native_CI=False, phone_USB=False, live_RPMh_state_captured=False,
        host_boot_admission_ready=False, device_execution_tested=False,
        may_create_RPMh_client_or_vote=False, may_start_MSS=False, radio_scan_join_data=False,
        raw_record_bytes=19264, two_records_already_inside_raw_extent=True,
        firmware_log_capacity=1572864, log_snapshot_uses_sizeof_actual_log_buffer=True,
        results=results, compiled_inputs=manifest['inputs'], additional_sources={f:sha(ROOT/f) for f in files})
    (out/'proof.json').write_text(json.dumps(proof, indent=2)+'\n')
    print(json.dumps(dict(passed=True, host_checks=host['checks'], compiler_checks=len(results),
                         driver=manifest['sha256'], proof_sha256=sha(out/'proof.json'))))

if __name__ == '__main__':
    main()
