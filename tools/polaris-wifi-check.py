#!/usr/bin/env python3
"""Check only the new Polaris SMEM/GLINK/QRTR/CAP components. No device I/O."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    results = []
    with tempfile.TemporaryDirectory(prefix='polaris-wifi-check-') as tmp:
        tmp = Path(tmp)
        for name in ('transport', 'probe'):
            source = ROOT / 'tools' / f'polaris-wifi-{name}-test.c'
            binary = tmp / name
            command = ['/usr/bin/clang', '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                       '-Wpedantic', '-fsanitize=address,undefined', '-I' + str(ROOT / 'tools'),
                       str(source), '-o', str(binary)]
            compile_result = subprocess.run(command, capture_output=True, text=True)
            (args.out / f'{name}-build.log').write_text(compile_result.stdout + compile_result.stderr)
            result = {'check': name, 'compile_exit': compile_result.returncode,
                      'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest()}
            if not compile_result.returncode:
                run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
                (args.out / f'{name}-run.log').write_text(run.stdout + run.stderr)
                result.update(run_exit=run.returncode, output=run.stdout.strip())
            results.append(result)
        (tmp / 'probe-arm64.c').write_text('#include "polaris-wifi-smem-probe.h"\n'
            'bool witness(const struct polaris_wifi_probe_io *i,unsigned r,'
            'struct polaris_wifi_probe_result *o,struct polaris_wifi_probe_workspace *w) '
            '{return polaris_wifi_smem_probe(i,r,o,w);}\n')
        command = ['/usr/bin/clang', '-target', 'aarch64-none-elf', '-ffreestanding', '-std=c11',
                   '-O2', '-Wall', '-Wextra', '-Werror', '-Wframe-larger-than=1024',
                   '-I' + str(ROOT / 'tools'), '-c', str(tmp / 'probe-arm64.c'),
                   '-o', str(tmp / 'probe-arm64.o')]
        arm = subprocess.run(command, capture_output=True, text=True)
        (args.out / 'probe-aarch64-build.log').write_text(arm.stdout + arm.stderr)
        results.append({'check': 'aarch64-probe-header-no-stubs-max-frame1024', 'compile_exit': arm.returncode})
    passed = all(v['compile_exit'] == 0 and v.get('run_exit', 0) == 0 for v in results)
    sources = [p for p in (ROOT / 'tools').glob('polaris-wifi-*') if p.is_file()]
    proof = {'passed': passed, 'scope': 'Software peer/FIFO + ASAN/UBSAN and freestanding ARM64 RO witness only',
             'physical_SMEM_or_MPU_or_owner': False, 'radio_scan_join': False, 'results': results,
             'sources': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(sources)}}
    (args.out / 'component-check.json').write_text(json.dumps(proof, indent=2) + '\n')
    print(json.dumps({'passed': passed, 'checks': len(results), 'device_io': False}))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
