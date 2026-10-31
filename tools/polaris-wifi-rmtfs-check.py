#!/usr/bin/env python3
"""Exercise the NV RAM-shadow service through real software GLINK/QRTR frames.

No device, network, firmware bytes or physical I/O. Optional existing native
command verifies an ARM64 object against the locally staged real XNU headers.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', required=True, type=Path)
    p.add_argument('--native-command', type=Path,
                   help='Existing audited command JSON with command/cwd; not a shell string')
    a = p.parse_args()
    out = a.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    results = []
    def run(name, cmd, cwd=ROOT):
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=60)
        (out / (name + '.log')).write_text(r.stdout + r.stderr)
        results.append(dict(name=name, exit=r.returncode, command=[str(x) for x in cmd]))
        if r.returncode:
            raise RuntimeError(f'{name} failed; see {out / (name + ".log")}')
        return r.stdout.strip()
    with tempfile.TemporaryDirectory(prefix='polaris-rmtfs-check-') as tmp:
        for name in ('rmtfs', 'transport'):
            binary = Path(tmp) / name
            source = ROOT / 'tools' / f'polaris-wifi-{name}-test.c'
            run(name+'-ASAN-UBSAN-build', ['/usr/bin/clang', '-std=c11', '-O1', '-g',
                '-Wall', '-Wextra', '-Werror', '-Wpedantic', '-fsanitize=address,undefined',
                '-I'+str(ROOT/'tools'), str(source), '-o', str(binary)])
            result = run(name+'-ASAN-UBSAN-run', [str(binary)])
            results[-1]['output'] = result
    if a.native_command:
        j = json.loads(a.native_command.read_text())
        c = j['command'][:]
        # Audited locally emitted XNU command only; no script or link execution.
        if c[0] != '/usr/bin/clang' or '-c' not in c or '-o' not in c:
            raise ValueError('requires an explicit clang single-object command')
        c[c.index('-c')+1] = str(ROOT/'tools/polaris-wifi-rmtfs.c')
        c[c.index('-o')+1] = str(out/'polaris-wifi-rmtfs.o')
        run('native-ARM64-object', c, Path(j['cwd']))
        results[-1]['scope'] = 'actual staged XNU headers/architecture flags; no kernel link or boot'
        results[-1]['object_sha256'] = hashlib.sha256((out/'polaris-wifi-rmtfs.o').read_bytes()).hexdigest()
    files = ['tools/polaris-wifi-rmtfs.c', 'tools/polaris-wifi-rmtfs.h',
             'tools/polaris-wifi-rmtfs-test.c', 'tools/polaris-wifi-rmtfs-check.py',
             'tools/polaris-wifi-glink.c', 'tools/polaris-wifi-glink.h',
             'tools/polaris-wifi-transport-test.c']
    proof = dict(passed=True, scope='software GLINK FIFO/QRTR/RMTFS service; fake peer and RAM only',
        reference_commit='e930c26c4303283d7f2f5fc87479946d46409783',
        whole_original_NV_current=False, physical_shared_region_assigned=False,
        native_registered=False, MSS_started=False, radio_scan_join_data=False,
        may_serve_NV_to_remote=False, may_start_MSS=False, durable_NV=False,
        results=results, sources={f:hashlib.sha256((ROOT/f).read_bytes()).hexdigest() for f in files})
    (out/'proof.json').write_text(json.dumps(proof, indent=2)+'\n')
    print(json.dumps(dict(passed=True, checks=len(results), physical_io=False,
        proof_sha256=hashlib.sha256((out/'proof.json').read_bytes()).hexdigest())))

if __name__ == '__main__':
    main()
