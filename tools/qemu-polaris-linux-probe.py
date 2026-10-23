#!/usr/bin/env python3
"""Exercise the actual register wrapper, FDT write bounds and Linux resume.

The original Linux entry is replaced with a parked instruction for the test.
This verifies instrumentation, not a Linux or iOS boot in QEMU.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import time


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--qemu', default='qemu-system-aarch64')
    ap.add_argument('--fdtput', default='fdtput')
    ap.add_argument('--dtb', required=True, type=Path)
    ap.add_argument('--build-dir', type=Path)
    ap.add_argument('--outdir', type=Path)
    a = ap.parse_args()
    root = Path(__file__).resolve().parents[1]
    build = a.build_dir.resolve() if a.build_dir else root / 'shim/out/polaris-linux-probe-0001'
    out = a.outdir.resolve() if a.outdir else root / 'research/polaris/qemu-linux-probe'
    out.mkdir(parents=True, exist_ok=True)
    spec = importlib.util.spec_from_file_location('builder', root / 'tools/build-polaris-linux-probe.py')
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    manifest = json.loads((build / 'manifest.json').read_text())
    image = bytearray((build / 'Image').read_bytes())
    target = manifest['original_entry']
    struct.pack_into('<I', image, target, 0x14000000)
    (out / 'parked-Image').write_bytes(image)
    # x0=DTB, x1..x3 sentinels; defined original SP verifies stack restoration.
    (out / 'stub.bin').write_bytes(struct.pack('<10I3Q',
        0x58000140, 0xd2800221, 0xd2800442, 0xd2800663,
        0x58000109, 0x9100013f, 0x58000110, 0xd61f0200,
        0xd503201f, 0xd503201f, 0x90000000, 0x92000000, 0x80080000))
    results = []
    for name in ('valid', 'wrong-board', 'bad-marker'):
        path = out / name
        path.mkdir(exist_ok=True)
        tree = path / 'tree.dtb'
        tree.write_bytes(a.dtb.read_bytes())
        marker = builder.MARKER if name != 'bad-marker' else b'X' + builder.MARKER[1:]
        subprocess.run([a.fdtput, '-p', '-t', 'bx', str(tree), '/chosen',
                        'polaris,boot-registers', *[f'{b:02x}' for b in marker]], check=True)
        if name == 'wrong-board':
            subprocess.run([a.fdtput, '-t', 's', str(tree), '/', 'model', 'Other device'], check=True)
        before = tree.read_bytes()
        assert before.count(marker) == 1
        field = before.index(marker)
        cmd = [a.qemu, '-M', 'virt,gic-version=3', '-cpu', 'cortex-a76', '-smp', '1',
               '-m', '2G', '-display', 'none', '-serial', 'none', '-monitor', 'none',
               '-qmp', 'stdio', '-S', '-no-reboot', '-d', 'int,guest_errors',
               '-D', str(path / 'exceptions.log')]
        for file, address, cpu in [(out / 'stub.bin', 0x80000000, True),
                                   (out / 'parked-Image', 0x80080000, False),
                                   (tree, 0x90000000, False)]:
            cmd += ['-device', f'loader,file={file},addr={address:#x}' + (',cpu-num=0' if cpu else '')]
        with (path / 'stderr.log').open('wb') as err:
            process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=err)
            try:
                assert 'QMP' in json.loads(process.stdout.readline())

                def qmp(command, arguments=None):
                    request = dict(execute=command)
                    if arguments: request['arguments'] = arguments
                    process.stdin.write(json.dumps(request).encode() + b'\n')
                    process.stdin.flush()
                    while True:
                        response = json.loads(process.stdout.readline())
                        if 'event' not in response:
                            if 'error' in response: raise RuntimeError(response)
                            return response['return']

                qmp('qmp_capabilities'); qmp('cont'); time.sleep(2); qmp('stop')
                registers = qmp('human-monitor-command', {'command-line': 'info registers'})
                (path / 'registers.txt').write_text(registers)
                qmp('pmemsave', dict(val=0x90000000, size=len(before), filename=str(path / 'after.dtb')))
                qmp('quit'); process.wait(timeout=10)
            finally:
                if process.poll() is None: process.kill(); process.wait()
        assert not (path / 'exceptions.log').stat().st_size, name + ': guest exception'
        assert f'PC={0x80080000 + target:016x}' in registers, registers
        for reg, value in [('X00', 0x90000000), ('X01', 0x11), ('X02', 0x22),
                           ('X03', 0x33), ('SP', 0x92000000)]:
            assert re.search(r'\b' + reg + r'\s*=\s*' + f'{value:016x}', registers), registers
        after = (path / 'after.dtb').read_bytes()
        if name == 'valid':
            values = struct.unpack_from('<12Q', after, field + 16)
            assert values[0] == 1 and values[1] == 4 and values[8] == 62500000
            assert (values[4] >> 20) & 15 == 1 and values[10] == 0x90000000
            assert after[:field + 16] == before[:field + 16]
            assert after[field + 112:] == before[field + 112:]
        else:
            assert after == before, name + ': refused case changed FDT'
        results.append(dict(case=name, passed=True))
        print(name + ': passed', flush=True)
    (out / 'result.json').write_text(json.dumps(dict(cases=results,
        scope='wrapper only, parked original entry; no real Linux boot'), indent=2) + '\n')


if __name__ == '__main__':
    main()
