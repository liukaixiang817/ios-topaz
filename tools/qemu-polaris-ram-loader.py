#!/usr/bin/env python3
"""Test actual loader code with a synthetic parked entry, NOT an XNU boot.

Valid case checks segment tail/BSS copies and 64-bit boot_args in upper RAM.
A malformed destination must leave the whole destination region untouched.
No phone commands, disk devices or Apple artifacts are used.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import time

VA, PA = 0xfffffe0006000000, 0x180000000


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--qemu', default='qemu-system-aarch64')
    ap.add_argument('--dtc', default='dtc')
    a = ap.parse_args()
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location('probe_qemu', root / 'tools/qemu-polaris-probe.py')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    out = root / 'research/polaris/qemu-ram-loader'
    out.mkdir(parents=True, exist_ok=True)
    code = struct.pack('<2I', 0x14000000, 0xd503201f) + b'Z'  # b . ; nop; tail byte
    payload = bytearray(0x420)
    struct.pack_into('<8sII7Q', payload, 0, b'SWEETXNU', 1, 1, VA, VA + 0x4000,
                     0x400, 32, VA + 0x8000, PA, 0xfc8a0000)
    payload[0x48:0x4e] = b'cpus=1'
    struct.pack_into('<4Q', payload, 0x2a8, VA + 0x4000, 0x4000, 0x300, len(code))
    payload[0x300:0x309] = code
    payload[0x400:0x420] = b'TEST-ADT' + bytes(24)
    malformed = bytearray(payload)
    struct.pack_into('<Q', malformed, 0x2a8, VA - 8)
    results = []
    for name, content in [('valid-copy', payload), ('bad-destination', malformed)]:
        path = out / name
        path.mkdir(exist_ok=True)
        (path / 'payload.bin').write_bytes(content)
        (path / 'stub.bin').write_bytes(struct.pack('<4I2Q', 0x58000080, 0x580000b0,
                                       0xd61f0200, 0xd503201f, 0x90000000, 0x80080000))
        (path / 'tree.dts').write_text('''/dts-v1/;
/ { #address-cells = <2>; #size-cells = <2>;
model = "Xiaomi Polaris"; compatible = "qcom,sdm845";
chosen { linux,initrd-start = <0 0x84000000>; linux,initrd-end = <0 0x84000420>; };
reserved-memory { #address-cells = <2>; #size-cells = <2>; ranges;
cont_splash_region@9d400000 { reg = <0 0x9d400000 0 0x2400000>; }; }; };
''')
        subprocess.run([a.dtc, '-I', 'dts', '-O', 'dtb', '-o', str(path / 'tree.dtb'),
                        str(path / 'tree.dts')], check=True)
        cmd = [a.qemu, '-M', 'virt,gic-version=3', '-cpu', 'cortex-a76', '-smp', '1',
               '-m', '8G', '-display', 'none', '-serial', 'none', '-monitor', 'none',
               '-qmp', 'stdio', '-S', '-no-reboot', '-d', 'int,guest_errors', '-D',
               str(path / 'exceptions.log')]
        for file, address, cpu in [(path / 'stub.bin', 0x80000000, True),
                                   (root / 'shim/out/polaris-ram-loader/Image', 0x80080000, False),
                                   (path / 'tree.dtb', 0x90000000, False),
                                   (path / 'payload.bin', 0x84000000, False)]:
            cmd += ['-device', f'loader,file={file},addr={address:#x}' + (',cpu-num=0' if cpu else '')]
        if name == 'valid-copy':
            (path / 'poison.bin').write_bytes(b'\xa5' * 0x4000)
            cmd += ['-device', f'loader,file={path / "poison.bin"},addr=0x180004000']
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

                qmp('qmp_capabilities'); qmp('cont'); time.sleep(3); qmp('stop')
                registers = qmp('human-monitor-command', {'command-line': 'info registers'})
                (path / 'registers.txt').write_text(registers)
                for address, size, file in [(0x9d400000, 1080 * 2160 * 4, 'fb.raw'),
                                            (PA, 0x10000, 'destination.bin')]:
                    qmp('pmemsave', dict(val=address, size=size, filename=str(path / file)))
                qmp('quit'); process.wait(timeout=10)
            finally:
                if process.poll() is None: process.kill(); process.wait()
        if (path / 'exceptions.log').stat().st_size:
            raise RuntimeError(f'{name}: guest exception or invalid access')
        screen = helper.decode((path / 'fb.raw').read_bytes(), (root / 'shim/font.h').read_text())
        (path / 'fb.txt').write_text(screen)
        memory = (path / 'destination.bin').read_bytes()
        if name == 'valid-copy':
            assert 'PC=0000000180004000' in registers, registers
            assert 'RAM-only kernel handoff' in screen, screen
            assert memory[0x4000:0x4009] == code
            assert not any(memory[0x4009:0x8000]), 'BSS not zeroed'
            assert memory[0x8000:0x8020] == content[0x400:0x420]
            assert struct.unpack_from('<4Q', memory, 0xc008) == (VA, PA, 0xfc8a0000, PA + 0x10000)
            assert struct.unpack_from('<6Q', memory, 0xc028) == (0x9d400000, 1, 4320, 1080, 2160, 32)
            assert struct.unpack_from('<QI', memory, 0xc060) == (VA + 0x8000, 32)
        else:
            assert 'segment destination bounds' in screen, screen
            assert not any(memory), 'malformed payload wrote destination RAM'
        results.append(dict(case=name, passed=True))
        print(f'{name}: passed', flush=True)
    result = dict(cases=results, scope='QEMU loader-core synthetic payload; NOT an XNU/hardware boot')
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
