#!/usr/bin/env python3
"""Public, independently encrypted WPA2 GTK renewal messages; no credentials."""
from pathlib import Path
import argparse
import hashlib
import hmac
import json
import struct
import subprocess
import time

parser = argparse.ArgumentParser()
parser.add_argument('--out', type=Path, required=True)
out = parser.parse_args().out.resolve()
out.mkdir(parents=True, exist_ok=True)
root = Path(__file__).resolve().parent.parent
base = out / 'base/vectors.bin'
if not base.exists():
    subprocess.run(['python3', str(root / 'tools/polaris-wifi-wpa-check.py'), '--out', str(out / 'base')], check=True, cwd=root)
public = base.read_bytes()
assert public[:8] == b'PWPA001\0'
ptk = public[72:120]
gtk = bytes(range(80, 96))


def wrap(plain):
    accumulator = b'\xa6' * 8
    blocks = [plain[n:n + 8] for n in range(0, len(plain), 8)]
    assert len(plain) % 8 == 0
    for round_no in range(6):
        for index, block in enumerate(blocks):
            encrypted = subprocess.run(['openssl', 'enc', '-aes-128-ecb', '-nopad', '-K', ptk[16:32].hex()], input=accumulator + block, check=True, capture_output=True).stdout
            accumulator = (int.from_bytes(encrypted[:8], 'big') ^ (len(blocks) * round_no + index + 1)).to_bytes(8, 'big')
            blocks[index] = encrypted[8:]
    return accumulator + b''.join(blocks)


def message(info, counter, data=b'', rsc=0):
    p = bytearray(99 + len(data))
    p[:5] = bytes([2, 3]) + struct.pack('>H', len(p) - 4) + b'\x02'
    struct.pack_into('>HHQ', p, 5, info, 16 if info & 128 else 0, counter)
    p[65:73] = rsc.to_bytes(8, 'little')
    struct.pack_into('>H', p, 97, len(data))
    p[99:] = data
    p[81:97] = hmac.new(ptk[:16], p, 'sha1').digest()[:16]
    return bytes(p)


plain = bytes.fromhex('dd16000fac010200') + gtk
cipher = wrap(plain)
bad_flags = bytearray(plain)
bad_flags[7] = 1
bad_wrap = bytearray(cipher)
bad_wrap[0] ^= 1
other_id = bytearray(plain)
other_id[6] = 3
next_key = bytes(range(96, 112))
next_plain = bytes.fromhex('dd16000fac010200') + next_key
messages = [message(0x1382, 4, cipher, 7), message(0x302, 4), message(0x1382, 5, cipher, 11), message(0x302, 5),
            message(0x1382, 6, wrap(bad_flags), 3), message(0x1382, 6, bad_wrap, 3), message(0x1382, 6, wrap(other_id), 3),
            message(0x1382, 6, wrap(next_plain), 3), message(0x302, 6)]
vector = b'PWPG001\0' + gtk + next_key + b''.join(struct.pack('<I', len(p)) + p for p in messages)
(out / 'vectors.bin').write_bytes(vector)
results = []


def run(name, command):
    start = time.monotonic()
    with (out / (name + '.log')).open('w') as log:
        result = subprocess.run(command, cwd=root, stdout=log, stderr=subprocess.STDOUT)
    results.append(dict(name=name, command=command, exit=result.returncode, seconds=round(time.monotonic() - start, 3)))
    (out / 'validation-results.json').write_text(json.dumps(results, indent=2) + '\n')
    print(name, result.returncode, flush=True)
    if result.returncode:
        print((out / (name + '.log')).read_text())
        raise SystemExit(result.returncode)


run('compile', ['clang', '-std=c11', '-O1', '-g', '-fsanitize=address,undefined', '-Wall', '-Wextra', '-Werror', '-Wpedantic', '-Itools', 'tools/polaris-wifi-wpa-group-test.c', '-o', str(out / 'test')])
run('test', [str(out / 'test'), str(base), str(out / 'vectors.bin')])
print((out / 'test.log').read_text(), end='', flush=True)
export = out / 'native-export.c'
export.write_text((out / 'base/native-export.c').read_text() + '''
int group_install(struct pwpa_state*s,uint64_t t){return pwpa_group_install(s,t);}
int group_installed(struct pwpa_state*s,uint64_t t,int ok){return pwpa_group_installed(s,t,ok);}
''')
for target, ext in [('aarch64-unknown-windows', 'obj'), ('arm64-apple-macos11', 'o')]:
    run('native-' + ext, ['clang', '--target=' + target, '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-mgeneral-regs-only', '-O2', '-Wall', '-Wextra', '-Werror', '-Wframe-larger-than=1024', '-Itools', '-c', str(export), '-o', str(out / ('native-export.' + ext))])
(out / 'proof-0001.json').write_text(json.dumps(dict(scope='SOFTWARE GTK renewal protocol, public independent vectors; no physical key installation', vector_sha256=hashlib.sha256(vector).hexdigest(), validation=results), indent=2) + '\n')
