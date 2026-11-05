#!/usr/bin/env python3
"""Build deterministic public test vectors with hashlib/hmac and OpenSSL.

No network, phone, passphrase prompt or actual Wi-Fi credentials are used.
RFC3394 section4.1 anchors AES unwrap; FIPS197 anchors AES block decryption.
"""
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
args = parser.parse_args()
out = args.out.resolve()
out.mkdir(parents=True, exist_ok=True)
records = []


def add(kind, key, data, expected):
    records.append(struct.pack('<IIII', kind, len(key), len(data), len(expected)) + key + data + expected)


def pattern(length, seed):
    return bytes((n * 37 + seed) & 255 for n in range(length))


def encrypt(cipher, key, data, iv=None):
    cmd = ['openssl', 'enc', '-' + cipher, '-K', key.hex(), '-nopad']
    if iv is not None:
        cmd += ['-iv', iv.hex()]
    return subprocess.run(cmd, input=data, check=True, capture_output=True).stdout


def wrap(key, plain):
    # OpenSSL enc refuses streaming RFC3394. Use its independent AES-ECB
    # encryption for the RFC's forward transform; the C code does the inverse.
    accumulator = b'\xa6' * 8
    blocks = [plain[n:n + 8] for n in range(0, len(plain), 8)]
    for round_no in range(6):
        for index, block in enumerate(blocks):
            encrypted = encrypt('aes-128-ecb', key, accumulator + block)
            counter = len(blocks) * round_no + index + 1
            accumulator = (int.from_bytes(encrypted[:8], 'big') ^ counter).to_bytes(8, 'big')
            blocks[index] = encrypted[8:]
    return accumulator + b''.join(blocks)


for data in [b'', b'abc', b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'] + [pattern(n, 17) for n in [1, 55, 56, 63, 64, 65, 127, 128, 129, 1024, 4096]]:
    add(1, b'', data, hashlib.sha1(data).digest())
for length in [0, 1, 20, 63, 64, 65, 128]:
    key = pattern(length, 9)
    data = pattern(271, 18)
    add(2, key, data, hmac.new(key, data, 'sha1').digest())
add(2, b'\x0b' * 20, b'Hi There', bytes.fromhex('b617318655057264e28bc0b6fb378c8ef146be00'))
for password, ssid in [(b'password', b'IEEE'), (b'password', b'salt'), (b'ThisIsAPassword', b'ThisIsASSID'), (b'x' * 63, pattern(32, 0)), (b'12345678', b'\0')]:
    expected = hashlib.pbkdf2_hmac('sha1', password, ssid, 4096, 32)
    if ssid == b'salt':
        assert expected[:20].hex() == '4b007901b765489abead49d926f721d065a429c1'
    add(3, password, ssid, expected)
key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
plain = bytes.fromhex('00112233445566778899aabbccddeeff')
add(4, key, bytes.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a'), plain)
add(5, key, bytes.fromhex('1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5'), plain)
assert wrap(key, plain).hex() == '1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5'
for seed in range(8):
    key, plain = pattern(16, seed * 19), pattern(16, seed * 7)
    add(4, key, encrypt('aes-128-ecb', key, plain), plain)
for length in [16, 24, 32, 64, 128, 512]:
    key, plain = pattern(16, length), pattern(length, length * 3)
    add(5, key, wrap(key, plain), plain)
vectors = out / 'vectors.bin'
vectors.write_bytes(b'PWCRYP1\0' + struct.pack('<I', len(records)) + b''.join(records))
root = Path(__file__).resolve().parent.parent
results = []


def run(name, cmd):
    start = time.monotonic()
    with (out / (name + '.log')).open('w') as log:
        result = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, cwd=root)
    results.append(dict(name=name, command=cmd, exit=result.returncode, seconds=round(time.monotonic() - start, 3)))
    (out / 'validation-results.json').write_text(json.dumps(results, indent=2) + '\n')
    print(name, result.returncode, results[-1]['seconds'], flush=True)
    if result.returncode:
        print((out / (name + '.log')).read_text())
        raise SystemExit(result.returncode)


run('compile', ['clang', '-std=c11', '-O1', '-g', '-fsanitize=address,undefined', '-Wall', '-Wextra', '-Werror', '-Wpedantic', '-Itools', 'tools/polaris-wifi-wpa-crypto-test.c', '-o', str(out / 'test')])
run('test', [str(out / 'test'), str(vectors)])
print((out / 'test.log').read_text(), end='', flush=True)
export = out / 'native-export.c'
export.write_text('''#include "polaris-wifi-wpa-crypto.h"
int pmk_open(struct pwch_pmk*s,const uint8_t*p,unsigned n,const uint8_t*b,unsigned z){return pwch_pmk_open(s,p,n,b,z);}
int pmk_step(struct pwch_pmk*s,unsigned n){return pwch_pmk_step(s,n);}
int unwrap_open(struct pwch_unwrap*s,const uint8_t*k,const uint8_t*p,unsigned n){return pwch_unwrap_open(s,k,p,n);}
int unwrap_step(struct pwch_unwrap*s,unsigned n){return pwch_unwrap_step(s,n);}
''')
for target, ext in [('aarch64-unknown-windows', 'obj'), ('arm64-apple-macos11', 'o')]:
    run('native-' + ext, ['clang', '--target=' + target, '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-mgeneral-regs-only', '-O2', '-Wall', '-Wextra', '-Werror', '-Wframe-larger-than=1024', '-Itools', '-c', str(export), '-o', str(out / ('native-export.' + ext))])
(out / 'proof-0001.json').write_text(json.dumps(dict(scope='SOFTWARE crypto primitives only; no entropy/EAPOL/key installation or phone success', vectors=len(records), vector_sha256=hashlib.sha256(vectors.read_bytes()).hexdigest(), validation=results, sources={str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(__file__).resolve(), root / 'tools/polaris-wifi-wpa-crypto.h', root / 'tools/polaris-wifi-wpa-crypto-test.c']}), indent=2) + '\n')
