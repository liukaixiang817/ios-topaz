#!/usr/bin/env python3
"""Independent public WPA2 exchange vectors using hashlib and OpenSSL AES.

No network or phone access; all keys/MACs/SSID are deterministic test data.
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
out = parser.parse_args().out.resolve()
out.mkdir(parents=True, exist_ok=True)
root = Path(__file__).resolve().parent.parent
own, peer = bytes.fromhex('020000000007'), bytes.fromhex('020000000009')
nonce, anonce = bytes(range(1, 33)), bytes(range(160, 192))
pmk = hashlib.pbkdf2_hmac('sha1', b'public-test-passphrase', b'public-test-ssid', 4096, 32)
data = min(own, peer) + max(own, peer) + min(nonce, anonce) + max(nonce, anonce)
ptk = b''.join(hmac.new(pmk, b'Pairwise key expansion\0' + data + bytes([n]), 'sha1').digest() for n in range(3))[:48]
gtk = bytes(range(240, 256))
rsn = bytes.fromhex('30140100000fac040100000fac040100000fac020000')


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


def message(info, counter, key_nonce=b'', key_data=b'', rsc=0):
    packet = bytearray(99 + len(key_data))
    packet[:5] = bytes([2, 3]) + struct.pack('>H', len(packet) - 4) + b'\x02'
    struct.pack_into('>HHQ', packet, 5, info, 16 if info & 128 else 0, counter)
    packet[17:17 + len(key_nonce)] = key_nonce
    packet[65:73] = rsc.to_bytes(8, 'little')
    struct.pack_into('>H', packet, 97, len(key_data))
    packet[99:] = key_data
    if info & 256:
        packet[81:97] = hmac.new(ptk[:16], packet, 'sha1').digest()[:16]
    return bytes(packet)


plain = rsn + bytes.fromhex('dd16000fac010100') + gtk + b'\xdd\0'
cipher = wrap(plain)
messages = [message(0x8a, 1, anonce), message(0x10a, 1, nonce, rsn), message(0x13ca, 2, anonce, cipher, 1), message(0x30a, 2), message(0x13ca, 3, anonce, cipher, 9), message(0x30a, 3)]
bad_rsn = bytearray(plain)
bad_rsn[7] = 2
bad_gtk = bytearray(plain)
bad_gtk[len(rsn) + 7] = 1
bad_wrap = bytearray(cipher)
bad_wrap[0] ^= 1
messages += [message(0x13ca, 2, anonce, wrap(bad_rsn), 1), message(0x13ca, 2, anonce, wrap(bad_gtk), 1), message(0x13ca, 2, anonce, bad_wrap, 1)]
vector = b'PWPA001\0' + pmk + nonce + ptk + gtk + b''.join(struct.pack('<I', len(p)) + p for p in messages)
(out / 'vectors.bin').write_bytes(vector)
results = []


def run(name, command):
    start = time.monotonic()
    with (out / (name + '.log')).open('w') as log:
        result = subprocess.run(command, cwd=root, stdout=log, stderr=subprocess.STDOUT)
    results.append(dict(name=name, command=command, exit=result.returncode, seconds=round(time.monotonic() - start, 3)))
    (out / 'validation-results.json').write_text(json.dumps(results, indent=2) + '\n')
    print(name, result.returncode, results[-1]['seconds'], flush=True)
    if result.returncode:
        print((out / (name + '.log')).read_text())
        raise SystemExit(result.returncode)


run('compile', ['clang', '-std=c11', '-O1', '-g', '-fsanitize=address,undefined', '-Wall', '-Wextra', '-Werror', '-Wpedantic', '-Itools', 'tools/polaris-wifi-wpa-test.c', '-o', str(out / 'test')])
run('test', [str(out / 'test'), str(out / 'vectors.bin')])
print((out / 'test.log').read_text(), end='', flush=True)
export = out / 'native-export.c'
export.write_text('''#include "polaris-wifi-wpa.h"
int wpa_open(struct pwpa_state*s,const struct psta_state*a,const uint8_t*k,const uint8_t*n,uint64_t t){return pwpa_open(s,a,k,n,t);}
int wpa_rx(struct pwpa_state*s,const uint8_t*p,unsigned n,uint64_t t){return pwpa_receive(s,p,n,t);}
int wpa_step(struct pwpa_state*s,uint64_t t){return pwpa_step(s,t);}
int wpa_sent(struct pwpa_state*s,uint64_t t,int ok){return pwpa_sent(s,t,ok);}
int wpa_install(struct pwpa_state*s,uint64_t t){return pwpa_install(s,t);}
int wpa_installed(struct pwpa_state*s,uint64_t t,int ok){return pwpa_installed(s,t,ok);}
''')
for target, ext in [('aarch64-unknown-windows', 'obj'), ('arm64-apple-macos11', 'o')]:
    run('native-' + ext, ['clang', '--target=' + target, '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-mgeneral-regs-only', '-O2', '-Wall', '-Wextra', '-Werror', '-Wframe-larger-than=1024', '-Itools', '-c', str(export), '-o', str(out / ('native-export.' + ext))])
(out / 'proof-0001.json').write_text(json.dumps(dict(scope='SOFTWARE EAPOL protocol only; no real entropy, native key installer or phone success; group rekey pending', vector_sha256=hashlib.sha256(vector).hexdigest(), validation=results, sources={str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(__file__).resolve(), root / 'tools/polaris-wifi-wpa.h', root / 'tools/polaris-wifi-wpa-test.c']}), indent=2) + '\n')
