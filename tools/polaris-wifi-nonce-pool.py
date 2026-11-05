#!/usr/bin/env python3
"""Fresh host-CSPRNG SNonce pools for one temporary-boot candidate only.

The eventual boot helper must call consume() BEFORE sending that candidate.
Creating a pool alone is neither a fresh-device-entropy claim nor permission
to reuse an image. No nonce bytes are printed or included in the manifest.
"""
from pathlib import Path
import argparse
import datetime
import hashlib
import json
import os
import secrets
import stat
import struct

COUNT = 64
HEADER = 80
SIZE = HEADER + COUNT * 32
MAGIC = b'PWNPOOL1'
LEDGER = Path(__file__).resolve().parent.parent / 'research/polaris/wifi-nonce-consumed'


def validate(data):
    if len(data) != SIZE or data[:8] != MAGIC:
        raise ValueError('invalid nonce-pool size or magic')
    if struct.unpack_from('<IIII', data, 8) != (1, COUNT, 32, 0) or any(data[72:80]) or not any(data[24:40]):
        raise ValueError('invalid nonce-pool header')
    if hashlib.sha256(data[HEADER:]).digest() != data[40:72]:
        raise ValueError('nonce-pool body digest mismatch')
    entries = [data[HEADER + n * 32:HEADER + (n + 1) * 32] for n in range(COUNT)]
    if len(set(entries)) != COUNT or any(not any(p) for p in entries):
        raise ValueError('zero or duplicate nonce entry')
    return data


def write_exclusive(path, data, directory_fd=None):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
    with os.fdopen(fd, 'wb') as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def create(directory):
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    entries = []
    while len(entries) < COUNT:
        value = secrets.token_bytes(32)
        if any(value) and value not in entries:
            entries.append(value)
    session = secrets.token_bytes(16)
    while not any(session):
        session = secrets.token_bytes(16)
    body = b''.join(entries)
    data = MAGIC + struct.pack('<IIII', 1, COUNT, 32, 0) + session + hashlib.sha256(body).digest() + bytes(8) + body
    validate(data)
    digest = hashlib.sha256(data).hexdigest()
    manifest = dict(version=1, bytes=SIZE, entries=COUNT, sha256=digest,
                    created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    source='Python secrets.token_bytes / host operating-system CSPRNG',
                    usage='one new temporary-boot candidate; consume atomically before sending; never reuse image')
    write_exclusive(directory / 'nonce-pool.bin', data)
    write_exclusive(directory / 'manifest.json', (json.dumps(manifest, indent=2) + '\n').encode())
    return manifest


def binding(directory):
    """Private compiler header, before consumption; never a permission to boot."""
    directory = Path(directory).resolve()
    manifest = json.loads((directory / 'manifest.json').read_text())
    fd = os.open(directory / 'nonce-pool.bin', os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size != SIZE:
            raise ValueError('invalid nonce-pool source file')
        data = validate(source.read(SIZE + 1))
    digest = hashlib.sha256(data).hexdigest()
    if manifest.get('version') != 1 or manifest.get('bytes') != SIZE or manifest.get('entries') != COUNT or manifest.get('sha256') != digest:
        raise ValueError('nonce-pool manifest mismatch')
    if (directory / 'nonce-pool.used').exists() or (LEDGER / (digest + '.used')).exists():
        raise ValueError('cannot build with a consumed nonce pool')
    lines = ['/* PRIVATE generated fresh temporary-boot nonce input; never commit. */',
             '#ifndef POLARIS_WIFI_IMAGE_NONCE_POOL_H', '#define POLARIS_WIFI_IMAGE_NONCE_POOL_H',
             f'#define POLARIS_WIFI_IMAGE_NONCE_BYTES {SIZE}u']
    for name, raw in [('polaris_wifi_image_nonces', data), ('polaris_wifi_image_nonce_sha256', bytes.fromhex(digest))]:
        lines.append(f'_Alignas(64) static const uint8_t {name}[{len(raw)}]={{')
        for offset in range(0, len(raw), 16):
            lines.append('    ' + ','.join(f'0x{x:02x}' for x in raw[offset:offset + 16]) + ',')
        lines.append('};')
    lines.append('#endif')
    metadata = dict(directory=str(directory), sha256=digest, bytes=SIZE, entries=COUNT,
                    consume_before_device_send=True, persistent_image_reuse=False,
                    native_pool_started=False)
    return '\n'.join(lines) + '\n', metadata


def consume(directory, expected_sha256):
    """Burn once before boot. An aborted send still burns this pool."""
    directory = Path(directory)
    if len(expected_sha256) != 64 or any(c not in '0123456789abcdef' for c in expected_sha256):
        raise ValueError('expected digest must come from the frozen candidate')
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open('nonce-pool.bin', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
        with os.fdopen(fd, 'rb') as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size != SIZE:
                raise ValueError('nonce pool must be an exact regular file')
            data = validate(source.read(SIZE + 1))
        if hashlib.sha256(data).hexdigest() != expected_sha256:
            raise ValueError('nonce pool differs from the frozen candidate')
        marker = dict(sha256=expected_sha256, consumed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      state='burned before device send; failed/aborted send does not permit reuse')
        marker_bytes = (json.dumps(marker, indent=2) + '\n').encode()
        # A copied/renamed pool directory cannot bypass the digest-wide ledger.
        LEDGER.mkdir(mode=0o700, parents=True, exist_ok=True)
        ledger_fd = os.open(LEDGER, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            write_exclusive(expected_sha256 + '.used', marker_bytes, ledger_fd)
            os.fsync(ledger_fd)
        finally:
            os.close(ledger_fd)
        write_exclusive('nonce-pool.used', marker_bytes, directory_fd)
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    make = sub.add_parser('create')
    make.add_argument('directory', type=Path)
    burn = sub.add_parser('consume')
    burn.add_argument('directory', type=Path)
    burn.add_argument('--expected-sha256', required=True)
    args = parser.parse_args()
    if args.command == 'create':
        print(json.dumps(create(args.directory), indent=2))
    else:
        consume(args.directory, args.expected_sha256)
        print(json.dumps(dict(consumed=True, sha256=args.expected_sha256)))


if __name__ == '__main__':
    main()
