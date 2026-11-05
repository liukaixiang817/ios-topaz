#!/usr/bin/env python3
"""Validate/burn the nonce input of a frozen EFI build before temporary boot.

This is one input boundary for the complete boot helper, not boot admission.
The caller must separately verify the packed image and all device preflight.
No USB command is executed here. Failed/aborted sends must never retry the pool.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import stat

spec = importlib.util.spec_from_file_location('polaris_nonce_pool', Path(__file__).with_name('polaris-wifi-nonce-pool.py'))
pool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pool)


def read_regular(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise ValueError('expected bounded regular build input')
        data = source.read(limit + 1)
        if len(data) != info.st_size:
            raise ValueError('build input changed while reading')
        return data


def verify(manifest_path, expected_sha256):
    manifest_path = Path(manifest_path).absolute()
    raw = read_regular(manifest_path, 4 * 1024 * 1024)
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError('driver manifest differs from the frozen candidate')
    manifest = json.loads(raw)
    metadata = manifest.get('wifi_host_nonce_pool', {})
    directory = manifest_path.parent / 'wifi-nonce'
    if (metadata.get('directory') != str(directory.resolve()) or
            metadata.get('bytes') != pool.SIZE or metadata.get('entries') != pool.COUNT or
            metadata.get('consume_before_device_send') is not True or
            metadata.get('persistent_image_reuse') is not False):
        raise ValueError('missing exact per-candidate nonce binding')
    artifact = manifest.get('artifact')
    if not isinstance(artifact, str) or Path(artifact).name != artifact or artifact in ('', '.', '..'):
        raise ValueError('invalid driver artifact name')
    image = read_regular(manifest_path.parent / artifact, 128 * 1024 * 1024)
    if len(image) != manifest.get('bytes') or hashlib.sha256(image).hexdigest() != manifest.get('sha256'):
        raise ValueError('driver differs from frozen manifest')
    header = read_regular(manifest_path.parent / 'uefi-wifi-image-nonce-pool.h', 64 * 1024)
    if hashlib.sha256(header).hexdigest() != manifest.get('wifi_host_nonce_header_sha256'):
        raise ValueError('generated compiler input differs from frozen manifest')
    data = pool.validate(read_regular(directory / 'nonce-pool.bin', pool.SIZE))
    digest = hashlib.sha256(data).hexdigest()
    if digest != metadata.get('sha256') or image.count(data) != 1 or image.count(bytes.fromhex(digest)) != 1:
        raise ValueError('nonce input is not uniquely embedded in the exact driver')
    # Also checks the nonce manifest and any prior digest-wide consumption.
    generated, bound = pool.binding(directory)
    if generated.encode() != header or bound['sha256'] != digest:
        raise ValueError('compiler input does not describe this nonce pool')
    return dict(directory=str(directory), sha256=digest,
                driver_sha256=manifest['sha256'], driver_manifest_sha256=expected_sha256)


def consume(manifest_path, expected_sha256):
    result = verify(manifest_path, expected_sha256)
    pool.consume(Path(result['directory']), result['sha256'])
    return dict(result, consumed=True, boot_admission=False, device_command_executed=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['verify', 'consume'])
    parser.add_argument('manifest', type=Path)
    parser.add_argument('--expected-manifest-sha256', required=True)
    args = parser.parse_args()
    operation = consume if args.command == 'consume' else verify
    print(json.dumps(operation(args.manifest, args.expected_manifest_sha256), indent=2))


if __name__ == '__main__':
    main()
