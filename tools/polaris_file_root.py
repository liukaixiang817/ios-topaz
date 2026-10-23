"""Validate a fresh readonly FIEMAP and form bounded polaris boot metadata.

This does not mount or write a device. Re-export after ANY writable outer mount;
never use this map to write raw extents. SHA256 is checked before boot by the
staging procedure; kernel edge CRCs additionally catch a wrong/stale handoff.
"""
import hashlib
import struct
import zlib

BLOCK = 4096


def validate(manifest):
    if manifest.get('version') != 1 or manifest.get('raw_write_allowed') is not False:
        raise ValueError('requires version 1 readonly file root')
    start, partition, size = manifest['layout']
    if not (256 <= start <= 0xffffffff and 0 < partition <= (1 << 32) - start
            and 0 < size <= (64 << 30) // BLOCK):
        raise ValueError('invalid partition/file geometry')
    extents = manifest['extents']
    if not 0 < len(extents) <= 4096:
        raise ValueError('invalid extent count')
    previous, physical_ranges = 0, []
    for logical, physical, blocks in extents:
        if (logical != previous or not 0 < blocks <= size - previous
                or not start <= physical < start + partition
                or blocks > start + partition - physical):
            raise ValueError('invalid extent geometry')
        previous += blocks
        physical_ranges.append((physical, physical + blocks))
    if previous != size:
        raise ValueError('incomplete file map')
    physical_ranges.sort()
    if any(a[1] > b[0] for a, b in zip(physical_ranges, physical_ranges[1:])):
        raise ValueError('physical overlap')
    if len(manifest['crc32']) != 3 or any(not 0 <= n <= 0xffffffff for n in manifest['crc32']):
        raise ValueError('invalid CRC fields')
    return manifest


def create(mapping, head, root, expected_sha256):
    if len(head) != 1 << 20 or head[510:512] != b'\x55\xaa' or head[4096:4104] != b'EFI PART':
        raise ValueError('requires verified 1MiB GPT head')
    table, count, stride = struct.unpack_from('<QII', head, 4096 + 72)
    if not (2 <= table < 256 and count and stride >= 128 and stride % 8 == 0
            and count * stride <= len(head) - table * BLOCK):
        raise ValueError('GPT table outside verified head')
    entries = []
    for i in range(count):
        entry = head[table * BLOCK + i * stride:table * BLOCK + (i + 1) * stride]
        if entry[56:128] == 'userdata'.encode('utf-16-le').ljust(72, b'\0'):
            entries.append(struct.unpack_from('<QQ', entry, 32))
    if len(entries) != 1 or entries[0][1] < entries[0][0]:
        raise ValueError('requires unique userdata partition')
    first, last = entries[0]
    if (mapping.get('version') != 1 or mapping.get('readonly_snapshot') is not True
            or mapping.get('raw_write_allowed') is not False or mapping['block_bytes'] != BLOCK
            or mapping['backing_device_bytes'] != (last - first + 1) * BLOCK):
        raise ValueError('wrong backing filesystem')
    size = root.stat().st_size
    if size != mapping['file_bytes'] or size % BLOCK or not 0 < size <= 64 << 30:
        raise ValueError('image size mismatch')
    digest = hashlib.sha256()
    with root.open('rb') as f:
        while chunk := f.read(8 << 20):
            digest.update(chunk)
        f.seek(0); initial = f.read(BLOCK)
        f.seek(-BLOCK, 2); final = f.read(BLOCK)
    if digest.hexdigest() != expected_sha256:
        raise ValueError('image SHA256 mismatch')
    if initial[1024:1028] != b'HX\x00\x05' or struct.unpack_from('>II', initial, 1064) != (BLOCK, size // BLOCK):
        raise ValueError('unsupported HFSX geometry')
    extents = []
    for e in mapping['extents']:
        if any(e[k] < 0 or e[k] % BLOCK for k in ('logical', 'physical', 'length')):
            raise ValueError('unaligned extent')
        extents.append([e['logical'] // BLOCK, first + e['physical'] // BLOCK, e['length'] // BLOCK])
    return validate(dict(version=1, raw_write_allowed=False,
                         layout=[first, last - first + 1, size // BLOCK], extents=extents,
                         crc32=[zlib.crc32(head), zlib.crc32(initial), zlib.crc32(final)],
                         image_sha256=digest.hexdigest()))


if __name__ == '__main__':
    import argparse
    import json
    from pathlib import Path
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--extents', type=Path, required=True)
    p.add_argument('--verified-gpt-head', type=Path, required=True)
    p.add_argument('--root-image', type=Path, required=True)
    p.add_argument('--expected-sha256', required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    result = create(json.loads(a.extents.read_text()), a.verified_gpt_head.read_bytes(),
                    a.root_image, a.expected_sha256)
    with a.output.open('x') as f:
        json.dump(result, f, indent=2); f.write('\n')
    a.output.chmod(0o600)
    print(f'{len(result["extents"])} extents; readonly metadata saved to {a.output}')
