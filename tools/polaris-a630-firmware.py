#!/usr/bin/env python3
"""Stage original Polaris A630 firmware in a private ADT, without executing it.

The source must be a hash-verified, read-only vendor collection. Bounds and
image layouts follow MiCode polaris-o-oss c7cb50c18f812629b9620b2b8fa684bc40d82080,
adreno_a6xx.c. This is a transport prerequisite, not a GPU driver or a secure
authentication implementation. No firmware bytes belong in Git.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import adt

MAX_FILE = 4 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def inspect_images(images):
    """Check the supported original flat-GMU/SQE/split-ZAP layout in RAM."""
    require(all(isinstance(v, bytes) and 0 < len(v) <= MAX_FILE
                for v in images.values()), 'invalid firmware span')
    require(all(n in images for n in ('a630_gmu.bin', 'a630_sqe.fw', 'a630_zap.mdt')),
            'missing A630 firmware')
    gmu, sqe, mdt = (images[n] for n in ('a630_gmu.bin', 'a630_sqe.fw', 'a630_zap.mdt'))
    # The original MAX_GMUFW_SIZE loop copies0x2000 uint32_t words to ITCM.
    require(len(gmu) == 0x8000, 'unsupported flat GMU size')
    stack, reset = struct.unpack_from('<II', gmu)
    require(0x40000 <= stack <= 0x44000 and stack % 8 == 0,
            'GMU stack outside original DTCM')
    require(reset & 1 and reset < 0x8000, 'GMU reset vector outside original ITCM')
    require(8 <= len(sqe) <= 1024 * 1024 and len(sqe) % 4 == 0,
            'invalid SQE word span')
    require(struct.unpack_from('<I', sqe)[0] == 0, 'unsupported SQE prefix')
    require(len(mdt) >= 52 and mdt[:7] == b'\x7fELF\x01\x01\x01', 'expected ELF32 little endian ZAP')
    h = struct.unpack_from('<16sHHIIIIIHHHHHH', mdt)
    require(h[1:4] == (2, 164, 1), 'unsupported ZAP ELF type/machine/version')
    phoff, ehsize, phsize, phnum = h[5], h[8], h[9], h[10]
    require(ehsize == 52 and phoff == 52 and phsize == 32 and 3 <= phnum <= 16,
            'unsupported ZAP program table')
    table_end = phoff + phnum * phsize
    require(table_end <= len(mdt), 'truncated ZAP program table')
    rows, load_count = [], 0
    for i in range(phnum):
        kind, offset, va, pa, size, memsz, flags, align = struct.unpack_from('<8I', mdt, phoff + i * phsize)
        name = 'a630_zap.b%02d' % i
        require(name in images and len(images[name]) == size,
                'missing or wrong-size ZAP split segment' + str(i))
        if i == 0:
            require(kind == 0 and offset == 0 and size == table_end and
                    images[name] == mdt[:table_end], 'ZAP header split mismatch')
        elif i == 1:
            require(kind == 0 and (flags & 0x07000000) == 0x02000000 and
                    mdt == images['a630_zap.b00'] + images[name],
                    'ZAP authentication metadata split mismatch')
        else:
            require(kind == 1 and (flags & 0x07000000) != 0x02000000 and
                    flags & 0x08000000, 'unsupported nonrelocatable ZAP load segment')
            require(size <= memsz <= MAX_FILE and pa + memsz <= 0x100000000 and
                    va + memsz <= 0x100000000 and align and align & (align - 1) == 0,
                    'invalid ZAP load bounds/alignment')
            load_count += 1
        rows.append(dict(index=i, type=kind, file=name, bytes=size,
                         memory_bytes=memsz, relative_address=pa, flags=flags, alignment=align))
    require(load_count > 0, 'ZAP has no load segment')
    return dict(gmu_bytes=len(gmu), gmu_format='flat ITCM', sqe_bytes=len(sqe),
                sqe_code_offset=4, sqe_code_words=(len(sqe) - 4) // 4,
                sqe_version=struct.unpack_from('<I', sqe, 4)[0], zap_segments=rows,
                bounds_checked=True, secure_authentication_performed=False,
                firmware_executed=False)


def read_collection(directory, manifest):
    require(manifest.get('state') == 'readonly_original_vendor_collected' and
            manifest.get('vendor_device') == 'sde47' and
            manifest.get('vendor_bytes') == 4294967296, 'wrong original vendor collection')
    require(all(manifest.get(k) is True for k in
                ('source_gpt_matches_backup', 'header_unchanged', 'unmounted', 'block_readonly')),
            'missing read-only collection proof')
    require(all(manifest.get(k) is False for k in
                ('journal_replayed', 'metadata_repaired', 'firmware_executed')),
            'collection changed or executed firmware')
    directory = Path(directory).resolve()
    images = {}
    for row in manifest['files']:
        name, size, expected = row['file'], row['bytes'], row['sha256']
        require(re.fullmatch(r'a630_(gmu\.bin|sqe\.fw|zap\.(mdt|b0[0-9a-f]))', name) and
                name not in images and type(size) is int and 0 < size <= MAX_FILE and
                re.fullmatch('[0-9a-f]{64}', expected), 'invalid or duplicate firmware record')
        path = directory / name
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_size == size and
                path.resolve().parent == directory, 'firmware is not an in-directory regular file')
        data = path.read_bytes()
        require(len(data) == size and hashlib.sha256(data).hexdigest() == expected,
                'firmware hash mismatch: ' + name)
        images[name] = data
    return images, inspect_images(images)


def attach(original, images):
    """Add only a firmware node; it advertises no IOService or powered GPU."""
    inspect_images(images)
    root, _ = adt.parse(original)
    require(adt.serialize(root) == original, 'noncanonical input ADT')
    props = lambda n: {k: v for k, _, v in n.props}
    def child(n, name):
        return next(c for c in n.children if props(c).get('name') == name.encode() + b'\0')
    require(b'xiaomi,polaris' in props(root).get('compatible', b'').split(b'\0'), 'not a Polaris ADT')
    reg = props(child(child(root, 'arm-io'), 'gic')).get('reg')
    require(reg == struct.pack('<4Q', 0x16a00000, 0x10000, 0x16a60000, 0x100000),
            'firmware staging requires the exact physical Polaris GIC, not QEMU')
    require(not any(props(c).get('name') == b'polaris-a630-firmware\0' for c in root.children),
            'firmware node already exists')
    node = adt.Node()
    node.props = [('name', 0, b'polaris-a630-firmware\0'),
                  ('version', 0, struct.pack('<I', 1)),
                  ('chip-id', 0, struct.pack('<I', 0x06030001)),
                  ('sqe-code-offset', 0, struct.pack('<I', 4))]
    for name, data in sorted(images.items()):
        key = name.removeprefix('a630_').replace('.', '-')
        node.props.extend([(key, 0, data), (key + '-sha256', 0, hashlib.sha256(data).digest())])
    root.children.append(node)
    result = adt.serialize(root)
    require(len(result) <= 2 * 1024 * 1024, 'firmware ADT too large')
    root.children.remove(node)
    require(adt.serialize(root) == original, 'unrelated ADT mutation')
    return result


def write_new(path, data):
    with Path(path).open('xb') as f:
        Path(path).chmod(0o600)
        f.write(data)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--firmware-dir', type=Path, required=True)
    p.add_argument('--vendor-manifest', type=Path, required=True)
    p.add_argument('--input-adt', type=Path)
    p.add_argument('--output-adt', type=Path)
    p.add_argument('--report', type=Path)
    a = p.parse_args()
    if bool(a.input_adt) != bool(a.output_adt):
        p.error('--input-adt and --output-adt are required together')
    for target in (a.output_adt, a.report):
        if target and target.exists():
            p.error('refusing existing output')
    images, report = read_collection(a.firmware_dir, json.loads(a.vendor_manifest.read_text()))
    report['image_sha256'] = {name: hashlib.sha256(data).hexdigest() for name, data in images.items()}
    if a.input_adt:
        original = a.input_adt.read_bytes()
        data = attach(original, images)
        write_new(a.output_adt, data)
        report.update(firmware_adt_sha256=hashlib.sha256(data).hexdigest(),
                      original_adt_sha256=hashlib.sha256(original).hexdigest(),
                      added_only_firmware_node=True, adt_bytes=len(data),
                      GPU_service_advertised=False)
    if a.report:
        write_new(a.report, (json.dumps(report, indent=2) + '\n').encode())
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
