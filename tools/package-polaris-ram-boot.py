#!/usr/bin/env python3
"""Package a storage-free shim using the proven recovery's gzip/DTB format.

Does not invoke phone tools. The input shim must be reviewed separately;
preserving boot options and DTBs does not prove shim execution or display.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import zlib

SOURCE_SHA = 'f9ad6529c1632fa2116377ec5f12c78f6d5cf7f5a1baa0b0f1bec4b5a518bd99'


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--image', required=True, type=Path)
    ap.add_argument('--ramdisk', required=True, type=Path)
    ap.add_argument('--output', required=True, type=Path)
    ap.add_argument('--mkbootimg', required=True)
    a = ap.parse_args()
    root = Path(__file__).resolve().parents[1]
    source = (root / 'shim/out/polaris-backup-recovery/polaris-backup-recovery.img').read_bytes()
    assert hashlib.sha256(source).hexdigest() == SOURCE_SHA
    ks, ka, _, ra, ss, sa, ta, page, version, osv = struct.unpack_from('<10I', source, 8)
    assert version == 0 and ss == 0
    d = zlib.decompressobj(31)
    original = d.decompress(source[page:page + ks]) + d.flush()
    trees = d.unused_data
    assert d.eof and original[56:60] == b'ARM\x64'
    offset = count = 0
    while offset < len(trees):
        assert trees[offset:offset + 4] == b'\xd0\x0d\xfe\xed'
        size = struct.unpack_from('>I', trees, offset + 4)[0]
        assert 40 <= size <= len(trees) - offset
        offset += size
        count += 1
    assert count == 65
    shim = a.image.read_bytes()
    assert shim[56:60] == b'ARM\x64'
    size = struct.unpack_from('<Q', shim, 16)[0]
    assert 64 <= size <= len(shim) and size <= 2 * 1024 * 1024
    # A prior diagnostic may have its own appended live DTB. Deliberately
    # replace it with the exact original compiled DTB table used by recovery.
    extra = shim[size:]
    if extra:
        assert extra[:4] == b'\xd0\x0d\xfe\xed'
        assert struct.unpack_from('>I', extra, 4)[0] == len(extra)
    image = bytearray(shim[:size])
    image[8:16] = original[8:16]  # Proven Linux Image text_offset=0x80000.
    assert image[24:32] == original[24:32], 'Image architecture flags mismatch'
    rd = a.ramdisk.read_bytes()
    assert 0 < len(rd) <= 128 * 1024 * 1024
    out = a.output.resolve().parent
    out.mkdir(parents=True, exist_ok=True)
    kernel = out / 'kernel'
    kernel.write_bytes(gzip.compress(image, mtime=0) + trees)
    (out / 'Image').write_bytes(image)
    cmd = (source[64:576].split(b'\0')[0] + source[608:1632].split(b'\0')[0]).decode()
    os_args = []
    if osv:
        value, patch = osv >> 11, osv & 0x7ff
        os_args = ['--os_version', f'{value >> 14}.{(value >> 7) & 127}.{value & 127}']
        if patch:
            os_args += ['--os_patch_level', f'{2000 + (patch >> 4)}-{patch & 15:02d}-01']
    subprocess.run([sys.executable, a.mkbootimg, '--header_version', str(version),
                    '--base', '0', '--kernel_offset', hex(ka), '--ramdisk_offset', hex(ra),
                    '--second_offset', hex(sa), '--tags_offset', hex(ta), '--pagesize', str(page),
                    '--kernel', str(kernel), '--ramdisk', str(a.ramdisk.resolve()),
                    '--cmdline', cmd, *os_args, '-o', str(a.output.resolve())], check=True)
    packed = a.output.read_bytes()
    newks = kernel.stat().st_size
    rdoff = page + (newks + page - 1) // page * page
    assert packed[page:page + newks] == kernel.read_bytes()
    assert packed[rdoff:rdoff + len(rd)] == rd
    assert packed[20:48] == source[20:48] and packed[12:16] == source[12:16]
    verify = zlib.decompressobj(31)
    assert verify.decompress(packed[page:page + newks]) + verify.flush() == image
    assert verify.unused_data == trees
    record = dict(image=str(a.output), sha256=hashlib.sha256(packed).hexdigest(),
                  bytes=len(packed), shim_sha256=hashlib.sha256(image).hexdigest(),
                  input_shim_sha256=hashlib.sha256(shim).hexdigest(),
                  ramdisk_sha256=hashlib.sha256(rd).hexdigest(),
                  source_recovery_sha256=SOURCE_SHA, dtb_count=count,
                  text_offset=struct.unpack_from('<Q', image, 8)[0],
                  hardware_boot_tested=False)
    (out / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    main()
