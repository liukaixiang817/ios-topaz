#!/usr/bin/env python3
"""Instrument the verified headless recovery's entry, then resume Linux.

No phone commands. Registers go into a preallocated RAM device-tree property
and can be read over ADB. All original kernel bytes except the first branch
and Image size remain identical, as do the recovery ramdisk and boot options.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import zlib

MARKER = b'POLARISREGS1'.ljust(16, b'\0') + bytes(96)
UFS_MARKER = b'POLARISUFS1'.ljust(16, b'\0') + bytes(112)
SOURCE_SHA = 'f9ad6529c1632fa2116377ec5f12c78f6d5cf7f5a1baa0b0f1bec4b5a518bd99'


def branch(delta):
    if delta % 4 or not -(1 << 27) <= delta < (1 << 27):
        raise ValueError('branch range/alignment')
    return 0x14000000 | ((delta // 4) & 0x3ffffff)


def symbols(elf):
    shoff = struct.unpack_from('<Q', elf, 40)[0]
    stride, count = struct.unpack_from('<HH', elf, 58)
    result = {}
    for i in range(count):
        sh = shoff + i * stride
        if struct.unpack_from('<I', elf, sh + 4)[0] != 2:
            continue
        offset, size = struct.unpack_from('<QQ', elf, sh + 24)
        link = struct.unpack_from('<I', elf, sh + 40)[0]
        strings, length = struct.unpack_from('<QQ', elf, shoff + link * stride + 24)
        names = elf[strings:strings + length]
        for at in range(offset, offset + size, 24):
            name, _, _, _, value, _ = struct.unpack_from('<IBBHQQ', elf, at)
            result[names[name:].split(b'\0')[0].decode()] = value
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--zig', required=True)
    ap.add_argument('--cc', default='clang')
    ap.add_argument('--fdtput', default='fdtput')
    ap.add_argument('--mkbootimg', required=True)
    ap.add_argument('--outdir', type=Path)
    ap.add_argument('--ufs-snapshot', action='store_true', help='read-only UFSHCI entry register capture')
    a = ap.parse_args()
    root = Path(__file__).resolve().parents[1]
    out = a.outdir.resolve() if a.outdir else root / 'shim/out/polaris-linux-probe-0001'
    if a.ufs_snapshot and not a.outdir:
        ap.error('--ufs-snapshot requires a separate --outdir to preserve CPU-only evidence')
    out.mkdir(parents=True, exist_ok=True)
    source = (root / 'shim/out/polaris-backup-recovery/polaris-backup-recovery.img').read_bytes()
    assert hashlib.sha256(source).hexdigest() == SOURCE_SHA
    ks, ka, rs, ra, ss, sa, ta, page, version, osv = struct.unpack_from('<10I', source, 8)
    assert version == 0 and ss == 0
    align = lambda n: (n + page - 1) // page * page
    decompressor = zlib.decompressobj(31)
    original = decompressor.decompress(source[page:page + ks]) + decompressor.flush()
    trees = decompressor.unused_data
    assert decompressor.eof and original[56:60] == b'ARM\x64'
    first = struct.unpack_from('<I', original)[0]
    assert first & 0xfc000000 == 0x14000000, 'original entry must be unconditional B'
    target = (first & 0x3ffffff) * 4
    if target & (1 << 27): target -= 1 << 28
    assert 64 <= target < len(original)
    old_size = struct.unpack_from('<Q', original, 16)[0]
    assert len(original) <= old_size < 64 * 1024 * 1024
    wrapper_offset = align(old_size)
    spec = importlib.util.spec_from_file_location('builder', root / 'tools/build-polaris-probe.py')
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    env = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(out / 'zig-cache'),
               ZIG_LOCAL_CACHE_DIR=str(out / 'zig-local-cache'))
    flags = ['-O2', '-ffreestanding', '-nostdlib', '-fno-pic', '-fno-pie',
             '-fno-stack-protector', '-mgeneral-regs-only', '-mstrict-align',
             '-Wall', '-Wextra', '-Werror']
    if a.ufs_snapshot:
        flags += ['-DPOLARIS_UFS_SNAPSHOT=1']
    objects = []
    for name in ('linux-probe.S', 'linux-probe.c', 'dt.c'):
        path = root / 'shim/polaris' / name
        obj = out / (name.replace('.', '-') + '.o')
        subprocess.run([a.cc, '-target', 'aarch64-none-elf', '-mcpu=cortex-a53',
                        *flags, '-c', str(path), '-o', str(obj)], check=True, env=env)
        if path.suffix == '.c': builder.reject_absolute_relocations(obj)
        objects.append(str(obj))
    script = out / 'wrapper.ld'
    script.write_text('''ENTRY(linux_probe_entry)
SECTIONS { . = 0; .text : { KEEP(*(.text.head)) *(.text*) }
.rodata : { *(.rodata*) } .data : { *(.data*) }
. = ALIGN(16); .stack (NOLOAD) : { *(.stack) }
wrapper_end = .; /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) } }
''')
    elf_path = out / 'wrapper.elf'
    subprocess.run([str(Path(a.zig).resolve()), 'cc', '-target', 'aarch64-freestanding',
                    *flags, '-static', '-Wl,--build-id=none', '-Wl,-e,linux_probe_entry',
                    '-Wl,-T,' + str(script),
                    *objects, '-o', str(elf_path)], check=True, env=env)
    elf = elf_path.read_bytes()
    syms = symbols(elf)
    assert syms['linux_probe_entry'] == 0
    wrapper = bytearray(builder.elf_image(elf))
    wrapper.extend(bytes(align(syms['wrapper_end']) - len(wrapper)))
    resume = syms['linux_probe_resume']
    struct.pack_into('<I', wrapper, resume, branch(target - wrapper_offset - resume))
    image = bytearray(original)
    image.extend(bytes(wrapper_offset - len(image)))
    image.extend(wrapper)
    struct.pack_into('<I', image, 0, branch(wrapper_offset))
    struct.pack_into('<Q', image, 16, len(image))
    assert image[4:16] == original[4:16] and image[24:len(original)] == original[24:]
    (out / 'Image').write_bytes(image)
    (out / 'wrapper.bin').write_bytes(wrapper)
    patched, offset, count = [], 0, 0
    while offset < len(trees):
        assert trees[offset:offset + 4] == b'\xd0\x0d\xfe\xed'
        size = struct.unpack_from('>I', trees, offset + 4)[0]
        assert 40 <= size <= len(trees) - offset
        path = out / f'tree-{count:03}.dtb'
        path.write_bytes(trees[offset:offset + size])
        subprocess.run([a.fdtput, '-p', '-t', 'bx', str(path), '/chosen',
                        'polaris,boot-registers', *[f'{b:02x}' for b in MARKER]], check=True)
        if a.ufs_snapshot:
            subprocess.run([a.fdtput, '-p', '-t', 'bx', str(path), '/chosen',
                            'polaris,ufs-handoff', *[f'{b:02x}' for b in UFS_MARKER]], check=True)
        patched.append(path.read_bytes())
        offset += size
        count += 1
    kernel = out / 'kernel'
    kernel.write_bytes(gzip.compress(image, mtime=0) + b''.join(patched))
    ramdisk = out / 'ramdisk.gz'
    ramdisk.write_bytes(source[page + align(ks):page + align(ks) + rs])
    cmd = (source[64:576].split(b'\0')[0] + source[608:1632].split(b'\0')[0]).decode()
    os_args = []
    if osv:
        value, patch = osv >> 11, osv & 0x7ff
        os_args = ['--os_version', f'{value >> 14}.{(value >> 7) & 127}.{value & 127}']
        if patch:
            os_args += ['--os_patch_level', f'{2000 + (patch >> 4)}-{patch & 15:02d}-01']
    boot = out / 'polaris-linux-probe-0001.img'
    subprocess.run([sys.executable, a.mkbootimg, '--header_version', str(version),
                    '--base', '0', '--kernel_offset', hex(ka), '--ramdisk_offset', hex(ra),
                    '--second_offset', hex(sa), '--tags_offset', hex(ta), '--pagesize', str(page),
                    '--kernel', str(kernel), '--ramdisk', str(ramdisk), '--cmdline', cmd,
                    *os_args, '-o', str(boot)], check=True)
    packed = boot.read_bytes()
    newks = kernel.stat().st_size
    assert packed[12:16] == source[12:16] and packed[20:48] == source[20:48]
    assert packed[page:page + newks] == kernel.read_bytes()
    assert packed[page + align(newks):page + align(newks) + rs] == ramdisk.read_bytes()
    record = dict(source_sha256=SOURCE_SHA, image=str(boot.relative_to(root)),
                  sha256=hashlib.sha256(packed).hexdigest(), bytes=len(packed),
                  dtb_count=count, wrapper_offset=wrapper_offset, resume_offset=resume,
                  original_entry=target, wrapper_size=len(wrapper),
                  original_kernel_size=old_size, image_size=len(image),
                  ufs_snapshot=a.ufs_snapshot,
                  purpose='RAM FDT register capture, resume headless Linux; no flash')
    (out / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    main()
