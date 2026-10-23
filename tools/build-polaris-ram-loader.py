#!/usr/bin/env python3
"""Cross-compile the bounded polaris RAM loader core for QEMU testing.

Produces an ELF and Linux Image, not a phone boot image. No XNU kernel is
included. Hardware packaging must wait for the diagnostic and CI validation.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--zig', required=True)
    ap.add_argument('--cc', default='clang')
    a = ap.parse_args()
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location('probe_builder', root / 'tools/build-polaris-probe.py')
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    out = root / 'shim/out/polaris-ram-loader'
    out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(out / 'zig-cache'),
               ZIG_LOCAL_CACHE_DIR=str(out / 'zig-local-cache'))
    flags = ['-O2', '-g0', '-ffreestanding', '-nostdlib', '-fno-pic', '-fno-pie',
             '-fno-stack-protector', '-mgeneral-regs-only', '-mstrict-align',
             '-Wall', '-Wextra', '-Werror', '-DFB_BASE=0x9d400000UL',
             '-DFB_W=1080', '-DFB_H=2160']
    objects = []
    for source in ['start.S', 'console.c', 'polaris/dt.c', 'polaris/payload.c',
                   'polaris/loader.c', 'polaris/boot.c']:
        path = root / 'shim' / source
        obj = out / (path.stem + '.o')
        subprocess.run([a.cc, '-target', 'aarch64-none-elf', '-mcpu=cortex-a53',
                        *flags, '-c', str(path), '-o', str(obj)], check=True, env=env)
        if path.suffix == '.c':
            builder.reject_absolute_relocations(obj)
        objects.append(str(obj))
    elf = out / 'loader.elf'
    subprocess.run([str(Path(a.zig).resolve()), 'cc', '-target', 'aarch64-freestanding',
                    *flags, '-static', '-Wl,--build-id=none', '-Wl,-e,_head',
                    '-Wl,-T,' + str(root / 'shim/shim.ld'), *objects, '-o', str(elf)],
                   check=True, env=env)
    data = builder.elf_image(elf.read_bytes())
    size = struct.unpack_from('<Q', data, 16)[0]
    if data[56:60] != b'ARM\x64' or not len(data) <= size <= 2 * 1024 * 1024:
        raise ValueError('invalid loader Image header')
    image = out / 'Image'
    image.write_bytes(data + bytes(size - len(data)))
    print(json.dumps(dict(image=str(image), bytes=size,
                          purpose='QEMU loader-core testing; no XNU or phone boot packaging')))


if __name__ == '__main__':
    main()
