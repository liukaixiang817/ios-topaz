#!/usr/bin/env python3
"""Build a standalone RAM-boot diagnostic for MIX 2S. Never invokes adb/fastboot.

Requires Clang (cross C), Zig (ELF linker), AOSP mkbootimg.py with v1 support,
and the backed-up live polaris DTB. Outputs stay in ignored shim/out/.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import os
import struct
import subprocess
import sys


def elf_image(data):
    """Flatten zero-based ELF64 PT_LOAD contents without a host objcopy."""
    if data[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<HH", data, 16) != (2, 183):
        raise ValueError("expected executable AArch64 little-endian ELF64")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phsize, phnum = struct.unpack_from("<HH", data, 54)
    if phsize != 56 or phoff + phsize * phnum > len(data):
        raise ValueError("invalid ELF program headers")
    image = bytearray()
    ranges = []
    for i in range(phnum):
        kind, _, off, va, pa, filesz, memsz, _ = struct.unpack_from("<II6Q", data, phoff + i * phsize)
        if kind != 1:
            continue
        if va != pa or filesz > memsz or off + filesz > len(data) or pa + memsz > 2 * 1024 * 1024:
            raise ValueError("invalid/non-zero-based ELF segment")
        if any(pa < end and pa + memsz > start for start, end in ranges):
            raise ValueError("overlapping ELF segments")
        ranges.append((pa, pa + memsz))
        if len(image) < pa + filesz:
            image.extend(bytes(pa + filesz - len(image)))
        image[pa:pa + filesz] = data[off:off + filesz]
    if not ranges or min(start for start, _ in ranges) != 0:
        raise ValueError("ELF is not linked at zero")
    return bytes(image)


def reject_absolute_relocations(path):
    data = path.read_bytes()
    if data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("not little-endian ELF64")
    shoff = struct.unpack_from("<Q", data, 40)[0]
    shsize, shnum = struct.unpack_from("<HH", data, 58)
    for i in range(shnum):
        section = shoff + i * shsize
        if struct.unpack_from("<I", data, section + 4)[0] == 4:  # SHT_RELA
            target = struct.unpack_from("<I", data, section + 44)[0]
            flags = struct.unpack_from("<Q", data, shoff + target * shsize + 8)[0]
            if not flags & 2:  # Debug sections do not become the boot Image.
                continue
            off, size = struct.unpack_from("<QQ", data, section + 24)
            stride = struct.unpack_from("<Q", data, section + 56)[0]
            for at in range(off, off + size, stride):
                kind = struct.unpack_from("<Q", data, at + 8)[0] & 0xffffffff
                if kind in (257, 258, 259):  # AArch64 ABS64/32/16
                    raise ValueError(f"{path}: absolute C relocation {kind}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zig", required=True)
    parser.add_argument("--cc", default="clang")
    parser.add_argument("--mkbootimg", required=True)
    parser.add_argument("--dtb", required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    out = root / "shim/out/polaris-probe-0001"
    out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(out / "zig-cache"),
               ZIG_LOCAL_CACHE_DIR=str(out / "zig-local-cache"))
    zig = str(Path(args.zig).resolve())

    def run(argv):
        subprocess.run(argv, check=True, env=env)

    cflags = ["-O2", "-g0", "-ffreestanding",
              "-nostdlib", "-fno-pic", "-fno-pie", "-fno-stack-protector",
              "-mgeneral-regs-only", "-mstrict-align", "-Wall", "-Wextra", "-Werror",
              "-DFB_BASE=0x9d400000UL", "-DFB_W=1080", "-DFB_H=2160"]
    objects = []
    for source in ("start.S", "console.c", "polaris/dt.c", "polaris/probe.c"):
        path = root / "shim" / source
        obj = out / (path.stem + ".o")
        run([args.cc, "-target", "aarch64-none-elf", "-mcpu=cortex-a53",
             *cflags, "-c", str(path), "-o", str(obj)])
        if path.suffix == ".c":
            reject_absolute_relocations(obj)
        objects.append(str(obj))
    elf = out / "probe.elf"
    run([zig, "cc", "-target", "aarch64-freestanding", *cflags,
         "-static", "-Wl,--build-id=none", "-Wl,-e,_head",
         "-Wl,-T," + str(root / "shim/shim.ld"),
         *objects, "-o", str(elf)])
    image = out / "Image"
    data = elf_image(elf.read_bytes())
    if data[56:60] != b"ARM\x64":
        raise ValueError("invalid arm64 Linux Image header")
    image_size = struct.unpack_from("<Q", data, 16)[0]
    if not len(data) <= image_size <= 2 * 1024 * 1024:
        raise ValueError("invalid ELF _end / Linux image_size")
    data += bytes(image_size - len(data))
    dtb = args.dtb.read_bytes()
    if dtb[:4] != b"\xd0\x0d\xfe\xed" or struct.unpack_from(">I", dtb, 4)[0] != len(dtb):
        raise ValueError("invalid input FDT length/magic")
    # ABL on this device uses appended DTBs with the existing v1 kernel.
    # Boot acceptance of this uncompressed Image remains a hardware test.
    image.write_bytes(data + dtb)
    # Empty newc archive. There is no init/Android process in the probe.
    fields = [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 11, 0]
    archive = b"070701" + b"".join(f"{x:08x}".encode() for x in fields) + b"TRAILER!!!\0"
    archive += bytes(-len(archive) % 4)
    ramdisk = out / "ramdisk.gz"
    ramdisk.write_bytes(gzip.compress(archive, mtime=0))
    boot = out / "polaris-probe-0001.img"
    run([sys.executable, str(Path(args.mkbootimg).resolve()), "--header_version", "1",
         "--base", "0", "--kernel_offset", "0x8000", "--ramdisk_offset", "0x1000000",
         "--tags_offset", "0x100", "--pagesize", "4096", "--os_version", "13.0.0",
         "--os_patch_level", "2022-12-01", "--kernel", str(image), "--ramdisk", str(ramdisk),
         "--cmdline", "console=null", "-o", str(boot)])
    packed = boot.read_bytes()
    if packed[:8] != b"ANDROID!" or struct.unpack_from("<I", packed, 40)[0] != 1:
        raise ValueError("not boot-v1")
    if struct.unpack_from("<I", packed, 44)[0] != 0x1a00016c:
        raise ValueError("OS version/patch-level differs from backed-up Android boot header")
    if packed[4096:4096 + len(data) + len(dtb)] != image.read_bytes():
        raise ValueError("packed kernel differs from input")
    rd_off = 4096 + ((len(data) + len(dtb) + 4095) & ~4095)
    if packed[rd_off:rd_off + ramdisk.stat().st_size] != ramdisk.read_bytes():
        raise ValueError("packed ramdisk differs from input")
    record = dict(kind="polaris CPU/FDT framebuffer diagnostic; no XNU or disk driver",
                  bytes=len(packed), sha256=hashlib.sha256(packed).hexdigest(),
                  dtb_sha256=hashlib.sha256(dtb).hexdigest(), image_size=image_size,
                  zig_version=subprocess.check_output([zig, "version"], env=env).decode().strip(),
                  mkbootimg_sha256=hashlib.sha256(Path(args.mkbootimg).read_bytes()).hexdigest(),
                  hardware_boot_tested=False)
    (out / "manifest.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record, indent=2))
    print(boot)


if __name__ == "__main__":
    main()
