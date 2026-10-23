#!/usr/bin/env python3
"""Prepare a headless RAM-only backup environment from a verified polaris TWRP.

Retains its kernel/drivers/tools, replaces init.rc with a minimal root-ADB
configuration. No recovery UI, factory-reset service, disk mount or fsck job is
started. This builder never invokes phone commands. Use temporary boot only.
"""
import argparse
import gzip
import hashlib
from pathlib import Path
import struct
import subprocess
import sys
import json

OFFICIAL_TWRP_SHA256 = "54905f7abae89b345c4b1a03d12fe74c1ff06cf5aa41119f1a7228dc22765ea0"


def unpack_newc(data):
    entries, off = [], 0
    while off + 110 <= len(data):
        magic = data[off:off + 6]
        if magic not in (b"070701", b"070702"):
            raise ValueError("unsupported cpio format")
        fields = [int(data[off + 6 + 8 * i:off + 14 + 8 * i], 16) for i in range(13)]
        size, namesize = fields[6], fields[11]
        nameoff = off + 110
        if not 1 <= namesize <= 4096 or nameoff + namesize > len(data):
            raise ValueError("invalid cpio name")
        name = data[nameoff:nameoff + namesize]
        if name[-1] or b"\0" in name[:-1]:
            raise ValueError("invalid cpio name terminator")
        name = name[:-1].decode()
        start = (nameoff + namesize + 3) & ~3
        if size > len(data) - start:
            raise ValueError("truncated cpio file")
        content = data[start:start + size]
        if magic == b"070702" and sum(content) & 0xffffffff != fields[12]:
            raise ValueError("cpio checksum mismatch")
        entries.append([name, fields, content])
        off = (start + size + 3) & ~3
        if name == "TRAILER!!!":
            return entries
    raise ValueError("missing cpio trailer")


def pack_newc(entries):
    archive = bytearray()
    for name, original, content in entries:
        fields = list(original)
        encoded = name.encode() + b"\0"
        fields[6], fields[11], fields[12] = len(content), len(encoded), 0
        archive.extend(b"070701" + b"".join(f"{v:08x}".encode() for v in fields))
        archive.extend(encoded)
        archive.extend(bytes(-len(archive) % 4))
        archive.extend(content)
        archive.extend(bytes(-len(archive) % 4))
    return bytes(archive)


def init_rc(adbd, ueventd):
    return f"""# polaris backup environment: all persistent block devices stay unmounted.
on early-init
    start ueventd

on init
    export PATH /sbin:/system/bin
    export LD_LIBRARY_PATH /sbin
    export ANDROID_ROOT /system
    symlink /proc/self/fd/0 /dev/stdin
    symlink /proc/self/fd/1 /dev/stdout
    symlink /proc/self/fd/2 /dev/stderr
    mkdir /dev/usb-ffs 0770 shell shell
    mkdir /dev/usb-ffs/adb 0770 shell shell
    mkdir /config
    mount configfs none /config
    mkdir /config/usb_gadget/g1 0770 shell shell
    write /config/usb_gadget/g1/bcdUSB 0x0200
    write /config/usb_gadget/g1/idVendor 0x18d1
    write /config/usb_gadget/g1/idProduct 0x4ee7
    mkdir /config/usb_gadget/g1/strings/0x409 0770 shell shell
    write /config/usb_gadget/g1/strings/0x409/serialnumber ${{ro.serialno}}
    write /config/usb_gadget/g1/strings/0x409/manufacturer Xiaomi
    write /config/usb_gadget/g1/strings/0x409/product polaris-backup
    mkdir /config/usb_gadget/g1/functions/ffs.adb
    mkdir /config/usb_gadget/g1/configs/b.1 0770 shell shell
    mkdir /config/usb_gadget/g1/configs/b.1/strings/0x409 0770 shell shell
    write /config/usb_gadget/g1/configs/b.1/strings/0x409/configuration adb
    mount functionfs adb /dev/usb-ffs/adb uid=2000,gid=2000
    setprop sys.usb.configfs 1
    setprop sys.usb.controller a600000.dwc3

on late-init
    trigger fs
    trigger boot

on fs
    wait /dev/block/platform/soc/${{ro.boot.bootdevice}} 10
    symlink /dev/block/platform/soc/${{ro.boot.bootdevice}} /dev/block/bootdevice

on boot
    setprop service.adb.root 1
    start adbd

on property:sys.usb.ffs.ready=1
    symlink /config/usb_gadget/g1/functions/ffs.adb /config/usb_gadget/g1/configs/b.1/f1
    write /config/usb_gadget/g1/UDC ${{sys.usb.controller}}

on property:sys.powerctl=*
    powerctl ${{sys.powerctl}}

service ueventd {ueventd}
    seclabel u:r:ueventd:s0

service adbd {adbd} --root_seclabel=u:r:su:s0 --device_banner=recovery
    disabled
    socket adbd stream 660 system system
    seclabel u:r:adbd:s0
""".encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--sha256-file", type=Path, required=True)
    parser.add_argument("--mkbootimg", type=Path, required=True)
    args = parser.parse_args()
    source = args.source.read_bytes()
    source_sha = hashlib.sha256(source).hexdigest()
    if (source_sha != OFFICIAL_TWRP_SHA256 or
            source_sha != args.sha256_file.read_text().split()[0] or source[:8] != b"ANDROID!"):
        raise ValueError("source does not match official SHA-256/boot magic")
    ks, ka, rs, ra, ss, sa, ta, ps, version, os_version = struct.unpack_from("<10I", source, 8)
    if version not in (0, 1, 2) or ps not in (2048, 4096):
        raise ValueError("unsupported source boot header")
    align = lambda value: (value + ps - 1) // ps * ps
    kernel = source[ps:ps + ks]
    rd_off = ps + align(ks)
    entries = unpack_newc(gzip.decompress(source[rd_off:rd_off + rs]))
    original_links = {name: data for name, fields, data in entries
                      if fields[1] & 0o170000 == 0o120000}
    names = {entry[0] for entry in entries}
    adbd = next(("/" + n for n in ("sbin/adbd", "system/bin/adbd") if n in names), None)
    ueventd = next(("/" + n for n in ("sbin/ueventd", "system/bin/ueventd") if n in names), None)
    if not adbd or not ueventd or "init.rc" not in names:
        raise ValueError("required init/adbd/ueventd files missing")
    overrides = {"ro.secure": "0", "ro.adb.secure": "0", "ro.debuggable": "1",
                 "ro.product.device": "polaris", "ro.build.product": "polaris"}
    property_files = 0
    for entry in entries:
        if entry[0] == "init.rc":
            if entry[1][1] & 0o170000 != 0o100000:
                raise ValueError("init.rc is not a regular file")
            entry[2] = init_rc(adbd, ueventd)
        elif entry[0] in ("default.prop", "prop.default", "system/etc/prop.default"):
            if entry[1][1] & 0o170000 == 0o120000:
                continue  # TWRP default.prop -> prop.default must remain a symlink.
            if entry[1][1] & 0o170000 != 0o100000:
                raise ValueError("property path is not a regular file or symlink")
            lines = [line for line in entry[2].decode().splitlines()
                     if line.split("=", 1)[0] not in overrides]
            lines.extend(f"{key}={value}" for key, value in overrides.items())
            entry[2] = ("\n".join(lines) + "\n").encode()
            property_files += 1
    if not property_files:
        raise ValueError("source property files missing")
    out = Path(__file__).resolve().parents[1] / "shim/out/polaris-backup-recovery"
    out.mkdir(parents=True, exist_ok=True)
    (out / "kernel").write_bytes(kernel)
    (out / "ramdisk.gz").write_bytes(gzip.compress(pack_newc(entries), mtime=0))
    cmd = source[64:576].split(b"\0")[0] + source[608:1632].split(b"\0")[0]
    cmd = " ".join(token for token in cmd.decode().split()
                   if not token.startswith("androidboot.selinux=")) + " androidboot.selinux=permissive"
    boot = out / "polaris-backup-recovery.img"
    args_list = [sys.executable, str(args.mkbootimg), "--header_version", str(version),
                 "--base", "0", "--kernel_offset", hex(ka), "--ramdisk_offset", hex(ra),
                 "--second_offset", hex(sa), "--tags_offset", hex(ta), "--pagesize", str(ps),
                 "--kernel", str(out / "kernel"), "--ramdisk", str(out / "ramdisk.gz"),
                 "--cmdline", cmd, "-o", str(boot)]
    if os_version:
        value, patch = os_version >> 11, os_version & 0x7ff
        args_list += ["--os_version", f"{value >> 14}.{(value >> 7) & 127}.{value & 127}"]
        if patch:
            args_list += ["--os_patch_level", f"{2000 + (patch >> 4)}-{patch & 15:02d}-01"]
    pos = rd_off + align(rs)
    if ss:
        (out / "second").write_bytes(source[pos:pos + ss])
        args_list += ["--second", str(out / "second")]
    pos += align(ss)
    if version >= 1:
        size, offset = struct.unpack_from("<IQ", source, 1632)
        if size:
            (out / "recovery_dtbo").write_bytes(source[offset:offset + size])
            args_list += ["--recovery_dtbo", str(out / "recovery_dtbo")]
        pos += align(size)
    if version == 2:
        size, address = struct.unpack_from("<IQ", source, 1648)
        (out / "dtb").write_bytes(source[pos:pos + size])
        args_list += ["--dtb", str(out / "dtb"), "--dtb_offset", hex(address)]
    subprocess.run(args_list, check=True)
    packed = boot.read_bytes()
    if packed[ps:ps + ks] != kernel:
        raise ValueError("kernel bytes changed during packing")
    nr = struct.unpack_from("<I", packed, 16)[0]
    written = unpack_newc(gzip.decompress(packed[rd_off:rd_off + nr]))
    if len(written) != len(entries):
        raise ValueError("packed archive entry count changed")
    for before, after in zip(entries, written):
        if before[0] != after[0] or before[1][:6] != after[1][:6] or before[2] != after[2]:
            raise ValueError("packed archive changed content or metadata")
        if after[0] in original_links and after[2] != original_links[after[0]]:
            raise ValueError("source symlink target changed")
    if next(e[2] for e in written if e[0] == "init.rc") != init_rc(adbd, ueventd):
        raise ValueError("packed init configuration mismatch")
    record = dict(source_sha256=source_sha, sha256=hashlib.sha256(packed).hexdigest(),
                  bytes=len(packed), header_version=version, kernel_preserved=True,
                  purpose="temporary root ADB with no persistent-filesystem mounts or recovery UI",
                  hardware_boot_tested=False)
    (out / "manifest.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record, indent=2))
    print(boot)


if __name__ == "__main__":
    main()
