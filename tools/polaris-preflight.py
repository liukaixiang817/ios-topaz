#!/usr/bin/env python3
"""Read-only MIX 2S inventory and recovery-material collection. Never installs iOS.

Remote operations are getprop, cat, blockdev, dd (input only), and sha256sum.
All output is kept under git-ignored backup/. Requires an already rooted phone.
These are GPT/boot/firmware backups, NOT a backup of Android or Windows user data.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import struct
import subprocess
import time
import zlib


def parse_gpt(head, tail, disk_bytes, block_size):
    """Validate both GPT headers and arrays; LBAs use the device block size."""
    if block_size not in (512, 4096) or disk_bytes % block_size:
        raise ValueError("unsupported disk geometry")
    blocks = disk_bytes // block_size

    def header(region, region_start, lba):
        off = lba * block_size - region_start
        raw = region[off:off + block_size]
        if raw[:8] != b"EFI PART":
            raise ValueError("missing GPT signature")
        size, crc = struct.unpack_from("<II", raw, 12)
        if not 92 <= size <= block_size:
            raise ValueError("invalid GPT header length")
        check = bytearray(raw[:size])
        check[16:20] = bytes(4)
        if zlib.crc32(check) != crc:
            raise ValueError("GPT header CRC mismatch")
        current, alternate, first, last = struct.unpack_from("<QQQQ", raw, 24)
        entries_lba, count, entry_size, entries_crc = struct.unpack_from("<QIII", raw, 72)
        if current != lba or alternate != (blocks - 1 if lba == 1 else 1):
            raise ValueError("GPT header location mismatch")
        if not 1 < first <= last < blocks - 1:
            raise ValueError("invalid GPT usable range")
        if entry_size < 128 or entry_size % 128 or not 0 < count <= 16384:
            raise ValueError("invalid GPT entry geometry")
        start = entries_lba * block_size - region_start
        length = count * entry_size
        if start < 0 or start + length > len(region):
            raise ValueError("GPT array outside captured region")
        entries = region[start:start + length]
        if zlib.crc32(entries) != entries_crc:
            raise ValueError("GPT entries CRC mismatch")
        return raw[56:72], first, last, count, entry_size, entries

    primary = header(head, 0, 1)
    secondary = header(tail, disk_bytes - len(tail), blocks - 1)
    if primary != secondary:
        raise ValueError("primary and backup GPT disagree")
    _, first, last, count, entry_size, entries = primary
    partitions = []
    for index in range(count):
        entry = entries[index * entry_size:(index + 1) * entry_size]
        if entry[:16] == bytes(16):
            continue
        start, end = struct.unpack_from("<QQ", entry, 32)
        if not first <= start <= end <= last:
            raise ValueError("partition outside usable range")
        name = entry[56:128].decode("utf-16-le").split("\0", 1)[0]
        partitions.append(dict(number=index + 1, name=name, first_lba=start,
                               last_lba=end, bytes=(end - start + 1) * block_size))
    gaps = []
    cursor = first
    for part in sorted(partitions, key=lambda p: p["first_lba"]):
        if part["first_lba"] < cursor:
            raise ValueError("overlapping GPT partitions")
        if part["first_lba"] > cursor:
            gaps.append(dict(first_lba=cursor, last_lba=part["first_lba"] - 1,
                             bytes=(part["first_lba"] - cursor) * block_size))
        cursor = part["last_lba"] + 1
    if cursor <= last:
        gaps.append(dict(first_lba=cursor, last_lba=last,
                         bytes=(last - cursor + 1) * block_size))
    return dict(block_size=block_size, disk_bytes=disk_bytes,
                both_gpt_copies_valid=True, partitions=partitions, unallocated=gaps)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--su", choices=["/debug_ramdisk/su", "/system/bin/su", "/sbin/su"],
                        default="/debug_ramdisk/su")
    parser.add_argument("--backup-critical", action="store_true",
                        help="also read boot/recovery/ESP/firmware; excludes OS user data")
    args = parser.parse_args()
    adb = [args.adb, "-d"]  # adb itself refuses multiple USB devices

    def root_command(command):
        # Older MagiskSU allocates a PTY even under adb exec-out. Disable its
        # newline conversion before streaming binary data (verified by SHA-256).
        return f"{args.su} -c {shlex.quote('stty raw -echo 2>/dev/null; ' + command)}"

    def remote(command, root=False, timeout=60):
        if root:
            command = root_command(command)
        return subprocess.run(adb + ["exec-out", command], check=True,
                              capture_output=True, timeout=timeout).stdout

    if remote("getprop ro.product.device").strip() != b"polaris":
        raise SystemExit("Refusing: connected device is not polaris")
    if not remote("id", root=True).startswith(b"uid=0(root)"):
        raise SystemExit("Root access required for read-only backups")
    root = Path(__file__).resolve().parents[1]
    out = root / "backup" / ("polaris-" + time.strftime("%Y%m%d-%H%M%S"))
    out.mkdir(parents=True, mode=0o700, exist_ok=False)
    manifest = []

    def save(name, command, expected=None):
        """Stream to an incomplete file; publish only after remote hash matches."""
        target = out / name
        partial = out / (name + ".partial")
        print(f"Reading {name}", flush=True)
        with partial.open("xb") as stream:
            partial.chmod(0o600)
            process = subprocess.Popen(adb + ["exec-out", root_command(command)],
                                       stdout=stream, stderr=subprocess.PIPE)
            try:
                _, stderr = process.communicate(timeout=300)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                raise
        partial.chmod(0o600)
        if process.returncode:
            raise RuntimeError(f"{name}: device read failed: {stderr.decode(errors='replace')}")
        if expected is not None and partial.stat().st_size != expected:
            raise RuntimeError(f"{name}: short read")
        with partial.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        device_digest = remote(f"{command} | sha256sum", root=True).decode().split()[0]
        if digest != device_digest:
            raise RuntimeError(f"{name}: SHA-256 mismatch (source may have changed)")
        partial.rename(target)
        manifest.append(dict(file=name, bytes=target.stat().st_size, sha256=digest))
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        return target

    metadata = """getprop ro.product.device; getprop ro.product.model
getprop ro.board.platform; getprop ro.build.version.release
getprop ro.crypto.state; getprop ro.crypto.type
uname -a; df -h /data /sdcard
ls -l /dev/block/bootdevice/by-name
cat /proc/mounts
cat /proc/meminfo
"""
    (out / "inventory.txt").write_bytes(remote(metadata))
    save("live.dtb", "cat /sys/firmware/fdt")
    layouts = {}
    for disk in ("sda", "sdb", "sdc", "sdd", "sde", "sdf"):
        block_size = int(remote(f"cat /sys/class/block/{disk}/queue/logical_block_size"))
        disk_bytes = int(remote(f"cat /sys/class/block/{disk}/size")) * 512
        region_bytes = min(1024 * 1024, disk_bytes // 2)
        count = region_bytes // block_size
        source = f"/dev/block/{disk}"
        head = save(f"{disk}.head.bin", f"dd if={source} bs={block_size} count={count} 2>/dev/null", region_bytes)
        skip = (disk_bytes - region_bytes) // block_size
        tail = save(f"{disk}.tail.bin", f"dd if={source} bs={block_size} skip={skip} count={count} 2>/dev/null", region_bytes)
        layouts[disk] = parse_gpt(head.read_bytes(), tail.read_bytes(), disk_bytes, block_size)
        if args.backup_critical and disk in ("sdb", "sdc", "sdd", "sdf"):
            save(f"{disk}.img", f"dd if={source} bs=1048576 2>/dev/null", disk_bytes)
    (out / "layout.json").write_text(json.dumps(layouts, indent=2) + "\n")
    if args.backup_critical:
        for name in ("boot", "recovery", "dtbo", "abl_a", "abl_b", "devinfo", "misc", "switch",
                     "persist", "persistbak", "modem", "mindowsesp"):
            source = f"/dev/block/bootdevice/by-name/{name}"
            size = int(remote(f"blockdev --getsize64 {source}", root=True))
            save(f"{name}.img", f"dd if={source} bs=1048576 2>/dev/null", size)
    print(f"Verified collection: {out}")
    print("NOT a backup of Android/Windows user data. No phone partitions were written.")


if __name__ == "__main__":
    main()
