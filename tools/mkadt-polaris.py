#!/usr/bin/env python3
"""ADT for single-CPU XNU bring-up on the observed 8GB MIX 2S.

Requires the polaris kernel patch profile. Defaults to a console/RAM-init
tree. An explicit fresh manifest enables a read-only file root on userdata;
WLAN remains absent. An explicit --wifi-mac-file supplies verified factory
identity bytes to MobileGestalt without advertising a network driver.
--display explicitly enables the bounded CPU framebuffer
service; it also requires the polarisdisplay=1 kernel argument.
The phone's upper RAM bank is from its verified live DT, not topaz constants.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parent))
import adt
import mkadt
import polaris_file_root

PHYS_BASE, MEM_SIZE = 0x180000000, 0xfc8a0000
FB, FB_SIZE, WIDTH, HEIGHT, STRIDE = 0x9d400000, 0x2400000, 1080, 2160, 4320
GICD, GICR = 0x17a00000, 0x17a60000
SOC_BASE = 0x1000000


def props(node):
    return {key: value for key, _, value in node.props}


def setprop(node, key, value):
    node.props = [(k, f, v) for k, f, v in node.props if k != key] + [(key, 0, value)]


def child(node, name):
    return next(c for c in node.children if props(c).get("name") == name.encode() + b"\0")


def build(seed=None, qemu=False, ufs_head=None, file_root=None, display=False,
          wifi_mac=None, touch=False):
    if ufs_head is not None and qemu:
        raise ValueError('QEMU cannot probe the phone UFS controller')
    if file_root is not None and (qemu or ufs_head is not None):
        raise ValueError('file root requires phone hardware and excludes probe mode')
    if touch and qemu:
        raise ValueError('physical Synaptics input is not available in QEMU')
    if wifi_mac is not None:
        if not isinstance(wifi_mac, bytes) or len(wifi_mac) != 6:
            raise ValueError('Wi-Fi factory identity must be exactly six raw bytes')
        if not any(wifi_mac) or wifi_mac[0] & 1:
            raise ValueError('Wi-Fi factory identity must be a nonzero unicast address')
    # Reuse the Apple boot-policy scaffold, with one CPU and no UFS node.
    # Explicitly replace/remove all topaz hardware values below.
    root = mkadt.build(seed=seed, qemu=True)
    setprop(root, "compatible", b"D22AP\0iPhone10,3\0xiaomi,polaris\0qcom,sdm845\0AppleARM\0")
    chosen = child(root, "chosen")
    setprop(chosen, "dram-base", mkadt.u64(PHYS_BASE))
    setprop(chosen, "dram-size", mkadt.u64(MEM_SIZE))
    setprop(chosen, "firmware-version", b"polaris-ram-bringup\0")
    setprop(chosen, "system-firmware-version", b"polaris-ram-bringup\0")
    setprop(chosen, "unique-chip-id", mkadt.u64(0x504f4c4152495301))  # synthetic, not device data
    setprop(chosen, "boot-manifest-hash", hashlib.sha384(b"polaris boot manifest").digest())
    if wifi_mac is not None:
        # iOS 16.7/20H392 MobileGestalt checks this CFData before falling back
        # to IONetworkController notifications (19c571710..19c571770).
        # The caller must supply verified device data, never a shared default.
        setprop(chosen, 'mac-address-wifi0', wifi_mac)
    timebase = 62500000 if qemu else 19200000
    cpu = child(child(root, "cpus"), "cpu0")
    setprop(cpu, "compatible", b"qcom,kryo385\0ARM,v8\0")
    setprop(cpu, "reg", mkadt.u32(0))
    setprop(cpu, "clock-frequency", mkadt.u32(1766400000))  # Linux CPU0 cpuinfo_max_freq
    # The scaffold's bus/memory frequency values are compatibility placeholders,
    # not hardware measurements. Timer conversion uses the verified timebase.
    for name in ("timebase-frequency", "peripheral-frequency", "fixed-frequency"):
        setprop(cpu, name, mkadt.u32(timebase))
    arm_io = child(root, "arm-io")
    arm_io.children = [node for node in arm_io.children
                       if props(node).get("name") != b"wlan\0" and
                       (display or props(node).get("name") != b"disp0\0")]
    if display:
        panel = child(arm_io, 'disp0')
        setprop(panel, 'polaris,boot-framebuffer', mkadt.u32(1))
        setprop(panel, 'canvas-width', mkadt.u32(1125))
        setprop(panel, 'canvas-height', mkadt.u32(2436))
    gic = child(arm_io, "gic")
    dist, redist = (0x8000000, 0x80a0000) if qemu else (GICD, GICR)
    setprop(gic, "reg", mkadt.u64(dist - SOC_BASE, 0x10000, redist - SOC_BASE, 0x100000))
    setprop(gic, "virtual-timer-intid", mkadt.u32(27 if qemu else 19))
    console = child(root, "sweet-fbcon")
    setprop(console, "reg", mkadt.u64(FB, FB_SIZE))
    for name, value in (("width", WIDTH), ("height", HEIGHT), ("stride", STRIDE)):
        setprop(console, name, mkadt.u32(value))
    if ufs_head is not None:
        if len(ufs_head) != 1 << 20 or ufs_head[510:512] != b'\x55\xaa' or ufs_head[4096:4104] != b'EFI PART':
            raise ValueError('probe needs the verified 1 MiB LUN0 GPT head backup')
        probe = adt.Node()
        setprop(probe, 'name', b'polaris-ufs-probe\0')
        setprop(probe, 'reg', mkadt.u64(0x1d84000, 0x2500))
        setprop(probe, 'head-crc32', mkadt.u32(zlib.crc32(ufs_head)))
        root.children.append(probe)
    if file_root is not None:
        polaris_file_root.validate(file_root)
        disk = adt.Node()
        setprop(disk, 'name', b'polaris-file-root\0')
        setprop(disk, 'reg', mkadt.u64(0x1d84000, 0x2500))
        setprop(disk, 'version', mkadt.u32(1))
        setprop(disk, 'layout', mkadt.u64(*file_root['layout']))
        setprop(disk, 'crc32', mkadt.u32(*file_root['crc32']))
        setprop(disk, 'extents', b''.join(mkadt.u64(*e) for e in file_root['extents']))
        root.children.append(disk)
    if touch:
        # Only an explicit caller may enable hardware access; the kernel also
        # requires polaristouch=1 (input) or2 (capability probe without events).
        device = adt.Node()
        setprop(device, 'name', b'polaris-touch\0')
        setprop(device, 'version', mkadt.u32(1))
        setprop(device, 'reg', mkadt.u64(0xa98000, 0x4000))
        setprop(device, 'address', mkadt.u32(0x20))
        root.children.append(device)
    return root


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--qemu", action="store_true")
    parser.add_argument('--display', action='store_true',
                        help='enable CPU framebuffer service; needs polarisdisplay=1')
    parser.add_argument('--wifi-mac-file', type=Path,
                        help='private file containing six raw verified factory Wi-Fi MAC bytes; does not enable WLAN')
    parser.add_argument('--touch', action='store_true',
                        help='opt in to MIX2S Synaptics input; also needs polaristouch=1 or2')
    parser.add_argument('--ufs-probe-head', type=Path,
                        help='verified LUN0 head backup for optional read-only probe; needs polarisufsprobe=1')
    parser.add_argument('--file-root-manifest', type=Path,
                        help='fresh readonly metadata from polaris_file_root.py; needs polarisfileroot=1')
    args = parser.parse_args()
    blob = adt.serialize(build(qemu=args.qemu, display=args.display, touch=args.touch,
                              wifi_mac=args.wifi_mac_file.read_bytes() if args.wifi_mac_file else None,
                              ufs_head=args.ufs_probe_head.read_bytes() if args.ufs_probe_head else None,
                              file_root=json.loads(args.file_root_manifest.read_text()) if args.file_root_manifest else None))
    args.output.write_bytes(blob)
    print(f"{args.output}: {len(blob)} bytes; CPU0; UFS probe={bool(args.ufs_probe_head)}, readonly file root={bool(args.file_root_manifest)}")
