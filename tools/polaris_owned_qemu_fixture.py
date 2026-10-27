"""Exclusive copies of one synthetic ext4/GPT fixture; no phone/device backend.

The native UFS driver must independently reread inode/CRC/UUID/extent metadata.
Host hashes and reopening compare bytes; they never manufacture durable SAFE.
"""
import hashlib
import os
from pathlib import Path
import struct

LUN_SHA = 'c23a0f1abdb441b3b0d93b269835793dca2d7d2d5cfbd05a1d3a70949182003f'
PACKET_SHA = '3672fb6865d29e9731ffd421eb1cfa4a3fa6c017dc5e8d2d85fc2e0c8cef01e1'
LUN_BYTES = 35072 * 4096


def digest(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def sources(root):
    folder = root / 'research/polaris/uefi-ios-0073/owned-virtual-fixture'
    lun, packet = folder / 'isolated-owned-lun0.raw', folder / 'runtime-owner.packet'
    for path in (lun, packet):
        if path.is_symlink() or not path.is_file():
            raise ValueError('regular synthetic fixture files required')
    if lun.stat().st_size != LUN_BYTES or digest(lun) != LUN_SHA or digest(packet) != PACKET_SHA:
        raise ValueError('synthetic fixture source changed')
    return lun, packet.read_bytes()


def create(root, destination, tree):
    """Only a new exclusive regular copy can ever be exposed as writable."""
    import polaris_uefi_cpu_tree as cpu
    node = cpu.child(tree, 'polaris-qemu-owned-file')
    p = cpu.props(node)
    lun, packet = sources(root)
    if p['owner-packet'] != packet or p['protected-map'] != struct.pack('<QQQ', 0, 2315, 256):
        raise ValueError('tree does not bind the exact synthetic owned and base files')
    if p['protected-blocks'] != struct.pack('<Q', 256):
        raise ValueError('incomplete protected base fixture')
    with lun.open('rb') as source, destination.open('xb') as output:
        while data := source.read(1 << 20):
            output.write(data)
        output.flush()
        os.fsync(output.fileno())
    if destination.is_symlink() or not destination.is_file() or destination.stat().st_nlink != 1:
        raise ValueError('backend must be a new exclusive regular copy')
    if digest(destination) != LUN_SHA:
        raise ValueError('new backend copy mismatch')
    return LUN_SHA


def reopen_check(root, backend, wrote):
    """Reopen after QEMU exits; compare the ENTIRE LUN and protected base."""
    source, packet = sources(root)
    nodes = struct.unpack_from('<I', packet, 72)[0]
    logical, physical, count = struct.unpack_from('<QQQ', packet, 384 + nodes * 4104)
    start = struct.unpack_from('<Q', packet, 16)[0]
    if logical or not count:
        raise ValueError('fixture first extent invalid')
    offset = (start + physical) * 4096
    pattern = bytes((i * 37 + 0x76) & 255 for i in range(4096))
    different = []
    full_match = backend.stat().st_size == LUN_BYTES
    with source.open('rb') as before, backend.open('rb') as after:
        for at in range(0, LUN_BYTES, 4096):
            old, new = before.read(4096), after.read(4096)
            expected = pattern if wrote and at == offset else old
            if old != new:
                different.append(at // 4096)
            if new != expected:
                full_match = False
        full_match = full_match and not after.read(1)
    with source.open('rb') as before, backend.open('rb') as after:
        before.seek(2315*4096); after.seek(2315*4096)
        base_before, base_after = before.read(1 << 20), after.read(1 << 20)
    return dict(all_LUN_bytes_match_expected=full_match,
                changed_blocks=different, expected_changed_blocks=[offset//4096] if wrote else [],
                original_source_unchanged=digest(source)==LUN_SHA,
                protected_base_unchanged=base_before==base_after,
                protected_base_sha256=hashlib.sha256(base_after).hexdigest(),
                backend_sha256=digest(backend), reopened_after_QEMU_exit=True,
                physical_phone_touched=False, full_iOS_persistence_proven=False)
