"""Snapshot a pinned ext4 file's inode/extent ownership for offline admission.

No allocation, mount, device access or write capability is provided. The CLI
accepts an existing ordinary filesystem image only. A later native consumer
must re-read and validate every metadata item before enabling any bounded I/O.
This packet is not a substitute for filesystem quiesce and cache-flush proof.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import struct

BLOCK = 4096
HEADER = 384
MAX_NODES = 64
MAX_EXTENTS = 4096
PINNED_FLAGS = 0x80090  # EXTENTS | IMMUTABLE | NOATIME
INCOMPAT_SUPPORTED = 0x10042 | 0x80 | 0x200 | 0x2000
RO_UNSUPPORTED = 0x200 | 0x1000 | 0x4000 | 0x10000


def u16(data, offset):
    return struct.unpack_from('<H', data, offset)[0]


def u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def crc32c(seed, data):
    for byte in data:
        seed ^= byte
        for _ in range(8):
            seed = seed >> 1 ^ (0x82f63b78 if seed & 1 else 0)
    return seed


def crc16(seed, data):
    for byte in data:
        seed ^= byte
        for _ in range(8):
            seed = seed >> 1 ^ (0xa001 if seed & 1 else 0)
    return seed


def snapshot(read_block, partition_start, partition_blocks, inode, fiemap=None):
    if not (256 <= partition_start <= 0xffffffff and
            0 < partition_blocks <= 0x100000000-partition_start):
        raise ValueError('unsupported partition geometry')
    def read(block):
        if not 0 <= block < partition_blocks:
            raise ValueError('metadata address outside partition')
        data = read_block(block)
        if len(data) != BLOCK:
            raise ValueError('short metadata read')
        return data
    sb = read(0)[1024:2048]
    incompat, ro = u32(sb, 96), u32(sb, 100)
    total = u32(sb, 4) | (u32(sb, 336) << 32 if incompat & 0x80 else 0)
    if (u16(sb, 56) != 0xef53 or u32(sb, 24) != 2 or u32(sb, 28) != 2 or
            u32(sb, 20) or u32(sb, 76) != 1 or
            total != partition_blocks or u16(sb, 58) != 1 or u32(sb, 232) or
            incompat & ~INCOMPAT_SUPPORTED or not incompat & 0x40 or
            ro & RO_UNSUPPORTED or not ro & (0x400|0x10) or
            u16(sb, 88) != 256 or u32(sb, 72)):
        raise ValueError('requires clean supported 4KiB ext4, no pending journal/orphans')
    metadata_csum = bool(ro & 0x400)
    seed = u32(sb, 624) if incompat & 0x2000 else crc32c(0xffffffff, sb[104:120])
    if metadata_csum and (sb[373] != 1 or u32(sb, 1020) != crc32c(0xffffffff, sb[:1020])):
        raise ValueError('invalid superblock checksum')
    inodes, per_group, bpg = u32(sb, 0), u32(sb, 40), u32(sb, 32)
    desc_size = u16(sb, 254) if incompat & 0x80 else 32
    if (not 0 < inode <= inodes or not 16 <= per_group <= 32768 or
            not 1024 <= bpg <= 32768 or bpg & (bpg-1) or u32(sb, 36) != bpg or
            desc_size not in (32, 64) or not any(sb[104:120])):
        raise ValueError('unsupported inode/group geometry')
    group, index = divmod(inode-1, per_group)
    descriptor_lba, descriptor_offset = divmod(group*desc_size, BLOCK)
    descriptor_lba += 1
    desc = read(descriptor_lba)[descriptor_offset:descriptor_offset+desc_size]
    number = struct.pack('<I', group)
    if metadata_csum:
        calculated = crc32c(crc32c(seed, number), desc[:30]+b'\0\0'+desc[32:]) & 0xffff
    else:
        calculated = crc16(crc16(crc16(0xffff, sb[104:120]), number), desc[:30]+desc[32:])
    if calculated != u16(desc, 30):
        raise ValueError('invalid inode group descriptor checksum')
    table = u32(desc, 8) | (u32(desc, 40) << 32 if desc_size == 64 else 0)
    inode_lba, inode_offset = divmod(index*256, BLOCK)
    inode_lba += table
    if not table or table >= partition_blocks:
        raise ValueError('invalid inode table')
    raw_inode = read(inode_lba)[inode_offset:inode_offset+256]
    file_bytes = u32(raw_inode, 4) | u32(raw_inode, 108) << 32
    allocated = u32(raw_inode, 28) | u16(raw_inode, 116) << 32
    if (u16(raw_inode, 0) != 0x8180 or u16(raw_inode, 2) or
            u16(raw_inode, 24) or u16(raw_inode, 120) or u16(raw_inode, 122) or
            u16(raw_inode, 26) != 1 or u32(raw_inode, 20) or
            u32(raw_inode, 32) != PINNED_FLAGS or u32(raw_inode, 104) or
            u16(raw_inode, 118) or not 0 < file_bytes <= 64 << 30 or
            file_bytes % BLOCK or allocated < file_bytes//512 or
            u16(raw_inode, 128) > 128 or u16(raw_inode, 128) % 4):
        raise ValueError('requires root-owned0600, single-link, immutable/noatime extent file')
    file_blocks = file_bytes//BLOCK
    file_seed = crc32c(crc32c(seed, struct.pack('<I', inode)), raw_inode[100:104])
    if metadata_csum:
        clean = bytearray(raw_inode)
        provided = u16(raw_inode, 124)
        clean[124:126] = b'\0\0'
        high = u16(raw_inode, 128) >= 4
        if high:
            provided |= u16(raw_inode, 130) << 16
            clean[130:132] = b'\0\0'
        calculated = crc32c(file_seed, clean)
        if not high:
            calculated &= 0xffff
        if provided != calculated:
            raise ValueError('invalid owned inode checksum')
    nodes, extents, used = [], [], set()
    def tree(data, depth, low, high):
        entries, maximum, actual_depth = u16(data, 2), u16(data, 4), u16(data, 6)
        if (u16(data, 0) != 0xf30a or actual_depth != depth or not entries or
                entries > maximum or maximum > (len(data)-12)//12):
            raise ValueError('invalid extent node header')
        for i in range(entries):
            entry = data[12+i*12:24+i*12]
            logical = u32(entry, 0)
            end = u32(data, 12+(i+1)*12) if i+1 < entries else high
            if not low <= logical < high or i == 0 and logical != low or end <= logical:
                raise ValueError('unordered or sparse extent tree')
            if depth:
                block = u32(entry, 4) | u16(entry, 8) << 32
                if u16(entry, 10) or block in used or block in (0, descriptor_lba, inode_lba):
                    raise ValueError('duplicate/aliased extent metadata')
                if len(nodes) == MAX_NODES:
                    raise ValueError('too many extent nodes')
                used.add(block)
                raw = read(block)
                if metadata_csum:
                    tail = 12+u16(raw, 4)*12
                    if tail > BLOCK-4 or u32(raw, tail) != crc32c(file_seed, raw[:tail]):
                        raise ValueError('invalid extent node checksum')
                nodes.append((block, raw))
                tree(raw, depth-1, logical, end)
            else:
                count = u16(entry, 4)
                physical = u16(entry, 6) << 32 | u32(entry, 8)
                if (not 0 < count <= 32768 or count != end-logical or
                        not 0 < physical < partition_blocks or
                        count > partition_blocks-physical or len(extents) == MAX_EXTENTS):
                    raise ValueError('unwritten, sparse, oversized or outside extent')
                extents.append((logical, physical, count))
    depth = u16(raw_inode, 46)
    if depth > 5:
        raise ValueError('extent tree depth exceeds bound')
    tree(raw_inode[40:100], depth, 0, file_blocks)
    metadata = {0, descriptor_lba, inode_lba} | used
    physical = sorted((p, p+n) for _, p, n in extents)
    if any(a[1] > b[0] for a, b in zip(physical, physical[1:])):
        raise ValueError('data extents overlap')
    if any(p <= m < p+n for _, p, n in extents for m in metadata):
        raise ValueError('file data aliases ownership metadata')
    def merge(rows):
        result = []
        for logical, physical, count in rows:
            if result and logical == result[-1][0]+result[-1][2] and physical == result[-1][1]+result[-1][2]:
                result[-1][2] += count
            else:
                result.append([logical, physical, count])
        return result
    if fiemap is not None:
        if (fiemap.get('file_bytes') != file_bytes or fiemap.get('inode') != inode or
                not fiemap.get('readonly_snapshot') or fiemap.get('raw_write_allowed') is not False):
            raise ValueError('wrong read-only FIEMAP identity')
        fm = [[e['logical']//BLOCK, e['physical']//BLOCK, e['length']//BLOCK]
              for e in fiemap['extents']]
        if any(e[k] % BLOCK for e in fiemap['extents'] for k in ('logical','physical','length')) or merge(extents) != merge(fm):
            raise ValueError('raw extent tree differs from independent FIEMAP')
    packet = bytearray(HEADER)
    packet[:8] = b'PROWN001'
    total_bytes = HEADER + len(nodes)*(BLOCK+8) + len(extents)*24
    struct.pack_into('<IIQQQIIQQIIIIQ', packet, 8, HEADER, total_bytes,
                     partition_start, partition_blocks, file_blocks, inode,
                     u32(raw_inode, 100), inode_lba, descriptor_lba,
                     descriptor_offset, inode_offset, len(nodes), len(extents), table)
    packet[88:104] = sb[104:120]
    struct.pack_into('<IIIIII', packet, 104, inodes, per_group, bpg,
                     desc_size, incompat, ro)
    packet[128:384] = raw_inode
    for block, data in nodes:
        packet.extend(struct.pack('<Q', block))
        packet.extend(data)
    for extent in extents:
        packet.extend(struct.pack('<QQQ', *extent))
    assert len(packet) == total_bytes
    return bytes(packet), dict(version=1, inventory_only=True, raw_write_allowed=False,
                              inode=inode, generation=u32(raw_inode, 100),
                              file_bytes=file_bytes, inode_lba=inode_lba,
                              descriptor_lba=descriptor_lba, extent_nodes=len(nodes),
                              extents=len(extents), independently_matched_FIEMAP=fiemap is not None,
                              packet_sha256=hashlib.sha256(packet).hexdigest())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True, type=Path)
    parser.add_argument('--inode', required=True, type=int)
    parser.add_argument('--partition-start', required=True, type=int)
    parser.add_argument('--fiemap', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    fd = os.open(args.image, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size % BLOCK:
            raise ValueError('existing ordinary aligned filesystem-image file required')
        packet, proof = snapshot(lambda block: os.pread(fd, BLOCK, block*BLOCK),
                                 args.partition_start, info.st_size//BLOCK, args.inode,
                                 json.loads(args.fiemap.read_text()) if args.fiemap else None)
    finally:
        os.close(fd)
    with args.output.open('xb') as output:
        output.write(packet)
    with args.output.with_suffix('.json').open('x') as output:
        json.dump(proof, output, indent=2)
        output.write('\n')
    print(json.dumps(proof, indent=2))


if __name__ == '__main__':
    main()
