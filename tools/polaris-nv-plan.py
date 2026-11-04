#!/usr/bin/env python3
"""Build a PRIVATE own-GPT identity plan, never NV content or device access.

Historical GPT bytes select expected identities only. The consumer must read
both GPT copies and two whole current NV passes on every physical boot.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import zlib


def sha(data):
    return hashlib.sha256(data).hexdigest()


def header(data, current, other, disk_bytes):
    if len(data) != 4096 or data[:8] != b'EFI PART':
        raise ValueError('GPT header size/magic')
    revision, size, crc, reserved = struct.unpack_from('<IIII', data, 8)
    if revision != 0x10000 or size != 92 or reserved:
        raise ValueError('GPT header ABI')
    checked = bytearray(data[:size]); checked[16:20] = bytes(4)
    if zlib.crc32(checked) != crc:
        raise ValueError('GPT header CRC')
    here, alternate, first, last = struct.unpack_from('<QQQQ', data, 24)
    lba, count, stride, table_crc = struct.unpack_from('<QIII', data, 72)
    if (here, alternate) != (current, other) or not 2 <= first <= last < disk_bytes // 4096 - 1:
        raise ValueError('GPT usable/header bounds')
    if not 1 <= count <= 512 or stride != 128 or count * stride % 4096:
        raise ValueError('GPT table ABI')
    length = count * stride
    if lba < 2 or lba + length // 4096 > disk_bytes // 4096 - 1:
        raise ValueError('GPT table bounds')
    return dict(lba=lba, count=count, bytes=length, crc=table_crc, first=first, last=last)


def build(backup, out):
    layout = json.loads((backup / 'layout.json').read_text())
    manifest = {x['file']: x for x in json.loads((backup / 'manifest.json').read_text())}
    disks, rows, hashes = [], {}, {}
    fixture = {}
    for index, disk in enumerate(('sde', 'sdf')):
        desc = layout[disk]; disk_bytes = desc['disk_bytes']
        if desc['block_size'] != 4096 or not desc['both_gpt_copies_valid'] or disk_bytes % 4096:
            raise ValueError('own disk geometry')
        pieces = []
        for suffix in ('head', 'tail'):
            name = f'{disk}.{suffix}.bin'; data = (backup / name).read_bytes()
            if len(data) != manifest[name]['bytes'] or sha(data) != manifest[name]['sha256']:
                raise ValueError('backup manifest mismatch')
            hashes[name] = sha(data); pieces.append(data)
        head, tail = pieces; blocks = disk_bytes // 4096
        headers = [head[4096:8192], tail[-4096:]]
        a = header(headers[0], 1, blocks - 1, disk_bytes)
        b = header(headers[1], blocks - 1, 1, disk_bytes)
        if headers[0][40:72] != headers[1][40:72] or a['count'] != b['count'] or a['crc'] != b['crc']:
            raise ValueError('GPT copies disagree')
        table = head[a['lba'] * 4096:a['lba'] * 4096 + a['bytes']]
        at = b['lba'] * 4096 - (disk_bytes - len(tail))
        if at < 0 or table != tail[at:at + b['bytes']] or len(table) != a['bytes'] or zlib.crc32(table) != a['crc']:
            raise ValueError('GPT tables/CRC disagree')
        for number in range(a['count']):
            entry = table[number * 128:(number + 1) * 128]
            if not any(entry[:16]):
                continue
            name = entry[56:128].decode('utf-16le').split('\0')[0]
            if name not in ('modemst1', 'modemst2', 'fsg', 'fsc'):
                continue
            if name in rows or not any(entry[16:32]):
                raise ValueError('ambiguous NV partition')
            first, last = struct.unpack_from('<QQ', entry, 32)
            if not a['first'] <= first <= last <= a['last']:
                raise ValueError('NV partition bounds')
            rows[name] = dict(start=first, blocks=last - first + 1, disk=index, number=number + 1, guid=entry[16:32].hex())
        disks.append(dict(blocks=blocks, table_lba=[a['lba'], b['lba']], table_bytes=a['bytes'],
                          header_hash=[sha(x) for x in headers], table_hash=sha(table)))
        fixture[f'gpt{index}-primary.bin'] = headers[0]
        fixture[f'gpt{index}-backup.bin'] = headers[1]
        fixture[f'gpt{index}-table.bin'] = table
    ordered = [rows[name] for name in ('modemst1', 'modemst2', 'fsg', 'fsc')]
    if [x['blocks'] * 4096 for x in ordered] != [0x800000, 0x800000, 0x800000, 0x40000]:
        raise ValueError('own full NV sizes')
    def wire(value):
        return '{' + ','.join('0x' + value[n:n + 2] for n in range(0, len(value), 2)) + '}'
    lines = ['/* PRIVATE generated device identities; do not commit. */', 'static const struct pnv_plan polaris_nv_plan={.disk={']
    for d in disks:
        lines.append('{.blocks=%d,.table_lba={%d,%d},.table_bytes=%d,.header_hash={%s,%s},.table_hash=%s},' %
                     (d['blocks'], *d['table_lba'], d['table_bytes'], *[wire(h) for h in d['header_hash']], wire(d['table_hash'])))
    lines.append('},.part={')
    for p in ordered:
        lines.append('{.start=%d,.blocks=%d,.disk=%d,.number=%d,.guid=%s},' %
                     (p['start'], p['blocks'], p['disk'], p['number'], wire(p['guid'])))
    lines.append('}};')
    out.mkdir(parents=True, exist_ok=False)
    (out / 'own-nv-plan.h').write_text('\n'.join(lines) + '\n')
    (out / 'plan.json').write_text(json.dumps(dict(disks=disks, parts=ordered, source_sha256=hashes,
        current_NV=False, physical_reads=False, fixture='historical GPT identity only'), indent=2) + '\n')
    for name, data in fixture.items():
        (out / name).write_bytes(data)
    print('Generated private plan: 2 GPTs, 4 NV identities; no NV contents, device access or current-NV claim')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('backup', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    build(args.backup, args.output)
