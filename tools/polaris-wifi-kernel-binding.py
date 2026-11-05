#!/usr/bin/env python3
"""Locate the actual file-backed resident Wi-Fi page in a linked ARM64 kernel.

This proves a storage location, not firmware readiness or boot admission. No
device command is issued. The complete builder must also exclude other live
channels and bind this exact kernel into its payload before using the offset.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

NAME = b'_polaris_wifi_mailbox_page'
BYTES = 16384
INITIAL = b'PW' + bytes(BYTES - 2)


def layout(raw):
    if len(raw) < 32 or raw[:4] != b'\xcf\xfa\xed\xfe':
        raise ValueError('requires kernel Mach-O')
    count, command_bytes = struct.unpack_from('<II', raw, 16)
    if count > 4096 or command_bytes > len(raw)-32:
        raise ValueError('layout command bounds')
    at, segments, bases = 32, [], []
    for _ in range(count):
        if at+8 > 32+command_bytes:
            raise ValueError('layout command truncated')
        kind, size = struct.unpack_from('<II', raw, at)
        if size < 8 or size > 32+command_bytes-at:
            raise ValueError('layout command size')
        if kind == 0x19:
            if size < 72:
                raise ValueError('layout segment truncated')
            vm, memory = struct.unpack_from('<QQ', raw, at+24)
            segments.append(vm+memory)
            if raw[at+8:at+24].rstrip(b'\0') == b'__TEXT':
                bases.append(vm)
        at += size
    if len(bases) != 1 or not segments:
        raise ValueError('requires one kernel TEXT base')
    return bases[0], max(segments)-bases[0]


def binding(raw, base, span, other_spans=()):
    if len(raw) < 32:
        raise ValueError('truncated kernel')
    magic, cpu, _, filetype, count, command_bytes, _, _ = struct.unpack_from('<8I', raw)
    if magic != 0xfeedfacf or cpu != 0x100000c or filetype != 2:
        raise ValueError('requires linked ARM64 Mach-O executable')
    if not 0 < count <= 4096 or command_bytes > len(raw) - 32:
        raise ValueError('load command bounds')
    if not 0 < base < 1 << 64 or not 0 < span <= (1 << 64) - base:
        raise ValueError('kernel ownership bounds')
    sections, segments, tables = [], [], []
    at, end = 32, 32 + command_bytes
    for _ in range(count):
        if end - at < 8:
            raise ValueError('truncated command')
        kind, size = struct.unpack_from('<II', raw, at)
        if size < 8 or size % 8 or size > end - at:
            raise ValueError('invalid command size')
        if kind == 0x19:
            if size < 72:
                raise ValueError('truncated segment')
            name = raw[at+8:at+24].rstrip(b'\0')
            vm, memory, source, stored, maximum, protection, n, _ = struct.unpack_from('<4Q4I', raw, at+24)
            if (vm + memory > 1 << 64 or source > len(raw) or stored > len(raw)-source or
                    size != 72+80*n or protection & ~maximum):
                raise ValueError('invalid segment bounds')
            segments.append((vm, memory, source, stored))
            for i in range(n):
                off = at+72+80*i
                section = raw[off:off+16].rstrip(b'\0')
                owner = raw[off+16:off+32].rstrip(b'\0')
                address, length, fileoff, align = struct.unpack_from('<QQII', raw, off+32)
                flags = struct.unpack_from('<I', raw, off+64)[0]
                sections.append(dict(segment=name, section=section, owner=owner, address=address,
                    length=length, fileoff=fileoff, align=align, flags=flags,
                    vm=vm, memory=memory, source=source, stored=stored, protection=protection))
        elif kind == 2:
            if size != 24:
                raise ValueError('invalid symbol command')
            tables.append(struct.unpack_from('<4I', raw, at+8))
        at += size
    if at != end or len(tables) != 1:
        raise ValueError('requires exact commands and one symbol table')
    off, number, strings, string_bytes = tables[0]
    if off > len(raw) or number > (len(raw)-off)//16 or strings > len(raw) or string_bytes > len(raw)-strings:
        raise ValueError('symbol table outside file')
    found = []
    for i in range(number):
        name, kind, section, _, value = struct.unpack_from('<IBBHQ', raw, off+16*i)
        if kind & 0xe0:
            continue
        if name >= string_bytes:
            raise ValueError('symbol name outside strings')
        stop = raw.find(b'\0', strings+name, strings+string_bytes)
        if stop < 0:
            raise ValueError('unterminated symbol name')
        if raw[strings+name:stop] == NAME:
            if kind != 0x0f or not 0 < section <= len(sections):
                raise ValueError('mailbox must be a defined external section symbol')
            found.append((value, section))
    if len(found) != 1:
        raise ValueError('requires exactly one mailbox symbol')
    address, index = found[0]
    offset = address - base
    if address % BYTES or offset % BYTES or not 0 <= offset <= span-BYTES:
        raise ValueError('mailbox page alignment or kernel ownership')
    for start, length in other_spans:
        if start < 0 or length <= 0 or start > span-length:
            raise ValueError('invalid excluded channel span')
        if offset < start+length and start < offset+BYTES:
            raise ValueError('mailbox overlaps another live channel')
    s = sections[index-1]
    if (s['segment'] != b'__DATA' or s['owner'] != b'__DATA' or s['section'] != b'__data' or
            s['flags'] & 0xff or s['protection'] != 3 or s['stored'] > s['memory'] or
            not s['vm'] <= s['address'] <= address or
            s['length'] > s['memory']-(s['address']-s['vm']) or
            s['length'] > s['stored']-(s['address']-s['vm']) or
            not 0 <= address-s['address'] <= s['length']-BYTES or
            s['fileoff'] != s['source']+s['address']-s['vm']):
        raise ValueError('mailbox is not writable file-backed DATA in its actual symbol section')
    for i, other in enumerate(sections):
        if i != index-1 and address < other['address']+other['length'] and other['address'] < address+BYTES:
            raise ValueError('ambiguous overlapping kernel sections')
    containing = [v for v in segments if address < v[0]+v[1] and v[0] < address+BYTES]
    if len(containing) != 1:
        raise ValueError('ambiguous overlapping kernel segments')
    source = s['fileoff']+address-s['address']
    if source > len(raw) or BYTES > len(raw)-source or raw[source:source+BYTES] != INITIAL:
        raise ValueError('mailbox native initializer differs or is truncated')
    return dict(symbol=NAME.decode(), offset=offset, bytes=BYTES, alignment=BYTES,
        segment='__DATA', section='__data', file_offset=source, BSS=False,
        kernel_sha256=hashlib.sha256(raw).hexdigest(),
        initial_sha256=hashlib.sha256(INITIAL).hexdigest(), boot_admission=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kernel', type=Path)
    parser.add_argument('--base', type=lambda x: int(x, 0))
    parser.add_argument('--span', type=lambda x: int(x, 0))
    args = parser.parse_args()
    raw = args.kernel.read_bytes()
    if (args.base is None) != (args.span is None):
        parser.error('provide both base and span, or use actual kernel layout')
    base, span = layout(raw) if args.base is None else (args.base, args.span)
    print(json.dumps(binding(raw, base, span), indent=2))


if __name__ == '__main__':
    main()
