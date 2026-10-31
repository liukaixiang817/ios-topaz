#!/usr/bin/env python3
"""Bind original81 Polaris NpaDxe immutable spans; emits hashes/RVAs only."""
from pathlib import Path
import argparse
import hashlib
import json
import struct

EXPECTED = '0e4a6ce1eb72400ab70e281eea1f478ca3a35b209d3ff7ee75d10e680354b715'

def binding(path):
    raw = path.read_bytes()
    if len(raw) != 0x12000 or hashlib.sha256(raw).hexdigest() != EXPECTED:
        raise ValueError('requires exact own original NpaDxe/73728B')
    pe = struct.unpack_from('<I', raw, 60)[0]
    opt = pe + 24
    if raw[pe:pe+4] != b'PE\0\0' or struct.unpack_from('<H', raw, pe+4)[0] != 0xaa64:
        raise ValueError('original AArch64 PE required')
    if struct.unpack_from('<H', raw, opt)[0] != 0x20b:
        raise ValueError('original PE32+ required')
    base = struct.unpack_from('<Q', raw, opt+24)[0]
    size, headers = struct.unpack_from('<II', raw, opt+56)
    if (base, size, headers) != (0, 0x12000, 0x1000):
        raise ValueError('original NPA geometry')
    sections = []
    image = bytearray(size)
    image[:headers] = raw[:headers]
    for i in range(struct.unpack_from('<H', raw, pe+6)[0]):
        at = opt + struct.unpack_from('<H', raw, pe+20)[0] + 40*i
        virtual, rva, n, offset = struct.unpack_from('<IIII', raw, at+8)
        name = raw[at:at+8].rstrip(b'\0').decode()
        if rva > size or n > size-rva or offset > len(raw) or n > len(raw)-offset:
            raise ValueError('original section bounds')
        sections.append((name, rva, n))
        image[rva:rva+n] = raw[offset:offset+n]
    if sections != [('.text', 0x1000, 0xf000), ('.data', 0x10000, 0x1000), ('.reloc', 0x11000, 0x1000)]:
        raise ValueError('original NPA sections')
    at, n = struct.unpack_from('<II', raw, opt+112+5*8)
    end = at+n
    if at != 0x11000 or end > size:
        raise ValueError('original relocation directory')
    relocs = []
    while at+8 <= end:
        page, block = struct.unpack_from('<II', image, at)
        if not block:
            break
        if block < 8 or block % 2 or at+block > end:
            raise ValueError('relocation block')
        for entry in struct.unpack_from('<'+'H'*((block-8)//2), image, at+8):
            kind, slot = entry >> 12, page+(entry & 4095)
            if kind:
                if kind != 10 or slot > size-8:
                    raise ValueError('original DIR64 required')
                relocs.append(slot)
        at += block
    relocs.sort()
    if any(b < a+8 for a,b in zip(relocs, relocs[1:])):
        raise ValueError('overlapping relocation')
    ranges = [(0, 0x1000), (0x1000, 0xf000), (0x10060, 16), (0x100b0, 0x1b0), (0x11000, 0x1000)]
    spans = [dict(rva=a, bytes=n, sha256=hashlib.sha256(image[a:a+n]).hexdigest()) for a,n in ranges]
    lines = ['/* Original NpaDxe digest/RVA binding; no firmware bytes. */',
             '#ifndef POLARIS_WIFI_NPA_BINDING_H', '#define POLARIS_WIFI_NPA_BINDING_H',
             f'#define PWNPI_SOURCE_SHA256 "{EXPECTED}"', f'#define PWNPI_IMAGEBASE_RVA {opt+24}u',
             '#define PWNPI_IMAGE_BYTES 0x12000u', '#define PWNPI_RANGE_COUNT 5u',
             f'#define PWNPI_RELOC_COUNT {len(relocs)}u',
             'static const uint32_t pwnpi_relocs[PWNPI_RELOC_COUNT]={'+','.join(hex(x) for x in relocs)+'};',
             'static const struct pwnpi_span pwnpi_spans[PWNPI_RANGE_COUNT]={']
    for s in spans:
        digest = ','.join('0x'+s['sha256'][i:i+2] for i in range(0,64,2))
        lines.append(f'{{{s["rva"]}u,{s["bytes"]}u,{{{digest}}}}},')
    lines += ['};', '#endif', '']
    return '\n'.join(lines), dict(source_whole_sha256=EXPECTED, source_bytes=len(raw),
        immutable_spans=spans, relocations=relocs, protocol_rva=0x100b0,
        list_head_rva=0x108b0, protocol_revision=0x10002, firmware_executed=False)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--original-pe', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    header, proof = binding(a.original_pe)
    (a.out/'uefi-wifi-npa-binding.h').write_text(header)
    proof['binding_sha256'] = hashlib.sha256(header.encode()).hexdigest()
    (a.out/'binding.json').write_text(json.dumps(proof, indent=2)+'\n')
    print(json.dumps(dict(source=EXPECTED, immutable_spans=len(proof['immutable_spans']), firmware_executed=False)))

if __name__ == '__main__':
    main()
