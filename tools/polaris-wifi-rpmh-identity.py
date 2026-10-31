#!/usr/bin/env python3
"""Bind original81 Polaris RpmhDxe immutable spans; emits hashes/RVAs only."""
from pathlib import Path
import argparse
import hashlib
import json
import struct

EXPECTED = 'b718efb605db2c1d7be3b5e84d13adb148e24eebae66496e9569cfe9b34bfdc5'

def binding(path):
    raw = path.read_bytes()
    if len(raw) != 0xf000 or hashlib.sha256(raw).hexdigest() != EXPECTED:
        raise ValueError('requires exact own original RpmhDxe/61440B')
    pe = struct.unpack_from('<I', raw, 60)[0]
    opt = pe + 24
    if raw[pe:pe+4] != b'PE\0\0' or struct.unpack_from('<H', raw, pe+4)[0] != 0xaa64:
        raise ValueError('original AArch64 PE required')
    if struct.unpack_from('<H', raw, opt)[0] != 0x20b:
        raise ValueError('original PE32+ required')
    base = struct.unpack_from('<Q', raw, opt+24)[0]
    size, headers = struct.unpack_from('<II', raw, opt+56)
    if (base, size, headers) != (0, 0xf000, 0x1000):
        raise ValueError('original RPMh geometry')
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
    if sections != [('.text', 0x1000, 0xc000), ('.data', 0xd000, 0x1000), ('.reloc', 0xe000, 0x1000)]:
        raise ValueError('original RPMh sections')
    at, n = struct.unpack_from('<II', raw, opt+112+5*8)
    end = at+n
    if at != 0xe000 or end > size:
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
    ranges = [(0, 0x1000), (0x1000, 0xc000), (0xd078, 16), (0xd0d8, 0xc8), (0xe000, 0x1000)]
    spans = [dict(rva=a, bytes=n, sha256=hashlib.sha256(image[a:a+n]).hexdigest()) for a,n in ranges]
    lines = ['/* Original RpmhDxe digest/RVA binding; no firmware bytes. */',
             '#ifndef POLARIS_WIFI_RPMh_BINDING_H', '#define POLARIS_WIFI_RPMh_BINDING_H',
             f'#define PWRPI_SOURCE_SHA256 "{EXPECTED}"', f'#define PWRPI_IMAGEBASE_RVA {opt+24}u',
             '#define PWRPI_IMAGE_BYTES 0xf000u', '#define PWRPI_RANGE_COUNT 5u',
             f'#define PWRPI_RELOC_COUNT {len(relocs)}u',
             'static const uint32_t pwrpi_relocs[PWRPI_RELOC_COUNT]={'+','.join(hex(x) for x in relocs)+'};',
             'static const struct pwrpi_span pwrpi_spans[PWRPI_RANGE_COUNT]={']
    for s in spans:
        digest = ','.join('0x'+s['sha256'][i:i+2] for i in range(0,64,2))
        lines.append(f'{{{s["rva"]}u,{s["bytes"]}u,{{{digest}}}}},')
    lines += ['};', '#endif', '']
    return '\n'.join(lines), dict(source_whole_sha256=EXPECTED, source_bytes=len(raw),
        immutable_spans=spans, relocations=relocs, protocol_rva=0xd0d8,
        config_pointer_rva=0xb100, initialized_rva=0xd2e8, protocol_revision=0x10001, firmware_executed=False)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--original-pe', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    header, proof = binding(a.original_pe)
    (a.out/'uefi-wifi-rpmh-binding.h').write_text(header)
    proof['binding_sha256'] = hashlib.sha256(header.encode()).hexdigest()
    (a.out/'binding.json').write_text(json.dumps(proof, indent=2)+'\n')
    print(json.dumps(dict(source=EXPECTED, immutable_spans=len(proof['immutable_spans']), firmware_executed=False)))

if __name__ == '__main__':
    main()
