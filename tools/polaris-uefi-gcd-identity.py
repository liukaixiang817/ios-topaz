"""Digest-only binding for the exact original registered DxeCore query provider."""
from pathlib import Path
import hashlib, struct

def binding(p: Path):
    b = p.read_bytes()
    if not (len(b) == 233472 and hashlib.sha256(b).hexdigest() == '61236b079f66c1340bfb3e9e15e055ecfe9bdfa2e7eabed157832147bc8f3609'):
        raise ValueError('not the exact original AArch64 DxeCore identity/layout')
    pe = struct.unpack_from('<I', b, 60)[0]
    op = pe + 24
    if not (struct.unpack_from('<HH', b, pe + 4) == (43620, 3) and struct.unpack_from('<Q', b, op + 24)[0] == 0 and (struct.unpack_from('<II', b, op + 56) == (233472, 4096))):
        raise ValueError('not the exact original AArch64 DxeCore identity/layout')
    if not (b[113432:113440] == b'DXE_SERV' and struct.unpack_from('<II', b, 113440) == (65606, 168) and (struct.unpack_from('<Q', b, 113432 + 56)[0] == 11368)):
        raise ValueError('not the exact original AArch64 DxeCore identity/layout')
    if not b[110848:110864] == bytes.fromhex('ba34ad05026f1442952e4da0398e2bb9'):
        raise ValueError('not the exact original AArch64 DxeCore identity/layout')
    at, n = struct.unpack_from('<II', b, op + 112 + 5 * 8)
    end = at + n
    rel = []
    while at + 8 <= end:
        page, z = struct.unpack_from('<II', b, at)
        if not z:
            break
        if not (z >= 8 and z % 2 == 0 and (at + z <= end)):
            raise ValueError('not the exact original AArch64 DxeCore identity/layout')
        for word in struct.unpack_from('<' + 'H' * ((z - 8) // 2), b, at + 8):
            if word >> 12:
                if not word >> 12 == 10:
                    raise ValueError('not the exact original AArch64 DxeCore identity/layout')
                rel.append(page + (word & 4095))
        at += z
    rel.sort()
    if not (len(set(rel)) == len(rel) and all((y >= x + 8 for x, y in zip(rel, rel[1:])))):
        raise ValueError('not the exact original AArch64 DxeCore identity/layout')
    ranges = [(0, 4096), (4096, 106496), (110848, 16), (113432, 168), (229376, 4096)]
    out = ['#ifndef PGCD_ORIGINAL_CORE_BINDING_H', '#define PGCD_ORIGINAL_CORE_BINDING_H', '#define PGCI_IMAGE_BYTES 233472u', '#define PGCI_ORIGINAL_BASE UINT64_C(0)', f'#define PGCI_IMAGEBASE_RVA {op + 24}u', f'#define PGCI_RELOC_COUNT {len(rel)}u', '#define PGCI_RANGE_COUNT 5u', 'static const uint32_t pgci_relocations[PGCI_RELOC_COUNT]={' + ','.join((hex(x) for x in rel)) + '};', 'static const struct pgci_range pgci_ranges[PGCI_RANGE_COUNT]={']
    spans = []
    for a, z in ranges:
        h = hashlib.sha256(b[a:a + z]).digest()
        out.append('    {' + str(a) + 'u,' + str(z) + 'u,{' + ','.join(('0x' + format(x, '02x') for x in h)) + '}},')
        spans.append(dict(rva=a, bytes=z, sha256=h.hex()))
    out += ['};', '#endif', '']
    header = '\n'.join(out)
    meta = dict(original_PE_name=p.name, whole_SHA256=hashlib.sha256(b).hexdigest(), image_bytes=233472, DS_RVA=113432, BS_RVA=112640, DS_GetMemorySpaceDescriptor_RVA=11368, BS_GetMemoryMap_RVA=54252, CurrentTPL_RVA=110744, GCD_memory_lock_RVA=113992, registered_DS_GUID_RVA=110848, ranges=spans, relocations=rel, DS_CRC32_normalized_only_after_zero_or_valid_CRC_check=True, firmware_executed=False)
    return (header, meta)
