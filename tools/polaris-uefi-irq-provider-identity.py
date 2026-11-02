"""Digest/RVA-only bindings for the three exact original Polaris providers.

No proprietary PE bytes enter the generated header. Mutable driver globals and
the CPU exception stack are excluded from immutable spans and sampled as RAM
separately by the caller. This never executes firmware or admits a device.
"""
from pathlib import Path
import hashlib
import struct

SOURCES = (
    ('Timer', '49ea041e-6752-42ca-b0b1-7344fe2546b7.efi', 16384,
     'efbe4f1a52392752ea42decdcdcda9b8077330e67123b94f57b70344223a3052',
     ((0, 4096), (4096, 4096), (0x2000, 0x58), (0x20a8, 0xf58), (0x3000, 4096)), 0x2038, 32, 0x2058, 80),
    ('GIC', 'de371f7c-dec4-4d21-adf1-593abcc15882.efi', 20480,
     'add88fe4fd7156fcc720f2ea3515cd92595508e8d22cc1b79de2d75ae3b19d53',
     ((0, 4096), (4096, 8192), (0x3000, 0x108), (0x3170, 0xe90), (0x4000, 4096)), 0, 40, 0x3108, 104),
    ('CPU', 'b8d9777e-d72a-451f-9bdb-bafb52a68415.efi', 36864,
     '311318e64550b590592a1c2914ec5c0d382340459e5d342b746d4981e8ec48e0',
     ((0, 4096), (4096, 16384), (0x5000, 0x420), (0x8000, 4096)), 0x53d8, 72, 0x5420, 80),
)


def binding(directory: Path):
    declarations, entries, metadata = [], [], []
    for index, (name, filename, size, expected, spans, table, table_bytes, state, state_bytes) in enumerate(SOURCES):
        image = (directory / filename).read_bytes()
        if len(image) != size or hashlib.sha256(image).hexdigest() != expected:
            raise ValueError('not the exact original ' + name + ' provider')
        pe = struct.unpack_from('<I', image, 60)[0]
        optional = pe + 24
        if image[pe:pe + 4] != b'PE\0\0' or struct.unpack_from('<H', image, pe + 4)[0] != 0xaa64:
            raise ValueError('not original AArch64 PE')
        if struct.unpack_from('<Q', image, optional + 24)[0] or struct.unpack_from('<II', image, optional + 56) != (size, 4096):
            raise ValueError('unexpected original provider geometry')
        sections = pe + 24 + struct.unpack_from('<H', image, pe + 20)[0]
        for i in range(struct.unpack_from('<H', image, pe + 6)[0]):
            _, rva, raw_bytes, raw_offset = struct.unpack_from('<4I', image, sections + 40 * i + 8)
            if rva != raw_offset or raw_offset + raw_bytes > size:
                raise ValueError('provider file/RAM layout differs')
        at, count = struct.unpack_from('<II', image, optional + 112 + 5 * 8)
        end, relocations = at + count, []
        while at + 8 <= end:
            page, length = struct.unpack_from('<II', image, at)
            if not length:
                break
            if length < 8 or length % 2 or at + length > end:
                raise ValueError('bad original relocation block')
            for word in struct.unpack_from('<' + 'H' * ((length - 8) // 2), image, at + 8):
                if word >> 12:
                    if word >> 12 != 10 or page + (word & 4095) + 8 > size:
                        raise ValueError('unsupported original relocation')
                    relocations.append(page + (word & 4095))
            at += length
        relocations.sort()
        if not relocations or len(set(relocations)) != len(relocations) or any(b < a + 8 for a, b in zip(relocations, relocations[1:])):
            raise ValueError('overlapping original relocations')
        declarations.append('static const uint32_t pwmc_irq_reloc_' + str(index) + '[]={' + ','.join(hex(x) for x in relocations) + '};')
        ranges = []
        for start, length in spans:
            digest = hashlib.sha256(image[start:start + length]).digest()
            ranges.append('{' + f'{start}u,{length}u,' + '{' + ','.join(hex(x) for x in digest) + '}}')
        entries.append('{' + ','.join([str(size)+'u', str(optional+24)+'u', str(table)+'u', str(table_bytes)+'u', str(state)+'u', str(state_bytes)+'u', str(len(spans))+'u', str(len(relocations))+'u', 'pwmc_irq_reloc_'+str(index), '{'+','.join(ranges)+'}']) + '}')
        metadata.append(dict(name=name, file=filename, whole_SHA256=expected, bytes=size,
                             immutable_spans=spans, relocations=relocations, table_RVA=table,
                             table_bytes=table_bytes, state_RVA=state, state_bytes=state_bytes,
                             original_firmware_executed=False))
    header = '\n'.join(['#ifndef POLARIS_IRQ_PROVIDER_BINDING_H', '#define POLARIS_IRQ_PROVIDER_BINDING_H',
                        *declarations, 'static const struct pwmc_irq_binding pwmc_irq_bindings[3]={' + ',\n'.join(entries) + '};', '#endif', ''])
    return header, metadata
