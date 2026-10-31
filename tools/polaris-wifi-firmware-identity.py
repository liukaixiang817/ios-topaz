#!/usr/bin/env python3
"""Generate digest-only binding for the exact backed-up Polaris SmemDxe.

Never executes the original image. Output goes to an ignored build directory,
and contains SHA256/ranges/relocation RVAs, never original firmware bytes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

EXPECTED = "9e366873287fbde6452bb8990ee233f7e53513454befb48df01378d88a072ea8"


def binding(source):
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != EXPECTED:
        raise ValueError("requires exact own original SmemDxe whole SHA256")
    pe = struct.unpack_from("<I", raw, 0x3C)[0]
    opt = pe + 24
    if raw[pe:pe + 4] != b"PE\0\0" or struct.unpack_from("<H", raw, pe + 4)[0] != 0xAA64:
        raise ValueError("original AArch64 PE identity")
    if struct.unpack_from("<H", raw, opt)[0] != 0x20B:
        raise ValueError("requires PE32+")
    base = struct.unpack_from("<Q", raw, opt + 24)[0]
    size, headers = struct.unpack_from("<II", raw, opt + 56)
    if (base, size, headers) != (0, 0x9000, 0x1000):
        raise ValueError("original image geometry")
    count, optional = struct.unpack_from("<H", raw, pe + 6)[0], struct.unpack_from("<H", raw, pe + 20)[0]
    image = bytearray(size)
    image[:headers] = raw[:headers]
    sections = []
    for n in range(count):
        at = opt + optional + 40 * n
        virtual, rva, length, offset = struct.unpack_from("<IIII", raw, at + 8)
        name = raw[at:at + 8].rstrip(b"\0").decode()
        if rva > size or length > size-rva or offset > len(raw) or length > len(raw)-offset:
            raise ValueError("section bounds")
        image[rva:rva + length] = raw[offset:offset + length]
        sections.append(dict(name=name, rva=rva, bytes=length, file=offset, virtual=virtual))
    if [(s["name"], s["rva"], s["bytes"]) for s in sections] != [
            (".text", 0x1000, 0x6000), (".data", 0x7000, 0x1000), (".reloc", 0x8000, 0x1000)]:
        raise ValueError("original section layout")
    at, length = struct.unpack_from("<II", raw, opt + 112 + 5*8)
    end = at + length
    relocations = []
    while at + 8 <= end:
        page, block = struct.unpack_from("<II", image, at)
        if not block:
            break
        if block < 8 or block % 2 or at + block > end:
            raise ValueError("relocation block")
        for entry in struct.unpack_from("<" + "H" * ((block-8)//2), image, at+8):
            kind = entry >> 12
            if kind:
                slot = page + (entry & 4095)
                if kind != 10 or slot > size-8:
                    raise ValueError("requires original DIR64 entries")
                relocations.append(slot)
        at += block
    relocations.sort()
    if len(relocations) != 63 or len(set(relocations)) != 63 or any(
            b < a+8 for a, b in zip(relocations, relocations[1:])):
        raise ValueError("exact nonoverlapping63 DIR64 relocations")
    if any(0x7118 <= a < 0x7390 for a in relocations) or any(image[0x7118:0x7390]):
        raise ValueError("original zero constructor cache")
    # .text includes code and literal/constant data. Writable data after0x70b8
    # cannot match a file after constructors, and is never represented as such.
    ranges = [(0, 0x1000), (0x1000, 0x6000), (0x7008, 0xB0), (0x8000, 0x1000)]
    spans = [dict(rva=a, bytes=n, sha256=hashlib.sha256(image[a:a+n]).hexdigest()) for a, n in ranges]
    out = ["/* PRIVATE generated original-firmware digest binding; no firmware bytes. */",
           "#ifndef POLARIS_UEFI_WIFI_CACHE_BINDING_H", "#define POLARIS_UEFI_WIFI_CACHE_BINDING_H",
           f'#define PWFI_SOURCE_SHA256 "{EXPECTED}"', "#define PWFI_IMAGE_BYTES UINT64_C(0x9000)",
           "#define PWFI_ORIGINAL_BASE UINT64_C(0)", f"#define PWFI_IMAGEBASE_RVA {opt+24}u",
           "#define PWFI_RELOC_COUNT 63u", "#define PWFI_RANGE_COUNT 4u",
           "static const uint32_t pwfi_relocations[PWFI_RELOC_COUNT]={" + ",".join(hex(x) for x in relocations) + "};",
           "static const struct pwfi_range pwfi_ranges[PWFI_RANGE_COUNT]={"]
    for s in spans:
        digest = ",".join("0x" + s["sha256"][i:i+2] for i in range(0, 64, 2))
        out.append(f'    {{{s["rva"]}u,{s["bytes"]}u,{{{digest}}}}},')
    out += ["};", "#endif", ""]
    return "\n".join(out), dict(source_whole_sha256=EXPECTED, source_bytes=len(raw),
                                    sections=sections, relocations=relocations, immutable_ranges=spans,
                                    mutable_cache=dict(rva=0x7118, bytes=632), firmware_executed=False)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--original-smem-pe", required=True, type=Path)
    p.add_argument("--out-dir", required=True, type=Path)
    a = p.parse_args()
    a.out_dir.mkdir(parents=True, exist_ok=True)
    header, proof = binding(a.original_smem_pe)
    target = a.out_dir / "uefi-wifi-cache-binding.h"
    if target.exists() and target.read_text() != header:
        raise ValueError("refuse changing an existing frozen binding")
    target.write_text(header)
    proof["binding_sha256"] = hashlib.sha256(header.encode()).hexdigest()
    (a.out_dir / "wifi-cache-binding.json").write_text(json.dumps(proof, indent=2) + "\n")
    print(json.dumps({k:proof[k] for k in ("source_whole_sha256", "binding_sha256", "firmware_executed")}))


if __name__ == "__main__":
    main()
