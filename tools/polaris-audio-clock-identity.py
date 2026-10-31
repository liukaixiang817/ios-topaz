#!/usr/bin/env python3
"""Bind the exact saved Polaris ClockDxe; emit digests/RVAs, no firmware bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

EXPECTED = "b9e618d63edbe81e4e3f04b1d7a51e21584e113d2dd79320ba6a90d2c63377ed"
TARGETS = [
    ("gcc_qupv3_wrap0_s5_clk",0x2d248,0x126e7,0x117620,0x15200c,0x8000,True),
    ("gcc_qupv3_wrap_0_m_ahb_clk",0x2b148,0x125ee,0x117004,0x15200c,0x40,True),
    ("gcc_qupv3_wrap_0_s_ahb_clk",0x2ba48,0x125d3,0x117008,0x15200c,0x80,True),
    ("gcc_camera_ahb_clk",0x2b628,0x149f5,0x10b008,0,0,True),
    ("gcc_camera_xo_clk",0x2eaa8,0x12d3b,0x10b02c,0,0,True),
    ("gcc_mss_cfg_ahb_clk",0x2b7a8,0x14a3d,0x18a000,0,0,True),
    ("gcc_mss_snoc_axi_clk",0x2b088,0x1496a,0x18a150,0,0,True),
    ("gcc_mss_q6_memnoc_axi_clk",0x2c708,0x14c2d,0x18a154,0,0,True),
    ("cam_cc_cci_clk",0x283e8,0x144eb,0xad0b0f0,0,0,False),
    ("cam_cc_mclk0_clk",0x291c8,0x146f8,0xad0401c,0,0,False),
    ("cam_cc_mclk2_clk",0x29288,0x1471a,0xad0405c,0,0,False),
    ("cam_cc_mclk3_clk",0x292e8,0x1472b,0xad0407c,0,0,False),
    ("cam_cc_camnoc_axi_clk",0x2c288,0x12986,0xad0b124,0,0,False),
    ("cam_cc_cpas_ahb_clk",0x29408,0x1474f,0xad0b11c,0,0,False),
    ("cam_cc_soc_ahb_clk",0x2b4a8,0x149b3,0xad0b13c,0,0,False),
]


def binding(path):
    raw = path.read_bytes()
    if len(raw) != 266240 or hashlib.sha256(raw).hexdigest() != EXPECTED:
        raise ValueError("requires exact own original ClockDxe whole SHA256/266240B")
    pe = struct.unpack_from("<I", raw, 0x3c)[0]
    opt = pe + 24
    if raw[pe:pe+4] != b"PE\0\0" or struct.unpack_from("<H", raw, pe+4)[0] != 0xaa64 or struct.unpack_from("<H", raw, opt)[0] != 0x20b:
        raise ValueError("requires original AArch64 PE32+")
    base = struct.unpack_from("<Q", raw, opt+24)[0]
    size, headers = struct.unpack_from("<II", raw, opt+56)
    if (base, size, headers) != (0, 0x41000, 0x1000):
        raise ValueError("original ClockDxe geometry")
    count, optional = struct.unpack_from("<H", raw, pe+6)[0], struct.unpack_from("<H", raw, pe+20)[0]
    sections = []
    image = bytearray(size)
    image[:headers] = raw[:headers]
    for n in range(count):
        at = opt + optional + 40*n
        virtual, rva, length, offset = struct.unpack_from("<IIII", raw, at+8)
        name = raw[at:at+8].rstrip(b"\0").decode()
        if rva > size or length > size-rva or offset > len(raw) or length > len(raw)-offset:
            raise ValueError("section bounds")
        image[rva:rva+length] = raw[offset:offset+length]
        sections.append(dict(name=name, rva=rva, bytes=length, file=offset, virtual=virtual))
    if [(s["name"],s["rva"],s["bytes"]) for s in sections] != [
            (".text",0x1000,0x27000),(".data",0x28000,0x17000),(".reloc",0x3f000,0x2000)]:
        raise ValueError("original ClockDxe sections")
    at, length = struct.unpack_from("<II", raw, opt+112+5*8)
    end = at+length
    relocations = []
    while at+8 <= end:
        page, block = struct.unpack_from("<II", image, at)
        if not block:
            break
        if block < 8 or block%2 or at+block > end:
            raise ValueError("relocation block")
        for entry in struct.unpack_from("<"+"H"*((block-8)//2),image,at+8):
            kind = entry >> 12
            if kind:
                slot = page+(entry&4095)
                if kind != 10 or slot > size-8:
                    raise ValueError("original DIR64 bounds")
                relocations.append(slot)
        at += block
    relocations.sort()
    if len(set(relocations)) != len(relocations) or any(b < a+8 for a,b in zip(relocations,relocations[1:])):
        raise ValueError("nonoverlapping original relocations")
    if struct.unpack_from("<6Q",image,0x28140) != (0x10006,0x1d80,0x1dc8,0x1dfc,0x1e30,0x1eb0):
        raise ValueError("exact original EFI Clock query prefix")
    if struct.unpack_from("<2Q",image,0x3ce60) != (0xf5fc,0xf634):
        raise ValueError("exact pure-read GCC leaf table")
    targets = []
    for name,descriptor,name_rva,branch,vote,mask,allowed in TARGETS:
        d = image[descriptor:descriptor+96]
        if (struct.unpack_from("<Q",d,0)[0],struct.unpack_from("<Q",d,0x18)[0],
            struct.unpack_from("<Q",d,0x28)[0],struct.unpack_from("<I",d,0x30)[0],
            struct.unpack_from("<Q",d,0x38)[0]) != (name_rva,branch,vote,mask,0x3ce50):
            raise ValueError("exact original descriptor for "+name)
        if image[name_rva:name_rva+len(name)+1] != name.encode()+b"\0":
            raise ValueError("exact original name for "+name)
        targets.append(dict(name=name,descriptor_rva=descriptor,name_rva=name_rva,branch=branch,vote=vote,mask=mask,
                            original_HAL_table_rva=0x3ce50,possible_query=allowed,
                            refusal=None if allowed else "COLD_CAMCC_UNQUALIFIED_EVEN_IF_GCC_PARENTS_ON"))
    ranges = [(0,0x1000),(0x1000,0x27000),(0x28078,16),(0x28140,0xb0),(0x3ce50,40),(0x3f000,0x2000)]
    spans = [dict(rva=a,bytes=n,sha256=hashlib.sha256(image[a:a+n]).hexdigest()) for a,n in ranges]
    out = ["/* PRIVATE original ClockDxe digest binding; no firmware bytes. */",
           "#ifndef POLARIS_AUDIO_CLOCK_BINDING_H", "#define POLARIS_AUDIO_CLOCK_BINDING_H",
           f'#define PACQI_SOURCE_SHA256 "{EXPECTED}"', "#define PACQI_IMAGE_BYTES UINT64_C(0x41000)",
           "#define PACQI_ORIGINAL_BASE UINT64_C(0)",f"#define PACQI_IMAGEBASE_RVA {opt+24}u",
           f"#define PACQI_RELOC_COUNT {len(relocations)}u", "#define PACQI_RANGE_COUNT 6u",
           "static const uint32_t pacqi_relocations[PACQI_RELOC_COUNT]={"+",".join(hex(x) for x in relocations)+"};",
           "static const struct pacqi_range pacqi_ranges[PACQI_RANGE_COUNT]={"]
    for s in spans:
        digest = ",".join("0x"+s["sha256"][i:i+2] for i in range(0,64,2))
        out.append(f'    {{{s["rva"]}u,{s["bytes"]}u,{{{digest}}}}},')
    out += ["};", "#endif", ""]
    return "\n".join(out), dict(source_whole_sha256=EXPECTED,source_bytes=len(raw),sections=sections,
        relocations=relocations,immutable_ranges=spans,protocol_rva=0x28140,protocol_version=0x10006,
        clock_DAL_handle_cache_rva=0x3cf48,pure_read_leaf_rvas=[0xf5fc,0xf634],
        combined_target_descriptors=targets,combined_descriptor_targets=15,combined_possible_GCC_baselines=8,
        combined_max_original_query_calls=16,combined_CAMCC_NOT_ISSUED=7,
        MMIO_gate="WHOLE_PAGE_EFI_MMIO_TYPE11_UC_NO_RUNTIME_PLUS_ACTUAL_AT_S1E1R_NS_DEVICE00_OR04_IDENTITY",
        query_observation="ORIGINAL_EFI_BOOL_ONLY_INNER_DAL_STATUS_NOT_EXPOSED_NOT_RAW_CSR_NOT_LEASE",
        forbidden_methods=["GetFreqHz(NULL cache)","Enable","Disable","Reset","SetFreq","I2C Open"],firmware_executed=False)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--original-clock-pe", type=Path, required=True)
    p.add_argument("--out-dir", type=Path, required=True)
    a = p.parse_args()
    header, proof = binding(a.original_clock_pe)
    a.out_dir.mkdir(parents=True,exist_ok=True)
    target = a.out_dir/"uefi-audio-clock-binding.h"
    if target.exists() and target.read_text() != header:
        raise ValueError("refuse changing frozen Clock binding")
    target.write_text(header)
    proof["binding_sha256"] = hashlib.sha256(header.encode()).hexdigest()
    (a.out_dir/"binding.json").write_text(json.dumps(proof,indent=2)+"\n")
    print(json.dumps(dict(original_sha256=EXPECTED,binding_sha256=proof["binding_sha256"],firmware_executed=False)))


if __name__ == "__main__":
    main()
