#!/usr/bin/env python3
"""Package the phone's already extracted, verified MSS files into private inputs.

No download, extraction, execution or device operation. Own self-auth ELF32 MDT
semantics follow peripheral-loader.c; fixed reserved addresses are never load
destinations. Generated proprietary bytes must stay in ignored research output.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

MODEM_BYTES = 0x7800000
SOURCE_SHA256 = '46144cad9b1d1af12691f0dbab10c91c6595011485f7a4f92906517cf40bae81'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def parse_mdt(data):
    if len(data) != 8412:
        raise ValueError('own MDT must contain 8412 bytes')
    ident,kind,machine,version,entry,phoff,shoff,flags,ehsize,phsize,phnum,shsize,shnum,shstr = struct.unpack_from('<16sHHIIIIIHHHHHH',data)
    if ident != b'\x7fELF\x01\x01\x01'+bytes(9) or (kind,machine,version,phoff,ehsize,phsize,phnum) != (2,164,1,52,52,32,30):
        raise ValueError('not the own ELF32 QDSP MDT geometry')
    segments=[]
    for n in range(phnum):
        typ,offset,va,pa,filesz,memsz,pflags,align=struct.unpack_from('<8I',data,phoff+n*phsize)
        if typ != 1 or pflags & 0x7000000 == 0x2000000 or not memsz:
            continue
        if not pflags & 0x8000000 or filesz > memsz or pa+memsz > 1<<32 or not align or align & (align-1):
            raise ValueError(f'invalid/nonrelocatable loadable segment {n}')
        segments.append(dict(index=n,original_pa=pa,filesz=filesz,memsz=memsz,flags=pflags,alignment=align))
    segments.sort(key=lambda q:q['original_pa'])
    if len(segments)!=28 or {s['index'] for s in segments} != set(range(2,30)):
        raise ValueError('own MDT must have loadable segments 2..29')
    base=segments[0]['original_pa'];end=max(s['original_pa']+s['memsz'] for s in segments)
    if base != 0x8e400000 or (end+4095)//4096*4096-base != MODEM_BYTES or segments[0]['alignment'] != 0x100000:
        raise ValueError('own modem relocation geometry changed')
    if any(a['original_pa']+a['memsz'] > b['original_pa'] for a,b in zip(segments,segments[1:])):
        raise ValueError('loadable segments overlap')
    if not any(s['original_pa'] <= entry < s['original_pa']+s['memsz'] and s['flags'] & 1 for s in segments):
        raise ValueError('entry is outside executable segment')
    for s in segments:s['target_offset']=s['original_pa']-base
    return dict(base=base,bytes=MODEM_BYTES,alignment=0x100000,entry_offset=entry-base,segments=segments)


def verified_files(directory):
    directory=directory.resolve(strict=True)
    proof=json.loads((directory/'proof.json').read_text())
    if proof.get('passed') is not True or proof.get('source_sha256')!=SOURCE_SHA256 or proof.get('current0096_full_modem_SHA_exact') is not True:
        raise ValueError('requires the existing own backup/physical SHA evidence')
    entries=proof.get('files',[]);files={}
    if len(entries)!=30:raise ValueError('requires the existing 30-file verified extraction')
    for item in entries:
        name=item['path']
        if not re.fullmatch(r'(?:modem\.(?:b[0-9]{2}|mdt)|mba\.mbn|wlanmdsp\.mbn)',name) or name in files:
            raise ValueError('duplicate/unexpected file name')
        path=(directory/name).resolve(strict=True)
        if path.parent!=directory:raise ValueError('source escapes verified directory')
        if not 0 < item['bytes'] <= 64*1024*1024 or path.stat().st_size!=item['bytes']:
            raise ValueError('source size mismatch: '+name)
        data=path.read_bytes()
        if digest(data)!=item['sha256']:raise ValueError('source hash mismatch: '+name)
        files[name]=data
    return files,proof


def payload_transport(raw,manifest):
    """Validate an exact padded ADT end + own firmware tail; no ABI changes."""
    if len(raw)<0x2a8 or raw[:8]!=b'SWEETXNU' or struct.unpack_from('<I',raw,8)[0]!=1:
        raise ValueError('requires a version1 kernel payload')
    off,size=struct.unpack_from('<QQ',raw,32);end=off+size
    offset=(end+4095)&~4095
    if off<0x2a8 or size<8 or size>0x100000 or end>len(raw) or offset>128*1024*1024:
        raise ValueError('payload ADT extent')
    if len(raw)!=offset+manifest['bytes'] or len(raw)>128*1024*1024 or any(raw[end:offset]):
        raise ValueError('exact aligned firmware tail and transport limit required')
    if digest(raw[offset:])!=manifest['sha256']:
        raise ValueError('payload firmware tail differs from verified own bundle')
    return dict(mode='payload-tail',offset=offset,base_bytes=end,base_sha256=digest(raw[:end]),
                payload_bytes=len(raw),payload_sha256=digest(raw))


def combine_payload(payload,output,manifest):
    root=Path(__file__).resolve().parents[1];research=(root/'research').resolve()
    payload=payload.resolve(strict=True);output=output.resolve()
    if not payload.is_relative_to(research) or not output.is_relative_to(research) or output.exists():
        raise ValueError('new combined payload must remain private and not overwrite an input')
    raw=payload.read_bytes()
    if len(raw)<0x2a8 or raw[:8]!=b'SWEETXNU':raise ValueError('kernel payload header')
    off,size=struct.unpack_from('<QQ',raw,32)
    if off+size!=len(raw):raise ValueError('base kernel payload must end exactly at ADT')
    bundle=(output.parent/'mss-firmware.bin').read_bytes()
    if len(bundle)!=manifest['bytes'] or digest(bundle)!=manifest['sha256']:raise ValueError('bundle changed')
    combined=raw+bytes((-len(raw))%4096)+bundle
    transport=payload_transport(combined,manifest);output.write_bytes(combined)
    (output.parent/'payload-transport.json').write_text(json.dumps(transport,indent=2)+'\n')
    return transport


def package(directory,output):
    root=Path(__file__).resolve().parents[1];research=(root/'research').resolve()
    directory=directory.resolve(strict=True);output=output.resolve()
    if not directory.is_relative_to(research) or not output.is_relative_to(research) or output==research:
        raise ValueError('firmware input and generated bytes must remain in private research')
    if output.exists() and any(output.iterdir()):raise ValueError('output directory must be new or empty')
    files,proof=verified_files(directory);layout=parse_mdt(files['modem.mdt'])
    if len(files['mba.mbn'])!=238304:raise ValueError('own MBA length changed')
    if files['modem.mdt']!=files['modem.b00']+files['modem.b01']:
        raise ValueError('metadata differs from own ELF headers plus hash blob')
    names=['mba.mbn','modem.mdt']
    for s in layout['segments']:
        name=f"modem.b{s['index']:02d}"
        if s['filesz']:
            if name not in files or len(files[name])!=s['filesz']:raise ValueError('segment source size: '+name)
            names.append(name)
        elif name in files:raise ValueError('unexpected source for zero-file BSS segment')
    names+=['wlanmdsp.mbn'];blob=bytearray();assets=[]
    for name in names:
        offset=len(blob);data=files[name];blob+=data;blob+=bytes((-len(blob))%4096)
        assets.append(dict(name=name,offset=offset,bytes=len(data),sha256=digest(data)))
    for s in layout['segments']:
        name=f"modem.b{s['index']:02d}"
        s['asset']=names.index(name) if s['filesz'] else 0xffffffff
    output.mkdir(parents=True,exist_ok=True);(output/'mss-firmware.bin').write_bytes(blob)
    # All names are fixed, but reject assembler metacharacters in the containing
    # path too. The compiler never executes shell interpolation of this path.
    path=str(output/'mss-firmware.bin')
    if any(c in path for c in ('"','\\','\n','\r')):raise ValueError('unsupported assembler path')
    assembly='.section .rdata,"dr"\n.balign 4096\n.globl pmsf_blob\npmsf_blob:\n.incbin "'+path+'"\n'
    (output/'mss-firmware.S').write_text(assembly)
    lines=['/* Private generated own firmware identity; never commit this output. */',
           '#include "uefi-mss-firmware-types.h"','extern const uint8_t pmsf_blob[];',
           f'#define PMSF_BLOB_BYTES {len(blob)}u',f'#define PMSF_ASSETS {len(assets)}u',
           'static const struct pmsf_asset pmsf_assets[PMSF_ASSETS]={']
    for a in assets:
        h=','.join('0x'+a['sha256'][n:n+2] for n in range(0,64,2))
        lines.append(f'    {{{a["offset"]}u,{a["bytes"]}u,{{{h}}}}},')
    lines+=['};','static const struct pmsf_segment pmsf_segments[28]={']
    for s in layout['segments']:
        values=[s[k] for k in ('index','target_offset','filesz','memsz','flags','alignment','asset')]
        lines.append('    {'+','.join(f'{v}u' for v in values)+'},')
    lines+=['};',f'#define PMSF_WLAN_ASSET {len(assets)-1}u',f'#define PMSF_MODEM_ENTRY_OFFSET {layout["entry_offset"]}u']
    (output/'uefi-mss-firmware-binding.h').write_text('\n'.join(lines)+'\n')
    manifest=dict(source_sha256=SOURCE_SHA256,extraction_proof_sha256=digest((directory/'proof.json').read_bytes()),
        bytes=len(blob),sha256=digest(blob),assets=assets,layout=layout,
        source_files={name:dict(bytes=len(data),sha256=digest(data)) for name,data in files.items()},
        firmware_executed=False,physical_wifi_proven=False)
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    return manifest


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('directory',type=Path)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--payload',type=Path,help='append verified firmware to this private kernel payload; emits payload.bin for the existing RAM protocol')
    a=p.parse_args();m=package(a.directory,a.output)
    if a.payload:combine_payload(a.payload,a.output/'payload.bin',m)
    print(json.dumps({k:m[k] for k in ('bytes','sha256','firmware_executed','physical_wifi_proven')}))


if __name__=='__main__':main()
