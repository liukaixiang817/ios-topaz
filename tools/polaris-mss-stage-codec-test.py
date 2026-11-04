#!/usr/bin/env python3
"""Check C layout and independently reject corrupt native staging evidence."""
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import struct
import subprocess


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('raw',type=Path)
    p.add_argument('--output-directory',type=Path,required=True)
    p.add_argument('--firmware-manifest',type=Path);a=p.parse_args()
    root=Path(__file__).resolve().parents[1];out=a.output_directory;out.mkdir(parents=True,exist_ok=True)
    spec=importlib.util.spec_from_file_location('stage_codec',Path(__file__).with_name('polaris-mss-stage-codec.py'))
    c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
    lines=['#define PMSI_TEST_ENTRY unused_stage_suite',f'#include "{root}/tools/polaris-mss-stage-test.c"','int main(void) {'];expected={}
    for name,layout in c.LAYOUTS.items():
        for field,value,expr in [('size',layout.size,f'sizeof(struct {name})'),('align',layout.align,f'_Alignof(struct {name})')]+[
                (field,data[0],f'offsetof(struct {name},{field})') for field,data in layout.fields.items()]:
            key=f'{name}.{field}';expected[key]=value;lines.append(f'printf("{key}=%zu\\n",{expr});')
    lines+=['return 0;}'];(out/'layout.c').write_text('\n'.join(lines)+'\n')
    subprocess.run(['clang','-std=c11','-D_POSIX_C_SOURCE=200809L','-D_DARWIN_C_SOURCE','-O1','-Wall','-Wextra','-Werror','-Wno-unused-function',
        '-I'+str(root/'shim/polaris'),'-I'+str(root/'research/polaris/uefi-ios-0189/wifi/parent-incoming-map-0001'),
        '-I'+str(root/'research/polaris/uefi-ios-0188/physical-runtime-driver-0002'),'-I'+str(root/'tools'),
        str(out/'layout.c'),'-o',str(out/'layout')],check=True)
    actual=dict(line.split('=') for line in subprocess.check_output([str(out/'layout')],text=True).splitlines())
    assert {k:int(v) for k,v in actual.items()}==expected
    raw=a.raw.read_bytes();mraw=Path(str(a.raw)+'.memory').read_bytes()
    eraw=Path(str(a.raw)+'.early').read_bytes();hraw=Path(str(a.raw)+'.retained').read_bytes();checks=0
    def check(ok):
        nonlocal checks
        checks+=1;assert ok,checks
    firmware=json.loads(a.firmware_manifest.read_text()) if a.firmware_manifest else None
    baseline=c.decode(raw,mraw,eraw,hraw,firmware);check(baseline['local_completion_consistent'])
    if firmware and firmware.get('payload_transport'):
        check(not c.decode(raw,mraw,eraw,hraw)['local_completion_consistent'])
        for field,value in [('mode','embedded'),('offset',0),('offset',8192),('payload_bytes',1)]:
            changed=copy.deepcopy(firmware);changed['payload_transport'][field]=value
            check(not c.decode(raw,mraw,eraw,hraw,changed)['local_completion_consistent'])
    def offset(*path):
        at=0;layout=c.NATIVE
        for key,index in path:
            off,kind,count=layout.fields[key];assert index<count
            at+=off+index*(kind.size if isinstance(kind,c.Layout) else kind);layout=kind
        return at
    changes=[]
    for k in ('attempted','unknown','error','pages','assets_complete','complete'):
        changes.append((offset((k,0)),4,1 if k in ('unknown','error') else 0))
    for k in ('memory_digest','retained_digest','source_hash','copied_hash'):
        changes.append((offset((k,0)),8,0))
    changes += [(offset(('blob',0)),8,1),(offset(('blob_bytes',0)),8,0),(offset(('asset_count',0)),8,1)]
    for kind in range(2):
        changes += [(offset(('asset',kind),('bytes',0)),4,1),(offset(('asset',kind),('sha256',0)),8,0),
                    (offset(('source_pages',kind)),4,0)]
        for n in (0,(58,2)[kind]):
            for key in ('page','write_par','restored'):
                changes.append((offset(('source_AT',64*kind+n),(key,0)),8,1))
    for n in (0,58,59,255,256,258):
        for key in ('bytes','words_issued','words_returned','complete'):
            changes.append((offset(('page',n),(key,0)),4,4097 if key=='bytes' else 0))
        for key in ('page','write_par','restored'):
            changes.append((offset(('page',n),('target',0),(key,0)),8,1))
        for key in ('operation','line_bytes','lines_returned','barrier_returned','complete'):
            changes.append((offset(('page',n),('cache',0),(key,0)),4,0))
        changes += [(offset(('page',n),('after',0),('cpu',0),('ttbr0',0)),8,1),
                    (offset(('page',n),('source',0),('page',0)),8,1)]
    for n in range(2):
        changes += [(offset(('core',n),('hash_count',0)),4,0),(offset(('core',n),('hashes',0)),8,0),
                    (offset(('core',n),('AT',56),('raw',0)),8,0)]
    for at,size,value in changes:
        changed=bytearray(raw);struct.pack_into('<'+('Q' if size==8 else 'I'),changed,at,value)
        check(not c.decode(changed,mraw,eraw,hraw,firmware)['local_completion_consistent'])
    for length in (0,1,len(raw)-1,len(raw)+1):
        try:c.decode((raw+b'\0')[:length],mraw,eraw,hraw)
        except ValueError:check(True)
        else:check(False)
    result=dict(passed=True,layout_checks=len(expected),corruption_checks=checks,raw_bytes=c.NATIVE.size,hardware=False)
    (out/'codec-proof.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))


if __name__=='__main__':main()
