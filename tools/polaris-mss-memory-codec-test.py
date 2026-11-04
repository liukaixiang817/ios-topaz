#!/usr/bin/env python3
"""Independent raw geometry and corruption checks from the actual software caller."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import subprocess


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('raw',type=Path);p.add_argument('--output-directory',type=Path,required=True)
    a=p.parse_args();root=Path(__file__).resolve().parents[1];out=a.output_directory
    out.mkdir(parents=True,exist_ok=True)
    spec=importlib.util.spec_from_file_location('mss_codec',Path(__file__).with_name('polaris-mss-memory-codec.py'))
    c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
    lines=['#define PMMN_TEST_ENTRY unused_mss_suite',
           f'#include "{root}/tools/polaris-mss-memory-test.c"','int main(void) {']
    expected={}
    for name,layout in c.LAYOUTS.items():
        for field,value,expr in [('size',layout.size,f'sizeof(struct {name})'),
                                 ('align',layout.align,f'_Alignof(struct {name})')]+[
                (field,data[0],f'offsetof(struct {name},{field})') for field,data in layout.fields.items()]:
            key=f'{name}.{field}';expected[key]=value
            lines.append(f'printf("{key}=%zu\\n",{expr});')
    lines+=['return 0;}'];(out/'layout.c').write_text('\n'.join(lines)+'\n')
    subprocess.run(['clang','-std=c11','-D_POSIX_C_SOURCE=200809L','-O1','-Wall','-Wextra','-Werror','-Wno-unused-function',
        '-I'+str(root/'shim/polaris'),'-I'+str(root/'research/polaris/uefi-ios-0189/wifi/parent-incoming-map-0001'),
        '-I'+str(root/'research/polaris/uefi-ios-0188/physical-runtime-driver-0002'),'-I'+str(root/'tools'),
        str(out/'layout.c'),'-o',str(out/'layout')],check=True)
    actual=dict(line.split('=') for line in subprocess.check_output([str(out/'layout')],text=True).splitlines())
    assert {k:int(v) for k,v in actual.items()}==expected
    raw=a.raw.read_bytes();eraw=Path(str(a.raw)+'.early').read_bytes();hraw=Path(str(a.raw)+'.retained').read_bytes()
    checks=0
    def check(value):
        nonlocal checks
        checks+=1;assert value,checks
    check(c.decode(raw,eraw,hraw)['local_completion_consistent'])
    def offset(*path):
        at=0;layout=c.NATIVE
        for key,index in path:
            off,kind,count=layout.fields[key];assert index<count
            at+=off+index*(kind.size if isinstance(kind,c.Layout) else kind);layout=kind
        return at
    mutations=[(offset((k,0)),4,1 if k in ('unknown','error') else 0) for k in ('attempted','unknown','error','complete')]
    mutations += [(offset(('early_digest',0)),8,0),(offset(('memory',0),('input',0),('metadata_bytes',0)),8,0),
                  (offset(('memory',0),('input',0),('owner',0),('bank',0)),8,1)]
    for n in range(3):
        for key in ('bytes','pages','status','requested','returned_address','exposed','exposed_bytes'):
            mutations.append((offset(('memory',0),('claim',n),(key,0)),8,1))
    for n in range(4):
        for key in ('key','stride','bytes'):
            mutations.append((offset(('memory',0),('map',n),('map',0),(key,0)),8,0))
        data=offset(('memory',0),('map',n),('data',0))
        mutations += [(data+40,4,7),(data+4,4,1),(data+32,8,9)]
    for n in range(7):
        for key in ('issued','returned','complete'):
            mutations.append((offset(('call',n),(key,0)),4,0))
        mutations += [(offset(('call',n),('fp',0),('restored',0)),4,0),
                      (offset(('call',n),('after',0),('cpu',0),('ticks',0)),8,0),
                      (offset(('call',n),('before',0),('cpu',0),('mair',0)),8,0)]
        for phase in range(2):
            for key in ('pages','hash_count','complete'):
                mutations.append((offset(('call',n),('source',phase),(key,0)),4,0))
            mutations += [(offset(('call',n),('source',phase),('hashes',0)),8,0),
                          (offset(('call',n),('source',phase),('AT',56),('raw',0)),8,0)]
    for at,size,value in mutations:
        changed=bytearray(raw);struct.pack_into('<'+('Q' if size==8 else 'I'),changed,at,value)
        check(not c.decode(changed,eraw)['local_completion_consistent'])
    for n in range(3):
        changed=bytearray(hraw)
        at=c.early.HOLD.fields['map'][0]+c.early.MAP.fields['data'][0]+160+40*n
        struct.pack_into('<I',changed,at,7)
        check(not c.decode(raw,eraw,changed)['local_completion_consistent'])
    for length in (0,1,len(raw)-1,len(raw)+1):
        try:c.decode((raw+b'\0')[:length],eraw)
        except ValueError:check(True)
        else:check(False)
    result=dict(passed=True,layout_checks=len(expected),corruption_checks=checks,raw_bytes=c.NATIVE.size,hardware=False)
    (out/'codec-proof.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))


if __name__=='__main__':main()
