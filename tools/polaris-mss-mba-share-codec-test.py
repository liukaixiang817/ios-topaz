#!/usr/bin/env python3
"""Check independent secure-call prefix ABI and reject corrupted continuations."""
import argparse
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
    spec=importlib.util.spec_from_file_location('share_codec',Path(__file__).with_name('polaris-mss-mba-share-codec.py'))
    c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
    lines=['#define PMSB_TEST_ENTRY unused_share_suite',f'#include "{root}/tools/polaris-mss-mba-share-test.c"','int main(void) {'];expected={}
    for name,layout in c.LAYOUTS.items():
        size=f'offsetof(struct {name},page)' if name=='pmsb_result' else f'sizeof(struct {name})'
        for field,value,expr in [('size',layout.size,size),('align',layout.align,f'_Alignof(struct {name})')]+[
                (field,data[0],f'offsetof(struct {name},{field})') for field,data in layout.fields.items()]:
            key=f'{name}.{field}';expected[key]=value;lines.append(f'printf("{key}=%zu\\n",{expr});')
    lines+=['return 0;}'];(out/'layout.c').write_text('\n'.join(lines)+'\n')
    subprocess.run(['clang','-std=c11','-D_POSIX_C_SOURCE=200809L','-D_DARWIN_C_SOURCE','-O1','-Wall','-Wextra','-Werror','-Wno-unused-function',
        '-I'+str(root/'shim/polaris'),'-I'+str(root/'research/polaris/uefi-ios-0189/wifi/parent-incoming-map-0001'),
        '-I'+str(root/'research/polaris/uefi-ios-0188/physical-runtime-driver-0002'),'-I'+str(root/'tools'),
        str(out/'layout.c'),'-o',str(out/'layout')],check=True)
    actual=dict(line.split('=') for line in subprocess.check_output([str(out/'layout')],text=True).splitlines())
    assert {k:int(v) for k,v in actual.items()}==expected
    raw=a.raw.read_bytes();paired=[Path(str(a.raw)+suffix).read_bytes() for suffix in ('.stage','.memory','.early','.retained')];checks=0
    firmware=json.loads(a.firmware_manifest.read_text()) if a.firmware_manifest else None
    def check(ok):
        nonlocal checks
        checks+=1;assert ok,checks
    check(c.decode(raw,*paired,firmware=firmware)['local_completion_consistent'])
    photo=Path(str(a.raw)+'.photo')
    if photo.exists():
        decoded=c.decode(photo.read_bytes(),*[Path(str(photo)+suffix).read_bytes()
            for suffix in ('.stage','.memory','.early','.retained')],firmware=firmware)
        check(decoded['local_completion_consistent'])
        observed=c.PREFIX.decode(photo.read_bytes())
        check(3840000<observed['restored']['cpu']['ticks']-observed['entry']['cpu']['ticks']<=9600000)
    check(not c.decode(Path(str(a.raw)+'.unknown').read_bytes(),*[Path(str(a.raw)+'.unknown'+suffix).read_bytes()
        for suffix in ('.stage','.memory','.early','.retained')],firmware=firmware)['local_completion_consistent'])
    def offset(*path):
        at=0;layout=c.PREFIX
        for key,index in path:
            off,kind,count=layout.fields[key];assert index<count
            at+=off+index*(kind.size if isinstance(kind,c.Layout) else kind);layout=kind
        return at
    changes=[]
    entry=c.PREFIX.decode(raw)['entry']['cpu']['ticks']
    for key in ('assigned','restored'):
        changes.append((offset((key,0),('cpu',0),('ticks',0)),8,entry+9600001))
    for key in ('attempted','unknown','error','mask_issued','cpu_held','assignment_issued','assignment_returned_zero','restore_issued','complete'):
        changes.append((offset((key,0)),4,1 if key in ('unknown','error','cpu_held') else 0))
    changes += [(offset(('stage_digest',0)),8,0),(offset(('base',0)),8,1),(offset(('bytes',0)),8,0x200000),
                (offset(('fp',0),('restored',0)),4,0),(offset(('descriptor_AT',0),('write_par',0)),8,0)]
    for key in ('mask','restore'):
        for field in ('returned','daif_written','group_observed'):
            changes.append((offset((key,0),(field,0)),4,0))
    for n in range(14):changes.append((offset(('peer',n),('raw',0)),8,0))
    for key in ('started','unknown','error','pending','step','events','rounds','complete'):
        changes.append((offset(('transaction',0),(key,0)),4,1 if key in ('unknown','error','pending') else 0))
    changes += [(offset(('transaction',0),('expected',0)),4,0),
                (offset(('transaction',0),('spec',0),('destination',0),('vmid',0)),4,3),
                (offset(('transaction',0),('spec',0),('region_bytes',0)),8,0x200000),
                (offset(('transaction',0),('initial',0),('x',0)),8,0)]
    for n in range(6):
        changes += [(offset(('transaction',0),('event',n),('returned',0)),4,0),
                    (offset(('transaction',0),('event',n),('command',0),('sequence',0)),4,0),
                    (offset(('step',n),('cpu',0),('ttbr0',0)),8,1)]
        if 1<=n<=4:
            changes += [(offset(('transaction',0),('event',n),('command',0),('registers',0),('x',1)),8,0),
                        (offset(('transaction',0),('event',n),('response',0),('x',0)),8,2)]
        else:changes.append((offset(('transaction',0),('event',n),('cache',0),('barrier_returned',0)),4,0))
    for n in range(2):changes += [(offset(('source',n),('hash_count',0)),4,0),(offset(('source',n),('hashes',0)),8,0)]
    for at,size,value in changes:
        changed=bytearray(raw);struct.pack_into('<'+('Q' if size==8 else 'I'),changed,at,value)
        check(not c.decode(changed,*paired,firmware=firmware)['local_completion_consistent'])
    for length in (0,1,len(raw)-1,len(raw)+1,len(raw)+4096):
        try:c.decode((raw+bytes(4096))[:length],*paired)
        except ValueError:check(True)
        else:check(False)
    result=dict(passed=True,layout_checks=len(expected),corruption_checks=checks,raw_prefix_bytes=c.PREFIX.size,
                descriptor_page_excluded=True,hardware=False)
    (out/'codec-proof.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))


if __name__=='__main__':main()
