#!/usr/bin/env python3
"""Check the independent codec using a raw record from the actual C software peer."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('raw',type=Path)
    parser.add_argument('--retained',type=Path)
    args=parser.parse_args()
    spec=importlib.util.spec_from_file_location('codec',Path(__file__).with_name('polaris-wifi-early-codec.py'))
    c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
    raw=args.raw.read_bytes();checks=0
    def check(value):
        nonlocal checks
        checks+=1
        assert value,checks
    baseline=c.decode(raw)
    check(baseline['local_completion_consistent'])
    check(not baseline['physical_wifi_proven'] and not baseline['secure_ownership_proven'])
    for length in (0,1,len(raw)-1,len(raw)+1):
        try:c.decode((raw+b'\0')[:length])
        except ValueError:check(True)
        else:check(False)
    def offset(*path):
        layout=c.NATIVE;at=0
        for field,index in path:
            off,kind,count=layout.fields[field]
            at+=off+index*(kind.size if isinstance(kind,c.Layout) else kind)
            layout=kind
        return at
    changes=[(offset((key,0)),4,1 if key in ('error','unknown') else 0) for key in ('attempted','complete','error','unknown')]
    for i in range(2):
        for key in ('status','returned_address','bytes','pages','exposed','exposed_bytes'):
            changes.append((offset(('memory',0),('claim',i),(key,0)),8,1))
        changes.append((offset(('translated',i)),4,0))
        for k in (0,(512,514)[i]-1):
            for key in ('page','read_par','write_par','restored'):
                changes.append((offset(('AT',514*i+k),(key,0)),8,1))
    for i in range(3):
        for key in ('key','stride','bytes'):
            changes.append((offset(('memory',0),('map',i),('map',0),(key,0)),8,0))
        # Change the bank descriptor, padding, extension-independent attributes
        # and unrelated memory geometry without touching any success flags.
        base=offset(('memory',0),('map',i),('data',0))
        changes += [(base+40,4,7),(base+4,4,1),(base+32,8,9),(base+80+8,8,0)]
    for i in range(5):
        for key in ('issued','returned','complete'):
            changes.append((offset(('call',i),(key,0)),4,0))
        changes.append((offset(('call',i),('fp',0),('restored',0)),4,0))
        for phase in range(2):
            if i==0 and phase==0:continue
            for key in ('pages','hash_count','complete'):
                changes.append((offset(('call',i),('source',phase),(key,0)),4,0))
            changes.append((offset(('call',i),('source',phase),('TPL',0)),8,8))
    for at,size,value in changes:
        changed=bytearray(raw);struct.pack_into('<'+('Q' if size==8 else 'I'),changed,at,value)
        check(not c.decode(changed)['local_completion_consistent'])
    body=b''.join(raw[n:n+64].hex().encode()+b'\r\n' for n in range(0,len(raw),64))
    framed=b'EARLY_WIFI_MEMORY_RAW_V1_BEGIN\r\n'+body+b'EARLY_WIFI_MEMORY_RAW_V1_END\r\n'
    check(c.extract(framed)==raw)
    for invalid in (framed[:-1],framed+framed,framed.replace(body[:2],b'zz',1),framed.replace(b'\r\n',b'\n')):
        try:c.extract(invalid)
        except ValueError:check(True)
        else:check(False)
    if args.retained:
        retained=args.retained.read_bytes();check(c.decode_retained(retained,raw)['local_completion_consistent'])
        mutations=[]
        for key in ('attempted','issued','returned','complete','error','unknown'):
            mutations.append((c.HOLD.fields[key][0],4,1 if key in ('error','unknown') else 0))
        mutations += [(c.HOLD.fields['early_digest'][0],4,0),
                      (c.HOLD.fields['payload_bytes'][0],8,4096),
                      (c.HOLD.fields['translated'][0],4,1)]
        for phase in range(2):
            base=c.HOLD.fields['source'][0]+phase*c.CORE.size
            mutations += [(base+c.CORE.fields['pages'][0],4,0),(base+c.CORE.fields['hashes'][0],4,0),
                          (base+c.CORE.fields['AT'][0]+c.CORE_AT.fields['raw'][0],8,0)]
        base=c.HOLD.fields['map'][0]+c.MAP.fields['data'][0]
        mutations += [(base+40*k,4,7) for k in range(1,6)]
        for k in (0,511,514,1027):
            mutations.append((c.HOLD.fields['AT'][0]+k*c.TRANSLATION.size+c.TRANSLATION.fields['write_par'][0],8,0))
        for at,size,value in mutations:
            changed=bytearray(retained);struct.pack_into('<'+('Q' if size==8 else 'I'),changed,at,value)
            check(not c.decode_retained(changed,raw)['local_completion_consistent'])
        huge=bytearray(raw)
        struct.pack_into('<Q',huge,offset(('memory',0),('claim',0),('pages',0)),(1<<64)-1)
        check(not c.decode_retained(retained,huge)['local_completion_consistent'])
    print(json.dumps(dict(passed=True,checks=checks,raw_bytes=len(raw),hardware=False)))


if __name__=='__main__':main()
