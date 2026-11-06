#!/usr/bin/env python3
"""Independent interval decoder checks using actual software-producer maps."""
from pathlib import Path
import importlib.util
import struct
import sys
spec=importlib.util.spec_from_file_location('mss',Path(__file__).with_name('polaris-mss-memory-codec.py'))
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
p=Path(sys.argv[1]);checks=0

def check(value):
    global checks
    checks+=1;assert value,checks

def changed(ds,index,offset,value,width=8):
    out=list(ds);raw=bytearray(out[index][4]);struct.pack_into('<'+('I' if width==4 else 'Q'),raw,offset,value)
    kind,_,base,_,pages,attrs=struct.unpack_from('<IIQQQQ',raw)
    out[index]=(base,base+pages*4096,kind,attrs,bytes(raw));return out

for stride in (40,48):
    native=(p/f'native-{stride}.bin').read_bytes();early=(p/f'early-{stride}.bin').read_bytes()
    check(c.decode(native,early)['local_completion_consistent'])
    m=c.MEMORY.decode((p/f'maps-{stride}.bin').read_bytes());before=c.early.descriptors(m['map'][2]);after=c.early.descriptors(m['map'][3]);q=m['claim'][2]
    owner=m['input']['owner'];exclude=c.RESERVED+[(owner['image'],owner['image_bytes']),(owner['bank'],owner['bank_bytes'])]+[(x['base'],x['bytes']) for x in m['input']['retained']]+[(x['requested'],x['bytes']) for x in m['claim']]
    delta=lambda a,b,e=exclude:c.allocation_delta(a,b,q['requested'],q['bytes'],e)
    check(delta(before,after));check(not c.early.allocation_delta(before,after,q['requested'],q['bytes']))
    bi=next(i for i,d in enumerate(before) if d[0]==0x17017b000)
    ai=next(i for i,d in enumerate(after) if d[0]==0x17017a000)
    for t in (0,1,2,3,5,6,7,8,9,10):check(not delta(before,changed(after,ai,0,t,4)))
    for offset,value,width in [(4,1,4),(16,4096,8),(32,9,8)]+([(40,1,8)] if stride==48 else []):
        check(not delta(before,changed(after,ai,offset,value,width)))
    check(not delta(changed(before,bi,0,2,4),after))
    check(not delta(before,after,exclude+[(0x17017b000,4096)]))
    # A second removed conventional page cannot hide in adjacent coalescence.
    expanded=list(before);left=changed(before,bi,24,2)[bi];right=changed(before,bi+1,8,0x17017d000)[bi+1]
    raw=bytearray(right[4]);struct.pack_into('<Q',raw,24,(right[1]-right[0])//4096-1)
    expanded[bi]=left;expanded[bi+1]=(right[0],right[1]-4096,right[2],right[3],bytes(raw))
    check(not delta(expanded,after))
    check(not delta(before,after[:-1]));check(not delta(before[:-1],after))
print(f'PASS {checks} independent MSS firmware-page codec checks; SOFTWARE only')
