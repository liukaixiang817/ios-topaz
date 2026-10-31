#!/usr/bin/env python3
"""Compile the actual native counter adapters to Mach-O and inspect opcodes.

No guest/device execution. Darwin AArch64 treats ';' as an assembly comment,
so a software adapter test cannot establish that a real MRS was emitted.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
ISB=0xd5033fdf
CNTVCT=0xd53be040
CNTFRQ=0xd53be000
RET=0xd65f03c0


def function(source,name):
    start=source.index('static uint64_t '+name+'(void)')
    opening=source.index('{',start);end=source.index('}',opening)+1
    return source[start:end]


def text_and_symbols(raw):
    if raw[:4]!=b'\xcf\xfa\xed\xfe':raise ValueError('actual Mach-O64 object required')
    commands,bytes_=struct.unpack_from('<II',raw,16);at=32;text=None;table=None
    if bytes_>len(raw)-32:raise ValueError('Mach-O commands outside object')
    for _ in range(commands):
        kind,size=struct.unpack_from('<II',raw,at)
        if size<8 or size>32+bytes_-at:raise ValueError('Mach-O command bounds')
        if kind==0x19:
            sections=struct.unpack_from('<I',raw,at+64)[0]
            if sections>(size-72)//80:raise ValueError('Mach-O section bounds')
            for i in range(sections):
                sec=at+72+80*i
                if raw[sec:sec+16].split(b'\0',1)[0]==b'__text':
                    address,count,offset=struct.unpack_from('<QQI',raw,sec+32)
                    if offset>len(raw) or count>len(raw)-offset:raise ValueError('actual text bytes out of bounds')
                    if text is not None:raise ValueError('duplicate text section')
                    text=(address,raw[offset:offset+count])
        elif kind==2:table=struct.unpack_from('<4I',raw,at+8)
        at+=size
    if text is None or table is None:raise ValueError('actual code and symbols required')
    offset,count,strings,length=table;symbols={}
    if count>(len(raw)-offset)//16 or strings>len(raw) or length>len(raw)-strings:
        raise ValueError('actual symbol table bounds')
    for i in range(count):
        name,typ,section,_,value=struct.unpack_from('<IBBHQ',raw,offset+16*i)
        if name>=length or typ&0xe0 or typ&0x0e!=0x0e or not section:continue
        end=raw.find(b'\0',strings+name,strings+length)
        if end<0:raise ValueError('unterminated actual symbol')
        symbols[raw[strings+name:end].decode()]=value
    return text,symbols


def instructions(raw,name):
    (address,text),symbols=text_and_symbols(raw);start=symbols[name]-address
    if start%4 or not 0<=start<len(text):raise ValueError('counter code outside actual text')
    words=[]
    for at in range(start,min(start+128,len(text)),4):
        word=struct.unpack_from('<I',text,at)[0];words.append(word)
        if word==RET:return words
    raise ValueError('bounded actual adapter return required')


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output',type=Path,help='exclusive private evidence folder; default temporary only')
    args=ap.parse_args();temporary=None
    if args.output:
        out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    else:
        temporary=tempfile.TemporaryDirectory(prefix='polaris-clock-instructions-');out=Path(temporary.name)
    native=(ROOT/'tools/polaris-clock-native.h').read_text()
    counter=function(native,'pc_counter');frequency=function(native,'pc_frequency')
    good='#include <stdint.h>\n'+counter+'\n'+frequency+'''\n
__attribute__((noinline,used)) uint64_t polaris_clock_counter_fixture(void){return pc_counter();}
__attribute__((noinline,used)) uint64_t polaris_clock_frequency_fixture(void){return pc_frequency();}
'''
    bad=good.replace('isb\\n\\tmrs','isb; mrs')
    if good==bad:raise ValueError('actual native adapter must use a newline instruction separator')
    records={}
    for label,source in (('actual-newline',good),('negative-semicolon',bad)):
        path=out/(label+'.c');path.write_text(source);obj=path.with_suffix('.o')
        command=['/usr/bin/clang','-target','arm64-apple-macos14.0','-ffreestanding','-fno-builtin',
            '-O2','-Wall','-Wextra','-Werror','-c',str(path),'-o',str(obj)]
        compiled=subprocess.run(command,capture_output=True,text=True)
        (out/(label+'.log')).write_text(compiled.stdout+compiled.stderr)
        if compiled.returncode:raise RuntimeError('actual Mach-O counter adapter compile failed: '+label)
        raw=obj.read_bytes();c=instructions(raw,'_polaris_clock_counter_fixture')
        f=instructions(raw,'_polaris_clock_frequency_fixture')
        emitted=[i for i,word in enumerate(c) if word&~31==CNTVCT]
        if label=='actual-newline':
            if len(emitted)!=1 or emitted[0]==0 or c[emitted[0]-1]!=ISB:
                raise ValueError('actual adapter omitted ordered MRS CNTVCT')
        elif emitted or ISB not in c:raise ValueError('negative control did not expose Darwin semicolon comment')
        if sum(word&~31==CNTFRQ for word in f)!=1:raise ValueError('actual frequency MRS missing')
        records[label]=dict(command=command,exit=compiled.returncode,
            object_sha256=hashlib.sha256(raw).hexdigest(),counter_words=[hex(x) for x in c],
            frequency_words=[hex(x) for x in f],CNTVCT_instructions=len(emitted))
    proof=dict(passed=True,native_header_sha256=hashlib.sha256(native.encode()).hexdigest(),
        actual_Darwin_object_instructions=True,records=records,
        guest_or_device_executed=False,clock_frequency_or_counter_written=False)
    if args.output:(out/'proof.json').write_text(json.dumps(proof,indent=2)+'\n')
    print(json.dumps(proof,indent=2))
    if temporary:temporary.cleanup()


if __name__=='__main__':main()
