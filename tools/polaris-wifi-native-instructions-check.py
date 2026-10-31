#!/usr/bin/env python3
"""Verify actual Apple-Clang Mach-O instructions from native Wi-Fi inline asm.

Compile/disassemble only. Does not execute AT, access SMEM or contact a phone.
The old templates remain only as negative fixtures proving the regression.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'tools/polaris-wifi-native-ro.c'
TOKEN=r'"(?:\\.|[^"\\])*"'

def template(text,start,end):
    block=text[text.index(start):text.index(end,text.index(start))]
    match=re.search(r'__asm__\s+volatile\(\s*((?:'+TOKEN+r'\s*)+):',block,re.S)
    if not match:raise ValueError('Cannot find exact native assembly template')
    return match.group(1).strip()

def instructions(disassembly,name):
    match=re.search(r'^_'+name+r':\n(.*?)(?=^_[A-Za-z0-9_]+:|\Z)',disassembly,re.M|re.S)
    if not match:raise ValueError('Missing fixture symbol '+name)
    return [' '.join(m.group(1).replace(',',' ').split()) for m in
            re.finditer(r'^[0-9a-f]+\s+([^\n]+)',match.group(1),re.M)]

def verify(disassembly):
    old_counter=instructions(disassembly,'old_counter')
    counter=instructions(disassembly,'new_counter')
    old_par=instructions(disassembly,'old_par')
    par=instructions(disassembly,'new_par')
    assert old_counter==['isb','ret'],old_counter
    assert counter==['isb','mrs x0 CNTVCT_EL0','ret'],counter
    assert not any(x.startswith(('at ','isb','msr ')) for x in old_par),old_par
    assert len(par)>=5,par
    first=re.fullmatch(r'mrs (x\d+) PAR_EL1',par[0]);assert first,par
    assert re.fullmatch(r'at s1e1r x\d+',par[1]),par
    assert par[2]=='isb',par
    assert re.fullmatch(r'mrs x\d+ PAR_EL1',par[3]),par
    assert par[4]=='msr PAR_EL1 '+first.group(1),par
    return {'old_counter':old_counter,'new_counter':counter,'old_par':old_par,'new_par':par}

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',required=True,type=Path)
    args=parser.parse_args();args.out.mkdir(parents=True,exist_ok=True)
    source=SOURCE.read_text()
    counter=template(source,'static uint64_t pwn_counter(void)','static bool pwn_order(')
    par=template(source,'static bool pwn_at(','static bool pwn_live(')
    fixture='''#include <stdint.h>
#include <stdbool.h>
__attribute__((noinline,used)) uint64_t old_counter(void) {
 uint64_t n;__asm__ volatile("isb; mrs %0,cntvct_el0":"=r"(n)::"memory");return n;
}
__attribute__((noinline,used)) uint64_t new_counter(void) {
 uint64_t n;__asm__ volatile('''+counter+''':"=r"(n)::"memory");return n;
}
__attribute__((noinline,used)) uint64_t old_par(uintptr_t address,uint64_t *sample) {
 uint64_t saved;__asm__ volatile("mrs %0,par_el1; at s1e1r,%2; isb; mrs %1,par_el1; msr par_el1,%0"
 :"=&r"(saved),"=&r"(*sample):"r"(address):"memory");return saved;
}
__attribute__((noinline,used)) uint64_t new_par(uintptr_t address,uint64_t *sample) {
 uint64_t saved;__asm__ volatile('''+par+'''
 :"=&r"(saved),"=&r"(*sample):"r"(address):"memory");return saved;
}
'''
    (args.out/'fixture.c').write_text(fixture)
    results=[]
    for target in ('arm64-apple-macos14.0','arm64-apple-ios16.5'):
        obj=args.out/(target+'.o')
        command=['/usr/bin/clang','-target',target,'-isysroot','/','-ffreestanding','-O2','-Wall','-Wextra','-Werror',
                 '-c',str(args.out/'fixture.c'),'-o',str(obj)]
        c=subprocess.run(command,capture_output=True,text=True)
        (args.out/(target+'.compile.log')).write_text(c.stdout+c.stderr)
        if c.returncode:raise RuntimeError('Actual AppleClang compile failed: '+c.stderr)
        d=subprocess.run(['/usr/bin/otool','-tvV',str(obj)],capture_output=True,text=True,check=True)
        (args.out/(target+'.disassembly.txt')).write_text(d.stdout)
        results.append({'target':target,'compile_exit':c.returncode,'command':command,
                        'object_sha256':hashlib.sha256(obj.read_bytes()).hexdigest(),
                        'verified_instructions':verify(d.stdout)})
    proof={'passed':True,'native_source_sha256':hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
           'fixture_sha256':hashlib.sha256(fixture.encode()).hexdigest(),'results':results,
           'scope':'Actual AppleClang Mach-O object text from exact native inline-asm strings; no instruction executed',
           'old_RAW_PAR_logs_invalid_as_AT_evidence':True,'no_SMEM_read_or_map_or_TX':True}
    (args.out/'result.json').write_text(json.dumps(proof,indent=2)+'\n')
    print(json.dumps({'passed':True,'targets':len(results),'source_sha256':proof['native_source_sha256'],
                      'old_PAR_is_not_AT_evidence':True}))
    return 0
if __name__=='__main__':raise SystemExit(main())
