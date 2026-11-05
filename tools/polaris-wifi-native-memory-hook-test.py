#!/usr/bin/env python3
"""Run the actual loader's NV/CE/HTT call-site with software allocation leaves."""
from pathlib import Path
import re
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
text=(ROOT/'shim/polaris/uefi-xnu.c').read_text()
start='#if EFI_XNU_WIFI_NATIVE_MEMORY_AVAILABLE\n    /* All original BlockIO reads'
assert text.count(start)==1
body=text.split(start,1)[1].split('#endif',1)[0]
body='    /* All original BlockIO reads'+body
constants=[]
for file,names in [('shim/polaris/uefi-wifi-nv-inputs.h',['PNV_INPUT_BYTES','PNV_SHADOW_BYTES','PNV_SCRATCH','PNV_BYTES']),
                   ('tools/polaris-wifi-ce-memory.h',['PWDM_USABLE','PWDM_BYTES'])]:
    raw=(ROOT/file).read_text()
    for name in names:
        matches=re.findall(r'^#define '+name+r' .+$',raw,re.M)
        assert len(matches)==1
        constants+=matches
source=r'''
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <setjmp.h>
struct pwea_map {unsigned identity;};
struct record {struct {uint64_t address;} allocation;struct pwea_map map[2];};
static struct record wifi_native_nv,wifi_native_ce_memory,wifi_native_htt_memory;
static unsigned early_wifi_memory,polaris_nv_plan,original_service_unknown,calls,fault;
static const struct pwea_map *early_map;
static jmp_buf hold;
static void ram_report(const char*name,int result){(void)name;(void)result;}
static void power_unknown_hold(void){assert(original_service_unknown);longjmp(hold,1);}
static int pnnv_run(struct record*r,void*e,void*p)
{assert(r==&wifi_native_nv&&e==&early_wifi_memory&&p==&polaris_nv_plan&&!calls);calls++;r->allocation.address=0x90000000;return fault!=1;}
static int pcdm_run(struct record*r,void*e)
{
    assert(e==&early_wifi_memory&&calls>=1&&calls<=2);calls++;
    assert(r==(calls==2?&wifi_native_ce_memory:&wifi_native_htt_memory));
    r->allocation.address=calls==2?0xa0000000:0xb0000000;
    if(fault==4&&calls==3)r->allocation.address=wifi_native_ce_memory.allocation.address;
    if(fault==5&&calls==2)r->allocation.address=wifi_native_nv.allocation.address;
    if(fault==6&&calls==3)r->allocation.address=wifi_native_nv.allocation.address;
    return fault!=calls;
}
static int pwea_disjoint(uint64_t a,uint64_t n,uint64_t b,uint64_t z)
{return a+n<=b||b+z<=a;}
static void actual_hook(void){
'''+body+r'''
}
int main(void)
{
    for(fault=0;fault<=6;fault++){
        original_service_unknown=calls=0;early_map=0;
        int held=setjmp(hold);if(!held)actual_hook();
        if(!fault)assert(!held&&calls==3&&early_map==&wifi_native_htt_memory.map[1]&&!original_service_unknown);
        else assert(held&&original_service_unknown&&!early_map&&calls==(fault<4?fault:3));
    }
    puts("PASS 7 actual loader memory-hook scenarios with software allocation leaves; no device IO");return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='polaris-native-memory-') as d:
    p=Path(d);(p/'test.c').write_text('\n'.join(constants)+'\n'+source)
    subprocess.run(['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror',
                    '-fsanitize=address,undefined',str(p/'test.c'),'-o',str(p/'test')],check=True)
    subprocess.run([str(p/'test')],check=True)
