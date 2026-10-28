"""Actual native callback meter: overlapping callers and invalid clocks.

No simulated GPU performance or physical timing claim. The native callbacks
remain permission checked and serialized exactly as before instrumentation.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest
from .test_polaris_gpu_lifetime import function

ROOT = Path(__file__).resolve().parents[2]


class MethodProfileTests(unittest.TestCase):
    def test_actual_meter_overlap_errors_clock_rejection_and_window_reset(self):
        text = (ROOT/'tools/PolarisGPU.cpp').read_text()
        start = text.index('struct PolarisMethodBin ')
        end = text.index('class PolarisGPUUserClient ', start)
        actual = text[start:end].replace('static PolarisMethodMeter gpuMethodMeter;\n', '')
        actual = function(text, 'static uint64_t polaris_gpu_elapsed_us(') + actual
        source = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
static char logs[8192];static size_t used;
static void absolutetime_to_nanoseconds(uint64_t ticks,uint64_t*out){*out=ticks;}
static void IOLog(const char*format,...){
 va_list ap;va_start(ap,format);int n=vsnprintf(logs+used,sizeof(logs)-used,format,ap);va_end(ap);
 assert(n>=0&&(size_t)n<sizeof(logs)-used);used+=(size_t)n;
}
''' + actual + r'''
int main(){PolarisMethodMeter m={},old;
 assert(polaris_gpu_method_bin(0x42)==0&&polaris_gpu_method_bin(0x46)==3);
 assert(polaris_gpu_method_bin(0x47)==4&&polaris_gpu_method_bin(0x10000)==7);
 assert(polaris_gpu_method_bin(UINT32_MAX)==8);
 assert(!polaris_gpu_method_record(nullptr,0x46,0,1,2,3,4,5));
 assert(!polaris_gpu_method_record(&m,0x42,7,1000,2000,3000,6000,10000));
 assert(m.calls==1&&m.bins[0].calls==1&&m.bins[0].errors==1);
 assert(m.bins[0].auth==1&&m.bins[0].dispatch==1&&m.bins[0].lock==3&&m.bins[0].body==4);
 assert(m.bins[0].total==9&&m.bins[0].maximum==9);
 /* Earlier entry can finish later: lock/authorization waits overlap. */
 assert(!polaris_gpu_method_record(&m,0x10000,0,500,2500,3000,11000,12500));
 assert(m.began==500&&m.lastEnded==12500&&m.calls==2&&m.bins[7].calls==1);
 old=m;
 uint64_t invalid[][5]={{10,9,12,13,14},{10,11,9,13,14},
                      {10,11,12,9,14},{10,11,12,13,9},{1,2,3,4,5}};
 for(auto&stamp:invalid){
  assert(!polaris_gpu_method_record(&m,0x46,0,stamp[0],stamp[1],stamp[2],stamp[3],stamp[4]));
  assert(!memcmp(&m,&old,sizeof(m)));
 }
 assert(polaris_gpu_method_record(&m,0x46,0,13000,14000,15000,16000,2000020000));
 assert(m.calls==3&&m.bins[3].calls==1&&!m.bins[3].errors);
 polaris_gpu_method_flush(&m,2000020000);
 assert(!m.calls&&!m.lastEnded&&!m.began&&strstr(logs,"kind=make calls=1 errors=1"));
 assert(strstr(logs,"kind=map calls=1 errors=0")&&strstr(logs,"kind=submit calls=1 errors=0"));
 assert(!strstr(logs,"kind=info"));
 /* Different bin patterns, exact integer-us stages; no count disappears. */
 uint64_t now=3000000000ull;unsigned state=37;
 for(unsigned n=0;n<5000;n++){
  state=state*1664525+1013904223;unsigned selector=state&0x1ffff;
  (void)polaris_gpu_method_record(&m,selector,n%3,now,now+1000,now+3000,now+6000,now+10000);
  now+=11000;
 }
 uint64_t calls=0,total=0;for(auto&b:m.bins){
  calls+=b.calls;total+=b.total;
  assert(b.auth+b.dispatch+b.lock+b.body==b.total&&b.maximum<=10);
 }
 assert(m.calls==5000&&calls==5000&&total==50000);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory); (p/'test.cpp').write_text(source)
            subprocess.run(['/usr/bin/clang++', '-std=c++17', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', str(p/'test.cpp'), '-o', str(p/'test')], check=True)
            subprocess.run([str(p/'test')], check=True)

    def test_permission_and_completion_checks_still_precede_observation(self):
        text = (ROOT/'tools/PolarisGPU.cpp').read_text()
        for name in ['IOReturn PolarisGPUUserClient::clientMemoryForType(',
                     'IOReturn PolarisGPUUserClient::externalMethod(']:
            actual = function(text, name)
            self.assertLess(actual.index('polaris_gpu_caller_allowed()'), actual.index('IOLockLock(gpuLock)'))
            self.assertLess(actual.index('polaris_gpu_method_record('), actual.index('IOLockUnlock(gpuLock)'))
        actual = function(text, 'IOReturn PolarisGPUUserClient::submit(')
        self.assertLess(actual.index('polaris_gpu_submit('), actual.index('cacheAfter('))
        self.assertLess(actual.index('cacheAfter('), actual.index('POLARIS GPU BO PERF:'))
