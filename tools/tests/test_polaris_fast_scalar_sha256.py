"""Actual scalar SHA header: digests, partial states and admitted byte bounds."""
from pathlib import Path
import hashlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools.tests import test_polaris_mss_word_trace as word_trace

ROOT = Path(__file__).resolve().parents[2]


def core():
    text = (ROOT/'tools/polaris-wifi-firmware-identity.h').read_text()
    return text[text.index('struct pwfi_sha256 '):text.index('static inline uint64_t pwfi_le(')]


class FastScalarShaTests(unittest.TestCase):
    def test_actual_header_matches_hashlib_with_general_registers_only(self):
        source = '#include <stdint.h>\n#include <stddef.h>\n#define POLARIS_WIFI_SCALAR_SHA256_FAST 1\n'+core()+r'''
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
static void emit(unsigned n){
 uint8_t*p=malloc(n?n:1),out[32];assert(p);
 for(unsigned i=0;i<n;i++)p[i]=(uint8_t)(i*17+i/7+3);
 struct pwfi_sha256 h;pwfi_init(&h);
 /* Multiple calls include every partial-block state. */
 for(unsigned at=0;at<n;){unsigned bytes=(at%131)+1;if(bytes>n-at)bytes=n-at;
  pwfi_volatile_bytes(&h,p+at,bytes);at+=bytes;}
 pwfi_final(&h,out);printf("%u ",n);for(unsigned i=0;i<32;i++)printf("%02x",out[i]);puts("");free(p);
}
int main(void){for(unsigned n=0;n<=1024;n++)emit(n);
 unsigned more[]={4095,4096,4097,8191,8192,65535};for(unsigned i=0;i<6;i++)emit(more[i]);return 0;}
'''
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            (path/'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                '-mgeneral-regs-only', str(path/'test.c'), '-o', str(path/'test')], check=True)
            result = subprocess.check_output([str(path/'test')], text=True)
            for row in result.splitlines():
                size, digest = row.split()
                data = bytes((i*17+i//7+3)&255 for i in range(int(size)))
                self.assertEqual(digest, hashlib.sha256(data).hexdigest())

    def test_actual_feed_never_reads_beyond_admitted_tail(self):
        text = core()
        source = '#include <stdint.h>\n#include <stddef.h>\n#define POLARIS_WIFI_SCALAR_SHA256_FAST 0\n'
        source += text.replace('pwfi_', 'baseline_')
        source += '\n#undef POLARIS_WIFI_SCALAR_SHA256_FAST\n#define POLARIS_WIFI_SCALAR_SHA256_FAST 1\n'+text+r'''
#include <assert.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
int main(void){
 size_t page=(size_t)sysconf(_SC_PAGESIZE);assert(page>=4096);
 uint8_t*all=mmap(0,3*page,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);assert(all!=MAP_FAILED);
 assert(!mprotect(all+page,page,PROT_READ|PROT_WRITE));
 for(size_t i=0;i<page;i++)all[page+i]=(uint8_t)(i*31+7);
 for(unsigned prefix=0;prefix<64;prefix++)for(unsigned n=0;n<=(prefix?129u:4096u);n++){
  const uint8_t*p=all+2*page-n;struct baseline_sha256 a;struct pwfi_sha256 b;
  baseline_init(&a);pwfi_init(&b);
  for(unsigned k=0;k<prefix;k++){baseline_byte(&a,(uint8_t)k);pwfi_byte(&b,(uint8_t)k);}
  for(unsigned k=0;k<n;k++)baseline_byte(&a,p[k]);
  pwfi_volatile_bytes(&b,p,n);uint8_t x[32],y[32];baseline_final(&a,x);pwfi_final(&b,y);
  assert(!memcmp(x,y,32));
 }
 assert(!munmap(all,3*page));return 0;
}
'''
        word_trace.execute(source)

    def test_actual_word_loop_and_protected_refusals_with_fast_sha(self):
        execute = word_trace.execute
        with patch.object(word_trace, 'execute',
                          lambda source: execute('#define POLARIS_WIFI_SCALAR_SHA256_FAST 1\n'+source)):
            word_trace.WordTraceTests().test_actual_loop_refuses_before_any_further_source_or_target_access()


if __name__ == '__main__':
    unittest.main()
