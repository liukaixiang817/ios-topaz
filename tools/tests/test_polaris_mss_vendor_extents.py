"""Actual vendor extent planner and exact partial-store loop on guarded RAM."""
from pathlib import Path
import subprocess
import tempfile
import unittest

from tools.tests.test_polaris_fast_scalar_sha256 import core
from tools.tests.test_polaris_mss_word_trace import execute, function

ROOT = Path(__file__).resolve().parents[2]


class VendorExtentTests(unittest.TestCase):
    def test_actual_planner_page_boundaries_and_refusals(self):
        source = '#include "'+str(ROOT/'shim/polaris/uefi-mss-vendor-extent.h')+'"\n'+r'''
#include <assert.h>
int main(void){
 struct pmve_extent e;
 for(unsigned start=0;start<30720;start++){
  unsigned tails[]={1,7,8,9,4095,4096};
  for(unsigned t=0;t<6;t++){
   struct pmsf_segment g={.target_offset=start*4096,.memsz=tails[t],.filesz=tails[t]/2};
   assert(pmve_plan(&g,0,start,&e)&&e.kind==PMVE_WRITE&&e.target_bytes==g.memsz&&e.source_bytes==g.filesz);
   if(start)assert(pmve_plan(&g,0,start-1,&e)&&e.kind==PMVE_UNTOUCHED&&!e.source_bytes&&!e.target_bytes);
   assert(!pmve_plan(&g,0,start+1,&e)&&!e.kind);
   assert(!pmve_plan(&g,start+1,start,&e));
   if(start)assert(!pmve_plan(&g,start,start-1,&e));
  }
 }
 for(unsigned n=1;n<=8192;n++)for(unsigned f=0;f<4;f++){
  struct pmsf_segment g={.target_offset=8192,.memsz=n,.filesz=f==0?0:f==1?n:f==2?n/2:n-1};
  for(unsigned page=0;page<5;page++){
   int ok=pmve_plan(&g,0,page,&e);unsigned at=page*4096;
   assert(ok==(at<8192+n));if(!ok)continue;
   if(at<8192){assert(e.kind==PMVE_UNTOUCHED&&!e.target_bytes&&!e.source_bytes);continue;}
   unsigned extent=8192+n-at;if(extent>4096)extent=4096;
   unsigned bytes=at-8192<g.filesz?g.filesz-(at-8192):0;if(bytes>extent)bytes=extent;
   assert(e.kind==PMVE_WRITE&&e.target_bytes==extent&&e.source_bytes==bytes);
  }
 }
 struct pmsf_segment good={.target_offset=4096,.filesz=1,.memsz=4096};
 for(unsigned fault=0;fault<5;fault++){
  struct pmsf_segment g=good;if(!fault)g.memsz=0;if(fault==1)g.filesz=4097;
  if(fault==2)g.target_offset++;if(fault==3)g.target_offset=PMVE_BANK_BYTES;
  if(fault==4)g.memsz=PMVE_BANK_BYTES;
  assert(!pmve_plan(&g,0,1,&e)&&!e.kind&&!e.target_bytes&&!e.source_bytes);
 }
 assert(!pmve_plan(0,0,0,&e)&&!pmve_plan(&good,0,0,0));return 0;
}
'''
        execute(source)

    def test_actual_words_exact_extents_hashes_canaries_and_protected_refusals(self):
        loop = function((ROOT/'shim/polaris/uefi-mss-modem-copy.h').read_text(),
                        'static inline int pmlc_vendor_words(')
        source = '#include <stdint.h>\n#include <stddef.h>\n#define POLARIS_WIFI_SCALAR_SHA256_FAST 1\n'+core()+r'''
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
struct pmsi_page {unsigned bytes,words_issued,words_returned;};
static unsigned calls,fail_call;static void *guard_src,*guard_dst;static size_t host_page;
static int observe(struct pmsi_page*p,unsigned stage){
 unsigned word=calls/4;assert(stage==6+calls%4);
 assert(p->words_issued==word+(stage>=8)&&p->words_returned==word+(stage==9));calls++;
 if(calls==fail_call){assert(!mprotect(guard_src,host_page,PROT_NONE)&&!mprotect(guard_dst,host_page,PROT_NONE));return 0;}
 return 1;
}
#define PMSI_WORD_OBSERVE(p,stage) do{if(!observe(p,stage))return 0;}while(0)
'''+loop+r'''
int main(void){
 for(unsigned extent=1;extent<=4096;extent++)for(unsigned mode=0;mode<4;mode++){
  unsigned bytes=mode==0?0:mode==1?extent:mode==2?extent-1:extent/2;
  uint8_t *src=malloc(bytes?bytes:1),*dst;assert(src&&!posix_memalign((void**)&dst,4096,extent));
  for(unsigned j=0;j<bytes;j++)src[j]=(uint8_t)(j*31+extent);
  memset(dst,0xa5,extent);struct pwfi_sha256 h,reference;pwfi_init(&h);pwfi_init(&reference);
  struct pmsi_page p={0};calls=fail_call=0;
  assert(pmlc_vendor_words((uintptr_t)dst,(uintptr_t)src,bytes,extent,&h,&p));
  for(unsigned j=0;j<extent;j++)assert(dst[j]==(j<bytes?src[j]:0));
  for(unsigned j=0;j<bytes;j++)pwfi_byte(&reference,src[j]);uint8_t a[32],b[32];pwfi_final(&h,a);pwfi_final(&reference,b);
  assert(!memcmp(a,b,32)&&p.bytes==bytes&&p.words_issued==(extent+7)/8&&p.words_returned==p.words_issued&&calls==4*p.words_issued);
  /* A separate full-page allocation checks all bytes beyond the admitted tail. */
  free(dst);assert(!posix_memalign((void**)&dst,4096,4096));memset(dst,0xa5,4096);p=(struct pmsi_page){0};pwfi_init(&h);calls=0;
  assert(pmlc_vendor_words((uintptr_t)dst,(uintptr_t)src,bytes,extent,&h,&p));
  for(unsigned j=extent;j<4096;j++)assert(dst[j]==0xa5);free(src);free(dst);
 }
 struct pwfi_sha256 h;struct pmsi_page p={0};pwfi_init(&h);calls=0;
 assert(!pmlc_vendor_words(4096,1,1,0,&h,&p));assert(!pmlc_vendor_words(4096,1,1,4097,&h,&p));
 assert(!pmlc_vendor_words(4097,1,1,1,&h,&p));assert(!pmlc_vendor_words(4096,1,2,1,&h,&p));
 assert(!pmlc_vendor_words(4096,0,1,1,&h,&p)&&!calls&&!p.words_issued);
 host_page=(size_t)sysconf(_SC_PAGESIZE);guard_src=mmap(0,host_page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 guard_dst=mmap(0,host_page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);assert(guard_src!=MAP_FAILED&&guard_dst!=MAP_FAILED);
 unsigned lengths[]={1,7,8,9,4095,4096};
 for(unsigned k=0;k<6;k++)for(fail_call=1;fail_call<=4*((lengths[k]+7)/8);fail_call++){
  calls=0;p=(struct pmsi_page){0};pwfi_init(&h);
  assert(!pmlc_vendor_words((uintptr_t)guard_dst,(uintptr_t)guard_src,lengths[k],lengths[k],&h,&p)&&calls==fail_call);
  assert(!mprotect(guard_src,host_page,PROT_READ|PROT_WRITE)&&!mprotect(guard_dst,host_page,PROT_READ|PROT_WRITE));
 }
 assert(!munmap(guard_src,host_page)&&!munmap(guard_dst,host_page));return 0;
}
'''
        execute(source)

    def test_builder_refuses_vendor_profile_outside_fault_diagnostic(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder)
            result = subprocess.run(['python3', str(ROOT/'tools/build-polaris-uefi-xnu.py'),
                '--zig', str(p/'missing'), '--kernel', str(p/'kernel'), '--payload', str(p/'payload'),
                '--output', str(p/'output'), '--wifi-vendor-segment-extents'], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('requires --wifi-native-fault-hold', result.stderr)
            self.assertFalse((p/'output').exists())


if __name__ == '__main__':
    unittest.main()
