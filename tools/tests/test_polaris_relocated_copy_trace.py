"""Actual bounded trace selectors at the next observed native copy boundary."""
from pathlib import Path
import unittest
from tools.tests.test_polaris_mss_word_trace import execute, function

ROOT = Path(__file__).resolve().parents[2]


class RelocatedCopyTraceTests(unittest.TestCase):
    def test_actual_word_selector_uses_only_current_page_in_window(self):
        observer = function((ROOT/'shim/polaris/uefi-xnu.c').read_text(),
                            'static int wifi_native_fault_word_progress(struct pmsi_page*p,')
        execute(r'''
#include <assert.h>
#include <stdint.h>
#define EFI_XNU_WIFI_NATIVE_COPY_TRACE_FIRST 864
struct pmsi_page {unsigned words_issued,words_returned;};
struct pmlc_copy {struct pmsi_page page[1121];unsigned pages,observe_page,observe_stage,
 observe_words_issued,observe_words_returned;};
static struct {struct pmlc_copy copy;}wifi_native_parent;
static unsigned calls,fail;
static int wifi_native_fault_publish(unsigned force){assert(force==1);calls++;return !fail;}
''' + observer + r'''
int main(void){
 struct pmlc_copy*c=&wifi_native_parent.copy;
 for(unsigned page=864;page<1120;page++)for(unsigned word=0;word<512;word++)for(unsigned stage=6;stage<=9;stage++){
  c->pages=page;c->page[page].words_issued=word+(stage>=8);c->page[page].words_returned=word+(stage==9);
  unsigned before=calls;assert(wifi_native_fault_word_progress(&c->page[page],stage));
  assert(calls==before+(!(word&63)||word==511));
  if(calls!=before)assert(c->observe_page==page&&c->observe_stage==stage);
 }
 assert(calls==9216);
 for(unsigned page=0;page<864;page++)assert(wifi_native_fault_word_progress(&c->page[page],6));
 assert(wifi_native_fault_word_progress(&c->page[1120],6)&&calls==9216);
 c->pages=873;assert(!wifi_native_fault_word_progress(&c->page[874],6));
 c->pages=874;c->page[874].words_issued=c->page[874].words_returned=0;
 assert(!wifi_native_fault_word_progress(&c->page[874],8));
 assert(!wifi_native_fault_word_progress((void*)((uintptr_t)&c->page[874]+1),6));
 fail=1;assert(!wifi_native_fault_word_progress(&c->page[874],6)&&calls==9217);
 return 0;
}
''')

    def test_actual_page_macro_selects_exact_256_pages_and_five_stages(self):
        header = (ROOT/'shim/polaris/uefi-mss-modem-copy.h').read_text()
        start = header.index('#define PMLC_TRACE_PAGE')
        macro = header[start:header.index('\n#else', start)]
        execute(r'''
#include <assert.h>
#define EFI_XNU_WIFI_NATIVE_COPY_TRACE_FIRST 864
struct page {unsigned words_issued,words_returned;};
struct copy {unsigned observe_page,observe_stage,observe_words_issued,observe_words_returned;};
static unsigned calls,fail;
#define PMLC_OBSERVE(r) do{(void)(r);calls++;if(fail)return 0;}while(0)
''' + macro + r'''
static int trace(struct copy*c,struct page*p,unsigned index,unsigned stage){PMLC_TRACE_PAGE(c,p,index,stage);return 1;}
int main(void){
 struct copy c={0};struct page p={17,16};
 for(unsigned index=0;index<30720;index++)for(unsigned stage=1;stage<=5;stage++){
  unsigned before=calls;assert(trace(&c,&p,index,stage));
  assert(calls==before+(index>=864&&index<1120));
  if(calls!=before)assert(c.observe_page==index&&c.observe_stage==stage&&
   c.observe_words_issued==(stage>=3?17u:0u)&&c.observe_words_returned==(stage>=3?16u:0u));
 }
 assert(calls==1280);fail=1;assert(!trace(&c,&p,874,2)&&calls==1281);return 0;
}
''')


if __name__ == '__main__':
    unittest.main()
