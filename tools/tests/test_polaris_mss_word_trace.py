"""Execute the actual word loop and terminal prefix with software observers."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


def function(text, signature):
    start = text.index(signature)
    at = text.index('{', start)
    depth = 1
    end = at + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]


def execute(source):
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder)
        (path/'test.c').write_text(source)
        subprocess.run(['/usr/bin/clang', '-std=c11', '-O1', '-g', '-Wall', '-Wextra',
                        '-Werror', '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                        str(path/'test.c'), '-o', str(path/'test')], check=True)
        subprocess.run([str(path/'test')], check=True)


class WordTraceTests(unittest.TestCase):
    def test_actual_loop_refuses_before_any_further_source_or_target_access(self):
        stage = (ROOT/'shim/polaris/uefi-mss-stage.h').read_text()
        loop = function(stage, 'static inline int pmsi_words(')
        sha = (ROOT/'tools/polaris-wifi-firmware-identity.h').read_text()
        sha = sha[sha.index('struct pwfi_sha256 '):]
        final = function(sha, 'static inline void pwfi_final(')
        sha = sha[:sha.index('static inline void pwfi_final(')] + final
        loader = (ROOT/'shim/polaris/uefi-xnu.c').read_text()
        observer = function(loader, 'static int wifi_native_fault_word_progress(struct pmsi_page*p,')
        source = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
/* Field-only software types: production layouts are qualified separately. */
struct pmsi_page {unsigned bytes,words_issued,words_returned;};
struct pmlc_copy {struct pmsi_page page[256];unsigned pages,observe_page,observe_stage,
 observe_words_issued,observe_words_returned;};
static struct {struct pmlc_copy copy;} wifi_native_parent;
static unsigned publications;
static int wifi_native_fault_publish(unsigned force){assert(force==1);publications++;return 1;}
''' + sha + observer + r'''
static void *src,*dst;static size_t page_bytes;
static unsigned calls,fail_call;
static int observe(struct pmsi_page*p,unsigned stage){
 unsigned word=calls/4,expected=6+calls%4;
 assert(stage==expected && p->words_issued==word+(stage>=8) && p->words_returned==word+(stage==9));
 calls++;
 if(calls==fail_call){
  assert(!mprotect(src,page_bytes,PROT_NONE));assert(!mprotect(dst,page_bytes,PROT_NONE));return 0;
 }
 return 1;
}
#define PMSI_WORD_OBSERVE(p,stage) do{if(!observe(p,stage))return 0;}while(0)
''' + loop + r'''
#undef PMSI_WORD_OBSERVE
#define PMSI_WORD_OBSERVE(p,stage) do{}while(0)
''' + loop.replace('pmsi_words(', 'words_without_observer(', 1) + r'''
int main(void){
 page_bytes=(size_t)sysconf(_SC_PAGESIZE);assert(page_bytes>=4096);
 src=mmap(0,page_bytes,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 dst=mmap(0,page_bytes,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 assert(src!=MAP_FAILED && dst!=MAP_FAILED);
 uint8_t reference[4096] __attribute__((aligned(4096)));
 for(unsigned i=0;i<4096;i++)((uint8_t*)src)[i]=(uint8_t)(i*17+3);
 for(unsigned bytes=0;bytes<=4096;bytes+=1){
  struct pwfi_sha256 a,b;struct pmsi_page p={0},q={0};pwfi_init(&a);pwfi_init(&b);
  calls=fail_call=0;assert(pmsi_words((uintptr_t)dst,(uintptr_t)src,bytes,&a,&p));
  assert(words_without_observer((uintptr_t)reference,(uintptr_t)src,bytes,&b,&q));
  uint8_t ha[32],hb[32];pwfi_final(&a,ha);pwfi_final(&b,hb);
  assert(calls==2048 && !memcmp(dst,reference,4096) && !memcmp(ha,hb,32) && !memcmp(&p,&q,sizeof(p)));
 }
 for(fail_call=1;fail_call<=2048;fail_call++){
  struct pwfi_sha256 hash;struct pmsi_page p={0};pwfi_init(&hash);calls=0;
  assert(!pmsi_words((uintptr_t)dst,(uintptr_t)src,4096,&hash,&p) && calls==fail_call);
  assert(!mprotect(src,page_bytes,PROT_READ|PROT_WRITE));assert(!mprotect(dst,page_bytes,PROT_READ|PROT_WRITE));
 }
 struct pmlc_copy*c=&wifi_native_parent.copy;c->pages=255;
 assert(wifi_native_fault_word_progress((void*)1,6) && !publications);
 for(unsigned page=0;page<256;page++)for(unsigned word=0;word<512;word++)for(unsigned stage=6;stage<=9;stage++){
  c->pages=page;c->page[page].words_issued=word+(stage>=8);c->page[page].words_returned=word+(stage==9);
  unsigned before=publications;
  assert(wifi_native_fault_word_progress(&c->page[page],stage));
  assert(publications==before+(!(word&63)||word==511));
  if(publications!=before)assert(c->observe_page==page && c->observe_stage==stage &&
    c->observe_words_issued==word+(stage>=8) && c->observe_words_returned==word+(stage==9));
 }
 assert(publications==9216);c->pages=254;assert(!wifi_native_fault_word_progress(&c->page[255],6));
 c->pages=255;assert(!wifi_native_fault_word_progress(&c->page[255],5));
 assert(!wifi_native_fault_word_progress(&c->page[255],10) && publications==9216);
 assert(!wifi_native_fault_word_progress((void*)((uintptr_t)&c->page[255]+1),6));
 c->pages=256;assert(!wifi_native_fault_word_progress(&c->page[0],6));
 assert(wifi_native_fault_word_progress(&c->page[256],6));
 c->pages=255;c->page[255].words_issued=c->page[255].words_returned=0;
 assert(!wifi_native_fault_word_progress(&c->page[255],8));
 c->page[255].words_returned=512;assert(!wifi_native_fault_word_progress(&c->page[255],6));
 assert(publications==9216);
 assert(!munmap(src,page_bytes) && !munmap(dst,page_bytes));
 puts("PASS actual word loop4097lengths/2048 protected refusals and bounded-range observer");return 0;
}
'''
        execute(source)

    def test_actual_terminal_prefix_publishes_before_logging(self):
        loader = (ROOT/'shim/polaris/uefi-xnu.c').read_text()
        prefix = function(loader, '__attribute__((noreturn)) static void power_unknown_hold(void)')
        prefix = prefix[:prefix.index('#if EFI_XNU_WIFI_TERMINAL_GOP_DIAGNOSTICS')]
        while '__asm__ volatile(' in prefix:
            start = prefix.index('__asm__ volatile(')
            at = start + len('__asm__ volatile(')
            depth, quote = 1, False
            while depth:
                char = prefix[at]
                if char == '"' and prefix[at-1] != '\\':
                    quote = not quote
                if not quote:
                    depth += (char == '(') - (char == ')')
                at += 1
            self.assertEqual(prefix[at], ';')
            prefix = prefix[:start] + 'arch_samples++;' + prefix[at+1:]
        execute(r'''
#include <assert.h>
#include <stdint.h>
#include <setjmp.h>
#include <stddef.h>
#define EFI_XNU_WIFI_NATIVE_FAULT_HOLD 1
static unsigned arch_samples,publishes,logs;
static jmp_buf stop;
static struct {uint64_t raw[4];} power_hold_raw;
static int wifi_native_fault_publish(unsigned force){assert(force==1 && arch_samples==3 && !logs);publishes++;return 0;}
static void ram_text(const char*s){(void)s;assert(publishes==1);logs++;}
static void ram_hex(const void*p,size_t n){assert(p==&power_hold_raw && n==sizeof(power_hold_raw));logs++;}
''' + prefix + r'''
longjmp(stop,1);}
int main(void){if(!setjmp(stop))power_unknown_hold();assert(publishes==1 && logs==3);return 0;}
''')


if __name__ == '__main__':
    unittest.main()
