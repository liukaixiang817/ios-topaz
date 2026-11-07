"""Actual own-state boundary policy, native identity guard and caller order."""
import subprocess
import tempfile
from pathlib import Path
import unittest

from tools.tests.test_polaris_mss_word_trace import ROOT, execute, function


class CopyBoundaryTests(unittest.TestCase):
    def test_actual_policy_identity_fields_callbacks_and_refusals(self):
        header = (ROOT/'shim/polaris/uefi-mss-modem-copy.h').read_text()
        policy = function(header, 'static inline int pmlc_mark_boundary(')
        source = (ROOT/'shim/polaris/uefi-xnu.c').read_text()
        copy = function(source, 'static int pmlc_copy_boundary(')
        auth = function(source, 'static int pmsn_copy_boundary(')
        execute(r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>
#define PMLC_PAGES 30720
#define PMIM_SEGMENTS 28
struct pmlc_copy {unsigned attempted,ready,unknown,error,complete,pages,segments;
 unsigned observe_page,observe_stage,observe_words_issued,observe_words_returned;};
struct pmsn_state {uintptr_t copy;};
static struct {struct pmlc_copy copy;struct pmsn_state auth;}wifi_native_parent;
static unsigned calls,fail;
static int wifi_native_fault_publish(unsigned force){assert(force==1);calls++;return !fail;}
''' + policy + copy + auth + r'''
static void init(void){memset(&wifi_native_parent,0,sizeof(wifi_native_parent));
 wifi_native_parent.copy.attempted=wifi_native_parent.copy.ready=1;
 wifi_native_parent.auth.copy=(uintptr_t)&wifi_native_parent.copy;}
int main(void){
 struct pmlc_copy*c=&wifi_native_parent.copy;struct pmsn_state*a=&wifi_native_parent.auth;
 init();unsigned before;
 for(unsigned page=0;page<30720;page++)for(unsigned stage=11;stage<=15;stage++){
  c->pages=page;c->observe_words_issued=512;c->observe_words_returned=511;before=calls;
  assert(pmsn_copy_boundary(a,stage)&&calls==before+1);
  assert(c->observe_page==page&&c->observe_stage==stage&&!c->observe_words_issued&&!c->observe_words_returned);
  assert(c->pages==page&&!c->unknown&&!c->error&&!c->complete);
 }
 assert(calls==30720*5);
 for(unsigned fault=0;fault<10;fault++){
  init();struct pmlc_copy other=*c;
  if(!fault)c->attempted=0;if(fault==1)c->ready=0;if(fault==2)c->unknown=1;
  if(fault==3)c->error=1;if(fault==4)c->complete=1;if(fault==5)c->pages=30720;
  if(fault==6)c->segments=28;if(fault==7)a->copy=1;
  before=calls;struct pmlc_copy saved=*c;
  assert(!(fault==8?pmlc_copy_boundary(&other,13):fault==9?pmsn_copy_boundary((void*)1,12):pmsn_copy_boundary(a,12)));
  assert(calls==before&&!memcmp(c,&saved,sizeof(saved)));
 }
 init();before=calls;assert(!pmlc_copy_boundary(c,10)&&!pmlc_copy_boundary(c,16)&&calls==before);
 assert(!pmlc_mark_boundary(0,c,11));fail=1;assert(!pmsn_copy_boundary(a,11)&&calls==before+1&&c->observe_stage==11);
 return 0;
}
''')

    def test_actual_compiler_builder_scope_and_parent_order(self):
        text = (ROOT/'shim/polaris/uefi-mss-modem-copy.h').read_text()
        start = text.index('#ifndef EFI_XNU_WIFI_NATIVE_COPY_BOUNDARY_TRACE')
        guard = text[start:text.index('#ifndef EFI_XNU_WIFI_VENDOR_SEGMENT_EXTENTS', start)]
        for value, fault, accepted in [(0, 0, True), (1, 1, True), (1, 0, False), (2, 1, False), (-1, 1, False)]:
            result = subprocess.run(['/usr/bin/clang', '-E', '-x', 'c', '-'],
                input=f'#define EFI_XNU_WIFI_NATIVE_COPY_BOUNDARY_TRACE {value}\n#define EFI_XNU_WIFI_NATIVE_FAULT_HOLD {fault}\n'+guard,
                capture_output=True, text=True)
            self.assertEqual(result.returncode == 0, accepted)
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder)
            result = subprocess.run(['python3', str(ROOT/'tools/build-polaris-uefi-xnu.py'),
                '--zig', str(p/'missing'), '--kernel', str(p/'kernel'), '--payload', str(p/'payload'),
                '--output', str(p/'output'), '--wifi-native-copy-boundary-trace'], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('requires --wifi-native-fault-hold', result.stderr)
            self.assertFalse((p/'output').exists())
        parent = function((ROOT/'shim/polaris/uefi-wifi-startup-parent.h').read_text(),
                          'static inline int pwns_step(')
        # Actual parent prefix, with all subsequent producer cases excluded.
        parent = parent[:parent.index('    s->turns++;')]+'return 1;}\n'
        execute(r'''
#include <assert.h>
#include <stdint.h>
#define EFI_XNU_WIFI_NATIVE_COPY_BOUNDARY_TRACE 1
#define PWNS_IMAGES 1
#define PWNS_AUTH 19
#define PWNS_READY 46
#define PMSN_COPY 5
struct pmsn_state {unsigned phase;};
struct pwns_parent {unsigned attempted,unknown,error,phase;uint64_t turns;
 struct pmsn_state auth;struct {unsigned held;}owner;};
static unsigned order,fail_boundary,fail_live;
static int pmsn_copy_boundary(struct pmsn_state*s,unsigned stage){assert(s->phase==5&&stage==11&&!order);order=1;return !fail_boundary;}
static int pmsc_live(void*o){(void)o;assert(order==1);order=2;return !fail_live;}
static int pwns_fail(struct pwns_parent*s,unsigned error){s->unknown=1;s->error=error;return -1;}
''' + parent + r'''
int main(void){
 for(unsigned b=0;b<2;b++){for(unsigned l=0;l<2;l++){
 struct pwns_parent s={.attempted=1,.phase=19,.auth={5}};fail_boundary=b;fail_live=l;order=0;
 assert(pwns_step(&s)==(b||l?-1:1));assert(order==(b?1:2));
 if(b||l){assert(s.unknown&&s.error==3);unsigned before=order;assert(pwns_step(&s)==-1&&order==before);}
 }}
 return 0;}
''')


if __name__ == '__main__':
    unittest.main()
