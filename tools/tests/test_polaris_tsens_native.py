"""Native readonly boundaries and future display deadlines, no hardware claim."""
from pathlib import Path
import importlib.util,json,subprocess,tempfile,unittest
from .test_polaris_gpu_lifetime import function

ROOT=Path(__file__).resolve().parents[2]
PATCH=ROOT/'xnu/profiles/polaris/0893-polaris-own-TSENS-readonly-and-future-display-deadlines.patch'
ADDED='\n'.join(s[1:] for s in PATCH.read_text().splitlines() if s.startswith('+') and not s.startswith('+++'))
spec=importlib.util.spec_from_file_location('tsens_builder',ROOT/'tools/build-polaris-uefi-xnu.py')
builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)

class TsensNative(unittest.TestCase):
    def test_exact_wire_core_and_pre_mapping_platform_refusal(self):
        header=(ROOT/'tools/polaris-tsens-readonly.h').read_text()
        header=header.replace('#ifndef POLARIS_TSENS_READONLY_H\n#define POLARIS_TSENS_READONLY_H\n','').replace('#include <stdint.h>\n','').replace('#include <stdbool.h>\n','')[:-7]
        body=ADDED.split('/* BEGIN OWN TSENS READONLY CORE: tested verbatim host implementation. */\n',1)[1].split('\n/* END OWN TSENS READONLY CORE. */',1)[0]
        self.assertEqual(body,header)
        prepare=function(ADDED,'static void polaris_tsens_prepare(')
        self.assertLess(prepare.index('if(flag!=1 || !physical'),prepare.index('withPhysicalAddress(0xc263000,0x1ff,kIODirectionIn)'))
        self.assertIn('kIOMapInhibitCache|kIOMapReadOnly',prepare)
        self.assertIn('const volatile uint32_t *polaris_tsens_regs',ADDED)
        self.assertNotRegex(ADDED,r'polaris_tsens_regs\[[^\]]+\]\s*(?:=(?!=)|\+\+|--|[|&^+\-]=)')
        self.assertIn('offset<0xbc || offset>0xd0 || (offset&3)',ADDED)
        self.assertIn('polaris_tsens_prepare(thermal_platform)',ADDED)
        self.assertIn('__atomic_store_n(&polaris_tsens_ready,0,__ATOMIC_RELEASE)',ADDED)

    def test_exact_deadlines_do_not_create_overdue_or_idle_spin(self):
        actual=function(ADDED,'static uint32_t polaris_fb_precise_deadline_us(')
        source='#include <stdint.h>\n#include <assert.h>\n#include "polaris-display-cadence.h"\n'+actual+r'''
int main(){
 assert(polaris_fb_precise_deadline_us(10000,10500,0,0)==500);
 assert(polaris_fb_precise_deadline_us(10000,20000,10200,1)==200);
 assert(polaris_fb_precise_deadline_us(10000,20000,9000,0)==10000);
 assert(polaris_fb_precise_deadline_us(10000,9000,0,0)==1000);
 assert(polaris_fb_precise_deadline_us(UINT64_MAX,0,0,0)==1000);
 for(uint64_t gap=1;gap<1000;gap++) {
  uint64_t now=100000;
  /* Known future notification: one exact wake, then next period advances. */
  assert(polaris_fb_precise_deadline_us(now,now+gap,0,0)==gap);
  assert(polaris_fb_precise_deadline_us(now+gap,now+gap,0,0)==1000);
  uint64_t next=polaris_fb_next_vsync_us(now+gap,now+gap);
  assert(next==now+gap+16667);
  assert(polaris_fb_precise_deadline_us(now+gap,next,0,0)==16667);
  /* Future clean-copy wake may catch a just-published frame. Once expired,
   * it must yield to VSYNC, never re-arm the same microsecond deadline. */
  assert(polaris_fb_precise_deadline_us(now,now+16667,now+gap,0)==gap);
  assert(polaris_fb_precise_deadline_us(now+gap,now+16667,now+gap,0)==16667-gap);
 }
 for(uint64_t n=1;n<100000;n+=17)for(unsigned dirty=0;dirty<2;dirty++) {
  uint64_t vsync=n+1+(n%20000),present=n+1+(n%17000);
  unsigned delay=polaris_fb_precise_deadline_us(n,vsync,present,dirty);
  assert(delay>=1&&delay<=16667);
  if(delay<1000)assert(n+delay==vsync||n+delay==present);
  assert(polaris_fb_next_vsync_us(n,vsync)==vsync); /* no early notification */
 }
 return 0;}
'''
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp);(p/'a.cpp').write_text(source)
            subprocess.run(['/usr/bin/clang++','-std=c++17','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(ROOT/'tools'),str(p/'a.cpp'),'-o',str(p/'a')],check=True)
            subprocess.run([str(p/'a')],check=True)

    def test_readonly_payload_intent_is_explicit_and_bound_to_RAM_mode(self):
        tokens=[b'polaristsens=1',b'polarisramcow=1',b'ufsrw=0',b'polarisquiesce=1']
        call=builder.tsens_readonly_intent
        self.assertTrue(call(tokens,True,7,4,False,None,True,False,False,True))
        self.assertTrue(call(tokens,True,7,4,True,'success',False,False,False,True))
        cases=[(tokens,False,7,4,False,None,True,False,False,True),
               (tokens,True,1,4,False,None,True,False,False,True),
               (tokens,True,7,2,False,None,True,False,False,True),
               (tokens,True,7,4,False,None,False,False,False,True),
               (tokens,True,7,4,False,None,True,True,False,True),
               (tokens,True,7,4,False,None,True,False,True,True),
               (tokens,True,7,4,False,None,True,False,False,False)]
        for args in cases:
            with self.assertRaisesRegex(ValueError,'TSENS'):call(*args)
        for wrong in [[],tokens+tokens[:1],[b'polaristsens=2']+tokens[1:],tokens[:-1],tokens[:2]+[b'ufsrw=1']+tokens[3:]]:
            with self.assertRaisesRegex(ValueError,'TSENS'):call(wrong,True,7,4,False,None,True,False,False,True)

if __name__=='__main__':unittest.main()
