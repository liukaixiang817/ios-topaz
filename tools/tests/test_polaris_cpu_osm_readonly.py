"""Own-board RO admission and original OSM LUT wire decoding, never HW timing."""
from pathlib import Path
import subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[2]
class OSMReadOnly(unittest.TestCase):
 def test_native_guard_and_bounded_original_LUT_decoder(self):
  source=r'''
#include "polaris-uefi-cpu.h"
#include <assert.h>
#include <string.h>
int main(void){
#define GUARD(F,M,T,N,A,I,C,B,S,P) polaris_osm_ro_allowed(F,M,T,N,A,I,C,B,S,P)
#define GOOD(F,M,T,N,A,I,C,B,S,P) assert(GUARD(F,M,T,N,A,I,C,B,S,P))
#define BAD(F,M,T,N,A,I,C,B,S,P) assert(!GUARD(F,M,T,N,A,I,C,B,S,P))
 GOOD(1,1,0x700,4,0x81000700,0x516f802d,19200000,0x180000000,0xfc8a0000,1);
 BAD(0,1,0x700,4,0x81000700,0x516f802d,19200000,0x180000000,0xfc8a0000,1);
 BAD(2,1,0x700,4,0x81000700,0x516f802d,19200000,0x180000000,0xfc8a0000,1);
 BAD(1,0,0x700,4,0x81000700,0x516f802d,19200000,0x180000000,0xfc8a0000,1);
 BAD(1,1,7,4,0x80000007,0x410fd050,62500000,0x130000000,0xfc8a0000,1);
 BAD(1,1,0x700,2,0x81000700,0x516f802d,19200000,0x180000000,0xfc8a0000,1);
 BAD(1,1,0x700,4,0x81000600,0x516f802d,19200000,0x180000000,0xfc8a0000,1);
 BAD(1,1,0x700,4,0x81000700,0x516f803d,19200000,0x180000000,0xfc8a0000,1);
 BAD(1,1,0x700,4,0x81000700,0x516f802d,62500000,0x180000000,0xfc8a0000,1);
 BAD(1,1,0x700,4,0x81000700,0x516f802d,19200000,0x130000000,0xfc8a0000,1);
 BAD(1,1,0x700,4,0x81000700,0x516f802d,19200000,0x180000000,0xfc8a4000,1);
 BAD(1,1,0x700,4,0x81000700,0x516f802d,19200000,0x180000000,0xfc8a0000,0);
 uint32_t words[40],old[40];
 for(unsigned i=0;i<40;i++)words[i]=(1u<<30)|(4u<<16)|(32+i);
 memcpy(old,words,sizeof(words));assert(polaris_osm_lut_rows(words)==40);
 assert(!polaris_osm_lut_rows(0));
 assert(polaris_osm_requested_hz(words,40,0)==614400000);
 assert(polaris_osm_requested_hz(words,40,39)==1363200000);
 assert(!polaris_osm_requested_hz(words,40,40));
 assert(!polaris_osm_requested_hz(words,41,0));
 assert(!polaris_osm_requested_hz(words,40,UINT32_MAX));
 assert(!polaris_osm_requested_hz(0,40,0));
 assert(polaris_osm_lut_requested_hz(4u<<16)==300000000);
 assert(!polaris_osm_lut_requested_hz(0));
 assert(!polaris_osm_lut_requested_hz((1u<<30)|(5u<<16)|146));
 assert(polaris_osm_lut_requested_hz((1u<<30)|(4u<<16)|146)==2803200000ull);
 assert(!memcmp(old,words,sizeof(words)));
 words[7]=words[6];assert(polaris_osm_lut_rows(words)==7);
 words[7]=(1u<<30)|(1u<<16)|38; /* Same Hz, different active core count is NOT terminator. */
 assert(polaris_osm_lut_rows(words)==40);
 unsigned seed=123;
 for(unsigned n=0;n<5000;n++){
  for(unsigned i=0;i<40;i++){seed=seed*1664525+1013904223;words[i]=seed;}
  memcpy(old,words,sizeof(words));unsigned rows=polaris_osm_lut_rows(words);assert(rows>=1&&rows<=40);
  for(unsigned i=0;i<=40;i++)(void)polaris_osm_requested_hz(words,rows,i);
  assert(!memcmp(old,words,sizeof(words)));
 }
 return 0;
}'''
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);(p/'a.c').write_text(source)
   subprocess.run(['/usr/bin/clang','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(ROOT/'tools'),str(p/'a.c'),'-o',str(p/'a')],check=True)
   subprocess.run([str(p/'a')],check=True)
 def test_register_inventory_is_bounded_and_no_register_store_is_added(self):
  patch=(ROOT/'xnu/profiles/polaris/0884-polaris-stock-OSMv2-readonly-inventory.patch').read_text()
  added='\n'.join(s[1:] for s in patch.splitlines() if s.startswith('+') and not s.startswith('+++'))
  self.assertIn('const volatile uint32_t *reg=',added)
  self.assertLess(added.index('if(!polaris_osm_ro_allowed('),added.index('withPhysicalAddress(0x17d45800,0x1400,kIODirectionIn)'))
  self.assertIn('kIOMapInhibitCache|kIOMapReadOnly',added)
  self.assertNotRegex(added,r'reg\[[^\]]+\]\s*(?:=(?!=)|\+\+|--|[|&^+\-]=)')
  for token in ['0x110+n*32','0x920+n*4','0x9c0+counter_core*4','no clock/voltage writes']:
   self.assertIn(token,added)
if __name__=='__main__':unittest.main()
