"""Pure eligibility/fault tests. No MMIO, frequency control or phone admission."""
from pathlib import Path
import subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[2]

class ThermalEligibility(unittest.TestCase):
 def test_real_decoder_gate_hysteresis_and_faults(self):
  source=r'''
#include "polaris-thermal-eligibility.h"
#include <assert.h>
#include <string.h>
static struct polaris_tsens_sample sample(uint64_t us,int32_t gold,int32_t gpu){
 struct polaris_tsens_sample p={0};p.began_us=us-30;p.ended_us=us;
 for(unsigned i=0;i<6;i++){
  int32_t v=i<4?gold:gpu;p.temperature_mC[i]=v;
  p.raw[0][i]=p.raw[1][i]=(1u<<21)|((uint32_t)(v/100)&0xfff);
 }p.max_gold_mC=gold;p.max_gpu_mC=gpu;return p;
}
static void feed(struct polaris_thermal_eligibility*s,uint64_t us,int32_t gold,int32_t gpu){
 struct polaris_tsens_sample p=sample(us,gold,gpu);assert(pte_observe(s,&p,0,us));
}
static void ready(struct polaris_thermal_eligibility*s){
 memset(s,0,sizeof(*s));feed(s,1000000,63000,50000);
 assert(pte_verdict(s,1000000)==PTE_WARMUP);
 feed(s,1250000,63100,50100);feed(s,1500000,63200,50200);
 assert(pte_verdict(s,1500000)==PTE_ALLOW);
}
int main(void){struct polaris_thermal_eligibility s;ready(&s);
 assert(pte_verdict(&s,2000000)==PTE_ALLOW);
 assert(pte_verdict(&s,2000001)==PTE_STALE);
 /* A late update has to build a new complete observation window. */
 feed(&s,2250000,63300,50300);assert(pte_verdict(&s,2250000)==PTE_WARMUP);
 ready(&s);struct polaris_tsens_sample p=sample(1750000,63300,50300);
 p.raw[1][4]&=~(1u<<21);assert(!pte_observe(&s,&p,0,1750000));
 assert(pte_verdict(&s,1750000)==PTE_REJECTED);
 for(uint64_t t=2000000;t<=11750000;t+=250000)feed(&s,t,63400+(t%500000?100:0),50400+(t%500000?100:0));
 assert(pte_verdict(&s,11750000)==PTE_ALLOW);
 /* Exact conservative cutoffs, ten-second lower-temperature hysteresis. */
 ready(&s);feed(&s,1750000,75000,50000);assert(pte_verdict(&s,1750000)==PTE_HOT);
 for(uint64_t t=2000000;t<=11750000;t+=250000)feed(&s,t,70100,55100);
 assert(pte_verdict(&s,11750000)==PTE_HOT);
 feed(&s,12000000,70000,55000);assert(!s.hot);
 ready(&s);feed(&s,1750000,63000,60000);assert(pte_verdict(&s,1750000)==PTE_HOT);
 /* Repeated identical registers do not become a freshness guarantee. */
 ready(&s);for(uint64_t t=1750000;t<=6750000;t+=250000)feed(&s,t,63200,50200);
 assert(pte_verdict(&s,6750000)==PTE_FROZEN);
 ready(&s);p=sample(1750000,63300,50300);p.max_gpu_mC=40000;
 assert(!pte_observe(&s,&p,0,1750000));
 ready(&s);p=sample(1750000,63300,50300);p.ended_us=1750001;
 assert(!pte_observe(&s,&p,0,1750000));
 ready(&s);assert(!pte_observe(&s,0,PTS_READ,1750000));
 ready(&s);assert(pte_verdict(&s,1499999)==PTE_CLOCK);
 assert(pte_verdict(&s,2000000)==PTE_CLOCK); /* Reversal is terminal this boot. */
 ready(&s);pte_stop(&s);assert(pte_verdict(&s,2000000)==PTE_STOPPED);
 p=sample(2000000,63400,50400);assert(!pte_observe(&s,&p,0,2000000));
 /* Every individual wire/summary byte mutation is independently decoded. */
 unsigned seed=100;
 for(unsigned n=0;n<10000;n++){
  ready(&s);p=sample(1750000,63300,50300);seed=seed*1664525u+1013904223u;
  unsigned char*bytes=(unsigned char*)&p;bytes[seed%sizeof(p)]^=1u<<((seed>>16)%8);
  if(pte_observe(&s,&p,0,1750000)){
   assert(pte_sample_valid(&p,1750000));
   unsigned verdict=pte_verdict(&s,1750000);assert(verdict==PTE_ALLOW||verdict==PTE_HOT);
  }else assert(pte_verdict(&s,1750000)!=PTE_ALLOW);
 }
 return 0;
}'''
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);(p/'test.c').write_text(source)
   subprocess.run(['/usr/bin/clang','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(ROOT/'tools'),str(p/'test.c'),'-o',str(p/'test')],check=True)
   subprocess.run([str(p/'test')],check=True)

if __name__=='__main__':unittest.main()
