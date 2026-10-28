"""Stock table limits, bounded activity policy and failed restore with injected IO.
These are policy/transaction tests, never a claim of hardware CPU frequency.
"""
from pathlib import Path
import subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[2]
class StockPerformance(unittest.TestCase):
 def test_real_policy_transactions_and_faults(self):
  source=r'''
#include "polaris-uefi-cpu.h"
#include <assert.h>
#include <string.h>
struct fake {uint32_t reg[0x1400/4],writes,barriers,deny;};
static uint32_t rd(void *c,uint32_t o){assert(!(o&3)&&o<0x1400);return ((struct fake*)c)->reg[o/4];}
static void wr(void *c,uint32_t value){struct fake*f=c;assert(value==0||value==22);f->writes++;if(!f->deny)f->reg[0x920/4]=value;}
static void bar(void*c){((struct fake*)c)->barriers++;}
static void setup(struct fake*f,struct polaris_cpu_perf_state*s,struct polaris_cpu_perf_io*io){
 memset(f,0,sizeof(*f));memset(s,0,sizeof(*s));uint32_t lut[40];
 for(unsigned i=0;i<40;i++){unsigned j=i<27?i:26;unsigned l=j<23?43+(138-43)*j/22:141+j-23;
  lut[i]=(1u<<30)|((j<23?4:1)<<16)|l;f->reg[(0x110+i*32)/4]=lut[i];}
 f->reg[0]=3;*io=(struct polaris_cpu_perf_io){f,rd,wr,bar};
 assert(polaris_cpu_perf_init(s,lut,3,0,0));assert(s->target==22&&s->saved==0);
}
int main(void){struct fake f;struct polaris_cpu_perf_state s;struct polaris_cpu_perf_io io;
 setup(&f,&s,&io);uint32_t before[0x1400/4];memcpy(before,f.reg,sizeof(before));
 assert(polaris_cpu_perf_tick(&s,&io,1,0)&&!f.writes);
 assert(polaris_cpu_perf_tick(&s,&io,1000000000,1000000000)&&s.current==22&&f.writes==1&&f.barriers==1);
 assert(polaris_cpu_perf_tick(&s,&io,1100000000,1000000000)&&f.writes==1);
 assert(polaris_cpu_perf_tick(&s,&io,1250000001,1000000000)&&s.current==0&&f.writes==2);
 assert(polaris_cpu_perf_tick(&s,&io,2000000000,2000000000)&&s.current==22);
 assert(polaris_cpu_perf_tick(&s,&io,31999999999,31999999999)&&s.current==22);
 assert(polaris_cpu_perf_tick(&s,&io,32000000000,32000000000)&&s.current==0);
 assert(s.cool_until==42000000000ull);
 assert(polaris_cpu_perf_tick(&s,&io,41999999999,41999999999)&&s.current==0);
 assert(polaris_cpu_perf_tick(&s,&io,42000000000,42000000000)&&s.current==22);
 assert(polaris_cpu_perf_stop(&s,&io)&&s.current==0&&s.stopped);
 assert(!polaris_cpu_perf_tick(&s,&io,42000000001,42000000001));
 assert(!memcmp(before,f.reg,sizeof(before))); /* No non-request register changed. */
 setup(&f,&s,&io);f.deny=1;
 assert(!polaris_cpu_perf_tick(&s,&io,1,1)&&s.fault==3&&f.reg[0x920/4]==0);
 assert(polaris_cpu_perf_stop(&s,&io)); /* Denied boost left known original request. */
 setup(&f,&s,&io);assert(polaris_cpu_perf_tick(&s,&io,1,1));f.deny=1;
 assert(!polaris_cpu_perf_stop(&s,&io)&&s.fault==3&&f.reg[0x920/4]==22); /* Must refuse native reset. */
 setup(&f,&s,&io);f.reg[0x920/4]=7;
 assert(!polaris_cpu_perf_tick(&s,&io,1,1)&&s.fault==2&&f.writes==0);
 assert(!polaris_cpu_perf_stop(&s,&io)&&f.writes==0); /* Never overwrite another owner. */
 setup(&f,&s,&io);f.reg[(0x110+32)/4]^=1;
 assert(!polaris_cpu_perf_tick(&s,&io,1,1)&&s.fault==1&&f.writes==0);
 assert(!polaris_cpu_perf_stop(&s,&io)&&f.writes==0);
 setup(&f,&s,&io);assert(!polaris_cpu_perf_init(&s,s.lut,3,1,0));
 assert(!polaris_cpu_perf_init(&s,s.lut,1,0,0));assert(!polaris_cpu_perf_init(&s,s.lut,3,0,1));
 setup(&f,&s,&io);uint32_t lut[40];memcpy(lut,s.lut,sizeof(lut));
 lut[22]=(1u<<30)|(1u<<16)|138;assert(!polaris_cpu_perf_init(&s,lut,3,0,0));
 memcpy(lut,s.lut,sizeof(lut));lut[22]=(1u<<30)|(4u<<16)|146;assert(!polaris_cpu_perf_init(&s,lut,3,0,0));
 unsigned seed=72;
 for(unsigned n=0;n<5000;n++){
  setup(&f,&s,&io);memcpy(lut,s.lut,sizeof(lut));seed=seed*1664525+1013904223;
  lut[seed%40]^=1u<<((seed>>16)%32);struct polaris_cpu_perf_state mutated;
  if(polaris_cpu_perf_init(&mutated,lut,3,0,0)){
   assert(mutated.target==22&&((mutated.lut[22]>>16)&7)==4);
   assert(polaris_osm_requested_hz(mutated.lut,27,mutated.target)==2649600000ull);
  }
 }
 setup(&f,&s,&io);
 for(uint64_t n=1;n<20000;n++){
  uint64_t now=n*10000000,activity=n%100<70?now:0;
  assert(polaris_cpu_perf_tick(&s,&io,now,activity));
  assert(s.current==0||s.current==22);
 }
 assert(polaris_cpu_perf_stop(&s,&io));return 0;
}'''
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);(p/'test.c').write_text(source)
   subprocess.run(['/usr/bin/clang','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(ROOT/'tools'),str(p/'test.c'),'-o',str(p/'test')],check=True)
   subprocess.run([str(p/'test')],check=True)
 def test_explicit_performance_intent_and_mode_separation(self):
  import importlib.util
  spec=importlib.util.spec_from_file_location('builder',ROOT/'tools/build-polaris-uefi-xnu.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
  for q,drain,bridge in [(True,'success',False),(True,'peer-refused',False),(False,None,True)]:
   self.assertFalse(m.readonly_osm_intent([b'polarisosm=2'],False,7,4,q,drain,bridge,False,False,True))
  for tokens,ro,perf,n,ufs,marker in [([],False,True,4,False,False),([b'polarisosm=1'],False,True,4,False,False),([b'polarisosm=2'],True,True,4,False,False),([b'polarisosm=2'],False,False,4,False,False),([b'polarisosm=2']*2,False,True,4,False,False),([b'polarisosm=2'],False,True,2,False,False),([b'polarisosm=2'],False,True,4,True,False),([b'polarisosm=2'],False,True,4,False,True)]:
   with self.assertRaises(ValueError):m.readonly_osm_intent(tokens,ro,7,n,False,None,True,ufs,marker,perf)
 def test_native_only_request_store_and_shutdown_before_peer_off(self):
  p=(ROOT/'xnu/profiles/polaris/0885-polaris-bounded-stock-big-cluster-performance.patch').read_text()
  add='\n'.join(l[1:] for l in p.splitlines() if l.startswith('+') and not l.startswith('+++'))
  self.assertEqual(add.count('polaris_perf_regs[0x920/4]=value;'),1)
  import re
  stores=re.findall(r'polaris_perf_regs\[[^\]]+\]\s*=(?!=)',add)
  self.assertEqual(stores,['polaris_perf_regs[0x920/4]='])
  for s in ['if(flag!=2)return','!physical_inventory','cow!=1 || !has_rw || rw || owned || quiesce!=1','polaris_perf_shutdown()!=0','polaris_cpu_performance_poll();','polaris_cpu_performance_activity();']:
   self.assertIn(s,add)
if __name__=='__main__':unittest.main()
