"""Real pure planner under sanitizers, no device/frequency/thermal admission."""
from pathlib import Path
import subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[2]
class ThermalBudget(unittest.TestCase):
 def test_unrenewable_budget_and_actual_low_confirmation(self):
  source=r'''
#include "polaris-a630-thermal-performance.h"
#include <assert.h>
#include <string.h>
static void plan(struct a630_thermal_state*s,uint64_t now,bool eligible,unsigned expected){
 uint32_t p=99,b=99;assert(a630_thermal_plan(s,now,now,eligible,&p,&b));
 assert(p==expected && b==(expected==4?8u:4u));
}
int main(void){struct a630_thermal_state s={0};
 plan(&s,100,1,1);assert(s.reason==AT_UNCONFIRMED);
 assert(a630_thermal_confirm(&s,100,1,4));plan(&s,101,1,4);
 assert(a630_thermal_confirm(&s,101,4,8));uint64_t first=s.cycle_since_ns;
 /* Thousands of eligibility renewals cannot move the actual budget origin. */
 for(uint64_t t=1000000000;t<120000000101ull;t+=1000000000){
  plan(&s,t,1,4);assert(a630_thermal_confirm(&s,t,4,8));assert(s.cycle_since_ns==first);
 }
 plan(&s,120000000101ull,1,1);assert(s.cooling);
 /* A low INTENT without a successful transaction cannot serve a cooldown. */
 plan(&s,140000000101ull,1,1);assert(!s.low_since_ns);
 assert(a630_thermal_confirm(&s,140000000101ull,1,4));
 plan(&s,149999999999ull,1,1);assert(s.cooling);
 assert(a630_thermal_confirm(&s,149999999999ull,1,4));
 assert(s.low_since_ns==140000000101ull);
 plan(&s,150000000101ull,1,4);assert(!s.cooling && !s.cycle_since_ns);
 assert(a630_thermal_confirm(&s,150000000101ull,4,8));
 assert(s.cycle_since_ns==150000000101ull);
 plan(&s,150100000101ull,0,1);assert(s.reason==AT_SENSOR);
 assert(a630_thermal_confirm(&s,150100000101ull,1,4));
 plan(&s,150200000101ull,1,4); /* Sensor recovery alone cannot reset budget. */
 assert(a630_thermal_confirm(&s,150200000101ull,4,8));
 assert(s.cycle_since_ns==150000000101ull);
 uint32_t p,b;assert(a630_thermal_plan(&s,150500000102ull,150200000101ull,1,&p,&b));
 assert(p==1&&b==4&&s.reason==AT_IDLE);
 assert(!a630_thermal_plan(&s,150500000103ull,150500000104ull,1,&p,&b)&&s.fault);
 memset(&s,0,sizeof(s));assert(!a630_thermal_confirm(&s,1,4,8));
 memset(&s,0,sizeof(s));assert(a630_thermal_confirm(&s,100,1,4));
 assert(!a630_thermal_plan(&s,99,0,1,&p,&b));
 memset(&s,0,sizeof(s));assert(!a630_thermal_plan(&s,UINT64_MAX,0,1,&p,&b));
 unsigned seed=101;
 for(unsigned trial=0;trial<200;trial++){
  memset(&s,0,sizeof(s));uint64_t now=1;assert(a630_thermal_confirm(&s,now,1,4));
  for(unsigned n=0;n<3000;n++){
   seed=seed*1664525u+1013904223u;now+=100000000;
   bool eligible=(seed%31)!=0;uint64_t activity=(seed%13)?now:0;
   uint64_t before=s.cycle_since_ns;bool was_high=s.high;
   assert(a630_thermal_plan(&s,now,activity,eligible,&p,&b));
   if(p==4){assert(eligible&&activity);assert(!s.cooling);assert(!s.cycle_since_ns||now-s.cycle_since_ns<A630_THERMAL_HIGH_NS);}
   /* Delayed/failed IO is represented by NOT confirming it. */
   if(seed%7){assert(a630_thermal_confirm(&s,now,p,b));}
   if(was_high && p==4 && before)assert(s.cycle_since_ns==before);
  }
 }
 return 0;}
'''
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);(p/'t.c').write_text(source)
   subprocess.run(['/usr/bin/clang','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(ROOT/'tools'),str(p/'t.c'),'-o',str(p/'t')],check=True)
   subprocess.run([str(p/'t')],check=True)
if __name__=='__main__':unittest.main()
