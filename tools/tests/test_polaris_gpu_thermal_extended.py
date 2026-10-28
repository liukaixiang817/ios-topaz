"""Independent bounded-duration opt-in, budget immutability and failures."""
from pathlib import Path
import copy,hashlib,importlib.util,re,subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[2]
def load(n,p):
    s=importlib.util.spec_from_file_location(n,ROOT/p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
builder=load('extended_builder','tools/build-polaris-uefi-xnu.py')
image=load('extended_image','tools/polaris-uefi-xnu-image.py')

class ExtendedThermal(unittest.TestCase):
    def test_bounded_budget_confirmation_and_failures_under_sanitizers(self):
        source=r'''
#include "polaris-a630-thermal-performance.h"
#include <assert.h>
#include <string.h>
int main(void) {
 struct a630_thermal_state s={0};uint32_t p,b;
 assert(a630_thermal_plan_extended(&s,100,100,true,&p,&b)&&p==1);
 assert(s.limit_ns==600000000000ULL);
 assert(a630_thermal_confirm(&s,100,1,4));
 assert(a630_thermal_plan_extended(&s,101,101,true,&p,&b)&&p==4&&b==8);
 assert(a630_thermal_confirm(&s,101,4,8));
 for(uint64_t t=1000000000;t<600000000101ULL;t+=1000000000) {
  assert(a630_thermal_plan_extended(&s,t,t,true,&p,&b)&&p==4&&b==8);
  assert(a630_thermal_confirm(&s,t,4,8));assert(s.cycle_since_ns==101);
 }
 assert(a630_thermal_plan_extended(&s,600000000101ULL,600000000101ULL,true,&p,&b)&&p==1&&b==4&&s.cooling);
 assert(a630_thermal_plan_extended(&s,620000000101ULL,620000000101ULL,true,&p,&b)&&p==1);
 assert(!s.low_since_ns); /* elapsed time without an ACK/return is not a low */
 assert(a630_thermal_confirm(&s,620000000101ULL,1,4));
 assert(a630_thermal_plan_extended(&s,630000000100ULL,630000000100ULL,true,&p,&b)&&p==1);
 assert(a630_thermal_plan_extended(&s,630000000101ULL,630000000101ULL,true,&p,&b)&&p==4);
 assert(a630_thermal_confirm(&s,630000000101ULL,4,8));
 uint64_t first=s.cycle_since_ns;
 assert(a630_thermal_plan_extended(&s,630100000101ULL,630100000101ULL,false,&p,&b)&&p==1&&s.reason==AT_SENSOR);
 assert(a630_thermal_confirm(&s,630100000101ULL,1,4));
 assert(a630_thermal_plan_extended(&s,630200000101ULL,630200000101ULL,true,&p,&b)&&p==4);
 assert(a630_thermal_confirm(&s,630200000101ULL,4,8));assert(s.cycle_since_ns==first);
 assert(a630_thermal_plan_extended(&s,630450000102ULL,630200000101ULL,true,&p,&b)&&p==1&&s.reason==AT_IDLE);
 /* Switching a selected limit, even at idle/cooldown, is a sticky refusal. */
 assert(!a630_thermal_plan(&s,630450000103ULL,630450000103ULL,true,&p,&b)&&s.fault);
 assert(!a630_thermal_plan_extended(&s,630450000104ULL,630450000104ULL,true,&p,&b));
 memset(&s,0,sizeof(s));assert(a630_thermal_plan(&s,100,100,true,&p,&b));
 assert(!a630_thermal_plan_extended(&s,101,101,true,&p,&b)&&s.fault);
 memset(&s,0,sizeof(s));assert(!a630_thermal_plan_bounded(&s,100,100,true,&p,&b,UINT64_MAX)&&s.fault);
 memset(&s,0,sizeof(s));assert(!a630_thermal_plan_bounded(&s,100,100,true,&p,&b,0)&&s.fault);
 memset(&s,0,sizeof(s));assert(!a630_thermal_plan_extended(&s,UINT64_MAX,0,true,&p,&b)&&s.fault);
 memset(&s,0,sizeof(s));assert(!a630_thermal_plan_extended(&s,100,101,true,&p,&b)&&s.fault);
 unsigned seed=0x600120;
 for(unsigned trial=0;trial<150;trial++) {
  memset(&s,0,sizeof(s));uint64_t now=1;assert(a630_thermal_confirm(&s,now,1,4));
  for(unsigned n=0;n<9000;n++) {
   seed=seed*1664525u+1013904223u;now+=100000000;
   bool eligible=(seed%17)!=0;uint64_t active=(seed%31)?now:0;
   uint64_t origin=s.cycle_since_ns;bool was_high=s.high;
   assert(a630_thermal_plan_extended(&s,now,active,eligible,&p,&b));
   /* The plan may finish a real10s confirmed-low interval and open a new
    * cycle. Check its POST-plan origin, retaining the pre-plan origin below
    * to prove that an active high cycle is never renewed. */
   if(p==4)assert(eligible&&active&&!s.cooling&&(!s.cycle_since_ns||now-s.cycle_since_ns<600000000000ULL));
   if(seed%5)assert(a630_thermal_confirm(&s,now,p,b)); /* no confirming failed IO */
   if(was_high&&p==4&&origin)assert(s.cycle_since_ns==origin);
   assert(s.limit_ns==600000000000ULL);
  }
 }
 return 0;
}'''
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'a.c').write_text(source)
            subprocess.run(['/usr/bin/clang','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(ROOT/'tools'),str(p/'a.c'),'-o',str(p/'a')],check=True)
            subprocess.run([str(p/'a')],check=True)

    def test_explicit_host_optin_and_policy_tampering_refusal(self):
        tokens=[b'polaristsens=3',b'polarisramcow=1',b'ufsrw=0',b'polarisquiesce=1']
        args=[tokens,True,7,4,False,None,True,False,False,True,True,3,True,True]
        self.assertTrue(builder.tsens_readonly_intent(*args))
        for i,v in [(0,[b'polaristsens=2']+tokens[1:]),(0,tokens+tokens[:1]),(1,False),(3,2),(6,False),(7,True),(8,True),(10,False),(11,2),(12,False),(13,1),(13,False)]:
            bad=copy.deepcopy(args);bad[i]=v
            with self.assertRaises(ValueError):builder.tsens_readonly_intent(*bad)
        policy={'experimental_limits_mC':[75000,70000,60000,55000],'max_observation_age_us':500000,'hard_high_ns':600000000000,'confirmed_low_ns':10000000000,'idle_ns':250000000}
        driver=dict(GPU_thermal_extended_trial=True,GPU_thermal_lease_trial=True,CPU_OSM_stock_performance=True,GPU_thermal_policy=policy)
        names=['native_thermal_eligibility_and_budget','native_thermal_hard_budget','native_thermal_refused_before_virtual_requests','native_thermal_extended_budget','native_TSENS_valid_retry_core']
        q=dict(GPU_thermal_extended_trial=True,GPU_thermal_lease_trial=True,GPU_thermal_policy=copy.deepcopy(policy),checks={n:True for n in names})
        image.admit_thermal_policy(driver,q,True,3)
        for name in names:
            wrong=copy.deepcopy(q);wrong['checks'].pop(name)
            with self.assertRaises(ValueError):image.admit_thermal_policy(driver,wrong,True,3)
        for side in ('driver','qemu'):
            for field,value in [('GPU_thermal_extended_trial',False),('GPU_thermal_extended_trial',1),('GPU_thermal_lease_trial',False)]:
                d,c=copy.deepcopy(driver),copy.deepcopy(q);(d if side=='driver' else c)[field]=value
                with self.assertRaises(ValueError):image.admit_thermal_policy(d,c,True,3)
            for value in (120000000000,0,True,600000000000.0,601000000000):
                d,c=copy.deepcopy(driver),copy.deepcopy(q);(d if side=='driver' else c)['GPU_thermal_policy']['hard_high_ns']=value
                with self.assertRaises(ValueError):image.admit_thermal_policy(d,c,True,3)
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'must-not-exist'
            p=subprocess.run(['python3',str(ROOT/'tools/build-polaris-uefi-xnu.py'),'--gpu-thermal-extended','--zig','/no/zig','--kernel','/no/kernel','--payload','/no/payload','--output',str(out)],capture_output=True,text=True)
            self.assertEqual(p.returncode,2);self.assertIn('TSENS',p.stderr);self.assertFalse(out.exists())

    def test_exact_private_core_and_no_new_hardware_writers(self):
        raw=(ROOT/'tools/polaris-a630-thermal-performance.h').read_text().replace('#ifndef POLARIS_A630_THERMAL_PERFORMANCE_H\n#define POLARIS_A630_THERMAL_PERFORMANCE_H\n','').replace('#include <stdint.h>\n','').replace('#include <stdbool.h>\n','')[:-7]
        runtime=(ROOT/'tools/polaris-a630-runtime.h').read_text()
        body=runtime.split('/* BEGIN BOUNDED THERMAL PLANNER: exact tested pure implementation. */\n')[1].split('\n/* END BOUNDED THERMAL PLANNER. */')[0]
        self.assertEqual(raw,body)
        patch=(ROOT/'xnu/profiles/polaris/0896-polaris-explicit-bounded-extended-GPU-duration.patch').read_text()
        added='\n'.join(s[1:] for s in patch.splitlines() if s.startswith('+') and not s.startswith('+++'))
        self.assertEqual(set(re.findall(r'^\+\+\+ b/(.*)$',patch,re.M)),
                         {'iokit/Kernel/arm/SweetCPU.cpp','bsd/dev/polaris_a630_runtime.h'})
        self.assertNotIn('a630_ch_write(',added)
        self.assertNotIn('polaris_perf_regs[0x920/4]=',added)
        self.assertIn('polaris_gpu_thermal_mode()!=thermal',added)
        self.assertIn('a630_client_thermal_extended?A630_THERMAL_LONG_NS:A630_THERMAL_HIGH_NS',added)
        self.assertIn('CPU fixed guard unchanged',added)
        self.assertIn('!a630_thermal_plan_extended(&wrong,101,101,true,&p,&b) && wrong.fault',added)
        self.assertIn(hashlib.sha256(runtime.encode()).hexdigest(),(ROOT/'tools/xnu-iig-cache.py').read_text())

if __name__=='__main__':unittest.main()
