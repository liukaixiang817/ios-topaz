"""Native overlay and negative host admission for bounded thermal GPU trial."""
from pathlib import Path
import copy,importlib.util,subprocess,tempfile,unittest
from .test_polaris_gpu_lifetime import function
ROOT=Path(__file__).resolve().parents[2]
PATCH=ROOT/'xnu/profiles/polaris/0894-polaris-native-bounded-GPU-thermal-lease.patch'
ADDED='\n'.join(x[1:] for x in PATCH.read_text().splitlines() if x.startswith('+') and not x.startswith('+++'))
def load(name,path):
 s=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
builder=load('thermal_builder','tools/build-polaris-uefi-xnu.py')
image=load('thermal_image','tools/polaris-uefi-xnu-image.py')
class NativeThermal(unittest.TestCase):
 def test_explicit_intent_and_early_scope_rejection(self):
  tokens=[b'polaristsens=2',b'polarisramcow=1',b'ufsrw=0',b'polarisquiesce=1']
  args=[tokens,True,7,4,False,None,True,False,False,True,True,3,True]
  self.assertTrue(builder.tsens_readonly_intent(*args))
  for index,value in [(0,tokens+tokens[:1]),(1,False),(2,1),(3,2),(6,False),(7,True),(8,True),(9,False),(10,False),(11,1),(11,2),(12,False)]:
   bad=copy.deepcopy(args);bad[index]=value
   with self.assertRaises(ValueError):builder.tsens_readonly_intent(*bad)
  base=['python3',str(ROOT/'tools/build-polaris-uefi-xnu.py'),'--zig','/no/zig','--kernel','/no/kernel','--payload','/no/payload','--gpu-thermal-lease']
  valid=['--tsens-readonly','--kernel-core','7','--kernel-cpus','4','--cpu-osm-stock-performance','--gpu-stock-request','3','--ram-shutdown-bridge']
  bad=[[],valid[:-1],valid+['--kernel-cpus','2'],valid+['--test-qemu-ufs'],valid+['--physical-owned-marker'],valid+['--efi-application'],valid+['--gpu-stock-request','1']]
  with tempfile.TemporaryDirectory() as d:
   for n,flags in enumerate(bad):
    out=Path(d)/str(n);p=subprocess.run(base+flags+['--output',str(out)],capture_output=True,text=True)
    self.assertEqual(p.returncode,2,p.stderr);self.assertIn('TSENS',p.stderr);self.assertFalse(out.exists())

 def test_proof_and_policy_tampering_refused(self):
  policy={'experimental_limits_mC':[75000,70000,60000,55000],
          'max_observation_age_us':500000,'hard_high_ns':120000000000,
          'confirmed_low_ns':10000000000,'idle_ns':250000000}
  d={'GPU_thermal_lease_trial':True,'CPU_OSM_stock_performance':True,'GPU_thermal_policy':policy}
  checks={k:True for k in ['native_thermal_eligibility_and_budget','native_thermal_hard_budget','native_thermal_refused_before_virtual_requests']}
  q={'GPU_thermal_lease_trial':True,'GPU_thermal_policy':copy.deepcopy(policy),'checks':checks}
  image.admit_thermal_policy(d,q,True,3)
  for side in ['driver','qemu']:
   for key in policy:
    for value in [0,True,float(policy[key]) if type(policy[key]) is int else [float(x) for x in policy[key]]]:
     dd,qq=copy.deepcopy(d),copy.deepcopy(q);(dd if side=='driver' else qq)['GPU_thermal_policy'][key]=value
     with self.assertRaises(ValueError):image.admit_thermal_policy(dd,qq,True,3)
  for key in checks:
   qq=copy.deepcopy(q);qq['checks'].pop(key)
   with self.assertRaises(ValueError):image.admit_thermal_policy(d,qq,True,3)
  for thermal,gpu in [(False,3),(True,1),(True,2)]:
   with self.assertRaises(ValueError):image.admit_thermal_policy(d,q,thermal,gpu)
  for bad in [1,'true',False]:
   dd=copy.deepcopy(d);dd['GPU_thermal_lease_trial']=bad
   with self.assertRaises(ValueError):image.admit_thermal_policy(dd,q,True,3)
  image.admit_thermal_policy({}, {},False,0)
  with self.assertRaises(ValueError):image.admit_thermal_policy({'GPU_thermal_policy':policy},{},False,0)

 def test_exact_gate_and_no_new_hardware_writers(self):
  h=(ROOT/'tools/polaris-thermal-eligibility.h').read_text().replace('#ifndef POLARIS_THERMAL_ELIGIBILITY_H\n#define POLARIS_THERMAL_ELIGIBILITY_H\n','').replace('#include "polaris-tsens-readonly.h"\n','')[:-7]
  exact=ADDED.split('/* BEGIN THERMAL ELIGIBILITY CORE: exact tested pure implementation. */\n',1)[1].split('\n/* END THERMAL ELIGIBILITY CORE. */',1)[0]
  self.assertEqual(h,exact)
  verdict=function(ADDED,'extern "C" unsigned polaris_gpu_thermal_verdict(')
  self.assertLess(verdict.index('IOLockLock(polaris_thermal_lock)'),verdict.index('polaris_perf_now()/1000'))
  self.assertNotIn('IOLockLock(gpuLock)',ADDED)
  self.assertNotRegex(ADDED,r'polaris_tsens_regs\[[^\]]+\]\s*=(?!=)')
  for token in ['if(flag==2)','bool lease_mode=flag!=2 || (osm==2 && gpu==3)',
                'pte_observe(&polaris_thermal_state,&sample,error,polaris_perf_now()/1000)',
                'a630_thermal_confirm(&a630_client_thermal,a630_perf_now_ns(),perf,bus)',
                'pte_stop(&polaris_thermal_state)']:
   self.assertIn(token,ADDED)
  self.assertIn('a630_perf_change(s,&io,perf,bus,polaris_gpu_quiescent())',PATCH.read_text())
  self.assertNotIn('a630_ch_write(',ADDED)
  self.assertNotIn('polaris_perf_regs[0x920/4]=',ADDED)

if __name__=='__main__':unittest.main()
