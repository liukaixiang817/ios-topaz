"""Count1 and logicalDRV2 have separate pinned original ABI semantics."""
import ast,copy,subprocess,unittest
from pathlib import Path
from .test_polaris_prepared_power_admission import a,desc
class HALCountAdmission(unittest.TestCase):
 def test_new_exact_source_and_metadata(self):
  p=a.GCD_CLOCK_0164;self.assertIs(a.original_gcd_policy(desc(p)),p)
  for n,v in [('runtime_HAL_count_static_RVA',0xd238),('runtime_HAL_count_offset',4),('static_logical_DRV_RVA',0xd228),('HAL_count_and_logical_DRV_checked_separately',True)]:self.assertEqual(p['metadata'][a.POWER_PREFIX+n],v)
 def test_count_ID_not_interchangeable(self):
  for n,v in [('runtime_HAL_count_static_RVA',0xd228),('runtime_HAL_count_offset',0x20),('static_logical_DRV_RVA',0xd238),('HAL_count_and_logical_DRV_checked_separately',False)]:
   d=desc(a.GCD_CLOCK_0164);d[a.POWER_PREFIX+n]=v
   with self.subTest(n=n),self.assertRaises(ValueError):a.original_gcd_policy(d)
 def test_no_old_header_or_raw_deadline_substitution(self):
  for n in ('shim/polaris/uefi-wifi-rsc-baseline.h','tools/build-polaris-uefi-xnu.py'):
   d=desc(a.GCD_CLOCK_0164);d['inputs'][n]=a.GCD_CLOCK_0163['inputs'][n]
   with self.subTest(n=n),self.assertRaises(ValueError):a.original_gcd_policy(d)
  for n,v in [('prepared_original_private_deadline_ticks',3840001),('raw_bytes',1892335),('unknown_blocks_native_PON_receipt',False)]:
   d=desc(a.GCD_CLOCK_0164);d[a.POWER_PREFIX+n]=v
   with self.subTest(n=n),self.assertRaises(ValueError):a.original_gcd_policy(d)
 def test_all_old_profiles_immutable(self):
  root=Path(__file__).resolve().parents[2]
  old=subprocess.check_output(['git','show','eff4a01f7fb7955791461cbf882c31a0355b7da0:tools/polaris_wled_runtime_admission.py'],cwd=root,text=True)
  def vals(s):return {n.targets[0].id:ast.dump(n.value,include_attributes=False) for n in ast.parse(s).body if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and n.targets[0].id.startswith('GCD_CLOCK_')}
  now=vals((root/'tools/polaris_wled_runtime_admission.py').read_text())
  for k,v in vals(old).items():self.assertEqual(now[k],v,k)
