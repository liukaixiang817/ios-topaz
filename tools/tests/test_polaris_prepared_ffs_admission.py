"""Exact full-raw FFS capacity revision, no old profile or safety downgrade."""
import copy,ast,subprocess,unittest
from pathlib import Path
from .test_polaris_prepared_power_admission import a,desc
class PreparedFFSAdmission(unittest.TestCase):
 def test_distinct_literal_capacities_and_same_raw_extents(self):
  for p in (a.GCD_CLOCK_0163,a.GCD_CLOCK_0162,a.GCD_CLOCK_0161):self.assertIs(a.original_gcd_policy(desc(p)),p)
  self.assertEqual(a.GCD_CLOCK_0163['metadata']['original_GCD_new_scope_RAM_log_capacity'],10<<20)
  self.assertEqual(a.GCD_CLOCK_0162['metadata']['original_GCD_new_scope_RAM_log_capacity'],12<<20)
  for n in ('raw_bytes','client_raw_bytes','access_raw_bytes','prepared_binding_raw_bytes','prepared_masked_FULL_DB_bytes_per_snapshot','prepared_original_private_deadline_ticks'):
   self.assertEqual(a.GCD_CLOCK_0163['metadata'][a.POWER_PREFIX+n],a.GCD_CLOCK_0162['metadata'][a.POWER_PREFIX+n])
 def test_any_missing_raw_or_changed_scope_rejected(self):
  for k,v in [('original_GCD_new_scope_RAM_log_capacity',12<<20),('wifi_CPU0_power_raw_bytes',1892335),('wifi_CPU0_power_prepared_masked_FULL_DB_snapshots',1),('wifi_CPU0_power_prepared_original_private_deadline_ticks',3840001),('wifi_CPU0_power_UNKNOWN_no_USB_Console_Stall_or_firmware_return',False)]:
   d=desc(a.GCD_CLOCK_0163);d[k]=v
   with self.subTest(k=k),self.assertRaises(ValueError):a.original_gcd_policy(d)
 def test_no_old_input_or_resource_cap_substitution(self):
  d=desc(a.GCD_CLOCK_0163);d['inputs']=copy.deepcopy(a.GCD_CLOCK_0162['inputs'])
  with self.assertRaises(ValueError):a.original_gcd_policy(d)
  d=desc(a.GCD_CLOCK_0163);d['wifi_CPU0_resources_firmware_RAM_log_capacity']=12<<20
  with self.assertRaises(ValueError):a.resources_clock_scope(d)
 def test_all_previous_literals_unchanged(self):
  root=Path(__file__).resolve().parents[2];old=subprocess.check_output(['git','show','e7ad25fe2a996bd8d9a866f3a8266fcc48da195d:tools/polaris_wled_runtime_admission.py'],cwd=root,text=True)
  def v(s):return {n.targets[0].id:ast.dump(n.value,include_attributes=False) for n in ast.parse(s).body if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and n.targets[0].id.startswith('GCD_CLOCK_')}
  now=v((root/'tools/polaris_wled_runtime_admission.py').read_text())
  for n,value in v(old).items():self.assertEqual(now[n],value,n)
