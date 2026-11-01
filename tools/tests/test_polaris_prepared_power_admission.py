"""New source pin admits conditional runtime qualification, never a blank lease."""
import ast,copy
from pathlib import Path
import subprocess,sys,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import polaris_wled_runtime_admission as a

def desc(p):return dict(copy.deepcopy(p['metadata']),**copy.deepcopy(p['resource_fields']),inputs=copy.deepcopy(p['inputs']),kernel_sha256=p['kernel'],payload_sha256=p['payload'])
class PreparedPowerAdmission(unittest.TestCase):
 def test_new_scope_and_old_prepare_distinct(self):
  for p in (a.GCD_CLOCK_0162,a.GCD_CLOCK_0161,a.GCD_CLOCK_0160):self.assertIs(a.original_gcd_policy(desc(p)),p)
  self.assertEqual(len(a.GCD_CLOCK_0162['inputs']),86)
  self.assertTrue(a.GCD_CLOCK_0162['metadata']['wifi_CPU0_RPMh_private_client'])
  self.assertFalse(a.GCD_CLOCK_0161['metadata']['wifi_CPU0_RPMh_private_client'])
 def test_scope_metadata_raw_and_current_checks_exact(self):
  values=[('prepared_transaction',False),('prepared_transaction',1),('raw_bytes',1892335),('prepared_binding_raw_bytes',233519),('access_raw_bytes',399240),('guarded_PSCI_calls_max',7),('CmdDb_capture_only',True),('CmdDb_original_Query_calls_max',1),('prepared_current_selected_byte_passes',2),('prepared_masked_FULL_DB_snapshots',1),('prepared_masked_FULL_DB_bytes_per_snapshot',65536),('prepared_masked_fresh_NS_WB_PAR_restore_each_page',False),('prepared_binding_admission_and_close_arch_retained_separately',False)]
  for k,v in values:
   d=desc(a.GCD_CLOCK_0162);d[a.POWER_PREFIX+k]=v
   with self.subTest(k=k),self.assertRaises(ValueError):a.original_gcd_policy(d)
 def test_no_owner_lease_deadline_UNKNOWN_or_MSS_bypass(self):
  for k,v in [('hardware_ownership_independently_qualified',True),('prepared_original_private_deadline_ticks',3840001),('prepared_no_old_RO_ticket_reuse',False),('prepared_final_ticket_unopened_before_Clock',False),('UNKNOWN_no_USB_Console_Stall_or_firmware_return',False),('unknown_blocks_native_PON_receipt',False),('MSS_or_NVserve_or_radio',True)]:
   d=desc(a.GCD_CLOCK_0162);d[a.POWER_PREFIX+k]=v
   with self.subTest(k=k),self.assertRaises(ValueError):a.original_gcd_policy(d)
 def test_new_current_source_pinned_no_old_substitution(self):
  for n in ('shim/polaris/uefi-wifi-cmddb-prepared.h','shim/polaris/uefi-wifi-rsc-access.h','shim/polaris/uefi-wifi-power-path.h','shim/polaris/uefi-xnu.c','tools/build-polaris-uefi-xnu.py'):
   d=desc(a.GCD_CLOCK_0162);d['inputs'][n]='0'*64
   with self.subTest(n=n),self.assertRaises(ValueError):a.original_gcd_policy(d)
  d=desc(a.GCD_CLOCK_0162);d['inputs']=copy.deepcopy(a.GCD_CLOCK_0161['inputs'])
  with self.assertRaises(ValueError):a.original_gcd_policy(d)
 def test_log_capacity_exact_scope_and_resource(self):
  d=desc(a.GCD_CLOCK_0162);self.assertEqual(d['original_GCD_new_scope_RAM_log_capacity'],12<<20);self.assertTrue(a.resources_clock_scope(d))
  d['original_GCD_new_scope_RAM_log_capacity']=8<<20
  with self.assertRaises(ValueError):a.original_gcd_policy(d)
  d=desc(a.GCD_CLOCK_0162);d['wifi_CPU0_resources_firmware_RAM_log_capacity']=8<<20
  with self.assertRaises(ValueError):a.resources_clock_scope(d)
 def test_disabled_metadata_cannot_hide_current_reader(self):
  d=dict(a.GCD_CLOCK_DISABLED,inputs={'shim/polaris/uefi-wifi-cmddb-prepared.h':'0'*64})
  with self.assertRaises(ValueError):a.original_gcd_policy(d)
 def test_old_literal_profiles_all_unchanged(self):
  root=Path(__file__).resolve().parents[2]
  old=subprocess.check_output(['git','show','7836b94c7eb567b49247375f8f5932c58a08a26d:tools/polaris_wled_runtime_admission.py'],cwd=root,text=True)
  def values(s):return {n.targets[0].id:ast.dump(n.value,include_attributes=False) for n in ast.parse(s).body if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and n.targets[0].id.startswith('GCD_CLOCK_')}
  now=values((root/'tools/polaris_wled_runtime_admission.py').read_text())
  for n,v in values(old).items():self.assertEqual(now[n],v,n)
if __name__=='__main__':unittest.main()
