"""Same private READ work planning cannot alter runtime deadlines or ownership."""
import ast,subprocess,unittest
from pathlib import Path
from .test_polaris_prepared_power_admission import a,desc
class ReadWorkAdmission(unittest.TestCase):
    def test_exact_current_source(self):
        p=a.GCD_CLOCK_0171
        self.assertIs(a.original_gcd_policy(desc(p)),p)
        self.assertEqual((len(p['inputs']),len(p['resource_fields'])),(90,94))
        self.assertTrue(p['metadata'][a.POWER_PREFIX+'current_ARC_work_admission'])
        self.assertEqual(p['metadata'][a.POWER_PREFIX+'raw_bytes'],1943840)
        self.assertFalse(p['metadata'][a.POWER_PREFIX+'current_ARC_resource_WRITE_reachable'])
    def test_each_work_field_required_exact(self):
        for key in a.GCD_CLOCK_0171['metadata']:
            if 'current_ARC_work_' not in key:continue
            d=desc(a.GCD_CLOCK_0171);del d[key]
            with self.subTest(key=key),self.assertRaises(ValueError):a.original_gcd_policy(d)
    def test_no_deadline_sample_estimate_or_RAW_relaxation(self):
        for key,value in [('raw_format','CURRENT_ARC_READ_RAW_V2'),('raw_bytes',1941984),
            ('current_ARC_work_all_samples_including_slowest',67),('current_ARC_work_full_READ_reserve_ticks',959999),
            ('current_ARC_work_nonhash_reserve_ticks',479999),('current_ARC_work_generic_verifier_Core_units_each',1),
            ('current_ARC_work_no_new_or_rebased_ticket',False),('current_ARC_work_unknown_blocks_parent_native_PON_receipt',False),
            ('current_ARC_work_estimate_not_walltime_or_hardware_grant',False),('current_ARC_resource_WRITE_reachable',True)]:
            d=desc(a.GCD_CLOCK_0171);d[a.POWER_PREFIX+key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):a.original_gcd_policy(d)
    def test_old_source_or_partial_metadata_refused(self):
        for inputs in (a.GCD_CLOCK_0168['inputs'],a.GCD_CLOCK_0170['inputs']):
            d=desc(a.GCD_CLOCK_0171);d['inputs']=inputs
            with self.assertRaises(ValueError):a.original_gcd_policy(d)
        d=desc(a.GCD_CLOCK_0171);d['wifi_CPU0_resources_firmware_RAM_log_capacity']=8388608
        with self.assertRaises(ValueError):a.resources_clock_scope(d)
    def test_prior_twenty_four_literals_unchanged(self):
        root=Path(__file__).resolve().parents[2];old=subprocess.check_output(['git','show','f570804:tools/polaris_wled_runtime_admission.py'],cwd=root,text=True)
        def literals(s):return {n.targets[0].id:ast.dump(n.value,include_attributes=False) for n in ast.parse(s).body if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and n.targets[0].id.startswith('GCD_CLOCK_')}
        before,now=literals(old),literals((root/'tools/polaris_wled_runtime_admission.py').read_text());self.assertEqual(len(before)-1,24)
        for name,value in before.items():self.assertEqual(now[name],value,name)
