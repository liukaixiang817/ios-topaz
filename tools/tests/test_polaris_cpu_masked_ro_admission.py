"""Distinct CPU-local mask/restore diagnostic cannot become a hardware grant."""
import ast,subprocess,unittest
from pathlib import Path
from .test_polaris_prepared_power_admission import a,desc
class CPUMaskedROAdmission(unittest.TestCase):
    def test_exact_scope(self):
        p=a.GCD_CLOCK_0170
        self.assertIs(a.original_gcd_policy(desc(p)),p)
        self.assertEqual((len(p['inputs']),len(p['resource_fields'])),(64,94))
        self.assertFalse(p['metadata'][a.POWER_PREFIX+'transaction'])
        self.assertNotIn('shim/polaris/uefi-wifi-rpmh-client.h',p['inputs'])
        self.assertEqual(p['metadata'][a.POWER_PREFIX+'CPU_RO_raw_bytes'],50800)
    def test_each_new_field_required(self):
        for key in a.GCD_CLOCK_0170['metadata']:
            if not key.startswith(a.POWER_PREFIX):continue
            d=desc(a.GCD_CLOCK_0170);del d[key]
            with self.subTest(key=key),self.assertRaises(ValueError):a.original_gcd_policy(d)
    def test_no_lease_raw_time_or_restore_relaxation(self):
        for key,value in [('CPU_RO_raw_bytes',50799),('CPU_RO_deadline_ticks',3840001),
            ('CPU_RO_no_private_Create_Delete',False),('CPU_MASKED_RO_original_services_while_held',1),
            ('CPU_MASKED_RO_restore_DAIF',192),('CPU_MASKED_RO_restore_Group1',0),
            ('CPU_MASKED_RO_no_DRV_EE_EL3_VMID_MPU_grant',False),('CPU_MASKED_RO_masked_nonOFF_or_uncertainty_terminal',False),
            ('CPU_MASKED_RO_partial_restore_never_cleanup_or_service',False),('CPU_RO_nonreturning_SMC_walltime_bound_proven',True)]:
            d=desc(a.GCD_CLOCK_0170);d[a.POWER_PREFIX+key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):a.original_gcd_policy(d)
    def test_old_or_missing_shared_source_refused(self):
        for paths in (a.GCD_CLOCK_0169['inputs'],{k:v for k,v in a.GCD_CLOCK_0170['inputs'].items() if k!='shim/polaris/uefi-wifi-cpu-local-mask.h'}):
            d=desc(a.GCD_CLOCK_0170);d['inputs']=paths
            with self.assertRaises(ValueError):a.original_gcd_policy(d)
    def test_marker_literal_one(self):
        flags={k:1 for k in ('ORIGINAL_GCD_SOFTWARE_PHYSICAL_SERVICE_FP_COMPILED_OUT','AUDIO_CLOCK_GCD_SOFTWARE_PHYSICAL_QUERY_COMPILED_OUT','WIFI_CPU_RO_SOFTWARE_PHYSICAL_COMPILED_OUT','WIFI_CPU_MASKED_RO_SOFTWARE_PHYSICAL_COMPILED_OUT')}
        a.original_gcd_model_markers(dict(raw_fields=flags),cpu_ro=True,cpu_masked_ro=True)
        for v in (None,True,0,'1'):
            bad=dict(flags);bad['WIFI_CPU_MASKED_RO_SOFTWARE_PHYSICAL_COMPILED_OUT']=v
            with self.subTest(value=v),self.assertRaises(ValueError):a.original_gcd_model_markers(dict(raw_fields=bad),cpu_ro=True,cpu_masked_ro=True)
    def test_twenty_three_old_literals_immutable(self):
        root=Path(__file__).resolve().parents[2];old=subprocess.check_output(['git','show','c95d2b3:tools/polaris_wled_runtime_admission.py'],cwd=root,text=True)
        def literals(s):return {n.targets[0].id:ast.dump(n.value,include_attributes=False) for n in ast.parse(s).body if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and n.targets[0].id.startswith('GCD_CLOCK_')}
        before,now=literals(old),literals((root/'tools/polaris_wled_runtime_admission.py').read_text());self.assertEqual(len(before)-1,23)
        for name,value in before.items():self.assertEqual(now[name],value,name)
