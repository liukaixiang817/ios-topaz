"""Independent normal CPU RO scope cannot become a private or hardware lease."""
import ast,subprocess,unittest
from pathlib import Path
from .test_polaris_prepared_power_admission import a,desc

class CPUROAdmission(unittest.TestCase):
    def test_exact_source_scope(self):
        p=a.GCD_CLOCK_0169
        self.assertIs(a.original_gcd_policy(desc(p)),p)
        self.assertEqual((len(p['inputs']),len(p['metadata']),len(p['resource_fields'])),(63,89,94))
        self.assertFalse(p['metadata'][a.POWER_PREFIX+'transaction'])
        self.assertNotIn('shim/polaris/uefi-wifi-rpmh-client.h',p['inputs'])
        self.assertNotIn('shim/polaris/uefi-wifi-rsc-device.h',p['inputs'])
    def test_each_CPU_RO_field_required_exact(self):
        for key in a.GCD_CLOCK_0169['metadata']:
            if not key.startswith(a.POWER_PREFIX):continue
            d=desc(a.GCD_CLOCK_0169);del d[key]
            with self.subTest(key=key),self.assertRaises(ValueError):a.original_gcd_policy(d)
    def test_no_lease_unknown_deadline_raw_or_capacity_relaxation(self):
        for key,value in [('CPU_RO_all_states_raw_not_hardware_grant',False),('CPU_RO_deadline_ticks',3840001),
                ('CPU_RO_no_private_Create_Delete',False),('CPU_RO_unknown_blocks_Clock_native_PON_receipt',False),
                ('CPU_RO_raw_bytes',39343),('CPU_RO_nonreturning_SMC_walltime_bound_proven',True),
                ('CPU_RO_all_OFF_does_not_continue_private',False)]:
            d=desc(a.GCD_CLOCK_0169);d[a.POWER_PREFIX+key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):a.original_gcd_policy(d)
        d=desc(a.GCD_CLOCK_0169);d['original_GCD_new_scope_RAM_log_capacity']=262144
        with self.assertRaises(ValueError):a.original_gcd_policy(d)
    def test_old_read_source_or_added_private_source_refused(self):
        for inputs in (a.GCD_CLOCK_0168['inputs'],dict(a.GCD_CLOCK_0169['inputs'],**{'shim/polaris/uefi-wifi-rpmh-client.h':'0'*64})):
            d=desc(a.GCD_CLOCK_0169);d['inputs']=inputs
            with self.assertRaises(ValueError):a.original_gcd_policy(d)
    def test_CPU_RO_marker_integer_one_only(self):
        base=dict(raw_fields={k:1 for k in ('ORIGINAL_GCD_SOFTWARE_PHYSICAL_SERVICE_FP_COMPILED_OUT','AUDIO_CLOCK_GCD_SOFTWARE_PHYSICAL_QUERY_COMPILED_OUT','WIFI_CPU_RO_SOFTWARE_PHYSICAL_COMPILED_OUT')})
        a.original_gcd_model_markers(base,cpu_ro=True)
        for v in (None,True,0,'1'):
            m=dict(raw_fields=dict(base['raw_fields']));m['raw_fields']['WIFI_CPU_RO_SOFTWARE_PHYSICAL_COMPILED_OUT']=v
            with self.subTest(value=v),self.assertRaises(ValueError):a.original_gcd_model_markers(m,cpu_ro=True)
    def test_twenty_two_old_literals_immutable(self):
        root=Path(__file__).resolve().parents[2];old=subprocess.check_output(['git','show','f6759e1285b7adfe667052873297dd78a4e8d2c5:tools/polaris_wled_runtime_admission.py'],cwd=root,text=True)
        def values(s):return {n.targets[0].id:ast.dump(n.value,include_attributes=False) for n in ast.parse(s).body if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and n.targets[0].id.startswith('GCD_CLOCK_')}
        before,now=values(old),values((root/'tools/polaris_wled_runtime_admission.py').read_text());self.assertEqual(len(before)-1,22)
        for name,value in before.items():self.assertEqual(now[name],value,name)
