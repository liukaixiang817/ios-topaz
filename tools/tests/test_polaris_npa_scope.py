"""NPA candidate cannot shed metadata, substitute sources or borrow old scopes."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import polaris_wled_runtime_admission as a
from polaris_uefi_usb_transport import KernelProtocol


class NpaScope(unittest.TestCase):
    def candidate(self,policy=None):
        p=policy or a.GCD_CLOCK_0146
        return dict(copy.deepcopy(p['metadata']),**copy.deepcopy(p['resource_fields']),
            inputs=copy.deepcopy(p['inputs']),kernel_sha256=p['kernel'],payload_sha256=p['payload'],
            wifi_CPU0_firstread_readonly=False,
            **{a.NORMAL_NC_PREFIX+k:v for k,v in a.NORMAL_NC_PHYSICAL_FIELDS.items()},
            **{a.AUDIO_I2C_PREFIX+k:v for k,v in a.AUDIO_I2C_PHYSICAL_FIELDS.items()})

    def test_new_scope_and_both_frozen_legacy_scopes_remain_distinct(self):
        for policy in (a.GCD_CLOCK_0146,a.GCD_CLOCK_0145,a.GCD_CLOCK_0144,a.GCD_CLOCK_0143):
            d=self.candidate(policy)
            self.assertIs(a.original_gcd_policy(d),policy)
            for gate in (a.resources_clock_scope,a.normal_nc_firstread_scope,a.audio_i2c_cache_scope):
                self.assertTrue(gate(d))
        self.assertEqual(len(a.GCD_CLOCK_0146['inputs']),65)
        self.assertEqual(len(a.GCD_CLOCK_0146['metadata']),83)
        self.assertEqual(a.GCD_CLOCK_0146['firmware_source'],'53fcc867dffe6a08d637396bc7bb3cfab0315bfe')

    def test_every_compiled_input_and_new_field_is_bound(self):
        d=self.candidate()
        for name in d['inputs']:
            bad=copy.deepcopy(d);bad['inputs'][name]='changed'
            with self.subTest(input=name),self.assertRaises(ValueError):a.original_gcd_scope(bad)
        for name,value in a.GCD_CLOCK_0146['metadata'].items():
            if not name.startswith(a.NPA_PREFIX):continue
            for mutation in ('remove','value','type'):
                bad=copy.deepcopy(d)
                if mutation=='remove':del bad[name]
                elif mutation=='value':bad[name]=not value if type(value) is bool else 'changed'
                else:bad[name]=int(value) if type(value) is bool else True
                with self.subTest(field=name,mutation=mutation),self.assertRaises(ValueError):a.original_gcd_scope(bad)

    def test_NPA_cannot_hide_or_use_legacy_profile(self):
        for source in a.NPA_SOURCE_PATHS:
            for fields in ({},a.GCD_CLOCK_DISABLED):
                with self.subTest(source=source),self.assertRaises(ValueError):
                    a.original_gcd_scope(dict(fields,inputs={source:'hash'}))
        for legacy in (a.GCD_CLOCK_0145,a.GCD_CLOCK_0144,a.GCD_CLOCK_0143):
            for part in ('inputs','metadata','resource_fields'):
                bad=self.candidate()
                if part=='inputs':bad['inputs']=copy.deepcopy(legacy['inputs'])
                else:
                    prefixes=a.GCD_PREFIXES if part=='metadata' else (a.RESOURCES_PREFIX,a.CLOCK_QUERY_PREFIX)
                    bad={k:v for k,v in bad.items() if not k.startswith(prefixes)}
                    bad.update(copy.deepcopy(legacy[part]))
                with self.subTest(legacy=legacy['firmware_source'],part=part),self.assertRaises(ValueError):
                    a.resources_clock_scope(bad)

    def test_model_requires_literal_NPA_compiledout_marker_only_for_new_scope(self):
        raw=dict.fromkeys(('ORIGINAL_GCD_SOFTWARE_PHYSICAL_SERVICE_FP_COMPILED_OUT',
                          'AUDIO_CLOCK_GCD_SOFTWARE_PHYSICAL_QUERY_COMPILED_OUT'),1)
        a.original_gcd_model_markers({'raw_fields':raw})
        name='WIFI_NPA_SOFTWARE_PHYSICAL_NAMESPACE_COMPILED_OUT'
        for invalid in (None,True,False,'1',0,2):
            changed=dict(raw)
            if invalid is not None:changed[name]=invalid
            with self.subTest(invalid=invalid),self.assertRaises(ValueError):
                a.original_gcd_model_markers({'raw_fields':changed},npa=True)
        a.original_gcd_model_markers({'raw_fields':dict(raw,**{name:1})},npa=True)

    def test_firmware_snapshot_fits_bounded_native_log_transport(self):
        d=self.candidate()
        cap=d['original_GCD_new_scope_RAM_log_capacity']
        self.assertEqual(cap,1572864)
        self.assertEqual(d['wifi_CPU0_resources_firmware_RAM_log_capacity'],cap)
        self.assertGreaterEqual(KernelProtocol.limits['logs'],(4<<20)+cap+128)
        self.assertEqual(KernelProtocol.limits['logs'],(4<<20)+1572864+128)


if __name__=='__main__':unittest.main()
