"""The new RPMh physical scope cannot borrow a frozen legacy admission."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import polaris_wled_runtime_admission as a

class RpmhScope(unittest.TestCase):
    def candidate(self):
        p=a.GCD_CLOCK_0148
        return dict(copy.deepcopy(p['metadata']),**copy.deepcopy(p['resource_fields']),
            inputs=copy.deepcopy(p['inputs']),kernel_sha256=p['kernel'],payload_sha256=p['payload'])
    def test_new_source_and_exact_scope(self):
        d=self.candidate()
        self.assertIs(a.original_gcd_policy(d),a.GCD_CLOCK_0148)
        self.assertTrue(a.resources_clock_scope(d))
        self.assertEqual(len(d['inputs']),69)
        self.assertEqual(d['wifi_CPU0_RPMh_raw_bytes'],19264)
        self.assertEqual(d['wifi_CPU0_RPMh_provider_API_calls'],0)
        self.assertFalse(d['wifi_CPU0_RPMh_client_or_vote'])
    def test_every_RPMh_field_is_typed_and_mandatory(self):
        for k,v in a.GCD_CLOCK_0148['metadata'].items():
            if not k.startswith(a.RPMH_PREFIX):continue
            for mutation in ('missing','value','type'):
                d=self.candidate()
                if mutation=='missing':del d[k]
                elif mutation=='value':d[k]=not v if type(v) is bool else 'changed'
                else:d[k]=int(v) if type(v) is bool else True
                with self.subTest(k=k,mutation=mutation),self.assertRaises(ValueError):a.original_gcd_scope(d)
    def test_every_compiled_input_is_bound(self):
        for k in a.GCD_CLOCK_0148['inputs']:
            d=self.candidate();d['inputs'][k]='changed'
            with self.subTest(k=k),self.assertRaises(ValueError):a.original_gcd_scope(d)
    def test_sources_cannot_hide(self):
        for source in a.RPMH_SOURCE_PATHS:
            for fields in ({},a.GCD_CLOCK_DISABLED):
                with self.subTest(source=source),self.assertRaises(ValueError):
                    a.original_gcd_scope(dict(fields,inputs={source:'changed'}))
        d=self.candidate()
        for k in list(d):
            if k.startswith(a.RPMH_PREFIX):del d[k]
        with self.assertRaises(ValueError):a.original_gcd_scope(d)
    def test_legacy_profiles_cannot_admit_new_body(self):
        for p in (a.GCD_CLOCK_0143,a.GCD_CLOCK_0144,a.GCD_CLOCK_0145,a.GCD_CLOCK_0146,a.GCD_CLOCK_0147):
            d=self.candidate();d['inputs']=copy.deepcopy(p['inputs'])
            if p['metadata']==a.GCD_CLOCK_0148['metadata']:
                # Replacing ALL inputs reconstructs the exact old scope, not
                # a new body: it must select old, never the new profile.
                self.assertIs(a.original_gcd_policy(d),p)
            else:
                with self.assertRaises(ValueError):a.original_gcd_scope(d)
            d=self.candidate()
            for k in list(d):
                if k.startswith(a.GCD_PREFIXES):del d[k]
            d.update(copy.deepcopy(p['metadata']))
            if p['metadata']==a.GCD_CLOCK_0148['metadata']:
                self.assertIs(a.original_gcd_policy(d),a.GCD_CLOCK_0148)
                self.assertIsNot(a.original_gcd_policy(d),p)
            else:
                with self.assertRaises(ValueError):a.original_gcd_scope(d)
    def test_model_requires_literal_compiledout_marker(self):
        raw=dict.fromkeys(('ORIGINAL_GCD_SOFTWARE_PHYSICAL_SERVICE_FP_COMPILED_OUT',
            'AUDIO_CLOCK_GCD_SOFTWARE_PHYSICAL_QUERY_COMPILED_OUT','WIFI_NPA_SOFTWARE_PHYSICAL_NAMESPACE_COMPILED_OUT'),1)
        name='WIFI_RPMH_SOFTWARE_PHYSICAL_PROVIDER_RAM_COMPILED_OUT'
        for value in (None,True,False,'1',0,2):
            changed=dict(raw)
            if value is not None:changed[name]=value
            with self.subTest(value=value),self.assertRaises(ValueError):a.original_gcd_model_markers({'raw_fields':changed},npa=True,rpmh=True)
        a.original_gcd_model_markers({'raw_fields':dict(raw,**{name:1})},npa=True,rpmh=True)

if __name__=='__main__':unittest.main()
