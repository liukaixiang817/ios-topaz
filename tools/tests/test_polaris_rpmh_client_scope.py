"""Private provider API admission cannot inherit a read-only RPMh policy."""
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import polaris_wled_runtime_admission as a
from polaris_uefi_usb_transport import KernelProtocol

class PrivateRpmhScope(unittest.TestCase):
    def candidate(self):
        p=a.GCD_CLOCK_0149
        return dict(copy.deepcopy(p['metadata']),**copy.deepcopy(p['resource_fields']),
            inputs=copy.deepcopy(p['inputs']),kernel_sha256=p['kernel'],payload_sha256=p['payload'])
    def test_new_scope_exposes_private_mutation(self):
        d=self.candidate()
        self.assertIs(a.original_gcd_policy(d),a.GCD_CLOCK_0149)
        self.assertTrue(a.resources_clock_scope(d))
        self.assertFalse(d['wifi_CPU0_RPMh_RAM_readonly'])
        self.assertTrue(d['wifi_CPU0_RPMh_client_or_vote'])
        self.assertEqual(d['wifi_CPU0_RPMh_provider_API_calls'],2)
        self.assertEqual(d['wifi_CPU0_RPMh_private_vote_commandset_MMIO_SMC_MSS_NVserve_calls'],0)
        self.assertEqual(len(d['inputs']),70)
    def test_all_new_scope_values_are_typed_and_bound(self):
        for k,v in a.GCD_CLOCK_0149['metadata'].items():
            for mutation in ('missing','value','type'):
                d=self.candidate()
                if mutation=='missing':del d[k]
                elif mutation=='value':d[k]=not v if type(v) is bool else 'changed'
                else:d[k]=int(v) if type(v) is bool else True
                with self.subTest(field=k,mutation=mutation),self.assertRaises(ValueError):a.original_gcd_scope(d)
    def test_all_sources_bound(self):
        for k in a.GCD_CLOCK_0149['inputs']:
            d=self.candidate();d['inputs'][k]='changed'
            with self.subTest(source=k),self.assertRaises(ValueError):a.original_gcd_scope(d)
    def test_client_cannot_hide_behind_readonly_or_absent_scope(self):
        for source in a.RPMH_CLIENT_SOURCE_PATHS:
            for fields in ({},a.GCD_CLOCK_DISABLED):
                with self.subTest(source=source),self.assertRaises(ValueError):a.original_gcd_scope(dict(fields,inputs={source:'changed'}))
        for old in (a.GCD_CLOCK_0143,a.GCD_CLOCK_0144,a.GCD_CLOCK_0145,a.GCD_CLOCK_0146,a.GCD_CLOCK_0147,a.GCD_CLOCK_0148):
            d=self.candidate()
            for k in list(d):
                if k.startswith(a.GCD_PREFIXES):del d[k]
            d.update(copy.deepcopy(old['metadata']))
            with self.subTest(old=old['firmware_source']),self.assertRaises(ValueError):a.original_gcd_scope(d)
    def test_old_sources_cannot_borrow_private_metadata(self):
        for old in (a.GCD_CLOCK_0143,a.GCD_CLOCK_0144,a.GCD_CLOCK_0145,a.GCD_CLOCK_0146,a.GCD_CLOCK_0147,a.GCD_CLOCK_0148):
            d=self.candidate();d['inputs']=copy.deepcopy(old['inputs'])
            with self.assertRaises(ValueError):a.original_gcd_scope(d)
    def test_private_model_requires_both_literal_markers(self):
        names=('ORIGINAL_GCD_SOFTWARE_PHYSICAL_SERVICE_FP_COMPILED_OUT','AUDIO_CLOCK_GCD_SOFTWARE_PHYSICAL_QUERY_COMPILED_OUT',
            'WIFI_NPA_SOFTWARE_PHYSICAL_NAMESPACE_COMPILED_OUT','WIFI_RPMH_SOFTWARE_PHYSICAL_PROVIDER_RAM_COMPILED_OUT',
            'WIFI_RPMH_PRIVATE_SOFTWARE_PHYSICAL_CLIENT_COMPILED_OUT')
        raw=dict.fromkeys(names,1)
        for name in names:
            for value in (None,True,False,'1',0,2):
                changed=dict(raw)
                if value is None:del changed[name]
                else:changed[name]=value
                with self.subTest(name=name,value=value),self.assertRaises(ValueError):a.original_gcd_model_markers({'raw_fields':changed},npa=True,private_client=True)
        a.original_gcd_model_markers({'raw_fields':raw},npa=True,private_client=True)
    def test_full_raw_fits_bounded_transport(self):
        d=self.candidate();cap=d['original_GCD_new_scope_RAM_log_capacity']
        self.assertEqual(cap,2097152)
        self.assertEqual(d['wifi_CPU0_resources_firmware_RAM_log_capacity'],cap)
        self.assertEqual(KernelProtocol.limits['logs'],(4<<20)+cap+128)
        self.assertEqual(d['wifi_CPU0_RPMh_private_raw_bytes'],227104)

class OriginalAllocatorAlignmentScope(PrivateRpmhScope):
    def candidate(self):
        p=a.GCD_CLOCK_0150
        return dict(copy.deepcopy(p['metadata']),**copy.deepcopy(p['resource_fields']),
            inputs=copy.deepcopy(p['inputs']),kernel_sha256=p['kernel'],payload_sha256=p['payload'])
    def test_new_scope_exposes_private_mutation(self):
        d=self.candidate()
        self.assertIs(a.original_gcd_policy(d),a.GCD_CLOCK_0150)
        self.assertTrue(a.resources_clock_scope(d))
        self.assertEqual(len(d['inputs']),70)
    def test_0149_cannot_claim_corrected_source(self):
        d=self.candidate()
        header='shim/polaris/uefi-wifi-rpmh-client.h'
        self.assertNotEqual(d['inputs'][header],a.GCD_CLOCK_0149['inputs'][header])
        d['inputs'][header]=a.GCD_CLOCK_0149['inputs'][header]
        self.assertIs(a.original_gcd_policy(d),a.GCD_CLOCK_0149)
        self.assertIsNot(a.original_gcd_policy(d),a.GCD_CLOCK_0150)

if __name__=='__main__':unittest.main()
