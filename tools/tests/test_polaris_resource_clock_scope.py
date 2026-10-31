"""New physical readers cannot inherit an older scope or hide behind disabled metadata."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import polaris_wled_runtime_admission as a


class ResourceClockScope(unittest.TestCase):
    def enabled(self):
        d=dict(kernel_sha256='kernel',payload_sha256='payload',inputs={
            'shim/polaris/uefi-wifi-resources-readonly.h':'resource-source',
            'shim/polaris/uefi-audio-clock-query.h':'clock-source'},
            wifi_CPU0_normal_nc_firstread_readonly=True,audio_I2C_cache_readonly=True,
            wifi_CPU0_firstread_readonly=False)
        d.update(copy.deepcopy(a.RESOURCES_CLOCK_PHYSICAL_FIELDS))
        policy=dict(firmware_source='SOFTWARE-FIXTURE',kernel=d['kernel_sha256'],payload=d['payload_sha256'],inputs=copy.deepcopy(d['inputs']))
        return d,policy

    def test_old_scopes_or_exact_disabled_metadata_stay_disabled(self):
        self.assertFalse(a.resources_clock_scope({'inputs':{'old.c':'old'}}))
        self.assertFalse(a.resources_clock_scope(dict(a.RESOURCES_CLOCK_DISABLED,inputs={'old.c':'old'})))

    def test_source_cannot_hide_under_absent_or_disabled_fields(self):
        for name in ('shim/polaris/uefi-wifi-resources-readonly.h','shim/polaris/uefi-audio-clock-query.h'):
            for metadata in ({},a.RESOURCES_CLOCK_DISABLED):
                with self.subTest(source=name,disabled=bool(metadata)):
                    with self.assertRaisesRegex(ValueError,'cannot hide'):
                        a.resources_clock_scope(dict(metadata,inputs={name:'x'}))

    def test_unsealed_actual_policy_refuses_the_complete_new_scope(self):
        self.assertIsNone(a.RESOURCES_CLOCK_0142)
        with self.assertRaisesRegex(ValueError,'separately committed-source0142'):
            a.resources_clock_scope(self.enabled()[0])

    def test_synthetic_seal_is_exact_typed_source_and_payload_bound(self):
        d,policy=self.enabled()
        with patch.object(a,'RESOURCES_CLOCK_0142',policy):
            self.assertTrue(a.resources_clock_scope(d))
            changes={
                'wifi_CPU0_resources_GetMemoryMap_calls_max':3,
                'wifi_CPU0_resources_PSCI_calls_max':8,
                'wifi_CPU0_resources_RMTFS_address_assigned':True,
                'wifi_CPU0_resources_Reserved_is_free_or_owned':True,
                'wifi_CPU0_resources_cache_after_fresh_limit_ticks':3840001,
                'wifi_CPU0_resources_firmware_RAM_log_overflow_sticky':False,
                'wifi_CPU0_resources_map_buffer_capacity':65536,
                'wifi_CPU0_resources_raw_report_bytes':17415,
                'wifi_CPU0_resources_partial_GetMemoryMap_output_extent_unknown':False,
                'audio_Clock_query_clock_or_pin_ownership_proven':True,
                'audio_Clock_query_GetFreq_Enable_Disable_Open':True,
                'audio_Clock_query_query_calls_max':21,
                'audio_Clock_query_readonly':1,
                'audio_Clock_query_added_unreviewed_field':False,
                'wifi_CPU0_normal_nc_firstread_readonly':False,
                'audio_I2C_cache_readonly':False,
                'wifi_CPU0_firstread_readonly':True,
                'kernel_sha256':'changed','payload_sha256':'changed'}
            for key,value in changes.items():
                bad=copy.deepcopy(d);bad[key]=value
                with self.subTest(key=key):
                    with self.assertRaises(ValueError):a.resources_clock_scope(bad)
            bad=copy.deepcopy(d);bad['wifi_CPU0_resources_PSCI_calls_max']=True
            with self.assertRaises(ValueError):a.resources_clock_scope(bad)
            for which in ('changed-source','missing-source','extra-source','missing-field','SOFTWARE-body'):
                bad=copy.deepcopy(d)
                if which=='changed-source':bad['inputs']['shim/polaris/uefi-audio-clock-query.h']='changed'
                if which=='missing-source':del bad['inputs']['shim/polaris/uefi-wifi-resources-readonly.h']
                if which=='extra-source':bad['inputs']['unreviewed.c']='changed'
                if which=='missing-field':del bad['audio_Clock_query_binding_SHA256']
                if which=='SOFTWARE-body':bad['audio_Clock_query_physical_original_query_body']=False;bad['audio_Clock_query_physical_original_query_compiled_out']=True
                with self.subTest(which=which):
                    with self.assertRaises(ValueError):a.resources_clock_scope(bad)


if __name__=='__main__':unittest.main()
