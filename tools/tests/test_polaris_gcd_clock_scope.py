"""NEW original-call scope and actual-model marker gates remain fail closed."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import polaris_wled_runtime_admission as a
spec=importlib.util.spec_from_file_location('gcd_builder',Path(__file__).resolve().parents[1]/'build-polaris-uefi-xnu.py')
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)

class GcdClockScope(unittest.TestCase):
    def enabled(self):
        d=dict(inputs={p:'source' for p in ('shim/polaris/uefi-gcd-mmio-readonly.h','shim/polaris/gcd-core-identity.h','shim/polaris/uefi-audio-clock-gcd-query.h','tools/polaris-uefi-gcd-identity.py')},kernel_sha256='kernel',payload_sha256='payload')
        fields=b.gcd_clock_metadata(True,False,{'whole_SHA256':'core','binding_sha256':'binding'},'private.efi')
        d.update(fields);resource=copy.deepcopy(a.RESOURCES_CLOCK_PHYSICAL_FIELDS);resource.update(wifi_CPU0_resources_firmware_RAM_log_capacity=262144,audio_Clock_query_raw_report_format='RAW_V2',audio_Clock_query_raw_report_bytes=43504,audio_Clock_query_combined_I2C_Clock_RAM_report_bytes=98076,audio_Clock_query_actual_Device_identity_and_EFI_MMIO_required=False);d.update(resource)
        return d,dict(firmware_source='SOFTWARE-FIXTURE',inputs=copy.deepcopy(d['inputs']),kernel='kernel',payload='payload',metadata=fields,resource_fields=resource)

    def test_unsealed_new_source_refuses(self):
        with patch.object(a,'GCD_CLOCK_0143',None):
            with self.assertRaisesRegex(ValueError,'separately reviewed'):a.original_gcd_scope(self.enabled()[0])

    def test_new_source_cannot_hide_behind_missing_or_disabled_metadata(self):
        for source in self.enabled()[0]['inputs']:
            for metadata in ({},a.GCD_CLOCK_DISABLED):
                with self.subTest(source=source,metadata=bool(metadata)):
                    with self.assertRaisesRegex(ValueError,'cannot hide'):
                        a.original_gcd_scope(dict(metadata,inputs={source:'hash'}))

    def test_exact_typed_metadata_source_kernel_and_payload(self):
        d,policy=self.enabled()
        with patch.object(a,'GCD_CLOCK_0143',policy):
            self.assertTrue(a.original_gcd_scope(d));self.assertTrue(a.resources_clock_scope(d))
            for key,value in [('original_GCD_query',1),('original_GCD_original_getter_calls_max',True),('original_GCD_raw_bytes',29999),('original_GCD_Attributes_allowed',[0,1,8]),('original_GCD_CPACR_write',True),('original_GCD_indirect_event_hardware_side_effects_proven_absent',True),('original_GCD_unreviewed_field',False),('kernel_sha256','foreign'),('payload_sha256','foreign')]:
                bad=copy.deepcopy(d);bad[key]=value
                with self.subTest(key=key):
                    with self.assertRaises(ValueError):a.original_gcd_scope(bad)
            bad=copy.deepcopy(d);bad['inputs']['extra.c']='extra'
            with self.assertRaises(ValueError):a.original_gcd_scope(bad)
            bad=copy.deepcopy(d);bad['wifi_CPU0_resources_SFPB_writes']=True
            with self.assertRaises(ValueError):a.resources_clock_scope(bad)

    def test_actual_model_markers_are_both_exact_integer_one(self):
        names=('ORIGINAL_GCD_SOFTWARE_PHYSICAL_SERVICE_FP_COMPILED_OUT','AUDIO_CLOCK_GCD_SOFTWARE_PHYSICAL_QUERY_COMPILED_OUT')
        a.original_gcd_model_markers({'raw_fields':dict.fromkeys(names,1)})
        for name in names:
            for invalid in (None,True,False,'1',0,2):
                raw=dict.fromkeys(names,1)
                if invalid is None:del raw[name]
                else:raw[name]=invalid
                with self.subTest(name=name,invalid=invalid):
                    with self.assertRaises(ValueError):a.original_gcd_model_markers({'raw_fields':raw})

    def test_admit_itself_enforces_new_markers(self):
        # All other gates use their already-covered standard fixture. Only the
        # NEW GCD scope is mocked enabled to exercise the production admit loop.
        path=Path(__file__).with_name('test_polaris_wled_runtime_admission.py')
        spec=importlib.util.spec_from_file_location('existing_runtime_fixture',path);f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
        args=f.fixture();d,models,ci,pre,review=args;t=a.TARGETS['20F66'];d['kernel_sha256']=t['kernel'];ci.update(databaseId=t['CI'],headSha=t['source']);pre.update(build='20F66',full_image_sha256=t['root'],extent_count=t['extents']);review.update(build='20F66',post_unmount_RO_only=True,new_file_install_preceded_readonly_review=True,original_root_and_marker_preserved=True,new_root_immutable=True);f.add_runtime_services(args)
        names=('ORIGINAL_GCD_SOFTWARE_PHYSICAL_SERVICE_FP_COMPILED_OUT','AUDIO_CLOCK_GCD_SOFTWARE_PHYSICAL_QUERY_COMPILED_OUT')
        for m in models:m['raw_fields']=dict.fromkeys(names,1)
        with patch.object(a,'exact_scope',return_value=None),patch.object(a,'firstread_scope',return_value=False),patch.object(a,'normal_nc_firstread_scope',return_value=False),patch.object(a,'audio_i2c_cache_scope',return_value=False),patch.object(a,'resources_clock_scope',return_value=False),patch.object(a,'original_gcd_scope',return_value=True):
            a.admit(*args,build='20F66')
            for name in names:
                for invalid in (None,True,'1',0,2):
                    bad=copy.deepcopy(args)
                    if invalid is None:del bad[1][0]['raw_fields'][name]
                    else:bad[1][0]['raw_fields'][name]=invalid
                    with self.subTest(name=name,invalid=invalid):
                        with self.assertRaisesRegex(ValueError,'NEW GCD/Clock model'):a.admit(*bad,build='20F66')

if __name__=='__main__':unittest.main()
