"""Independent NC and I2C-cache source scopes stay fail-closed until reviewed."""
import copy
from unittest.mock import patch
import unittest
from .test_polaris_wled_runtime_admission import fixture,add_runtime_services
from tools import polaris_wled_runtime_admission as a
#The production client imports the same file by its tool-local module name.
import polaris_wled_runtime_admission as live

NC_HEADER='shim/polaris/uefi-wifi-firstread-normal-nc.h'
AUDIO_HEADER='shim/polaris/uefi-audio-i2c-cache.h'

def metadata(prefix,fields):return {prefix+k:copy.deepcopy(v) for k,v in fields.items()}

def source_fixture():
    d=fixture()[0]
    d.update(metadata(a.FIRSTREAD_PREFIX,a.FIRSTREAD_DISABLED))
    d.update(metadata(a.NORMAL_NC_PREFIX,a.NORMAL_NC_PHYSICAL_FIELDS))
    d.update(metadata(a.AUDIO_I2C_PREFIX,a.AUDIO_I2C_PHYSICAL_FIELDS))
    inputs={NC_HEADER:'synthetic-NC-SOURCE-only',AUDIO_HEADER:'synthetic-audio-SOURCE-only'}
    d.update(inputs=inputs,kernel_sha256='synthetic-kernel-only',payload_sha256='synthetic-payload-only')
    policy=dict(firmware_source='synthetic-committed-source-only',inputs=inputs,kernel=d['kernel_sha256'],payload=d['payload_sha256'])
    return d,policy

class DiagnosticScope(unittest.TestCase):
    def test_legacy_and_exact_disabled_scopes_do_not_gain_new_reads(self):
        d=fixture()[0];a.exact_scope(d)
        self.assertFalse(a.normal_nc_firstread_scope(d));self.assertFalse(a.audio_i2c_cache_scope(d))
        d.update(metadata(a.NORMAL_NC_PREFIX,a.NORMAL_NC_DISABLED));d.update(metadata(a.AUDIO_I2C_PREFIX,a.AUDIO_I2C_DISABLED))
        a.exact_scope(d)

    def test_enabled_scopes_are_not_admitted_without_committed_source_profile(self):
        d,_=source_fixture()
        with patch.object(a,'NORMAL_NC_0141',None),patch.object(a,'AUDIO_I2C_0141',None):
            with self.assertRaises(ValueError):a.normal_nc_firstread_scope(d)
            with self.assertRaises(ValueError):a.audio_i2c_cache_scope(d)
            with self.assertRaises(ValueError):a.exact_scope(d)

    def test_input_headers_cannot_hide_behind_absent_or_disabled_metadata(self):
        for header,prefix,fields,check in [(NC_HEADER,a.NORMAL_NC_PREFIX,a.NORMAL_NC_DISABLED,a.normal_nc_firstread_scope),
                (AUDIO_HEADER,a.AUDIO_I2C_PREFIX,a.AUDIO_I2C_DISABLED,a.audio_i2c_cache_scope)]:
            for values in ({},metadata(prefix,fields)):
                d=fixture()[0];d.update(values);d['inputs'][header]='unadmitted'
                with self.assertRaises(ValueError):check(d)

    def test_combined_source_fixture_keeps_both_complete_input_dicts(self):
        d,policy=source_fixture()
        with patch.object(a,'NORMAL_NC_0141',policy),patch.object(a,'AUDIO_I2C_0141',policy):
            self.assertTrue(a.normal_nc_firstread_scope(d));self.assertTrue(a.audio_i2c_cache_scope(d))
            for name in ('kernel_sha256','payload_sha256','inputs'):
                bad=copy.deepcopy(d);bad[name]='changed' if name!='inputs' else {NC_HEADER:'changed'}
                with self.assertRaises(ValueError):a.normal_nc_firstread_scope(bad)
                with self.assertRaises(ValueError):a.audio_i2c_cache_scope(bad)

    def test_old_device_flag_does_not_mix_with_new_NC_source(self):
        d,policy=source_fixture()
        with patch.object(a,'NORMAL_NC_0141',policy):
            for value in (True,1,None):
                bad=copy.deepcopy(d);bad['wifi_CPU0_firstread_readonly']=value
                with self.assertRaises(ValueError):a.normal_nc_firstread_scope(bad)
            bad=copy.deepcopy(d);bad['inputs']['shim/polaris/uefi-wifi-firstread.h']='foreignDevice'
            with self.assertRaises(ValueError):a.normal_nc_firstread_scope(bad)

    def test_all_metadata_fields_types_missing_extra_and_changed_values_refuse(self):
        d,policy=source_fixture()
        for prefix,fields,key,check in [(a.NORMAL_NC_PREFIX,a.NORMAL_NC_PHYSICAL_FIELDS,'NORMAL_NC_0141',a.normal_nc_firstread_scope),
                (a.AUDIO_I2C_PREFIX,a.AUDIO_I2C_PHYSICAL_FIELDS,'AUDIO_I2C_0141',a.audio_i2c_cache_scope)]:
            with patch.object(a,key,policy):
                for name,value in fields.items():
                    bad=copy.deepcopy(d);del bad[prefix+name]
                    with self.assertRaises(ValueError,msg=name):check(bad)
                    changed=not value if type(value) is bool else value+1 if type(value) is int else [] if type(value) is list else 'foreign'
                    bad=copy.deepcopy(d);bad[prefix+name]=changed
                    with self.assertRaises(ValueError,msg=name):check(bad)
                    if type(value) in (bool,int):
                        bad=copy.deepcopy(d);bad[prefix+name]=int(value) if type(value) is bool else bool(value)
                        with self.assertRaises(ValueError,msg=name):check(bad)
                bad=copy.deepcopy(d);bad[prefix+'unknown_permission']=False
                with self.assertRaises(ValueError):check(bad)

    def test_actual_SOFTWARE_models_need_exact_integer1_for_both_new_markers(self):
        args=add_runtime_services(fixture());d,models,ci,pre,review=args;t=a.TARGETS['20F66']
        values,policy=source_fixture();d.update(values);d['kernel_sha256']=t['kernel'];policy['kernel']=t['kernel']
        #Restore the runtime mailbox fields from the actualfixture after its
        #synthetic-source overlay; no hardware admission is asserted.
        add_runtime_services(args)
        markers=('WIFI_NORMAL_NC_FIRSTREAD_SOFTWARE_PHYSICAL_SMEM_READ_COMPILED_OUT','AUDIO_I2C_CACHE_SOFTWARE_PHYSICAL_IMAGE_INSPECTION_COMPILED_OUT')
        for m in models:m.update(inputs=d['inputs'],raw_fields={name:1 for name in markers})
        ci.update(databaseId=t['CI'],headSha=t['source']);pre.update(build='20F66',full_image_sha256=t['root'],extent_count=t['extents'])
        review.update(build='20F66',post_unmount_RO_only=True,new_file_install_preceded_readonly_review=True,original_root_and_marker_preserved=True,new_root_immutable=True)
        with patch.object(a,'NORMAL_NC_0141',policy),patch.object(a,'AUDIO_I2C_0141',policy):
            a.admit(*args,build='20F66')
            for name in markers:
                for badvalue in (None,True,False,0,2,'1'):
                    bad=copy.deepcopy(args);bad[1][0]['raw_fields'][name]=badvalue
                    with self.assertRaises(ValueError):a.admit(*bad,build='20F66')

if __name__=='__main__':unittest.main()
