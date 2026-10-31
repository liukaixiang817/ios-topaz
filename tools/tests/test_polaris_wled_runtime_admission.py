"""Independent runtime scope rejects old clients, mixed faults and writes."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from polaris_wled_runtime_admission import PHYSICAL,THERMAL,PAIR,KERNEL_SHA,NATIVE_SOURCE,ROOT_SHA,TARGETS,admit,exact_scope
ROOT=Path(__file__).resolve().parents[2]


def fixture():
    d=dict(PHYSICAL,kernel_sha256=KERNEL_SHA,GPU_thermal_policy=copy.deepcopy(THERMAL),TSENS_pair_policy=copy.deepcopy(PAIR),inputs={'exact.c':'x'})
    models=[dict(controlled_exit=k,passed=True,inputs=d['inputs'],SOFTWARE_PMIC=True,RAM_USB_sink=True,physical_admission=False,checks={str(n):True for n in range(18)}) for k in ('delayed-footer','lost-receipt-recovery')]
    ci=dict(conclusion='success',status='completed',databaseId=41056172330,headSha=NATIVE_SOURCE)
    pre=dict(may_boot_iOS=True,may_write_userdata=False,full_image_sha256=ROOT_SHA,extent_count=182,phone_partition_writes=False,outer_needs_journal_recovery=False,outer_state=1,write_ownership_baseline_update_permitted=False,permitted_boot_arguments={'ufsrw':0,'polarisramcow':1,'rootrw':1,'polarisrammb':512,'polarisownedmarker':0})
    for k in ('all_six_GPT_copies_match_original','fresh_maps_before_after_match','unmounted','block_readonly','outer_header_unchanged_during_readonly_check','outer_header_independently_reviewed','actual_expected_fastboot_after_verified','critical_partitions_match_reviewed_baselines'):pre[k]=True
    return d,models,ci,pre,dict(passed=True,may_boot_iOS=True,may_write_userdata=False)


class RuntimeAdmission(unittest.TestCase):
    def test_20F66_requires_its_kernel_CI_root_and_separate_post_unmount_review(self):
        args=fixture();d,models,ci,pre,review=args;t=TARGETS['20F66']
        d['kernel_sha256']=t['kernel'];ci.update(databaseId=t['CI'],headSha=t['source'])
        pre.update(build='20F66',full_image_sha256=t['root'],extent_count=t['extents'])
        review.update(build='20F66',post_unmount_RO_only=True,
            new_file_install_preceded_readonly_review=True,original_root_and_marker_preserved=True,new_root_immutable=True)
        admit(*args,build='20F66');exact_scope(d,'20F66')
        with self.assertRaises(ValueError):admit(*args)
        for at,key,value in [(0,'kernel_sha256',KERNEL_SHA),(2,'databaseId',41056172330),
                             (3,'full_image_sha256',ROOT_SHA),(3,'extent_count',182),
                             (4,'build','20H392'),(4,'post_unmount_RO_only',False),
                             (4,'new_file_install_preceded_readonly_review',False),
                             (4,'original_root_and_marker_preserved',False),(4,'new_root_immutable',False)]:
            bad=copy.deepcopy(args);bad[at][key]=value
            with self.assertRaises(ValueError):admit(*bad,build='20F66')

    def test_exact_scope_all_bits_and_integer_bool_confusion_refuse(self):
        d,*_=fixture();exact_scope(d)
        for k,v in PHYSICAL.items():
            b=copy.deepcopy(d);b[k]=not v if type(v) is bool else v+1
            with self.assertRaises(ValueError):exact_scope(b)
        for k in ('WLED_native_runtime_physical','PMIC_write_api'):
            b=copy.deepcopy(d);del b[k]
            with self.assertRaises(ValueError):exact_scope(b)
        for k,v in [('controlled_WLED_native_exit','delayed-footer'),('controlled_WLED_native_fault','timeout'),('chain_app',{})]:
            b=copy.deepcopy(d);b[k]=v
            with self.assertRaises(ValueError):exact_scope(b)
        b=copy.deepcopy(d);b['TSENS_pair_policy']['actual_words_only']=True
        with self.assertRaises(ValueError):exact_scope(b)

    def test_stale_models_foreign_CI_and_write_or_unreviewed_root_refuse(self):
        args=fixture();admit(*args)
        for at,change in [(1,lambda m:m.pop()),(1,lambda m:m[1].update(controlled_exit='delayed-footer')),
                          (2,lambda c:c.update(headSha='foreign')),(3,lambda p:p.update(may_write_userdata=True)),
                          (3,lambda p:p.update(outer_needs_journal_recovery=True)),(4,lambda r:r.update(may_boot_iOS=False))]:
            bad=copy.deepcopy(args);change(bad[at])
            with self.assertRaises(ValueError):admit(*bad)

    def test_new_scope_cannot_enter_the_ordinary_client_even_with_old_boot_label(self):
        spec=importlib.util.spec_from_file_location('old',ROOT/'tools/polaris-uefi-xnu.py');old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
        d,*_=fixture()
        with self.assertRaises(ValueError):old.binding(dict(state='temporary_UEFI_XNU_boot_command_succeeded'),d,d)
        spec=importlib.util.spec_from_file_location('new',ROOT/'tools/polaris-uefi-wled-runtime.py');new=importlib.util.module_from_spec(spec);spec.loader.exec_module(new)
        with self.assertRaises(ValueError):new.binding(dict(state='temporary_UEFI_XNU_boot_command_succeeded'),d,d)


if __name__=='__main__':unittest.main()
