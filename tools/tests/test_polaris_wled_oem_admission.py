"""Independent physical OEM scope, exact fault matrix and old-client rejection."""
import copy
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tools'))
from polaris_wled_oem_admission import PHYSICAL_SCOPE,BASE_CHECKS,admit
from .test_polaris_wled_power_scope import load


def fixture():
    d=dict(PHYSICAL_SCOPE,inputs={'fixed-source':'sha'},kernel_sha256='kernel',chain_app=None)
    models=[]
    for timeout,prepare,status in [(False,None,0),(True,None,0),(False,'owner',0),
                                   (False,'configuration',0),(False,'before-cycle',0),
                                   (False,None,2),(False,None,4),(False,None,128),
                                   (False,None,512),(False,None,1024),(False,None,32768)]:
        error={'owner':32,'configuration':33,'before-cycle':0}.get(prepare,65 if status else 36 if timeout else 0)
        issued=0 if prepare else 1 if (status or timeout) else 4
        completed=0 if timeout else issued
        checks=BASE_CHECKS|{'OEM_policy_explicit','retained_status_history','actual_binary_journal'}
        if prepare=='before-cycle':checks=(checks-{'OEM_policy_explicit'})|{'OEM_scope_compiled_but_not_entered'}
        if prepare:checks=(checks-{'preflight_succeeded'})|{'preflight_refused_without_write',
            'before_cycle_no_WLED_access' if prepare=='before-cycle' else 'source_status_retained_before_refusal','actual_zero_write_recovery_receipt'}
        elif status:checks|={'serious_word_retained','no_false_final_receipt'}
        elif timeout:checks|={'ILIM_history_not_discarded','no_false_final_receipt'}
        else:checks|={'ILIM_history_not_discarded','final_two_actual_reset_reads'}
        m=dict(passed=True,WLED_OEM_status_policy=True,WLED_power_cycle_only=True,
            inputs=d['inputs'],kernel_sha256='kernel',kernel_CPU_started=False,release_handoff_admitted=False,
            actual_phone_or_PMIC_emulated=False,physical_PMIC_power_control_tested=False,
            controlled_write_timeout=timeout,controlled_prepare_refusal=bool(prepare),controlled_prepare_kind=prepare,controlled_status_after_issue=status,
            checks={k:True for k in checks},raw_fields=dict(WLED_POWER_MOCK_BACKEND=1,WLED_KERNEL_AP_STAGE=0,
                WLED_POWER_FINAL_ERROR=error,WLED_POWER_FINAL_UNCERTAIN=int(bool(timeout or status)),
                WLED_POWER_FINAL_RESET_ALLOWED=int(not(timeout or status)),WLED_RESET_RECEIPT_READY=int(not(timeout or status))),
            binary_journal_evidence=dict(journal=dict(error=error,issued=issued,completed=completed,
                count=0 if prepare else 5 if (status or timeout) else 30,cycle_restored_readbacks=not(error or prepare))))
        if prepare:m['binary_journal_evidence']['zero_write_receipt']={'no_PMIC_command_issued_receipt':True}
        elif not error:m['binary_journal_evidence']['final_receipt']={'final_restore_receipt_valid':True}
        models.append(m)
    return d,models


class OemAdmission(unittest.TestCase):
    def test_all_exact_physical_scope_fields_required(self):
        d,m=fixture();admit(d,m)
        for k,v in PHYSICAL_SCOPE.items():
            bad=dict(d);bad[k]=not v if type(v) is bool else 'foreign' if v is None else v+1
            with self.subTest(key=k),self.assertRaises(ValueError):admit(bad,m)
            bad=dict(d);bad.pop(k)
            with self.assertRaises(ValueError):admit(bad,m)
        with self.assertRaises(ValueError):admit(dict(d,chain_app={}),m)

    def test_every_fault_case_and_every_native_check_are_required(self):
        d,m=fixture()
        for n in range(len(m)):
            with self.assertRaises(ValueError):admit(d,m[:n]+m[n+1:])
            bad=copy.deepcopy(m);bad[n]=copy.deepcopy(m[(n+1)%len(m)])
            with self.assertRaises(ValueError):admit(d,bad)
            for key in m[n]['checks']:
                bad=copy.deepcopy(m);bad[n]['checks'].pop(key)
                with self.subTest(case=n,key=key),self.assertRaises(ValueError):admit(d,bad)
        bad=copy.deepcopy(m);bad[0]['controlled_prepare_refusal']=1
        with self.assertRaises(ValueError):admit(d,bad)

    def test_wrong_error_or_false_restoration_never_passes(self):
        d,m=fixture()
        for n in range(len(m)):
            for key,value in [('kernel_CPU_started',True),('release_handoff_admitted',True),
                              ('actual_phone_or_PMIC_emulated',True),('inputs',{}),('kernel_sha256','stale')]:
                bad=copy.deepcopy(m);bad[n][key]=value
                with self.assertRaises(ValueError):admit(d,bad)
            for key in ('WLED_POWER_FINAL_ERROR','WLED_POWER_FINAL_UNCERTAIN','WLED_POWER_FINAL_RESET_ALLOWED'):
                bad=copy.deepcopy(m);bad[n]['raw_fields'][key]^=1
                with self.assertRaises(ValueError):admit(d,bad)
        for n in range(1,len(m)):
            bad=copy.deepcopy(m);bad[n]['binary_journal_evidence']['journal']['cycle_restored_readbacks']=True
            with self.assertRaises(ValueError):admit(d,bad)

    def test_old_packagers_cannot_accept_stripped_OEM_status_tag(self):
        for key in ('WLED_OEM_physical_cycle','controlled_WLED_prepare_refusal'):
            for name in ('polaris-uefi-wled-power-image','polaris-uefi-wled-image'):
                module=load(name)
                with self.assertRaises(ValueError):module.admit({key:True},[])
            with self.assertRaisesRegex(ValueError,'pre-XNU'):
                load('polaris-uefi-xnu-image').admit({key:True},{},None,None,None)

    def test_physical_and_mock_flags_cannot_be_combined(self):
        base=['python3',str(ROOT/'tools/build-polaris-uefi-xnu.py'),'--zig','/missing','--kernel','/missing','--payload','/missing','--output','/missing']
        for flags in [ ['--wled-oem-physical-cycle'],
             ['--wled-oem-physical-cycle','--wled-power-cycle-only','--test-qemu'],
             ['--wled-oem-physical-cycle','--wled-power-cycle-only','--test-wled-write-timeout'],
             ['--test-wled-prepare-refusal'],
             ['--wled-oem-status','--wled-power-cycle-only','--test-qemu','--test-wled-prepare-refusal','--test-wled-write-timeout']]:
            p=subprocess.run(base+flags,capture_output=True,text=True)
            self.assertEqual(p.returncode,2);self.assertNotIn('FileNotFoundError',p.stderr)

    def test_new_host_binding_rejects_old_session_and_wrong_scope(self):
        host=load('polaris-uefi-wled-oem');d,_=fixture();d['sha256']='driver'
        image=dict(d,sha256='image',driver_sha256='driver',driver_manifest_sha256='manifest',
                   final_reset_receipt_required=True,root_access_permitted=False,installer=False)
        boot=dict(state='temporary_WLED_OEM_power_cycle_boot_command_succeeded',sent_utc='time',
                  image_sha256='image',driver_manifest_sha256='manifest')
        host.binding(boot,image,d)
        for key,value in [('state','temporary_WLED_power_cycle_boot_command_succeeded'),
                          ('image_sha256','stale'),('driver_manifest_sha256','stale')]:
            with self.assertRaises(ValueError):host.binding(dict(boot,**{key:value}),image,d)
        with self.assertRaises(ValueError):host.binding(boot,dict(image,root_access_permitted=True),d)

    def test_electrical_cycle_readbacks_do_not_claim_physical_darkness(self):
        host=load('polaris-uefi-wled-oem')
        from .test_polaris_wled_power_scope import cycle_log
        text=cycle_log()+('WLED_POWER_OEM_STATUS_POLICY=0x0000000000000001\n'
                          'WLED_POWER_SOURCE_STATUS_VALID=0x0000000000000003\n'
                          'WLED_POWER_SOURCE_STATUS=0x0000000000000101\n')
        result=host.cycle_readbacks(text)
        self.assertTrue(result['electrical_module_off_and_restored_readbacks'])
        self.assertFalse(result['physical_darkness_proven'])
        for extra in ('WLED_POWER_MOCK_BACKEND=1\n','Darwin Kernel Version',
                      'WLED_POWER_SOURCE_STATUS_VALID=0x0000000000000003\n'):
            with self.assertRaises(ValueError):host.cycle_readbacks(text+extra)
        with self.assertRaises(ValueError):host.cycle_readbacks(text.replace('0000000000000101','0000000000000202'))


if __name__=='__main__':unittest.main()
