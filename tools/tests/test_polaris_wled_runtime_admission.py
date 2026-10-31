"""Independent runtime scope rejects old clients, mixed faults and writes."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from polaris_wled_runtime_admission import (PHYSICAL,THERMAL,PAIR,KERNEL_SHA,NATIVE_SOURCE,ROOT_SHA,
    TARGETS,RUNTIME_SERVICES,RUNTIME_DT,CLOCK_INITIAL_SHA,BASE_TERMINAL_CHECKS,admit,exact_scope)
ROOT=Path(__file__).resolve().parents[2]


def fixture():
    d=dict(PHYSICAL,kernel_sha256=KERNEL_SHA,GPU_thermal_policy=copy.deepcopy(THERMAL),TSENS_pair_policy=copy.deepcopy(PAIR),inputs={'exact.c':'x'})
    models=[dict(controlled_exit=k,passed=True,inputs=d['inputs'],SOFTWARE_PMIC=True,RAM_USB_sink=True,physical_admission=False,checks={str(n):True for n in range(18)}) for k in ('delayed-footer','lost-receipt-recovery')]
    ci=dict(conclusion='success',status='completed',databaseId=41056172330,headSha=NATIVE_SOURCE)
    pre=dict(may_boot_iOS=True,may_write_userdata=False,full_image_sha256=ROOT_SHA,extent_count=182,phone_partition_writes=False,outer_needs_journal_recovery=False,outer_state=1,write_ownership_baseline_update_permitted=False,permitted_boot_arguments={'ufsrw':0,'polarisramcow':1,'rootrw':1,'polarisrammb':512,'polarisownedmarker':0})
    for k in ('all_six_GPT_copies_match_original','fresh_maps_before_after_match','unmounted','block_readonly','outer_header_unchanged_during_readonly_check','outer_header_independently_reviewed','actual_expected_fastboot_after_verified','critical_partitions_match_reviewed_baselines'):pre[k]=True
    return d,models,ci,pre,dict(passed=True,may_boot_iOS=True,may_write_userdata=False)


def add_runtime_services(args):
    d,models,*_=args
    d.update(copy.deepcopy(RUNTIME_SERVICES),runtime_services_DT=copy.deepcopy(RUNTIME_DT),
        payload_bytes=0x100000,host_UTC_mailbox=dict(symbol='_polaris_uefi_clock',offset=0x1000,bytes=256,
            alignment=128,segment='__DATA',section='__data',file_offset=0x400,
            initial_sha256=CLOCK_INITIAL_SHA,BSS=False),
        battery_mailbox=dict(symbol='_polaris_uefi_battery',offset=0x2000,bytes=256,
            alignment=128,segment='__DATA',section='__common',BSS=True,pre_CPU_ON_publish=False),
        input_offset=0x3000,buttons_offset=0x3100,shutdown_offset=0x3200)
    for m in models:
        m.update(checks={k:True for k in BASE_TERMINAL_CHECKS|{'actual_clock_firmware_slot_prepared'}},
            QEMU_command=['qemu-system-aarch64','-accel','tcg','-cpu','cortex-a55,cntfrq=19200000'],
            SOFTWARE_CNTFRQ_hz=19200000,host_UTC_SET_sent=False,host_UTC_sync_applied_proven=False,
            battery_physical_PMIC_reads_compiled_out=True,battery_SOFTWARE_disabled_observed=True,
            physical_USB_or_PMIC_emulation=False,actual_guest_reset_proven=False)
    return args


class RuntimeAdmission(unittest.TestCase):
    def test_20F66_requires_its_kernel_CI_root_and_separate_post_unmount_review(self):
        args=fixture();d,models,ci,pre,review=args;t=TARGETS['20F66']
        d['kernel_sha256']=t['kernel'];ci.update(databaseId=t['CI'],headSha=t['source'])
        pre.update(build='20F66',full_image_sha256=t['root'],extent_count=t['extents'])
        review.update(build='20F66',post_unmount_RO_only=True,
            new_file_install_preceded_readonly_review=True,original_root_and_marker_preserved=True,new_root_immutable=True)
        if t.get('runtime_services') is True:add_runtime_services(args)
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


class RuntimeServicesAdmission(unittest.TestCase):
    def test_explicit_profile_only_uses19_checks_and_keeps_old18(self):
        args=add_runtime_services(fixture())
        with self.assertRaises(ValueError):admit(*args)
        with patch.dict(TARGETS['20H392'],runtime_services=True):
            admit(*args)
            for change in ('old18','missing-clock-name','false-clock'):
                bad=copy.deepcopy(args);checks=bad[1][0]['checks']
                if change=='old18':del checks['actual_clock_firmware_slot_prepared']
                elif change=='missing-clock-name':checks['unrelated']=checks.pop('actual_clock_firmware_slot_prepared')
                else:checks['actual_clock_firmware_slot_prepared']=False
                with self.assertRaises(ValueError,msg=change):admit(*bad)
        admit(*fixture())

    def test_physical_flags_DT_types_and_no_write_gates(self):
        args=add_runtime_services(fixture());d=args[0]
        with patch.dict(TARGETS['20H392'],runtime_services=True):
            exact_scope(d)
            for key,value in RUNTIME_SERVICES.items():
                bad=copy.deepcopy(d)
                bad[key]=not value if type(value) is bool else value+1 if type(value) is int else value+' changed'
                with self.assertRaises(ValueError,msg=key):exact_scope(bad)
                del bad[key]
                with self.assertRaises(ValueError,msg='missing '+key):exact_scope(bad)
            for change in ('extra','missing','version-bool','battery-bool-as-int','path'):
                bad=copy.deepcopy(d);dt=bad['runtime_services_DT']
                if change=='extra':dt['unverified']=True
                elif change=='missing':del dt['wifi_readonly']
                elif change=='version-bool':dt['version']=True
                elif change=='battery-bool-as-int':dt['battery_readonly']=1
                else:dt['path']='/other'
                with self.assertRaises(ValueError,msg=change):exact_scope(bad)

    def test_two_native_mailboxes_are_exact_and_independent(self):
        d=add_runtime_services(fixture())[0]
        with patch.dict(TARGETS['20H392'],runtime_services=True):
            for change in ('clock-short','clock-BSS','clock-seed','clock-file-offset','clock-extra',
                           'battery-DATA','battery-early','alias','partial-alias','input-alias','offset-bool','outside-bank'):
                bad=copy.deepcopy(d);clock=bad['host_UTC_mailbox'];battery=bad['battery_mailbox']
                if change=='clock-short':clock['bytes']=128
                elif change=='clock-BSS':clock['BSS']=True
                elif change=='clock-seed':clock['initial_sha256']='0'*64
                elif change=='clock-file-offset':clock['file_offset']=bad['payload_bytes']
                elif change=='clock-extra':clock['unchecked']=0
                elif change=='battery-DATA':battery['section']='__data'
                elif change=='battery-early':battery['pre_CPU_ON_publish']=True
                elif change=='alias':battery['offset']=clock['offset']
                elif change=='partial-alias':battery['offset']=clock['offset']+128
                elif change=='input-alias':clock['offset']=bad['input_offset']
                elif change=='offset-bool':clock['offset']=False
                else:battery['offset']=bad['RAM_bytes']
                with self.assertRaises(ValueError,msg=change):exact_scope(bad)

    def test_models_cannot_claim_physical_battery_calendar_or_send_SET(self):
        args=add_runtime_services(fixture())
        with patch.dict(TARGETS['20H392'],runtime_services=True):
            for key,value in [('SOFTWARE_CNTFRQ_hz',62500000),('host_UTC_SET_sent',True),
                ('host_UTC_sync_applied_proven',True),('battery_physical_PMIC_reads_compiled_out',False),
                ('battery_SOFTWARE_disabled_observed',False),('actual_guest_reset_proven',True),
                ('physical_USB_or_PMIC_emulation',True),('QEMU_command',['qemu','-cpu','cortex-a55']),
                ('checks',[True]*19)]:
                bad=copy.deepcopy(args);bad[1][0][key]=value
                with self.assertRaises(ValueError,msg=key):admit(*bad)


class ModelClockFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec=importlib.util.spec_from_file_location('terminal_model',ROOT/'tools/qemu-polaris-wled-runtime-exit.py')
        cls.runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.runner)

    def test_legacy_disabled_and_explicit_filebacked_clock(self):
        self.assertIsNone(self.runner.clock_fixture({}))
        self.assertIsNone(self.runner.clock_fixture({'host_UTC_sync':False}))
        d=add_runtime_services(fixture())[0]
        self.assertEqual(self.runner.clock_fixture(d),d['host_UTC_mailbox'])
        for key,value in [('host_UTC_sync',1),('RTC_write_api',True),('calendar_RAM_only',False)]:
            bad=copy.deepcopy(d);bad[key]=value
            with self.assertRaises(ValueError):self.runner.clock_fixture(bad)

    def test_real_dump_requires_zero_sequence_actual_cookie_frequency_and_source(self):
        import struct
        raw=bytearray(256);struct.pack_into('<8Q',raw,0,0x50434c4f434b3031,19,0,0,0,0,19200000,1)
        self.assertTrue(self.runner.clock_slot_prepared(raw))
        self.assertFalse(self.runner.clock_slot_prepared(raw[:128]))
        for index,value in [(0,0),(1,0),(2,1),(3,1577836800000000),(6,62500000),(7,0),(15,1)]:
            bad=raw[:];struct.pack_into('<Q',bad,index*8,value)
            self.assertFalse(self.runner.clock_slot_prepared(bad),str(index))

    def test_clock_enabled_actual_payload_DT_and_CPU_counter_must_match(self):
        import adt,struct
        command=['qemu','-accel','tcg','-cpu','cortex-a55,cntfrq=19200000']
        tree=adt.Node();cpus=adt.Node();cpus.props=[('name',0,b'cpus\0')];tree.children=[cpus]
        names=('timebase-frequency','peripheral-frequency','fixed-frequency')
        for i in range(4):
            cpu=adt.Node();cpu.props=[('name',0,('cpu'+str(i)+'\0').encode())]
            cpu.props += [(n,0,struct.pack('<I',19200000)) for n in names];cpus.children.append(cpu)
        def payload(t):
            blob=adt.serialize(t);raw=bytearray(72);struct.pack_into('<QQ',raw,32,72,len(blob));return raw+blob
        self.assertEqual(self.runner.clock_model_timebase(payload(tree),command)['frequency_hz'],19200000)
        for name in names:
            for change in ('old62_5MHz','u64','placeholder','duplicate','missing'):
                bad=copy.deepcopy(tree);cpu=bad.children[0].children[3]
                index=next(i for i,p in enumerate(cpu.props) if p[0]==name)
                if change=='old62_5MHz':cpu.props[index]=(name,0,struct.pack('<I',62500000))
                elif change=='u64':cpu.props[index]=(name,0,struct.pack('<Q',19200000))
                elif change=='placeholder':cpu.props[index]=(name,1,struct.pack('<I',19200000))
                elif change=='duplicate':cpu.props.append(cpu.props[index])
                else:cpu.props.pop(index)
                with self.assertRaises(ValueError,msg=(name,change)):
                    self.runner.clock_model_timebase(payload(bad),command)
        with self.assertRaises(ValueError):self.runner.clock_model_timebase(payload(tree),['qemu','-cpu','cortex-a55'])
        bad=payload(tree);at,size=struct.unpack_from('<QQ',bad,32);bad+=b'xxxx';struct.pack_into('<Q',bad,40,size+4)
        with self.assertRaises(ValueError):self.runner.clock_model_timebase(bad,command)


if __name__=='__main__':unittest.main()
