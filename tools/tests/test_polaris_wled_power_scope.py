"""A bounded electrical cycle is neither OS admission nor optical proof."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest
from .test_polaris_wled_physical_scope import fixture

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))


def load(name):
    spec = importlib.util.spec_from_file_location(name,ROOT/'tools'/(name+'.py'))
    m = importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    return m


image = load('polaris-uefi-wled-power-image')
host = load('polaris-uefi-wled-power')
ios = load('polaris-uefi-xnu-image')
readonly = load('polaris-uefi-wled-image')


def cycle_fixture():
    d,models = fixture()
    d.update(WLED_power_cycle_only=True,WLED_readonly_inventory_only=False,PMIC_write_api=True,
             controlled_WLED_write_timeout=False)
    for m,bad in zip(models,(False,True)):
        m.update(WLED_power_cycle_only=True,controlled_write_timeout=bad,
                 checks={k:True for k in image.MODEL_CHECKS},
                 raw_fields=dict(WLED_POWER_MOCK_BACKEND=1,WLED_KERNEL_AP_STAGE=0,
                    WLED_POWER_FINAL_ERROR=36 if bad else 0,WLED_POWER_FINAL_UNCERTAIN=int(bad),
                    WLED_POWER_WRITES_ISSUED=1 if bad else 4,WLED_POWER_WRITES_COMPLETED=0 if bad else 4,
                    WLED_POWER_FINAL_RESET_ALLOWED=int(not bad)))
    return d,models


def cycle_log():
    fields = dict(WLED_POWER_PREPARE_ERROR=0,WLED_KERNEL_AP_STAGE=0,WLED_AP_STAGE_ADDRESS=0x1000,
        WLED_POWER_INITIAL_VERSION=0x50000000,WLED_POWER_INITIAL_CTRL_MAP=0x0103d800,
        WLED_POWER_INITIAL_SINK_MAP=0x0103d900,WLED_POWER_INITIAL_CTRL_APID_OWNER=253<<32,
        WLED_POWER_INITIAL_SINK_APID_OWNER=254<<32,WLED_POWER_INITIAL_PSM=0x8480,
        WLED_POWER_OFF_MODULE=0,WLED_POWER_OFF_IRQ=0,WLED_POWER_RESTORED_MODULE=0x80,
        WLED_POWER_RESTORED_IRQ=2,WLED_POWER_WRITES_ISSUED=4,WLED_POWER_WRITES_COMPLETED=4,
        WLED_POWER_CYCLE_ERROR=0,WLED_POWER_OFF_US=100000,WLED_POWER_RESTORED_US=2120000,
        WLED_POWER_SOFTSTART_US=11000)
    return ''.join(f'{k}=0x{v:016x}\r\n' for k,v in fields.items())+'WLED_POWER_CYCLE_HOLD: NO_CPU_ON SAVED_STATE_RESTORED\r\n'


class PowerScope(unittest.TestCase):
    def test_prepare_refusal_can_recover_but_issued_or_running_cycle_cannot(self):
        text = ('WLED_POWER_PREPARE_ERROR=0x0000000000000007\r\n'
                'WLED_KERNEL_AP_STAGE=0x0000000000000000\r\n'
                'WLED_AP_STAGE_ADDRESS=0x0000000012345000\r\n'
                'WLED_POWER_CYCLE_ARMED: NO_CPU_ON\r\n')
        result = host.prestart_refusal(text)
        self.assertTrue(result['preparation_refused_before_writer'])
        self.assertTrue(result['firmware_reset_gate_still_required'])
        self.assertFalse(result['electrical_module_off_and_restore_readbacks'])
        for suffix in ('WLED_POWER_WRITES_ISSUED=0x0000000000000001\n',
                       'WLED_POWER_OFF_US=0x0000000000000001\n',
                       'WLED_POWER_CYCLE_ERROR=0x0000000000000024\n',
                       'WLED_POWER_MOCK_BACKEND=0x0000000000000001\n',
                       'Darwin Kernel Version','KERNEL_PSCI_STATUS=0'):
            with self.subTest(suffix=suffix),self.assertRaises(ValueError):
                host.prestart_refusal(text+suffix)
        for before,after in [('0000000000000007','0000000000000000'),
                             ('WLED_KERNEL_AP_STAGE=0x0000000000000000','WLED_KERNEL_AP_STAGE=0x0000000000000001')]:
            with self.assertRaises(ValueError):host.prestart_refusal(text.replace(before,after))

    def test_explicit_cycle_success_and_uncertain_are_required(self):
        d,m = cycle_fixture();image.admit(d,m)
        for key,value in [('PMIC_write_api',False),('kernel_handoff',True),('WLED_readonly_inventory_only',True),
                          ('kernel_CPU_ON_compiled_out',False),('storage_write_api',True),('NVRAM_write_api',True),
                          ('disk_payload_read_only',True),('QEMU_variant',True),('kernel_CPU_count',2),
                          ('RAM_host_idle_recovery_seconds',0),('controlled_WLED_write_timeout',True)]:
            with self.subTest(key=key),self.assertRaises(ValueError):
                image.admit(dict(d,**{key:value}),m)
        for key,value in [('checks',{}),('kernel_CPU_started',True),('release_handoff_admitted',True),
                          ('inputs',{}),('actual_phone_or_PMIC_emulated',True),('kernel_sha256','old')]:
            bad = copy.deepcopy(m);bad[0][key] = value
            with self.subTest(key=key),self.assertRaises(ValueError):image.admit(d,bad)
        for key in m[1]['raw_fields']:
            bad = copy.deepcopy(m);bad[1]['raw_fields'].pop(key)
            with self.subTest(key=key),self.assertRaises(ValueError):image.admit(d,bad)
        with self.assertRaises(ValueError):image.admit(d,[m[0],m[0]])

    def test_cycle_cannot_be_promoted_to_readonly_or_ios(self):
        d,m = cycle_fixture()
        with self.assertRaises(ValueError):readonly.admit(d,m)
        with self.assertRaisesRegex(ValueError,'pre-XNU'):ios.admit(d,{},None,None,None)
        for key in ('WLED_power_cycle_only','PMIC_write_api','kernel_CPU_ON_compiled_out'):
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'pre-XNU'):
                ios.admit({key:True},{'passed':True,'release_handoff_admitted':True},None,None,None)

    def test_binding_is_distinct_from_readonly_and_iOS(self):
        d,_ = cycle_fixture();d['sha256']='driver'
        i = dict(d,sha256='image',driver_sha256='driver')
        b = dict(state='temporary_WLED_power_cycle_boot_command_succeeded',image_sha256='image',sent_utc='time')
        host.binding(b,i,d)
        for state in ('temporary_WLED_inventory_boot_command_succeeded','temporary_UEFI_XNU_boot_command_succeeded'):
            with self.assertRaises(ValueError):host.binding(dict(b,state=state),i,d)
        with self.assertRaises(ValueError):host.binding(b,dict(i,PMIC_write_api=False),d)

    def test_electrical_readbacks_are_not_optical_or_OS_proof(self):
        text = cycle_log();r = host.parse(text)
        self.assertTrue(r['electrical_module_off_and_restore_readbacks'])
        self.assertFalse(r['physical_darkness_proven']);self.assertFalse(r['OS_started'])
        for suffix in ('WLED_POWER_MOCK_BACKEND=0x0000000000000001\n','Darwin Kernel Version','KERNEL_PSCI_STATUS=0'):
            with self.assertRaises(ValueError):host.parse(text+suffix)
        for n in range(len(text)):
            with self.assertRaises(ValueError):host.parse(text[:n])
        lines = text.splitlines(keepends=True)
        for n in range(len(lines)-1):
            with self.subTest(line=n),self.assertRaises(ValueError):host.parse(''.join(lines[:n]+lines[n+1:]))
        for key in ('WLED_POWER_CYCLE_ERROR','WLED_POWER_RESTORED_MODULE','WLED_POWER_WRITES_COMPLETED'):
            with self.assertRaises(ValueError):host.parse(text+f'{key}=0x0000000000000000\n')


if __name__=='__main__':
    unittest.main()
