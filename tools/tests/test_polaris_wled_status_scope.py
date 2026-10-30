"""The new OEM policy is model-only until independently admitted for a phone."""
import subprocess
import unittest
from pathlib import Path
from .test_polaris_wled_power_scope import cycle_fixture,load
from .test_polaris_wled_physical_scope import fixture
from .test_polaris_wled_power_scope import host

ROOT=Path(__file__).resolve().parents[2]
image=load('polaris-uefi-wled-power-image')
readonly=load('polaris-uefi-wled-image')
ios=load('polaris-uefi-xnu-image')


class StatusScope(unittest.TestCase):
    def test_model_policy_cannot_be_promoted_to_physical_power_readonly_or_iOS(self):
        for key,value in [('WLED_OEM_status_policy',True),('controlled_WLED_status_after_issue',2)]:
            d,m=cycle_fixture()
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'no physical'):
                image.admit(dict(d,**{key:value}),m)
            d,m=fixture()
            with self.assertRaisesRegex(ValueError,'not readonly'):
                readonly.admit(dict(d,**{key:value}),m)
            with self.assertRaisesRegex(ValueError,'pre-XNU'):
                ios.admit({key:value},{},None,None,None)

    def test_builder_refuses_physical_and_foreign_or_nonsensical_injection_before_inputs(self):
        base=['python3',str(ROOT/'tools/build-polaris-uefi-xnu.py'),
              '--zig','/missing','--kernel','/missing','--payload','/missing','--output','/missing']
        for flags,expected in [(['--wled-oem-status'],'QEMU power-cycle only'),
             (['--wled-oem-status','--wled-power-cycle-only'],'QEMU power-cycle only'),
             (['--wled-oem-status','--test-qemu'],'QEMU power-cycle only'),
             (['--test-wled-status-after-issue','2'],'status fault injection'),
             (['--wled-oem-status','--wled-power-cycle-only','--test-qemu',
               '--test-wled-status-after-issue','1'],'status fault injection'),
             (['--wled-oem-status','--wled-power-cycle-only','--test-qemu',
               '--test-wled-status-after-issue','65536'],'status fault injection'),
             (['--wled-oem-status','--wled-power-cycle-only','--test-qemu',
               '--test-wled-status-after-issue','2','--test-wled-write-timeout'],'status fault injection')]:
            with self.subTest(flags=flags):
                p=subprocess.run(base+flags,capture_output=True,text=True)
                self.assertEqual(p.returncode,2);self.assertIn(expected,p.stderr)

    def test_old_controller_cannot_operate_an_OEM_policy_session(self):
        d,_=cycle_fixture();d['sha256']='driver'
        image=dict(d,sha256='image',driver_sha256='driver')
        boot=dict(state='temporary_WLED_power_cycle_boot_command_succeeded',image_sha256='image',sent_utc='time')
        host.binding(boot,image,d)
        for item in range(3):
            records=[dict(boot),dict(image),dict(d)];records[item]['WLED_OEM_status_policy']=True
            with self.assertRaisesRegex(ValueError,'no physical'):
                host.binding(*records)


if __name__=='__main__':unittest.main()
