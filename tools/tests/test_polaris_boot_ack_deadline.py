"""Only explicit OEM-boot ACK waits may exceed10s. Fake libusb; no phone."""
from pathlib import Path
import ctypes as C
import subprocess
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from polaris_uefi_usb_transport import LibusbTransport,KernelProtocol
from polaris_wled_runtime_control import WledRuntimeProtocol

ROOT=Path(__file__).resolve().parents[2]
class USB:
    def __init__(self,replies):self.replies=list(replies);self.calls=[];self.commands=[]
    def libusb_bulk_transfer(self,handle,endpoint,buffer,count,done,timeout):
        self.calls.append((endpoint,count,timeout));completion=C.cast(done,C.POINTER(C.c_int))
        if endpoint==1:
            self.commands.append(bytes(buffer[:count]));completion.contents.value=count;return 0
        reply=self.replies.pop(0)
        if isinstance(reply,int):completion.contents.value=0;return reply
        buffer[:len(reply)]=reply;completion.contents.value=len(reply);return 0

def fake(replies):
    t=LibusbTransport.__new__(LibusbTransport);t.usb=USB(replies);t.claimed=True;t.handle=C.c_void_p(11)
    return t

class BootAckDeadline(unittest.TestCase):
    def test_explicit_long_boot_ack_leaves_product_and_state_at10s(self):
        for cls in (KernelProtocol,WledRuntimeProtocol):
            t=fake([b'OKAYpolaris-uefi-diag',b'OKAYvalidated',b'OKAY']);p=cls(t);p.product();p.boot(ack_seconds=90)
            self.assertEqual([v[2] for v in t.usb.calls if v[0]==0x81],[10000,10000,90000])
            self.assertEqual(t.usb.commands,[b'getvar:product',b'getvar:kernel-state',b'oem boot'])
            self.assertTrue(all(v[2]==10000 for v in t.usb.calls if v[0]==1))

    def test_default_boot_is_still10s_and_old_subclass_signature_works(self):
        class ExistingSubclass(KernelProtocol):
            def _control(self,command):return super()._control(command)
        for cls in (KernelProtocol,WledRuntimeProtocol,ExistingSubclass):
            t=fake([b'OKAYvalidated',b'OKAY']);p=cls(t);p.verified=True;p.boot()
            self.assertEqual([v[2] for v in t.usb.calls if v[0]==0x81],[10000,10000])

    def test_long_ack_failure_and_bad_ack_never_resend(self):
        for reply,exc in [(-7,RuntimeError),(b'FAILadmission',RuntimeError),(b'OKAYextra',ValueError),(b'',ValueError)]:
            t=fake([b'OKAYvalidated',reply]);p=WledRuntimeProtocol(t);p.verified=True
            with self.assertRaises(exc):p.boot(ack_seconds=90)
            self.assertEqual(t.usb.commands.count(b'oem boot'),1)
            self.assertEqual([v[2] for v in t.usb.calls if v[0]==0x81],[10000,90000])
            self.assertEqual(t.usb.replies,[])

    def test_nonboot_controls_cannot_borrow_the_long_deadline(self):
        commands=(b'getvar:kernel-state',b'getvar:input',b'oem shutdown:2',b'oem touch:1:1:1',b'reboot',b'oem drained-reboot:2',b'oem wled-exit:x',b'upload')
        for cls in (KernelProtocol,WledRuntimeProtocol):
            for command in commands:
                t=fake([]);p=cls(t);p.verified=True
                with self.assertRaises(ValueError):p._control(command,boot_ack_seconds=90)
                self.assertEqual(t.usb.calls,[])

    def test_invalid_deadlines_fail_before_any_transfer(self):
        for value in (0,-1,91,True,10.0,'90',None):
            t=fake([]);p=KernelProtocol(t);p.verified=True
            with self.assertRaises(ValueError):p.boot(ack_seconds=value)
            with self.assertRaises(ValueError):t.read_boot_reply(timeout_seconds=value)
            self.assertEqual(t.usb.calls,[])
        class NoSpecialReader:
            def write(self,data):raise AssertionError('no command without admitted reply path')
        p=KernelProtocol(NoSpecialReader());p.verified=True
        with self.assertRaises(ValueError):p._control(b'oem boot',boot_ack_seconds=90)

    def test_upload_and_zero_write_receipt_still_use10s(self):
        t=fake([b'OKAY',b'DATA00000004',b'data',b'OKAY']);p=WledRuntimeProtocol(t);p.verified=True;p.stage('logs')
        self.assertEqual(p.upload(),b'data')
        self.assertEqual([v[2] for v in t.usb.calls if v[0]==0x81],[10000]*4)
        t=fake([b'OKAYprepared',b'FAILreceipt']);p=WledRuntimeProtocol(t);p.verified=True
        with self.assertRaises(RuntimeError):p.recover_prestart()
        self.assertEqual(t.usb.commands,[b'getvar:kernel-state',b'reboot-bootloader'])
        self.assertEqual([v[2] for v in t.usb.calls if v[0]==0x81],[10000]*2)

    def test_atomic_WLR_footer_and_final_receipt_deadlines_stay10s(self):
        from .test_polaris_wled_runtime_exit import fixture
        prefix,footer,sealed,receipt=fixture();t=fake([b'DATA000000d4',footer,b'OKAY'+receipt])
        p=WledRuntimeProtocol(t);p.verified=True;p.shutdown_token=(456,1,2)
        self.assertEqual(p.atomic_exit(prefix)['total'],80)
        self.assertEqual([v[2] for v in t.usb.calls if v[0]==0x81],[10000]*3)
        self.assertEqual(len(t.usb.commands),1)

    def test_cli_rejects_nonboot_or_unbounded_wait_before_opening_files_or_USB(self):
        controller=ROOT/'tools/polaris-uefi-wled-runtime.py'
        common=[sys.executable,str(controller),'--libusb','/absent','--boot-record','/absent','--image-manifest','/absent','--driver-manifest','/absent','--output','/absent']
        for action,value in [('state','90'),('capture','90'),('recover-prestart','90'),('boot','0'),('boot','91')]:
            p=subprocess.run(common+[action,'--boot-ack-seconds',value],capture_output=True,text=True)
            self.assertNotEqual(p.returncode,0)
            self.assertIn('boot ACK wait1..90seconds is only configurable for boot',p.stderr)
            self.assertNotIn('FileNotFoundError',p.stderr)

if __name__=='__main__':unittest.main()
