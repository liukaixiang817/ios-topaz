import hashlib
import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('usb',Path(__file__).parents[1]/'polaris_uefi_usb_transport.py')
usb=importlib.util.module_from_spec(spec);spec.loader.exec_module(usb)
class Wire:
    def __init__(self,replies):self.replies=list(replies);self.commands=[];self.chunks=[]
    def write(self,p):self.commands.append(p)
    def write_data(self,p):self.chunks.append(p)
    def read(self,n):return self.replies.pop(0)

class KernelProtocolTests(unittest.TestCase):
    def test_boot_backup_is_bounded_and_keeps_inventory_reader_whitelist(self):
        wire=Wire([b'OKAYpolaris-uefi-diag',b'OKAY',b'DATA00000020',b'x'*32,b'OKAY'])
        p=usb.KernelProtocol(wire);p.product();p.stage('boot-options');self.assertEqual(p.upload(),b'x'*32)
        self.assertEqual(wire.commands,[b'getvar:product',b'oem boot-options',b'upload'])
        wire=Wire([b'OKAYpolaris-uefi-diag']);p=usb.ReadOnlyProtocol(wire);p.product()
        with self.assertRaises(ValueError):p.stage('boot-options')
        self.assertEqual(wire.commands,[b'getvar:product'])

    def test_exact_manifest_ram_payload_then_explicit_boot(self):
        data=b'x'*70000
        m=dict(RAM_only_XNU_loader=True,storage_write_api=False,NVRAM_write_api=False,
               QEMU_variant=False,payload_bytes=len(data),payload_sha256=hashlib.sha256(data).hexdigest())
        wire=Wire([b'OKAYpolaris-uefi-diag',b'OKAYwaiting-payload',b'DATA00011170',b'OKAY',b'OKAYvalidated',b'OKAYvalidated',b'OKAY'])
        p=usb.KernelProtocol(wire);p.product();p.stage_payload(data,m);p.boot()
        self.assertEqual([len(c) for c in wire.chunks],[65536,4464]);self.assertEqual(b''.join(wire.chunks),data)
        self.assertEqual(wire.commands[-1],b'oem boot')

    def test_running_kernel_cannot_be_replaced(self):
        wire=Wire([b'OKAYpolaris-uefi-diag',b'OKAYkernel-entered']);p=usb.KernelProtocol(wire);p.product()
        with self.assertRaises(ValueError):p.stage_payload(b'x',{})
        self.assertEqual(wire.chunks,[]);self.assertFalse(any(c.startswith(b'download:') for c in wire.commands))

    def test_bad_manifest_does_not_send_payload(self):
        wire=Wire([b'OKAYpolaris-uefi-diag',b'OKAYwaiting-payload']);p=usb.KernelProtocol(wire);p.product()
        with self.assertRaises(ValueError):p.stage_payload(b'x',{'payload_sha256':'0'*64})
        self.assertEqual(wire.chunks,[])

    def test_only_two_reset_targets_and_acknowledgement(self):
        wire=Wire([b'OKAYpolaris-uefi-diag',b'OKAY',b'OKAY']);p=usb.KernelProtocol(wire);p.product();p.reboot();p.reboot(True)
        self.assertEqual(wire.commands,[b'getvar:product',b'reboot',b'reboot-bootloader'])
        for command in [b'oem run',b'flash:boot',b'boot',b'reboot recovery']:
            with self.assertRaises(ValueError):p._control(command)

    def test_touch_requires_bounded_contact_and_kernel_consumption(self):
        wire=Wire([b'OKAYpolaris-uefi-diag',b'OKAY1/00000000/00000000/00000000',b'OKAY',
                   b'OKAY1/00000001/00000001/00000000'])
        p=usb.KernelProtocol(wire);p.product();self.assertEqual(p.touch(1,1079,2159),1)
        self.assertIn(b'oem touch:1:1079:2159',wire.commands)
        for contact in [(2,0,0),(1,1080,0),(1,0,2160),(1,-1,0),(1,0,0.5)]:
            with self.assertRaises(ValueError):p.touch(*contact)

    def test_not_ready_or_kernel_rejected_contact_does_not_prove_UI(self):
        wire=Wire([b'OKAYpolaris-uefi-diag',b'OKAY0/00000000/00000000/00000000'])
        p=usb.KernelProtocol(wire);p.product()
        with self.assertRaises(RuntimeError):p.touch(1,100,100)
        self.assertFalse(any(c.startswith(b'oem touch:') for c in wire.commands))

if __name__=='__main__':unittest.main()
