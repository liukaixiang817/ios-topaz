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

if __name__=='__main__':unittest.main()
