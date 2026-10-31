"""Exercise direct USB framing against bounds, bad identity and broken streams."""
import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('transport',Path(__file__).parents[1]/'polaris_uefi_usb_transport.py')
transport=importlib.util.module_from_spec(spec);spec.loader.exec_module(transport)


class Wire:
    def __init__(self,replies):self.replies=list(replies);self.commands=[];self.reads=[]
    def write(self,data):self.commands.append(data)
    def read(self,count):self.reads.append(count);return self.replies.pop(0)


class TransportTests(unittest.TestCase):
    def test_one_shot_disconnect_still_releases_interface_and_handle(self):
        class USB:
            def __init__(self):self.calls=[]
            def libusb_release_interface(self,handle,interface):self.calls.append(('release',handle.value,interface))
            def libusb_close(self,handle):self.calls.append(('close',handle.value))
            def libusb_exit(self,context):self.calls.append(('exit',context.value))
        for one_shot in (False,True):
            device=transport.LibusbTransport.__new__(transport.LibusbTransport)
            device.usb=USB();device.claimed=True
            device.handle=transport.C.c_void_p(11);device.context=transport.C.c_void_p(22)
            device.close(process_exit_after_disconnect=one_shot)
            expected=[('release',11,0),('close',11)]
            if not one_shot:expected.append(('exit',22))
            self.assertEqual(device.usb.calls,expected)
            self.assertFalse(device.claimed or device.handle or device.context)
            device.close()
            self.assertEqual(device.usb.calls,expected)

    def test_identity_before_capture_and_unsafe_commands_refused(self):
        wire=Wire([b'OKAYpolaris']);protocol=transport.ReadOnlyProtocol(wire)
        with self.assertRaises(ValueError):protocol.stage('logs')
        self.assertEqual(wire.commands,[])
        with self.assertRaises(ValueError):protocol.product()
        for cmd in [b'flash:boot',b'download:00000004',b'reboot',b'oem run',b'oem logs extra',b'getvar:all']:
            with self.assertRaises(ValueError):protocol._request(cmd)
        self.assertEqual(wire.commands,[b'getvar:product'])

    def test_chunked_capture_and_exact_final_status(self):
        data=bytes(range(256))*300
        wire=Wire([b'OKAYpolaris-uefi-diag',b'OKAY',f'DATA{len(data):08x}'.encode(),data[:65536],data[65536:],b'OKAY'])
        protocol=transport.ReadOnlyProtocol(wire);protocol.product();protocol.stage('screenshot')
        self.assertEqual(protocol.upload(),data)
        self.assertEqual(wire.commands,[b'getvar:product',b'oem screenshot',b'upload'])
        self.assertEqual(wire.reads,[64,64,64,65536,len(data)-65536,64])
        with self.assertRaises(ValueError):protocol.upload()

    def test_bad_or_excessive_length_and_incomplete_upload(self):
        for replies in [[b'DATA00000000'],[b'DATA00008001'],[b'DATAz0000001'],[b'OKAY'],
                        [b'DATA00000004',b''],[b'DATA00000004',b'12345'],
                        [b'DATA00000004',b'1234',b'OKAYextra'],[b'FAILcapture failed']]:
            wire=Wire([b'OKAYpolaris-uefi-diag',b'OKAY']+replies)
            protocol=transport.ReadOnlyProtocol(wire);protocol.product();protocol.stage('logs')
            with self.assertRaises((ValueError,RuntimeError)):protocol.upload()

    def test_actual_configuration_and_descriptor_corruption(self):
        raw=bytes([9,2,32,0,1,1,0,0x80,0x50,9,4,0,0,2,0xff,0x42,3,0,
                   7,5,0x81,2,0,2,0,7,5,1,2,0,2,0])
        transport.validate_configuration(raw)
        for at,value in [(0,0),(2,31),(4,2),(11,1),(15,0),(20,1),(21,3),(23,1),(27,0x81)]:
            bad=bytearray(raw);bad[at]=value
            with self.assertRaises(ValueError):transport.validate_configuration(bytes(bad))
        for bad in [b'',raw[:-1],raw+b'\x00']:
            with self.assertRaises(ValueError):transport.validate_configuration(bad)

    def test_native_capture_preserves_full_resource_prefix_and_native_ring(self):
        # Actual0142 firmware can publish128KiB before the4MiB XNU ring.
        data=b'R'*131072+b'\nNATIVE_RING\n'+b'N'*(4*1024*1024)
        replies=[b'OKAYpolaris-uefi-diag',b'OKAY',f'DATA{len(data):08x}'.encode()]
        replies += [data[n:n+65536] for n in range(0,len(data),65536)]+[b'OKAY']
        wire=Wire(replies);protocol=transport.KernelProtocol(wire)
        protocol.product();protocol.stage('logs')
        self.assertEqual(protocol.upload(),data)
        self.assertEqual(wire.commands,[b'getvar:product',b'oem logs',b'upload'])
        self.assertFalse(wire.replies)
        # Legacy bound stays unchanged; excessive native headers fail before
        # consuming any body bytes.
        for kind,count in ((transport.ReadOnlyProtocol,len(data)),
                           (transport.KernelProtocol,(4<<20)+131072+129)):
            wire=Wire([b'OKAYpolaris-uefi-diag',b'OKAY',f'DATA{count:08x}'.encode()])
            protocol=kind(wire);protocol.product();protocol.stage('logs')
            with self.assertRaisesRegex(ValueError,'exceeds diagnostic bounds'):protocol.upload()
            self.assertEqual(wire.reads,[64,64,64])


if __name__=='__main__':unittest.main()
