"""Check the ABI handed to an upper-bank polaris kernel by the QEMU runner."""
import importlib.util
from pathlib import Path
import struct
import unittest

spec = importlib.util.spec_from_file_location(
    "qemu_sweet", Path(__file__).resolve().parents[1] / "qemu-sweet.py")
qemu = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qemu)


class QEMUBootArgsTests(unittest.TestCase):
    def test_high_physical_addresses_and_video_abi(self):
        va, pa, size = 0xfffffe0007000000, 0x180000000, 0xfc8a0000
        payload = bytearray(0x300)
        struct.pack_into('<8sII7Q', payload, 0, b'SWEETXNU', 1, 1,
                         va, va + 0x4000, 0x2e0, 4, va + 0x8000, pa, size)
        payload[0x48:0x48 + 6] = b'cpus=1'
        struct.pack_into('<4Q', payload, 0x2a8, va + 0x4000, 0x4000, 0x2d0, 8)
        payload[0x2d0:0x2d8] = b'KERNEL!!'
        payload[0x2e0:0x2e4] = b'ADT!'
        for platform, video in [('sweet', (0x9c000000, 1, 4320, 1080, 2400, 32)),
                                ('polaris', (0x9d400000, 1, 4320, 1080, 2160, 32))]:
            with self.subTest(platform=platform):
                base, image, ba, entry = qemu.build_image(payload, qemu.FRAMEBUFFERS[platform])
                self.assertEqual((base, ba, entry), (pa, pa + 0xc000, pa + 0x4000))
                self.assertEqual(image[0x4000:0x4008], b'KERNEL!!')
                self.assertEqual(image[0x8000:0x8004], b'ADT!')
                offset = ba - base
                self.assertEqual(struct.unpack_from('<4Q', image, offset + 8),
                                 (va, pa, size, pa + 0x10000))
                self.assertEqual(struct.unpack_from('<6Q', image, offset + 40), video)
                self.assertEqual(struct.unpack_from('<QI', image, offset + 96), (va + 0x8000, 4))
                self.assertEqual(image[offset + 108:offset + 114], b'cpus=1')
                self.assertEqual(struct.unpack_from('<Q', image, offset + 728)[0], size)
                self.assertEqual(struct.unpack_from('<2Q', qemu.stub(ba, entry), 16), (ba, entry))


if __name__ == '__main__':
    unittest.main()
