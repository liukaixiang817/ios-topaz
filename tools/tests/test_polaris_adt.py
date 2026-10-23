import importlib.util
from pathlib import Path
import struct
import unittest
import zlib
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("polaris", Path(__file__).resolve().parents[1] / "mkadt-polaris.py")
polaris = importlib.util.module_from_spec(spec)
spec.loader.exec_module(polaris)


class ADTTests(unittest.TestCase):
    def test_optional_ufs_probe_is_bounded_and_not_for_qemu(self):
        head = bytearray(1 << 20)
        head[510:512] = b'\x55\xaa'
        head[4096:4104] = b'EFI PART'
        with patch.object(polaris.mkadt, 'd22ap_product', return_value=None):
            root = polaris.build(seed=b'x' * 64, ufs_head=head)
            props = polaris.props(polaris.child(root, 'polaris-ufs-probe'))
            self.assertEqual(struct.unpack('<2Q', props['reg']), (0x1d84000, 0x2500))
            self.assertEqual(struct.unpack('<I', props['head-crc32'])[0], zlib.crc32(head))
            with self.assertRaises(ValueError):
                polaris.build(qemu=True, ufs_head=head)
            for invalid in (b'', head[:-1], bytes(1 << 20)):
                with self.assertRaises(ValueError):
                    polaris.build(seed=b'x' * 64, ufs_head=invalid)

    def build(self, qemu=False):
        with patch.object(polaris.mkadt, "d22ap_product", return_value=None):
            root = polaris.build(seed=b"x" * 64, qemu=qemu)
        return polaris.adt.parse(polaris.adt.serialize(root))[0]

    def test_hardware_identity_and_ram(self):
        root = self.build()
        self.assertIn(b"xiaomi,polaris\0", polaris.props(root)["compatible"])
        self.assertNotIn(b"topaz", polaris.props(root)["compatible"])
        chosen = polaris.props(polaris.child(root, "chosen"))
        self.assertEqual(struct.unpack("<Q", chosen["dram-base"])[0], 0x180000000)
        self.assertEqual(struct.unpack("<Q", chosen["dram-size"])[0], 0xfc8a0000)
        cpus = polaris.child(root, "cpus").children
        self.assertEqual(len(cpus), 1)
        self.assertEqual(polaris.props(cpus[0])["reg"], bytes(4))
        self.assertEqual(polaris.props(cpus[0])["compatible"], b"qcom,kryo385\0ARM,v8\0")

    def test_no_unported_storage_wlan_or_display_services(self):
        root = self.build()
        self.assertNotIn(b"sweet-ufs\0", [polaris.props(c)["name"] for c in root.children])
        io = polaris.child(root, "arm-io")
        self.assertEqual([polaris.props(c)["name"] for c in io.children], [b"gic\0", b"wdt\0"])
        console = polaris.props(polaris.child(root, "sweet-fbcon"))
        self.assertEqual(struct.unpack("<I", console["height"])[0], 2160)

    def test_phone_and_qemu_interrupts(self):
        for qemu, dist, redist, timer in [(False, 0x17a00000, 0x17a60000, 19),
                                            (True, 0x8000000, 0x80a0000, 27)]:
            gic = polaris.props(polaris.child(polaris.child(self.build(qemu), "arm-io"), "gic"))
            self.assertEqual(struct.unpack("<4Q", gic["reg"]),
                             (dist - 0x1000000, 0x10000, redist - 0x1000000, 0x100000))
            self.assertEqual(struct.unpack("<I", gic["virtual-timer-intid"])[0], timer)


if __name__ == "__main__":
    unittest.main()
