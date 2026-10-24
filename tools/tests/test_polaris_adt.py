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

    def build(self, qemu=False, display=False):
        with patch.object(polaris.mkadt, "d22ap_product", return_value=None):
            root = polaris.build(seed=b"x" * 64, qemu=qemu, display=display)
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

    def test_display_opt_in_preserves_verified_geometry_and_no_wlan(self):
        for qemu in (False, True):
            root = self.build(qemu=qemu, display=True)
            io = polaris.child(root, 'arm-io')
            self.assertNotIn(b'wlan\0', [polaris.props(c)['name'] for c in io.children])
            panel = polaris.props(polaris.child(io, 'disp0'))
            self.assertEqual(panel['compatible'], b'sweet,display\0')
            for key, value in [('canvas-width', 1125), ('canvas-height', 2436),
                               ('polaris,boot-framebuffer', 1)]:
                self.assertEqual(struct.unpack('<I', panel[key])[0], value)
            fb = polaris.props(polaris.child(root, 'sweet-fbcon'))
            self.assertEqual(struct.unpack('<2Q', fb['reg']), (0x9d400000, 0x2400000))
            self.assertEqual(struct.unpack('<I', fb['stride'])[0], 4320)

    def test_wifi_identity_is_raw_data_and_adds_no_network_service(self):
        # Locally administered fixture only; never embed a phone's address.
        identity = bytes.fromhex('020000000001')
        for qemu in (False, True):
            with patch.object(polaris.mkadt, 'd22ap_product', return_value=None):
                original = polaris.build(seed=b'x' * 64, qemu=qemu, display=True)
                root = polaris.build(seed=b'x' * 64, qemu=qemu, display=True,
                                     wifi_mac=identity)
            root = polaris.adt.parse(polaris.adt.serialize(root))[0]
            chosen = polaris.child(root, 'chosen')
            self.assertEqual(polaris.props(chosen)['mac-address-wifi0'], identity)
            # Removing the sole added property restores the entire default tree.
            chosen.props = [p for p in chosen.props if p[0] != 'mac-address-wifi0']
            self.assertEqual(polaris.adt.serialize(root), polaris.adt.serialize(original))

    def test_wifi_identity_rejects_text_wrong_sizes_zero_and_multicast(self):
        invalid = [b'', b'x' * 5, b'x' * 7, b'02:00:00:00:00:01',
                   '020000000001', bytes(6), bytes.fromhex('010000000001'),
                   b'\xff' * 6]
        for identity in invalid:
            with self.subTest(identity_type=type(identity).__name__, size=len(identity)):
                with self.assertRaises(ValueError):
                    polaris.build(seed=b'x' * 64, wifi_mac=identity)

    def test_touch_requires_explicit_phone_opt_in(self):
        with patch.object(polaris.mkadt, 'd22ap_product', return_value=None):
            base = polaris.build(seed=b'x' * 64)
            root = polaris.build(seed=b'x' * 64, touch=True)
            with self.assertRaises(ValueError):
                polaris.build(qemu=True, touch=True)
        root = polaris.adt.parse(polaris.adt.serialize(root))[0]
        touch = polaris.props(polaris.child(root, 'polaris-touch'))
        self.assertEqual(struct.unpack('<QQ', touch['reg']), (0xa98000, 0x4000))
        self.assertEqual(struct.unpack('<I', touch['address']), (0x20,))
        root.children = [n for n in root.children if polaris.props(n)['name'] != b'polaris-touch\0']
        self.assertEqual(polaris.adt.serialize(root), polaris.adt.serialize(base))


if __name__ == "__main__":
    unittest.main()
