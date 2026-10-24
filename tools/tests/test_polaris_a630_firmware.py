"""Firmware bounds/provenance and isolated ADT transport, without execution."""
from pathlib import Path
import copy
import hashlib
import importlib.util
import struct
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def module(name, file):
    s = importlib.util.spec_from_file_location(name, ROOT / 'tools' / file)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


fw = module('a630_firmware', 'polaris-a630-firmware.py')
board = module('firmware_board', 'mkadt-polaris.py')


def fixture():
    gmu = struct.pack('<II', 0x43f80, 9) + bytes(0x8000 - 8)
    sqe = struct.pack('<III', 0, 0x12345678, 0x87654321)
    ident = b'\x7fELF\x01\x01\x01' + bytes(9)
    header = struct.pack('<16sHHIIIIIHHHHHH', ident, 2, 164, 1, 0, 52, 0, 0,
                         52, 32, 3, 0, 0, 0)
    header += struct.pack('<8I', 0, 0, 0, 0, 148, 0, 0x07000000, 0)
    header += struct.pack('<8I', 0, 4096, 0x6000, 0x6000, 32, 8192, 0x02200000, 4096)
    header += struct.pack('<8I', 1, 12288, 0x5000, 0x5000, 8, 16, 0x08000007, 0x100000)
    return {'a630_gmu.bin': gmu, 'a630_sqe.fw': sqe,
            'a630_zap.mdt': header + b'h' * 32,
            'a630_zap.b00': header, 'a630_zap.b01': b'h' * 32,
            'a630_zap.b02': b's' * 8}


def manifest(images):
    return dict(state='readonly_original_vendor_collected', vendor_device='sde47',
                vendor_bytes=4294967296, source_gpt_matches_backup=True,
                header_unchanged=True, unmounted=True, block_readonly=True,
                journal_replayed=False, metadata_repaired=False, firmware_executed=False,
                files=[dict(file=name, bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
                       for name, data in images.items()])


class FirmwareTests(unittest.TestCase):
    def test_original_wire_layout(self):
        r = fw.inspect_images(fixture())
        self.assertEqual(r['gmu_bytes'], 32768)
        self.assertEqual((r['sqe_code_offset'], r['sqe_code_words'], r['sqe_version']),
                         (4, 2, 0x12345678))
        self.assertEqual(len(r['zap_segments']), 3)
        self.assertEqual(r['zap_segments'][2]['relative_address'], 0x5000)
        self.assertFalse(r['firmware_executed'])
        self.assertFalse(r['secure_authentication_performed'])

    def test_truncated_and_wrong_arch_images(self):
        cases = [
            ('a630_gmu.bin', bytes(0x7fff)),
            ('a630_gmu.bin', struct.pack('<II', 0x80000000, 9) + bytes(0x7ff8)),
            ('a630_gmu.bin', struct.pack('<II', 0x43f80, 8) + bytes(0x7ff8)),
            ('a630_gmu.bin', struct.pack('<II', 0x43f80, 0x8001) + bytes(0x7ff8)),
            ('a630_sqe.fw', b'\0' * 7),
            ('a630_sqe.fw', struct.pack('<II', 1, 2)),
            ('a630_zap.mdt', b'\x7fELF\x02\x01\x01' + bytes(160)),
            ('a630_zap.mdt', fixture()['a630_zap.mdt'][:100]),
            ('a630_zap.b01', b'wrong' * 3),
            ('a630_zap.b02', b's' * 7),
        ]
        for name, data in cases:
            with self.subTest(name=name, length=len(data)):
                images = fixture()
                images[name] = data
                with self.assertRaises(ValueError):
                    fw.inspect_images(images)

    def test_reject_unsupported_load_address_or_flags(self):
        for field, value in ((3, 0xfffffff8), (5, 7), (6, 7), (7, 3)):
            images = fixture()
            header = bytearray(images['a630_zap.b00'])
            struct.pack_into('<I', header, 52 + 2 * 32 + field * 4, value)
            images['a630_zap.b00'] = bytes(header)
            images['a630_zap.mdt'] = bytes(header) + images['a630_zap.b01']
            with self.subTest(field=field), self.assertRaises(ValueError):
                fw.inspect_images(images)

    def test_hash_collection_refuses_wrong_source_and_symlink(self):
        images = fixture()
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            for name, data in images.items():
                (p / name).write_bytes(data)
            source = manifest(images)
            self.assertEqual(fw.read_collection(p, source)[0], images)
            for key, value in (('vendor_device', 'sda22'), ('block_readonly', False),
                               ('header_unchanged', False), ('journal_replayed', True),
                               ('firmware_executed', True)):
                bad = copy.deepcopy(source)
                bad[key] = value
                with self.subTest(key=key), self.assertRaises(ValueError):
                    fw.read_collection(p, bad)
            duplicate = copy.deepcopy(source)
            duplicate['files'].append(duplicate['files'][0])
            with self.assertRaises(ValueError):
                fw.read_collection(p, duplicate)
            (p / 'a630_sqe.fw').write_bytes(b'x' * len(images['a630_sqe.fw']))
            with self.assertRaises(ValueError):
                fw.read_collection(p, source)
            (p / 'a630_sqe.fw').unlink()
            (p / 'elsewhere').write_bytes(images['a630_sqe.fw'])
            (p / 'a630_sqe.fw').symlink_to(p / 'elsewhere')
            with self.assertRaises(ValueError):
                fw.read_collection(p, source)

    def test_adt_only_adds_firmware_and_rejects_wrong_board(self):
        with patch.object(board.mkadt, 'd22ap_product', return_value=None):
            tree = board.build(seed=b'x' * 64, display=True, touch=True,
                               touch_wake=True, touch_irq_input=True, usb=True)
            qemu = board.build(seed=b'x' * 64, qemu=True)
        before = board.adt.serialize(tree)
        after = fw.attach(before, fixture())
        parsed = board.adt.parse(after)[0]
        node = board.child(parsed, 'polaris-a630-firmware')
        props = board.props(node)
        self.assertEqual(props['version'], struct.pack('<I', 2))
        self.assertEqual(props['chip-id'], struct.pack('<I', 0x06030001))
        self.assertEqual(props['gpucc-reg'], struct.pack('<QQ', 0x5090000, 0x9000))
        self.assertEqual(props['gmu-reg'], struct.pack('<QQ', 0x506a000, 0x30000))
        self.assertEqual(props['smmu-reg'], struct.pack('<QQ', 0x5040000, 0x10000))
        self.assertEqual(props['gmu-bin'], fixture()['a630_gmu.bin'])
        self.assertEqual(props['gmu-bin-sha256'], hashlib.sha256(props['gmu-bin']).digest())
        parsed.children.remove(node)
        self.assertEqual(board.adt.serialize(parsed), before)
        with self.assertRaises(ValueError):
            fw.attach(after, fixture())
        with self.assertRaises(ValueError):
            fw.attach(board.adt.serialize(qemu), fixture())
        board.setprop(tree, 'compatible', b'other-phone\0')
        with self.assertRaises(ValueError):
            fw.attach(board.adt.serialize(tree), fixture())


if __name__ == '__main__':
    unittest.main()
