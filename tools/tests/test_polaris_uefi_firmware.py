#!/usr/bin/env python3
"""Exercise real container rewriting on synthetic, non-device firmware."""
import gzip
import importlib.util
from pathlib import Path
import struct
import unittest
import uuid
import lzma
import hashlib

spec = importlib.util.spec_from_file_location('firmware', Path(__file__).parents[1] / 'polaris-uefi-firmware.py')
fw = importlib.util.module_from_spec(spec); spec.loader.exec_module(fw)


def make_fv(file_list, length):
    header = bytearray(72)
    header[16:32] = uuid.UUID('8c8ce578-8a3d-4f1c-9935-896185c32dd3').bytes_le
    struct.pack_into('<Q4sIHHHBBIIII', header, 32, length, b'_FVH', 0x3feff,
                     72, 0, 0, 0, 2, length // 64, 64, 0, 0)
    struct.pack_into('<H', header, 50, -sum(struct.unpack('<36H', header)) & 65535)
    empty = bytes(header) + b'\xff' * (length - 72)
    return fw.volume(empty, file_list, fixed=True)


def make_file(guid, kind, data):
    template = bytearray(24); template[18] = kind; template[23] = 0xf8
    return fw.ffs(guid, data, template)


def fixture():
    other_guid = uuid.UUID('eed4cb94-0571-4a38-a955-7cb45d43ec4a')
    other = make_file(other_guid, 7, fw.section(0x10, b'UNCHANGED DXE DRIVER'))
    init = make_file(fw.SIMPLE_INIT, 9, fw.section(0x10, b'ORIGINAL SIMPLEINIT EXECUTABLE'))
    inner = make_fv([(other_guid, other), (fw.SIMPLE_INIT, init)], 4096)
    packed = fw.encode_edk2_lzma(fw.section(0x17, inner), 16 * 1024 * 1024)
    comp_guid = uuid.UUID('ad31426c-029d-4ba5-87ed-65224673167b')
    comp = make_file(comp_guid, 0xb, fw.section(2, fw.LZMA_GUID.bytes_le + struct.pack('<HH', 24, 1) + packed))
    outer = make_fv([(comp_guid, comp)], 65536)
    shim = bytearray(0x8000); shim[56:60] = b'ARMd'
    dtb = bytearray(40); dtb[:4] = b'\xd0\x0d\xfe\xed'; struct.pack_into('>I', dtb, 4, 40)
    kernel = gzip.compress(bytes(shim) + outer, mtime=0) + dtb
    header = bytearray(2048); header[:8] = b'ANDROID!'
    for off, n in [(8, len(kernel)), (16, 1), (36, 2048), (40, 1), (1644, 1648)]:
        struct.pack_into('<I', header, off, n)
    header[576:596] = hashlib.sha1(kernel + struct.pack('<I', len(kernel)) + b'\n' + struct.pack('<III', 1, 0, 0)).digest()
    android = bytes(header) + kernel + b'\0' * (fw.align(len(kernel), 2048) - len(kernel)) + b'\n' + b'\0' * 2047
    return android, inner, outer


class FirmwareTests(unittest.TestCase):
    def test_small_marker_label_is_explicit_and_does_not_admit_storage(self):
        original, _, _ = fixture()
        _, report = fw.package(original, b'MARKER APP', label='Polaris RAM small owned marker trial')
        self.assertEqual(report['unchanged_inner_files'], report['original_inner_files'])
        self.assertFalse(report['installer'])
        self.assertFalse(report['phone_writes'])
        with self.assertRaisesRegex(ValueError, 'unsupported added-driver label'):
            fw.package(original, b'APP', label='arbitrary storage installer')

    def test_preserves_shim_dtb_ramdisk_and_all_original_code(self):
        original, inner, _ = fixture()
        result, report = fw.package(original, b'NEW INVENTORY APP')
        oh, od, ot, oram = fw.unpack_android(original)
        nh, nd, nt, nram = fw.unpack_android(result)
        self.assertEqual(od[:0x8000], nd[:0x8000]); self.assertEqual(ot, nt); self.assertEqual(oram, nram)
        self.assertEqual(report['unchanged_inner_files'], 2)
        _, _, fs = fw.files(nd[0x8000:]); section_data = list(fw.sections(fs[0][1][24:]))[0][2]
        decoded = fw.decode_edk2_lzma(section_data[24:])
        new_inner = list(fw.sections(decoded))[0][1]
        previous = dict(fw.files(inner)[2]); new = dict(fw.files(new_inner)[2])
        for guid, data in previous.items():
            self.assertEqual(new[guid], data)
        self.assertEqual(new[fw.PROBE_DXE_GUID][18], 7)
        depex = [data for kind, data, _ in fw.sections(new[fw.PROBE_DXE_GUID][24:]) if kind == 0x13]
        self.assertEqual(depex, [b'\x06\x08'])
        self.assertEqual(len(new), len(previous) + 1)

    def test_damaged_boot_hash_rejected(self):
        original, _, _ = fixture(); bad = bytearray(original); bad[576] ^= 1
        with self.assertRaisesRegex(ValueError, 'digest'):fw.package(bytes(bad), b'PROBE')

    def test_ffs_checksum_and_duplicate_guid_rejected(self):
        _, inner, _ = fixture(); bad = bytearray(inner); bad[72 + 16] ^= 1
        with self.assertRaisesRegex(ValueError, 'checksum'):fw.files(bytes(bad))
        rows = fw.files(inner)[2]
        with self.assertRaisesRegex(ValueError, 'duplicate'):fw.volume(inner, rows + rows, fixed=False)

    def test_outer_capacity_is_a_hard_limit(self):
        _, _, outer = fixture(); g = uuid.UUID(int=1)
        large = make_file(g, 9, fw.section(0x10, b'x' * len(outer)))
        with self.assertRaisesRegex(ValueError, 'does not fit'):fw.volume(outer, [(g, large)], fixed=True)

    def test_refuses_repackaging_and_truncated_sections(self):
        original, _, _ = fixture(); once, _ = fw.package(original, b'PROBE')
        with self.assertRaisesRegex(ValueError, 'already modified'):fw.package(once, b'PROBE2')
        with self.assertRaisesRegex(ValueError, 'bounds'):list(fw.sections(b'\xff\x00\x00\x10'))

    def test_large_firmware_volume_section_uses_extended_header(self):
        data = b'v' * 0xfffffb  # Payload + short header reaches the sentinel.
        encoded = fw.section(0x17, data)
        self.assertEqual(encoded[:4], b'\xff\xff\xff\x17')
        decoded = list(fw.sections(encoded))
        self.assertEqual(len(decoded), 1); self.assertEqual(decoded[0][1], data)

    def test_EDK2_get_info_requires_explicit_bounded_length(self):
        stream = lzma.compress(b'actual firmware bytes', format=lzma.FORMAT_ALONE)
        self.assertEqual(struct.unpack_from('<Q', stream, 5)[0], 0xffffffffffffffff)
        with self.assertRaisesRegex(ValueError, 'explicit'):fw.decode_edk2_lzma(stream)
        fixed = fw.encode_edk2_lzma(b'actual firmware bytes', 16 * 1024 * 1024)
        self.assertEqual(struct.unpack_from('<Q', fixed, 5)[0], 21)
        bad = fixed[:5] + struct.pack('<Q', 22) + fixed[13:]
        with self.assertRaises((ValueError, lzma.LZMAError)):fw.decode_edk2_lzma(bad)


if __name__ == '__main__':unittest.main()
