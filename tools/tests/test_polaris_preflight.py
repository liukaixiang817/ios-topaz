"""Host-only checks for GPT validation; never connects to a phone."""
import importlib.util
from pathlib import Path
import struct
import unittest
import zlib

spec = importlib.util.spec_from_file_location(
    "preflight", Path(__file__).resolve().parents[1] / "polaris-preflight.py")
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


def fixture(block_size, overlap=False):
    blocks = 1024
    disk = bytearray(blocks * block_size)
    entries = bytearray(128 * 128)
    for i, (name, start, end) in enumerate([
            ("mindowswin", 40, 99), ("userdata", 90 if overlap else 200, 500)]):
        off = i * 128
        entries[off:off + 16] = b"T" * 16
        entries[off + 16:off + 32] = bytes([i + 1]) * 16
        struct.pack_into("<QQ", entries, off + 32, start, end)
        encoded = name.encode("utf-16-le")
        entries[off + 56:off + 56 + len(encoded)] = encoded
    array_blocks = len(entries) // block_size
    for lba, alternate, entry_lba in [(1, blocks - 1, 2),
                                       (blocks - 1, 1, blocks - 1 - array_blocks)]:
        header = bytearray(block_size)
        header[:8] = b"EFI PART"
        struct.pack_into("<IIIIQQQQ", header, 8, 0x10000, 92, 0, 0,
                         lba, alternate, 2 + array_blocks, blocks - 2 - array_blocks)
        header[56:72] = b"D" * 16
        struct.pack_into("<QIII", header, 72, entry_lba, 128, 128, zlib.crc32(entries))
        struct.pack_into("<I", header, 16, zlib.crc32(header[:92]))
        disk[lba * block_size:(lba + 1) * block_size] = header
        disk[entry_lba * block_size:entry_lba * block_size + len(entries)] = entries
    return disk


class GPTTests(unittest.TestCase):
    def parse(self, disk, block_size):
        region = min(1024 * 1024, len(disk) // 2)
        return preflight.parse_gpt(disk[:region], disk[-region:], len(disk), block_size)

    def test_512_and_4096_byte_lbas(self):
        for block_size in (512, 4096):
            with self.subTest(block_size=block_size):
                result = self.parse(fixture(block_size), block_size)
                self.assertTrue(result["both_gpt_copies_valid"])
                self.assertEqual(result["partitions"][0]["bytes"], 60 * block_size)
                self.assertEqual(result["unallocated"][1]["bytes"], 100 * block_size)

    def test_header_corruption(self):
        disk = fixture(4096)
        disk[4096 + 56] ^= 1
        with self.assertRaisesRegex(ValueError, "header CRC"):
            self.parse(disk, 4096)

    def test_array_corruption(self):
        disk = fixture(4096)
        disk[8192 + 56] ^= 1
        with self.assertRaisesRegex(ValueError, "entries CRC"):
            self.parse(disk, 4096)

    def test_backup_corruption(self):
        disk = fixture(4096)
        disk[-4096] ^= 1
        with self.assertRaisesRegex(ValueError, "signature"):
            self.parse(disk, 4096)

    def test_overlap(self):
        with self.assertRaisesRegex(ValueError, "overlapping"):
            self.parse(fixture(4096, overlap=True), 4096)

    def test_wrong_sector_units(self):
        with self.assertRaises(ValueError):
            self.parse(fixture(4096), 512)


if __name__ == "__main__":
    unittest.main()
