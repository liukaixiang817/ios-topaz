#!/usr/bin/env python3
"""Bounds tests for the exact native-symbol clock binding, no device action."""
from pathlib import Path
import importlib.util
import struct
import unittest

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("polaris_utc_builder", ROOT / "build-polaris-uefi-xnu.py")
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
VA = 0xFFFFFE0007000000
ADDRESS = VA + 0x4000


def image():
    raw = bytearray(0x1000)
    struct.pack_into("<8I", raw, 0, 0xFEEDFACF, 0x100000C, 0, 2, 1, 152, 0, 0)
    struct.pack_into("<II16sQQQQIIII", raw, 32, 0x19, 152, b"__DATA", ADDRESS, 0x1000, 0x200, 0x100, 3, 3, 1, 0)
    struct.pack_into("<16s16sQQIIIIIIII", raw, 104, b"__data", b"__DATA", ADDRESS, 256, 0x200, 7, 0, 0, 0, 0, 0, 0)
    struct.pack_into("<Q", raw, 0x200, 0x50434C4F434B3031)
    return raw


def bind(raw, others=()):
    return b.clock_mailbox_binding(raw, {"_polaris_uefi_clock": ADDRESS}, VA, 0x10000, others)


class Binding(unittest.TestCase):
    def test_exact_file_backed_data_initializer(self):
        result = bind(image())
        self.assertEqual((result["offset"], result["bytes"], result["BSS"]), (0x4000, 256, False))

    def test_bss_readonly_short_section_and_noncanonical_seed(self):
        for change in ("bss", "readonly", "short", "zerofill", "wrong-seed", "nonfile", "section-source"):
            raw = image()
            if change == "bss":
                raw[104:120] = b"__bss".ljust(16, b"\0")
            elif change == "readonly":
                struct.pack_into("<I", raw, 32 + 60, 1)
            elif change == "short":
                struct.pack_into("<Q", raw, 104 + 40, 128)
            elif change == "zerofill":
                struct.pack_into("<I", raw, 104 + 64, 1)
            elif change == "wrong-seed":
                raw[0x208] = 1
            elif change == "nonfile":
                struct.pack_into("<Q", raw, 32 + 48, 128)
            else:
                struct.pack_into("<I", raw, 104 + 48, 0x280)
            with self.assertRaises(ValueError, msg=change):
                bind(raw)

    def test_other_mailbox_or_console_overlap(self):
        for span in ((0x4000, 256), (0x3F80, 256), (0x4080, 256), (0x2000, 4 << 20)):
            with self.assertRaises(ValueError):
                bind(image(), [span])
        self.assertEqual(bind(image(), [(0x3F00, 256), (0x4100, 256)])["bytes"], 256)

    def test_absent_or_misaligned_global(self):
        for syms in ({}, {"_polaris_uefi_clock": ADDRESS + 1}):
            with self.assertRaises(ValueError):
                b.clock_mailbox_binding(image(), syms, VA, 0x10000, [])


if __name__ == "__main__":
    unittest.main()
