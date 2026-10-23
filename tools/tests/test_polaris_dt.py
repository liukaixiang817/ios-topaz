"""Compile and exercise the actual bare-metal FDT reader on the host."""
import ctypes
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest


def tree(model=b"Xiaomi Polaris\0", splash=0x9d400000):
    strings = bytearray()
    offsets = {}

    def u32(*values):
        return struct.pack(">" + "I" * len(values), *values)

    def pad(data):
        return data + bytes(-len(data) % 4)

    def prop(name, value):
        if name not in offsets:
            offsets[name] = len(strings)
            strings.extend(name.encode() + b"\0")
        return u32(3, len(value), offsets[name]) + pad(value)

    def node(name, contents):
        return u32(1) + pad(name.encode() + b"\0") + contents + u32(2)

    contents = prop("model", model) + prop("compatible", b"qcom,sdm845-mtp\0qcom,sdm845\0")
    contents += node("reserved-memory", node("cont_splash_region@9d400000",
                     prop("reg", u32(0, splash, 0, 0x2400000))))
    contents += node("chosen", prop("bootargs", b"test\0"))
    contents += node("sibling", prop("bootargs", b"other\0"))
    structure = node("", contents) + u32(9)
    string_start = 56 + len(structure)
    header = u32(0xd00dfeed, string_start + len(strings), 56, string_start,
                 40, 17, 16, 0, len(strings), len(structure))
    return header + bytes(16) + structure + strings


class FDTTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory()
        library = Path(cls.work.name) / "dt.dylib"
        source = Path(__file__).resolve().parents[2] / "shim/polaris/dt.c"
        subprocess.run(["cc", "-shared", "-fPIC", "-Wall", "-Wextra", "-Werror",
                        str(source), "-o", str(library)], check=True)
        cls.lib = ctypes.CDLL(str(library))
        cls.lib.polaris_dt_matches.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        cls.lib.polaris_dt_matches.restype = ctypes.c_int
        cls.lib.polaris_dt_prop.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                          ctypes.c_char_p, ctypes.c_char_p,
                                          ctypes.POINTER(ctypes.c_uint32)]
        cls.lib.polaris_dt_prop.restype = ctypes.c_void_p

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def matches(self, blob, available=None):
        buffer = ctypes.create_string_buffer(bytes(blob))
        return self.lib.polaris_dt_matches(buffer, len(blob) if available is None else available)

    def test_expected_board(self):
        self.assertEqual(self.matches(tree()), 1)

    def test_wrong_board_or_splash(self):
        self.assertEqual(self.matches(tree(model=b"Xiaomi topaz\0")), 0)
        self.assertEqual(self.matches(tree(splash=0x5c000000)), 0)

    def test_truncations(self):
        blob = tree()
        for size in range(len(blob)):
            self.assertEqual(self.matches(blob, size), 0)

    def test_bad_bounds(self):
        for offset in (4, 8, 12, 32, 36):
            blob = bytearray(tree())
            struct.pack_into(">I", blob, offset, 0xffffffff)
            self.assertEqual(self.matches(blob), 0)

    def test_nested_siblings(self):
        blob = tree()
        buffer = ctypes.create_string_buffer(bytes(blob))
        for path, expected in [(b"/chosen", b"test\0"), (b"/sibling", b"other\0")]:
            length = ctypes.c_uint32()
            pointer = self.lib.polaris_dt_prop(buffer, len(blob), path, b"bootargs", ctypes.byref(length))
            self.assertTrue(pointer)
            self.assertEqual(ctypes.string_at(pointer, length.value), expected)


if __name__ == "__main__":
    unittest.main()
