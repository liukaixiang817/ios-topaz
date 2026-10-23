"""Exercise the actual freestanding copy-plan validator before RAM writes."""
import ctypes
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

VA, PA, RAM = 0xfffffe0006000000, 0x180000000, 0xfc8a0000


def payload():
    blob = bytearray(0x420)
    struct.pack_into('<8sII7Q', blob, 0, b'SWEETXNU', 1, 1,
                     VA, VA + 0x4000, 0x400, 32, VA + 0x8000, PA, RAM)
    blob[0x48:0x4e] = b'cpus=1'
    struct.pack_into('<4Q', blob, 0x2a8, VA + 0x4000, 0x4000, 0x300, 9)
    return blob


class Plan(ctypes.Structure):
    _fields_ = [('adt', ctypes.c_uint64), ('args', ctypes.c_uint64),
                ('top', ctypes.c_uint64), ('entry', ctypes.c_uint64)]


class PayloadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        library = Path(cls.tmp.name) / 'payload.dylib'
        source = Path(__file__).resolve().parents[2] / 'shim/polaris/payload.c'
        subprocess.run(['cc', '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror',
                        str(source), '-o', str(library)], check=True)
        cls.lib = ctypes.CDLL(str(library))
        cls.lib.polaris_payload_check.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                                                 ctypes.c_uint64, ctypes.POINTER(Plan)]
        cls.lib.polaris_payload_check.restype = ctypes.c_char_p

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def check(self, blob, address=0x84000000, size=None):
        buffer = ctypes.create_string_buffer(bytes(blob))
        plan = Plan()
        error = self.lib.polaris_payload_check(buffer, len(blob) if size is None else size,
                                               address, ctypes.byref(plan))
        return error, plan

    def test_good_layout(self):
        error, p = self.check(payload())
        self.assertIsNone(error)
        self.assertEqual((p.adt, p.args, p.top, p.entry),
                         (PA + 0x8000, PA + 0xc000, PA + 0x10000, PA + 0x4000))

    def test_all_truncated_lengths(self):
        for size in range(len(payload())):
            self.assertIsNotNone(self.check(payload(), size=size)[0])

    def test_source_cannot_overlap_kernel_or_overflow(self):
        for source in (0x180000000, 0x27c8a0000, 0x7ffffff8, 0x17fffff00,
                       0x84000001, 0xfffffffffffffff8):
            self.assertIsNotNone(self.check(payload(), address=source)[0])

    def test_bad_fields_refused(self):
        mutations = [('I', 8, 2), ('I', 12, 0), ('I', 12, 65),
                     ('Q', 0x10, VA + 1), ('Q', 0x18, VA + 0x5000),
                     ('Q', 0x20, 0x2a8), ('Q', 0x20, 0xfffffffffffffff8),
                     ('Q', 0x28, 0x1000001), ('Q', 0x30, VA - 0x4000),
                     ('Q', 0x30, VA + RAM), ('Q', 0x38, 0xb0000000),
                     ('Q', 0x40, 0x40000000), ('Q', 0x2a8, VA - 8),
                     ('Q', 0x2b0, 0xffffffffffffffff), ('Q', 0x2b8, 0),
                     ('Q', 0x2b8, 0x3f8), ('Q', 0x2c0, 0x5000)]
        for kind, offset, value in mutations:
            with self.subTest(offset=offset, value=value):
                blob = payload()
                struct.pack_into('<' + kind, blob, offset, value)
                self.assertIsNotNone(self.check(blob)[0])

    def test_overlaps_and_unterminated_commandline(self):
        blob = payload()
        struct.pack_into('<I', blob, 12, 2)
        struct.pack_into('<4Q', blob, 0x2c8, VA + 0x5000, 0x1000, 0x310, 8)
        self.assertIn(b'overlapping', self.check(blob)[0])
        blob = payload()
        blob[0x48:0x2a8] = b'x' * 608
        self.assertIn(b'unterminated', self.check(blob)[0])


if __name__ == '__main__':
    unittest.main()
