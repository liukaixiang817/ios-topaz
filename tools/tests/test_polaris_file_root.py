import copy
import hashlib
import importlib.util
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
import polaris_file_root as policy
spec = importlib.util.spec_from_file_location('polaris_adt_file', TOOLS / 'mkadt-polaris.py')
adt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adt)


class RootMetadataTests(unittest.TestCase):
    def fixture(self, root):
        image = bytearray(8192)
        image[1024:1028] = b'HX\x00\x05'
        struct.pack_into('>II', image, 1064, 4096, 2)
        root.write_bytes(image)
        head = bytearray(1 << 20)
        head[510:512] = b'\x55\xaa'; head[4096:4104] = b'EFI PART'
        struct.pack_into('<QII', head, 4168, 2, 1, 128)
        struct.pack_into('<QQ', head, 8224, 900, 5899)
        head[8248:8320] = 'userdata'.encode('utf-16-le').ljust(72, b'\0')
        mapping = dict(version=1, readonly_snapshot=True, raw_write_allowed=False,
                       backing_device_bytes=5000*4096, file_bytes=8192, block_bytes=4096,
                       extents=[dict(logical=0, physical=4096, length=4096),
                                dict(logical=4096, physical=81920, length=4096)])
        return mapping, head, hashlib.sha256(image).hexdigest()

    def test_actual_file_and_adt_encoding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'root.img'
            mapping, head, sha = self.fixture(root)
            manifest = policy.create(mapping, head, root, sha)
            self.assertEqual(manifest['layout'], [900, 5000, 2])
            self.assertEqual(manifest['extents'], [[0, 901, 1], [1, 920, 1]])
            with patch.object(adt.mkadt, 'd22ap_product', return_value=None):
                tree = adt.build(seed=b'x'*64, file_root=manifest)
                tree = adt.adt.parse(adt.adt.serialize(tree))[0]
                props = adt.props(adt.child(tree, 'polaris-file-root'))
                self.assertEqual(struct.unpack('<3Q', props['layout']), (900, 5000, 2))
                self.assertEqual(struct.unpack('<6Q', props['extents']), (0, 901, 1, 1, 920, 1))
                self.assertEqual(struct.unpack('<3I', props['crc32']), tuple(manifest['crc32']))
                with self.assertRaises(ValueError): adt.build(qemu=True, file_root=manifest)
                with self.assertRaises(ValueError): adt.build(ufs_head=head, file_root=manifest)
            for key, value in [('raw_write_allowed', True), ('file_bytes', 4096),
                               ('backing_device_bytes', 1), ('readonly_snapshot', False)]:
                bad = dict(mapping, **{key: value})
                with self.assertRaises(ValueError): policy.create(bad, head, root, sha)
            with self.assertRaises(ValueError): policy.create(mapping, head, root, '0'*64)
            for extents in ([[0,901,1],[1,901,1]], [[0,901,1]], [[0,899,2]],
                            [[0,5899,2]], [[0,901,1],[2,920,1]]):
                bad = copy.deepcopy(manifest); bad['extents'] = extents
                with self.assertRaises(ValueError): policy.validate(bad)
            head[8248] = ord('x')
            with self.assertRaises(ValueError): policy.create(mapping, head, root, sha)


if __name__ == '__main__': unittest.main()
