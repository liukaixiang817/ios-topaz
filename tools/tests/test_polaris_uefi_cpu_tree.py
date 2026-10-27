import importlib.util
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import adt
import mkadt
import polaris_uefi_cpu_tree as cpu

spec = importlib.util.spec_from_file_location('polaris_adt', ROOT / 'tools/mkadt-polaris.py')
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class ResidentCoreTree(unittest.TestCase):
    def tree(self, qemu=False):
        # Seedless product data is irrelevant to CPU admission; do not require
        # a downloaded Apple artifact to run these structural refusal tests.
        saved = mkadt.d22ap_product
        mkadt.d22ap_product = lambda: []
        try:
            root = builder.build(seed=b'x' * 64)
        finally:
            mkadt.d22ap_product = saved
        p = cpu.child(cpu.child(root, 'cpus'), 'cpu0')
        builder.setprop(p, 'reg', struct.pack('<I', 1 if qemu else 0x100))
        if qemu:
            builder.setprop(cpu.child(root, 'chosen'), 'dram-base', struct.pack('<Q', 0x130000000))
            builder.setprop(cpu.child(cpu.child(root, 'arm-io'), 'gic'), 'reg',
                            struct.pack('<4Q', 0x7000000, 0x10000, 0x70a0000, 0x40000))
        return adt.serialize(root)

    def test_only_MPIDR_changes_and_control_is_byte_identical(self):
        for qemu in (False, True):
            raw = self.tree(qemu)
            self.assertEqual(cpu.select(raw, 1, qemu), raw)
            changed = cpu.select(raw, 7, qemu)
            root, _ = adt.parse(changed)
            node = cpu.child(root, 'cpus').children[0]
            self.assertEqual(cpu.props(node)['reg'], struct.pack('<I', 7 if qemu else 0x700))
            builder.setprop(node, 'reg', struct.pack('<I', 1 if qemu else 0x100))
            self.assertEqual(adt.serialize(root), raw)

    def test_foreign_RAM_GIC_core_and_multiCPU_refused(self):
        raw = self.tree()
        for core in (0, 2, 4, 8, True):
            with self.assertRaises(ValueError):cpu.select(raw, core)
        with self.assertRaises(ValueError):cpu.select(raw, 7, True)
        changes = [('compatible', b'other\0'), ('reg', struct.pack('<I', 0)),
                   ('cpu-id', struct.pack('<I', 1)), ('state', b'stopped\0')]
        for key, value in changes:
            root, _ = adt.parse(raw)
            node = root if key == 'compatible' else cpu.child(root, 'cpus').children[0]
            builder.setprop(node, key, value)
            with self.subTest(key=key), self.assertRaises(ValueError):cpu.select(adt.serialize(root), 7)
        root, _ = adt.parse(raw)
        cpus = cpu.child(root, 'cpus')
        cpus.children.append(cpus.children[0])
        with self.assertRaises(ValueError):cpu.select(adt.serialize(root), 7)
        with self.assertRaises(ValueError):cpu.select(raw + b'\0', 7)

    def test_explicit_big_pair_keeps_firmware_reserved_and_unrelated_tree_identical(self):
        for qemu in (False, True):
            raw = self.tree(qemu)
            changed = cpu.select(raw, 7, qemu, 2)
            root = cpu.validate(changed, 7, qemu, 2)
            cpus = cpu.child(root, 'cpus')
            ids = [struct.unpack('<I', cpu.props(n)['reg'])[0] for n in cpus.children]
            self.assertEqual(ids, [7, 6] if qemu else [0x700, 0x600])
            self.assertNotIn(0, ids)
            self.assertEqual(cpu.props(cpus.children[1])['state'], b'stopped\0')
            cpus.children.pop()
            builder.setprop(cpus.children[0], 'reg', struct.pack('<I', 1 if qemu else 0x100))
            self.assertEqual(adt.serialize(root), raw)
            for bad in (0, 7 if qemu else 0x700, 1 if qemu else 0x100):
                root, _ = adt.parse(changed)
                builder.setprop(cpu.child(root, 'cpus').children[1], 'reg', struct.pack('<I', bad))
                with self.assertRaises(ValueError):cpu.validate(adt.serialize(root), 7, qemu, 2)
            with self.assertRaises(ValueError):cpu.select(raw, 1, qemu, 2)


if __name__ == '__main__':
    unittest.main()
