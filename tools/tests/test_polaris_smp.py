from pathlib import Path
import importlib.util
import struct
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load(name, file):
    s = importlib.util.spec_from_file_location(name, ROOT / 'tools' / file)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


board = load('smp_board', 'mkadt-polaris.py')
smp = load('polaris_smp', 'polaris-smp.py')


class SMPTests(unittest.TestCase):
    def tree(self, **kwargs):
        with patch.object(board.mkadt, 'd22ap_product', return_value=None):
            return board.build(seed=b'x' * 64, **kwargs)

    def test_one_cpu_default_is_byte_identical(self):
        for kwargs in ({}, dict(display=True, touch=True, touch_wake=True,
                                touch_irq_input=True, usb=True)):
            before = board.adt.serialize(self.tree(**kwargs))
            self.assertEqual(smp.build(before), before)
            self.assertEqual(smp.build(before, 1), before)

    def test_only_adds_second_A55_and_preserves_unrelated_nodes(self):
        before = board.adt.serialize(self.tree(display=True, touch=True, touch_wake=True,
                                               touch_irq_input=True, usb=True))
        after = smp.build(before, 2)
        root = board.adt.parse(after)[0]
        cpus = smp.child(root, 'cpus')
        a, b = (smp.props(c) for c in cpus.children)
        self.assertEqual(a['reg'], struct.pack('<I', 0))
        self.assertEqual(b['reg'], struct.pack('<I', 0x100))
        self.assertEqual(b['state'], b'stopped\0')
        self.assertEqual(b['cluster-core-id'], struct.pack('<I', 1))
        self.assertEqual(b['l2-cache-id'], struct.pack('<I', 1))
        self.assertEqual(b['l3-cache-id'], a['l3-cache-id'])
        self.assertEqual(b['timebase-frequency'], a['timebase-frequency'])
        handles = [smp.props(n)['AAPL,phandle'] for n in smp.nodes(root)
                   if 'AAPL,phandle' in smp.props(n)]
        self.assertEqual(len(handles), len(set(handles)))
        cpus.children.pop()
        self.assertEqual(board.adt.serialize(root), before)
        with self.assertRaises(ValueError):
            smp.build(after, 2)

    def test_refuses_other_counts_qemu_and_changed_board(self):
        before = board.adt.serialize(self.tree())
        for n in (0, 3, 4, 8, True, 2.0, '2', None):
            with self.subTest(count=n), self.assertRaises(ValueError):
                smp.build(before, n)
        with self.assertRaises(ValueError):
            smp.build(board.adt.serialize(self.tree(qemu=True)), 2)
        for path, key, value in ((('chosen',), 'dram-size', struct.pack('<Q', 0x100000000)),
                                 (('cpus', 'cpu0'), 'reg', struct.pack('<I', 0x400)),
                                 (('cpus', 'cpu0'), 'state', b'stopped\0'),
                                 (('cpus', 'cpu0'), 'timebase-frequency', struct.pack('<I', 62500000))):
            root = self.tree()
            node = root
            for name in path:
                node = smp.child(node, name)
            smp.setprop(node, key, value)
            with self.subTest(key=key), self.assertRaises(ValueError):
                smp.build(board.adt.serialize(root), 2)

    def test_rejects_duplicate_phandle(self):
        root = self.tree()
        cpu = smp.child(smp.child(root, 'cpus'), 'cpu0')
        smp.setprop(cpu, 'AAPL,phandle', smp.props(root)['AAPL,phandle'])
        with self.assertRaises(ValueError):
            smp.build(board.adt.serialize(root), 2)

    def test_profile_only_changes_cpu_count(self):
        original = (ROOT / 'tools/polaris-ios-usb-debug.cmdline').read_text()
        new = (ROOT / 'tools/polaris-ios-smp.cmdline').read_text()
        self.assertEqual(new, original.replace('cpus=1', 'cpus=2'))
        self.assertIn('ufsrw=0', new.split())
        self.assertIn('polarisramcow=1', new.split())
        self.assertIn('polarisrammb=512', new.split())


if __name__ == '__main__':
    unittest.main()
