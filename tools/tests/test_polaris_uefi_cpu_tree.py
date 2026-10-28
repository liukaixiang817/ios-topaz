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
            if qemu:
                builder.setprop(cpu.child(cpu.child(root, 'arm-io'), 'gic'), 'reg',
                                struct.pack('<4Q', 0x7000000, 0x10000, 0x70a0000, 0x40000))
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
            if qemu:
                builder.setprop(cpu.child(cpu.child(root, 'arm-io'), 'gic'), 'reg',
                                struct.pack('<4Q', 0x7000000, 0x10000, 0x70a0000, 0x40000))
            self.assertEqual(adt.serialize(root), raw)
            for bad in (0, 7 if qemu else 0x700, 1 if qemu else 0x100):
                root, _ = adt.parse(changed)
                builder.setprop(cpu.child(root, 'cpus').children[1], 'reg', struct.pack('<I', bad))
                with self.assertRaises(ValueError):cpu.validate(adt.serialize(root), 7, qemu, 2)
            with self.assertRaises(ValueError):cpu.select(raw, 1, qemu, 2)

    def test_four_big_cores_preserve_reserved_firmware_and_tree(self):
        for qemu in (False, True):
            original=self.tree(qemu)
            raw=cpu.select(original,7,qemu,4)
            tree=cpu.validate(raw,7,qemu,4)
            nodes=cpu.child(tree,'cpus').children
            self.assertEqual([struct.unpack('<I',cpu.props(n)['reg'])[0] for n in nodes],
                             [7,6,5,4] if qemu else [0x700,0x600,0x500,0x400])
            self.assertEqual(len({cpu.props(n)['AAPL,phandle'] for n in nodes}),4)
            for i in range(1,4):
                self.assertEqual(cpu.props(nodes[i])['state'],b'stopped\0')
                bad,_=adt.parse(raw)
                builder.setprop(cpu.child(bad,'cpus').children[i],'reg',struct.pack('<I',0))
                with self.assertRaises(ValueError):cpu.validate(adt.serialize(bad),7,qemu,4)
            for count in (0,3,5,7,8,True):
                with self.assertRaises(ValueError):cpu.select(original,7,qemu,count)
            with self.assertRaises(ValueError):cpu.select(original,1,qemu,4)
            if qemu:
                with self.assertRaises(ValueError):cpu.isolated_qemu_ufs(raw,0)
            # Four-core admission does not broaden either owned-writing fixture.
            n=adt.Node();n.props=[('name',0,b'polaris-owned-marker\0')]
            tree.children.append(n)
            with self.assertRaises(ValueError):cpu.validate(adt.serialize(tree),7,qemu,4)

    def test_isolated_UFS_cannot_reach_phone_or_unbound_virtual_hardware(self):
        raw = cpu.select(self.tree(True), 7, True, 2)
        virtual = cpu.isolated_qemu_ufs(raw, 0x12345678)
        root = cpu.validate(virtual, 7, True, 2)
        self.assertEqual(cpu.props(cpu.child(root, 'polaris-qemu-ufs'))['head-crc32'],
                         struct.pack('<I', 0x12345678))
        with self.assertRaises(ValueError):cpu.validate(virtual, 7, False, 2)
        # Even transplanting the node into an otherwise valid phone tree fails.
        phone = cpu.validate(cpu.select(self.tree(), 7, False, 2), 7, False, 2)
        phone.children.append(cpu.child(root, 'polaris-qemu-ufs'))
        with self.assertRaises(ValueError):cpu.validate(adt.serialize(phone), 7, False, 2)

        for key in ('version', 'reg', 'ecam', 'compatible', 'head-crc32'):
            changed, _ = adt.parse(virtual)
            node = cpu.child(changed, 'polaris-qemu-ufs')
            builder.setprop(node, key, b'wrong')
            with self.subTest(key=key), self.assertRaises(ValueError):
                cpu.validate(adt.serialize(changed), 7, True, 2)
        node = cpu.child(root, 'polaris-qemu-ufs')
        node.props.append(node.props[-1])
        with self.assertRaises(ValueError):cpu.validate(adt.serialize(root), 7, True, 2)
        with self.assertRaises(ValueError):cpu.isolated_qemu_ufs(virtual, 1)
        for bad in (-1, 1 << 32, True, '1'):
            with self.assertRaises(ValueError):cpu.isolated_qemu_ufs(raw, bad)

    def test_owned_fixture_cannot_reach_phone_or_unbind_packet_and_base(self):
        raw = cpu.select(self.tree(True), 7, True, 2)
        packet = bytearray(384 + 24)
        packet[:8] = b'PROWN001'
        struct.pack_into('<IIQQQ', packet, 8, 384, len(packet), 2048, 32768, 8192)
        struct.pack_into('<II', packet, 72, 0, 1)
        protected = struct.pack('<QQQ', 0, 2315, 256)
        owned = cpu.isolated_qemu_owned(raw, 0x12345678, bytes(packet), protected, 256)
        tree = cpu.validate(owned, 7, True, 2)
        with self.assertRaises(ValueError):cpu.validate(owned, 7, False, 2)
        phone = cpu.validate(cpu.select(self.tree(), 7, False, 2), 7, False, 2)
        phone.children += [cpu.child(tree, n) for n in ('polaris-qemu-ufs', 'polaris-qemu-owned-file')]
        with self.assertRaises(ValueError):cpu.validate(adt.serialize(phone), 7, False, 2)
        changes = [('layout', struct.pack('<QQQ', 2049, 32768, 8192)),
                   ('protected-blocks', struct.pack('<Q', 257)),
                   ('protected-map', struct.pack('<QQQ', 1, 2315, 256)),
                   ('protected-map', struct.pack('<QQQ', 0, 2047, 256)),
                   ('owner-packet', bytes(packet[:-1]))]
        for key, value in changes:
            mutated, _ = adt.parse(owned)
            builder.setprop(cpu.child(mutated, 'polaris-qemu-owned-file'), key, value)
            with self.subTest(key=key), self.assertRaises(ValueError):
                cpu.validate(adt.serialize(mutated), 7, True, 2)



    def test_physical_marker_binds_entire_original_root_and_never_virtual(self):
        tree=cpu.validate(cpu.select(self.tree(),7,False,2),7,False,2)
        node=adt.Node()
        node.props=[(k,0,v) for k,v in {
            'name':b'polaris-file-root\0','version':struct.pack('<I',1),
            'reg':struct.pack('<QQ',0x1d84000,0x2500),
            'layout':struct.pack('<QQQ',2048,8388608,4194304),
            'extents':struct.pack('<QQQ',0,4096,4194304)}.items()]
        tree.children.append(node)
        packet=bytearray(408);packet[:8]=b'PROWN001'
        struct.pack_into('<IIQQQ',packet,8,384,len(packet),2048,8388608,2048)
        struct.pack_into('<II',packet,72,0,1)
        struct.pack_into('<QQQ',packet,384,0,5000000,2048)
        raw=cpu.physical_marker(adt.serialize(tree),bytes(packet))
        cpu.validate(raw,7,False,2)
        with self.assertRaises(ValueError):cpu.validate(raw,7,True,2)
        for key,value in [('protected-blocks',struct.pack('<Q',4194303)),
                          ('protected-map',struct.pack('<QQQ',0,4097,4194304))]:
            changed,_=adt.parse(raw);builder.setprop(cpu.child(changed,'polaris-owned-marker'),key,value)
            with self.subTest(key=key),self.assertRaises(ValueError):cpu.validate(adt.serialize(changed),7,False,2)
        for offset,value in [(32,2049),(392,4096-2048),(384,1),(400,2047)]:
            bad=bytearray(packet);struct.pack_into('<Q',bad,offset,value)
            with self.subTest(offset=offset),self.assertRaises(ValueError):cpu.physical_marker(adt.serialize(tree),bytes(bad))


if __name__ == '__main__':
    unittest.main()
