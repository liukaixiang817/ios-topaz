"""Read-only service opt-ins cannot replace or truncate original boot guards."""
import importlib.util
from pathlib import Path
import struct
import sys
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
import adt
spec=importlib.util.spec_from_file_location('runtime_payload',ROOT/'tools/mkpayload.py')
payload=importlib.util.module_from_spec(spec);spec.loader.exec_module(payload)


def tree(board=b'xiaomi,polaris\0'):
    node=adt.Node();node.props=[('name',0,b'DeviceTree\0'),('compatible',0,board)]
    return adt.serialize(node)


class RuntimeServices(unittest.TestCase):
    def test_disabled_is_byte_identical(self):
        raw=tree();self.assertEqual(payload.add_runtime_services(raw,None),raw)
        self.assertEqual(payload.command_line_bytes('x'*602),b'x'*602)

    def test_only_explicit_readonly_services_are_published(self):
        for services in (['battery-readonly'],['wifi-readonly'],['battery-readonly','wifi-readonly']):
            raw=payload.add_runtime_services(tree(),services);root,used=adt.parse(raw)
            self.assertEqual(used,len(raw));node=root.children[-1]
            self.assertEqual(node.name,'polaris-runtime-services')
            self.assertEqual(node.prop('version'),struct.pack('<I',1))
            for key in ('battery-readonly','wifi-readonly'):
                self.assertEqual(node.prop(key),struct.pack('<I',int(key in services)))

    def test_foreign_duplicate_unknown_and_write_intents_refuse(self):
        for services in ([],['wifi-readonly']*2,['radio-on'],['battery-write'],[1],{'wifi-readonly':True}):
            with self.assertRaises(ValueError):payload.add_runtime_services(tree(),services)
        with self.assertRaises(ValueError):payload.add_runtime_services(tree(b'xiaomi,dipper\0'),['wifi-readonly'])
        raw=payload.add_runtime_services(tree(),['battery-readonly'])
        with self.assertRaises(ValueError):payload.add_runtime_services(raw,['wifi-readonly'])


if __name__=='__main__':unittest.main()
