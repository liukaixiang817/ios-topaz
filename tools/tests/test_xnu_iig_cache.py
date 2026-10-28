"""Private implementation exceptions cannot admit changed interface sources."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('iig_cache',ROOT/'tools/xnu-iig-cache.py')
cache=importlib.util.module_from_spec(spec);spec.loader.exec_module(cache)


class PrivateHeaderBinding(unittest.TestCase):
    def test_exact_private_replacements_only(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'header'
            for name,(old,new) in cache.PRIVATE_IMPLEMENTATION_REPLACEMENTS.items():
                host=ROOT/'tools'/Path(name).name.replace('_','-')
                raw=host.read_bytes().replace(b'"polaris-a630-core.h"',b'"polaris_a630_core.h"')
                self.assertEqual(hashlib.sha256(raw).hexdigest(),new)
                p.write_bytes(raw)
                self.assertTrue(cache.header_matches(name,old,p))
                self.assertFalse(cache.header_matches(name,'0'*64,p))
                self.assertFalse(cache.header_matches('iokit/DriverKit/IOService.iig',old,p))
                self.assertFalse(cache.header_matches('bsd/sys/mount_internal.h',old,p))
                p.write_bytes(raw+b'\n/* unreviewed change */\n')
                self.assertFalse(cache.header_matches(name,old,p))

    def test_unchanged_headers_still_require_their_own_hash(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'header';p.write_bytes(b'unchanged interface')
            want=cache.sha(p)
            self.assertTrue(cache.header_matches('iokit/DriverKit/IOService.iig',want,p))
            p.write_bytes(b'changed interface')
            self.assertFalse(cache.header_matches('iokit/DriverKit/IOService.iig',want,p))


if __name__=='__main__':unittest.main()
