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
    def test_added_private_implementation_headers_have_exact_shipped_bytes(self):
        for name,want in cache.EXTRA_PRIVATE_HEADER_SHA.items():
            # The native file is shipped as an added-file patch. Some older
            # headers have no separate tools copy; the GPU copy deliberately
            # renames its one local include when staged into the kernel.
            bodies=[]
            for patch in (ROOT/'xnu/profiles/polaris').glob('*.patch'):
                text=patch.read_text();marker='+++ b/'+name+'\n'
                if marker not in text:continue
                body=text.split(marker,1)[1].split('--- ',1)[0]
                if not body.startswith('@@ -0,0 '):continue
                lines=body.splitlines(keepends=True)[1:]
                self.assertTrue(all(line.startswith('+') for line in lines))
                bodies.append(''.join(line[1:] for line in lines).encode())
            self.assertEqual(len(bodies),1,name)
            self.assertEqual(hashlib.sha256(bodies[0]).hexdigest(),want,name)
            source=ROOT/'tools'/Path(name).name.replace('_','-')
            if source.exists():
                raw=source.read_bytes().replace(b'"polaris-a630-post.h"',b'"polaris_a630_post.h"')
                if name=='iokit/Kernel/arm/polaris_wled_native.h':
                    raw=raw.replace(b'"polaris-wled-mailbox.h"',b'"polaris_wled_mailbox.h"')
                self.assertEqual(raw,bodies[0],name)

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
