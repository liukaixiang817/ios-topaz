"""Real C overlay parser with independent Python SHA/wire/negative fixtures."""
import ctypes
import hashlib
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class GPUBundleTests(unittest.TestCase):
    def test_exact_build_and_digest_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory)
            (p / 'build.c').write_text('''#include "polaris-gpu-build.h"
int check(const void *v,size_t n,const void *h){return pgpu_build_matches(v,n,h);}
''')
            subprocess.run(['/usr/bin/clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-dynamiclib', '-I', str(ROOT / 'tools'), str(p / 'build.c'),
                            '-o', str(p / 'build.dylib')], check=True)
            lib = ctypes.CDLL(str(p / 'build.dylib'))
            lib.check.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
            digest = bytes.fromhex('6ab8e26039824073356156923be7cca267713359f90a3bd3ad63488647771b3b')
            self.assertEqual(lib.check(b'20H392\0', 7, bytes(32)), 1)
            self.assertEqual(lib.check(b'20F66\0', 6, digest), 1)
            for version in (b'20H392X', b'20F66X', b'20F65\0', b'20F66\0extra'):
                self.assertEqual(lib.check(version, len(version), digest), 0)
            for length in (0, 1, 5, 7, 8):
                self.assertEqual(lib.check(b'20F66\0xx', length, digest), 0)
            for i in range(32):
                broken = bytearray(digest); broken[i] ^= 1
                self.assertEqual(lib.check(b'20F66\0', 6, bytes(broken)), 0)
            self.assertEqual(lib.check(None, 6, digest), 0)
            self.assertEqual(lib.check(b'20F66\0', 6, None), 0)

    def test_all_hashes_before_outputs_and_malformed_ranges(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory)
            (p / 'test.c').write_text(r'''
#include "polaris-gpu-bundle.h"
#include <CommonCrypto/CommonDigest.h>
#include <string.h>
static bool digest(const void *p,size_t n,const uint8_t *want){
 unsigned char h[32];CC_SHA256(p,(CC_LONG)n,h);return !memcmp(h,want,32);}
int check(const void*p,size_t n){
 struct pgpu_file out[6],before[6];memset(out,0xa5,sizeof(out));memcpy(before,out,sizeof(out));
 bool ok=pgpu_parse(p,n,out,digest);
 if(!ok)return memcmp(before,out,sizeof(out))? -1:0;
 for(unsigned i=0;i<6;i++)if(out[i].kind!=i||!out[i].bytes)return -2;
 return 1;}
''')
            subprocess.run(['/usr/bin/clang', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                            '-dynamiclib', '-I', str(ROOT / 'tools'), str(p / 'test.c'),
                            '-o', str(p / 'test.dylib')], check=True)
            library = ctypes.CDLL(str(p / 'test.dylib'))
            library.check.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            library.check.restype = ctypes.c_int

            def check(b):
                return library.check(ctypes.create_string_buffer(bytes(b)), len(b))

            data = bytearray(304)
            struct.pack_into('<8sII', data, 0, b'PGPU0047', 6, 0)
            for n in range(6):
                data.extend(b'\0' * (-len(data) & 15))
                blob = bytes([n + 1]) * (256 + n)
                struct.pack_into('<IIQ32s', data, 16 + n * 48, n, len(blob), len(data), hashlib.sha256(blob).digest())
                data.extend(blob)
            struct.pack_into('<I', data, 12, len(data))
            self.assertEqual(check(data), 1)
            for at in [0, 8, 12, 16, 20, 24, 32, 16 + 48 * 5 + 16, 304, len(data) - 1]:
                broken = bytearray(data)
                broken[at] ^= 1
                self.assertEqual(check(broken), 0, at)
            for length in [0, 8, 15, 16, 303, len(data) - 1]:
                self.assertEqual(check(data[:length]), 0, length)
            for address in [0, 16, 303, 305, 2**64 - 1]:
                broken = bytearray(data)
                struct.pack_into('<Q', broken, 24, address)
                self.assertEqual(check(broken), 0, address)
            self.assertEqual(check(data + b'x'), 0)


if __name__ == '__main__':
    unittest.main()
