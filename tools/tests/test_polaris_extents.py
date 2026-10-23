"""Boundary checks on the actual FIEMAP policy used by the phone inspector."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ExtentPolicyTests(unittest.TestCase):
    def test_reject_unsafe_maps(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            source = folder / 'test.c'
            source.write_text(r'''
#include <assert.h>
#include "polaris-extent-policy.h"
int main(void) {
    assert(polaris_extent_valid(0, 0, 4096, 8192, 1, 8192, 16384, true));
    assert(polaris_extent_valid(0, 0, 4096, 4096, 0, 8192, 16384, false));
    assert(polaris_extent_valid(4096, 4096, 12288, 4096, 1, 8192, 16384, true));
    /* Every unknown/status flag and prematurely marked last extent fails. */
    for (unsigned bit = 1; bit < 32; bit++) {
        assert(!polaris_extent_valid(0, 0, 4096, 8192, 1u | (1u << bit), 8192, 16384, true));
        assert(!polaris_extent_valid(0, 0, 4096, 4096, 1u << bit, 8192, 16384, false));
    }
    assert(!polaris_extent_valid(0, 0, 4096, 4096, 1, 8192, 16384, true));
    assert(!polaris_extent_valid(0, 0, 4096, 8192, 0, 8192, 16384, false));
    assert(!polaris_extent_valid(0, 4096, 4096, 4096, 1, 8192, 16384, true));
    assert(!polaris_extent_valid(8192, 4096, 4096, 4096, 1, 8192, 16384, true));
    assert(!polaris_extent_valid(0, 0, 0, 8192, 1, 8192, 16384, true));
    assert(!polaris_extent_valid(0, 0, 12288, 8192, 1, 8192, 16384, true));
    assert(!polaris_extent_valid(0, 0, 4096, 0, 1, 8192, 16384, true));
    assert(!polaris_extent_valid(0, 0, UINT64_MAX - 4095, 8192, 1, 8192, 16384, true));
    assert(!polaris_extent_valid(UINT64_MAX - 4095, UINT64_MAX - 4095,
        4096, 8192, 1, 8192, 16384, true));
    assert(!polaris_extent_valid(0, 0, 4096, UINT64_MAX - 4095, 1, 8192, 16384, true));
    for (uint64_t offset = 1; offset < 4096; offset++) {
        assert(!polaris_extent_valid(0, 0, 4096 + offset, 8192, 1, 8192, 16384, true));
        assert(!polaris_extent_valid(0, 0, 4096, 8192 + offset, 1, 8192, 16384, true));
    }
    return 0;
}
''')
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', '-I', str(ROOT / 'tools'),
                            str(source), '-o', str(folder / 'test')], check=True)
            subprocess.run([str(folder / 'test')], check=True)


if __name__ == '__main__':
    unittest.main()
