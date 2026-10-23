"""Compile and execute the actual C policy shipped in the kernel patch."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class UFSPolicyTests(unittest.TestCase):
    def test_actual_kernel_policy(self):
        patch = (ROOT / 'xnu/profiles/polaris/0801-polaris-readonly-ufs-probe.patch').read_text()
        section = patch.split('+++ b/bsd/dev/polaris_ufs_probe_policy.h\n', 1)[1].split('--- a/', 1)[0]
        header = '\n'.join(line[1:] for line in section.splitlines() if line.startswith('+'))
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            (folder / 'policy.h').write_text(header + '\n')
            (folder / 'test.c').write_text(r'''
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#include "policy.h"
int main(void) {
    uint8_t tur[6] = {0};
    uint8_t rd[10] = {0x28, 0, 0, 0, 0, 0, 0, 1, 0, 0};
    assert(polaris_probe_cdb_allowed(tur, 6, 0, false, 0));
    assert(polaris_probe_cdb_allowed(rd, 10, 1u << 20, false, 0));
    /* Exhaust every one-byte mutation, including opcodes, LBA and count. */
    for (unsigned i = 0; i < 10; i++) {
        uint8_t saved = rd[i];
        for (unsigned v = 0; v < 256; v++) {
            rd[i] = v;
            assert(polaris_probe_cdb_allowed(rd, 10, 1u << 20, false, 0) == (v == saved));
        }
        rd[i] = saved;
    }
    for (unsigned i = 0; i < 6; i++) {
        for (unsigned v = 1; v < 256; v++) {
            tur[i] = v;
            assert(!polaris_probe_cdb_allowed(tur, 6, 0, false, 0));
        }
        tur[i] = 0;
    }
    for (unsigned n = 0; n < 32; n++) {
        assert(polaris_probe_cdb_allowed(rd, n, 1u << 20, false, 0) == (n == 10));
        assert(polaris_probe_cdb_allowed(tur, n, 0, false, 0) == (n == 6));
    }
    assert(!polaris_probe_cdb_allowed(rd, 10, 4096, false, 0));
    assert(!polaris_probe_cdb_allowed(rd, 10, 0, false, 0));
    assert(!polaris_probe_cdb_allowed(tur, 6, 4096, false, 0));
    assert(!polaris_probe_cdb_allowed(rd, 10, 1u << 20, true, 0));
    assert(!polaris_probe_cdb_allowed(tur, 6, 0, true, 0));
    assert(!polaris_probe_cdb_allowed(0, 10, 1u << 20, false, 0));
    for (unsigned lun = 1; lun < 256; lun++) {
        assert(!polaris_probe_cdb_allowed(rd, 10, 1u << 20, false, lun));
        assert(!polaris_probe_cdb_allowed(tur, 6, 0, false, lun));
    }
    assert(polaris_probe_crc32((const uint8_t *)"123456789", 9) == 0xcbf43926);
    assert(polaris_probe_crc32((const uint8_t *)"", 0) == 0);
    return 0;
}
''')
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', str(folder / 'test.c'),
                            '-o', str(folder / 'test')], check=True)
            subprocess.run([str(folder / 'test')], check=True)


if __name__ == '__main__':
    unittest.main()
