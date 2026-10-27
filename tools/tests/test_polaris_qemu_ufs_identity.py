"""Compile the exact kernel identity gate; this is not native I/O proof."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class VirtualUfsIdentity(unittest.TestCase):
    def test_actual_native_gate_rejects_physical_and_mutated_metadata(self):
        patch = (ROOT / 'xnu/profiles/polaris/0872-polaris-native-ufs-queue-and-isolated-emulator.patch').read_text()
        section = patch.split('#define POLARIS_QEMU_UFS_H\n', 1)[1].split('+#ifndef POLARIS_UFS_POLICY_TEST', 1)[0]
        header = '\n'.join(line[1:] for line in section.splitlines() if line.startswith('+'))
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            (folder / 'gate.h').write_text(header + '\n')
            (folder / 'test.c').write_text(r'''
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#define POLARIS_UFS_POLICY_TEST 1
#include "gate.h"
int main(void) {
    uint64_t reg[2]={0x10100000,0x2000},ecam[2]={0x4010000000,0x100000};
#define CHECK(a,t,m,c,n,w,b,s) polaris_qemu_ufs_identity(a,t,m,c,n,w,b,s,reg,ecam)
    assert(CHECK(7,62500000,1,7,2,0,0x130000000,0xfc8a0000));
    assert(CHECK(0x80000007,62500000,1,7,2,0,0x130000000,0xfc8a0000));
    for (unsigned cpu=0;cpu<0x1000;cpu++) {
        assert(CHECK(cpu,62500000,1,7,2,0,0x130000000,0xfc8a0000)==(cpu==7));
        /* Physical Polaris MPIDR700/600 cannot pass, even with a VM node. */
        assert(!CHECK(cpu,19200000,1,1792,2,0,0x180000000,0xfc8a0000));
    }
    for (unsigned bit=0;bit<64;bit++) {
        uint64_t flip=UINT64_C(1)<<bit;
        assert(!CHECK(7,62500000^flip,1,7,2,0,0x130000000,0xfc8a0000));
        assert(!CHECK(7,62500000,1,7,2,0,0x130000000^flip,0xfc8a0000));
        assert(!CHECK(7,62500000,1,7,2,0,0x130000000,0xfc8a0000^flip));
        for (unsigned i=0;i<2;i++) {
            reg[i]^=flip;
            assert(!CHECK(7,62500000,1,7,2,0,0x130000000,0xfc8a0000));
            reg[i]^=flip;ecam[i]^=flip;
            assert(!CHECK(7,62500000,1,7,2,0,0x130000000,0xfc8a0000));
            ecam[i]^=flip;
        }
    }
    for (unsigned bit=0;bit<32;bit++) {
        uint32_t flip=1u<<bit;
        assert(!CHECK(7,62500000,1^flip,7,2,0,0x130000000,0xfc8a0000));
        assert(!CHECK(7,62500000,1,7^flip,2,0,0x130000000,0xfc8a0000));
        assert(!CHECK(7,62500000,1,7,2^flip,0,0x130000000,0xfc8a0000));
        assert(!CHECK(7,62500000,1,7,2,flip,0x130000000,0xfc8a0000));
    }
    return 0;
}
''')
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', str(folder / 'test.c'),
                            '-o', str(folder / 'test')], check=True)
            subprocess.run([str(folder / 'test')], check=True)


if __name__ == '__main__':
    unittest.main()
