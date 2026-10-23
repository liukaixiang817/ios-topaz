"""Real COW engine with a finite, pre-reserved RAM allocator."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ArenaTests(unittest.TestCase):
    def test_shipped_allocator_matches(self):
        patch = (ROOT / 'xnu/profiles/polaris/0806-polaris-reserved-root-memory.patch').read_text()
        section = patch.split('+++ b/bsd/dev/polaris_cow_arena.h\n')[1].split('--- a/')[0]
        shipped = '\n'.join(s[1:] for s in section.splitlines() if s.startswith('+')) + '\n'
        self.assertEqual(shipped, (ROOT / 'tools/polaris-cow-arena.h').read_text())

    def test_actual_finite_allocator_and_overlay(self):
        source = r'''
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "polaris-ram-cow.h"
#include "polaris-cow-arena.h"
int main(void) {
    size_t bytes=123; unsigned groups=456;
    const unsigned bad[]={0,1,15,513,~0u};
    for(unsigned i=0;i<sizeof(bad)/sizeof(*bad);i++) {
        assert(!polaris_arena_budget(bad[i],&bytes,&groups));
        assert(bytes==123&&groups==456);
    }
    assert(!polaris_arena_budget(128,NULL,&groups));
    assert(!polaris_arena_budget(128,&bytes,NULL));
    for(unsigned m=16;m<=512;m++) {
        assert(polaris_arena_budget(m,&bytes,&groups));
        assert(bytes==(size_t)m*1048576 && groups==m*64);
        assert(groups<=POLARIS_COW_GROUPS);
    }
    /* Cross the old8192-group ceiling using real distinct backing. Only one
     * 4KiB slot per16KiB group is dirty: expose fragmentation in accounting. */
    const unsigned n=8200;
    struct polaris_cow *c=calloc(1,sizeof(*c)); assert(c);
    struct polaris_cow_arena a={malloc((size_t)n*16384), (size_t)n*16384, 0};
    assert(a.base); c->nblocks=(uint64_t)n*4; c->limit=n;
    unsigned char input[4096],readback[4096];
    for(unsigned i=0;i<n;i++) {
        memset(input,(unsigned char)(i*17),sizeof(input));
        assert(polaris_cow_put(c,(uint64_t)i*4,1,input,polaris_arena_allocate,&a));
    }
    assert(c->used==n && c->dirty_blocks==n && c->written_blocks==n);
    assert(a.used==a.size);
    assert(!polaris_arena_allocate(16384,&a) && a.used==a.size);
    for(unsigned i=0;i<n;i++) {
        memset(readback,0x55,sizeof(readback));
        assert(polaris_cow_overlay(c,(uint64_t)i*4,1,readback));
        for(unsigned j=0;j<sizeof(readback);j++) assert(readback[j]==(unsigned char)(i*17));
    }
    /* With the arena full, existing dirty blocks must still be rewritable. */
    memset(input,0xa5,sizeof(input));
    assert(polaris_cow_put(c,0,1,input,polaris_arena_allocate,&a));
    assert(c->dirty_blocks==n && c->written_blocks==n+1);
    assert(polaris_cow_overlay(c,0,1,readback) && !memcmp(input,readback,sizeof(input)));
    /* Adding a new logical group fails without changing previous data. */
    c->nblocks+=4; c->limit++;
    assert(!polaris_cow_put(c,(uint64_t)n*4,1,input,polaris_arena_allocate,&a));
    assert(c->used==n && c->dirty_blocks==n && c->written_blocks==n+1);
    assert(polaris_cow_overlay(c,0,1,readback) && !memcmp(input,readback,sizeof(input)));
    size_t used=a.used;
    assert(!polaris_arena_allocate(4096,&a) && a.used==used);
    a.used=SIZE_MAX; assert(!polaris_arena_allocate(16384,&a));
    assert(!polaris_arena_allocate(16384,NULL));
    free(a.base);free(c);return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / 'test.c').write_text(source)
            subprocess.run(['cc', '-O1', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', '-I', str(ROOT / 'tools'),
                            str(p / 'test.c'), '-o', str(p / 'test')], check=True)
            subprocess.run([str(p / 'test')], check=True)


if __name__ == '__main__':
    unittest.main()
