"""Independent SMMUv2 walk/permission/ownership fixtures, no hardware access."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class A630MMUTests(unittest.TestCase):
    def test_tables_boundaries_and_atomic_refusals(self):
        source = r'''
#include "polaris-a630-mmu.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
static void inspect(const uint64_t *pool, uint64_t root_pa, uint64_t va, uint64_t want, uint64_t attributes) {
 /* Independently use literal architectural indices/descriptor bits. */
 uint64_t a=pool[(va/0x40000000)&511];assert((a&3)==3);
 uint64_t pa=a&0x0000000ffffff000ull;assert(pa>=root_pa&&pa-root_pa<0x20000);
 const uint64_t *b=pool+(pa-root_pa)/8;
 a=b[(va/0x200000)&511];assert((a&3)==3);
 pa=a&0x0000000ffffff000ull;assert(pa>=root_pa&&pa-root_pa<0x20000);
 b=pool+(pa-root_pa)/8;a=b[(va/0x1000)&511];
 assert(a==(want|attributes));
}
int main(void) {
 void *allocation=aligned_alloc(4096,32*4096);assert(allocation);
 uint64_t *pool=allocation;struct a630_mmu s;uint64_t pa=0,entry=0;
 assert(!a630_mmu_init(0,pool,0x180000000,32));
 assert(!a630_mmu_init(&s,(char*)pool+8,0x180000000,32));
 assert(!a630_mmu_init(&s,pool,0x180000001,32));
 assert(!a630_mmu_init(&s,pool,0xfffffff000,32));
 assert(!a630_mmu_init(&s,pool,0x180000000,33));
 assert(a630_mmu_init(&s,pool,0x180000000,32));
 assert(a630_mmu_lookup(&s,0x60000000,&pa,&entry)==A630_MMU_UNMAPPED);
 assert(a630_mmu_map(&s,0x60000001,0x190000000,0)==A630_MMU_ARGUMENT);
 assert(a630_mmu_map(&s,0x60000000,0x190000001,0)==A630_MMU_ARGUMENT);
 assert(a630_mmu_map(&s,1ull<<39,0x190000000,0)==A630_MMU_ARGUMENT);
 assert(a630_mmu_map(&s,0x60000000,1ull<<36,0)==A630_MMU_ARGUMENT);
 assert(a630_mmu_map(&s,0x60000000,0x180000000,0)==A630_MMU_ARGUMENT);
 assert(a630_mmu_map(&s,0x60000000,0x190000000,16)==A630_MMU_ARGUMENT);
 assert(s.used==1&&s.dirty==1&&!pool[1]);
 /* HFI16KiB: four 4KiB pages in a 16KiB CPU allocation. */
 for(unsigned n=0;n<4;n++)assert(!a630_mmu_map(&s,0x60000000+4096*n,0x190000000ull+4096*n,0));
 assert(s.used==3&&s.dirty==7);
 inspect(pool,0x180000000,0x60000000,0x190000000,0x60000000000e03ull);
 for(unsigned n=0;n<16384;n+=127) {
  assert(!a630_mmu_lookup(&s,0x60000000+n,&pa,&entry));assert(pa==0x190000000ull+n);
 }
 assert(a630_mmu_lookup(&s,0x60004000,&pa,&entry)==A630_MMU_UNMAPPED);
 uint64_t saved[32*512];memcpy(saved,pool,sizeof(saved));unsigned used=s.used;
 assert(a630_mmu_map(&s,0x60000000,0x190004000,0)==A630_MMU_CONFLICT);
 assert(s.used==used&&!memcmp(pool,saved,sizeof(saved)));
 assert(!a630_mmu_map(&s,0x60000000,0x190000000,0));assert(s.used==used);
 /* 2MiB/1GiB/39-bit edges, including a physical page above4GiB. */
 const uint64_t va[]={0,0x1ff000,0x200000,0x3ffff000,0x40000000,0x7ffffff000};
 for(unsigned n=0;n<6;n++) {
  uint64_t physical=0x200000000ull+n*4096;
  assert(!a630_mmu_map(&s,va[n],physical,A630_MMU_CACHED|A630_MMU_USER|A630_MMU_READONLY|A630_MMU_EXEC));
  inspect(pool,0x180000000,va[n],physical,0xec7);
  assert(!a630_mmu_lookup(&s,va[n]+4095,&pa,&entry)&&pa==physical+4095);
 }
 /* Full pool never leaves half a newly linked hierarchy. */
 assert(a630_mmu_init(&s,pool,0x180000000,2));memcpy(saved,pool,sizeof(saved));
 assert(a630_mmu_map(&s,0x60000000,0x190000000,0)==A630_MMU_FULL);
 assert(s.used==1&&s.dirty==1&&!memcmp(pool,saved,2*4096));
 assert(a630_mmu_init(&s,pool,0x180000000,3));
 assert(!a630_mmu_map(&s,0x60000000,0x190000000,0));memcpy(saved,pool,3*4096);
 assert(a630_mmu_map(&s,0x80000000,0x190004000,0)==A630_MMU_FULL);
 assert(s.used==3&&!memcmp(pool,saved,3*4096));
 /* Reject corrupt, external, recursive and wrong-level table pointers. */
 for(unsigned n=0;n<5;n++) {
  assert(a630_mmu_init(&s,pool,0x180000000,32));
  assert(!a630_mmu_map(&s,0x60000000,0x190000000,0));
  pool[1]=n==0?0x180000001ull:n==1?0x190000003ull:n==2?0x180000003ull:
          n==3?0x180002003ull:0x180001007ull;
  assert(a630_mmu_lookup(&s,0x60000000,&pa,&entry)==A630_MMU_CORRUPT);
  assert(a630_mmu_map(&s,0x60004000,0x190004000,0)==A630_MMU_CORRUPT);
 }
 free(allocation);return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory)
            (p / 'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang', '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', '-I', str(ROOT / 'tools'),
                            str(p / 'test.c'), '-o', str(p / 'test')], check=True)
            subprocess.run([str(p / 'test')], check=True)


if __name__ == '__main__':
    unittest.main()
