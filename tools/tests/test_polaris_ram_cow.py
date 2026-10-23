"""Actual overlay code: immutable base, fragmented writes, bounds and ENOSPC."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class RamCowTests(unittest.TestCase):
    def test_patch_header_matches(self):
        text = (ROOT / 'xnu/profiles/polaris/0804-polaris-volatile-root-writes.patch').read_text()
        section = text.split('+++ b/bsd/dev/polaris_ram_cow.h\n')[1].split('--- a/')[0]
        shipped = '\n'.join(s[1:] for s in section.splitlines() if s.startswith('+')) + '\n'
        self.assertEqual(shipped, (ROOT / 'tools/polaris-ram-cow.h').read_text())

    def test_actual_c_overlay(self):
        source = r'''
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "polaris-ram-cow.h"
static int budget=-1;
static void *ram(size_t n, void *ctx) {
    (void)ctx; assert(n==16384);
    if(!budget)return NULL;
    if(budget>0)budget--;
    void *p=malloc(n);assert(p);memset(p,0xa5,n);return p;
}
static void clear(struct polaris_cow *c) {
    for(unsigned i=0;i<c->used;i++)free(c->groups[i].data);
    memset(c,0,sizeof(*c));
}
int main(void) {
    struct polaris_cow *c=calloc(1,sizeof(*c));assert(c);
    uint8_t *buf=malloc(1<<20),*input=malloc(1<<20);assert(buf&&input);
    memset(input,0x42,1<<20);c->nblocks=8192;c->limit=2;
    assert(polaris_cow_put(c,3,2,input,ram,NULL));assert(c->used==2);
    memset(buf,0x10,8*4096);assert(polaris_cow_overlay(c,0,8,buf));
    for(unsigned i=0;i<8*4096;i++)assert(buf[i]==(i/4096==3||i/4096==4?0x42:0x10));
    memset(input,0x33,1<<20);
    assert(!polaris_cow_put(c,7,2,input,ram,NULL)); /* would exceed limit */
    memset(buf,0x10,8*4096);assert(polaris_cow_overlay(c,0,8,buf));
    assert(buf[7*4096]==0x10 && buf[4*4096]==0x42);
    for(unsigned n=0;n<258;n++) if(!n||n>256) {
        assert(!polaris_cow_put(c,0,n,input,ram,NULL));
        assert(!polaris_cow_overlay(c,0,n,buf));
    }
    assert(!polaris_cow_put(c,8192,1,input,ram,NULL));
    assert(!polaris_cow_put(c,UINT64_MAX,1,input,ram,NULL));
    assert(!polaris_cow_put(c,8191,2,input,ram,NULL));
    assert(!polaris_cow_put(c,0,1,NULL,ram,NULL));
    assert(!polaris_cow_put(c,0,1,input,NULL,NULL));
    clear(c);c->nblocks=8192;c->limit=8;budget=1;
    assert(!polaris_cow_put(c,3,2,input,ram,NULL));assert(c->used==1);
    memset(buf,0x10,8*4096);assert(polaris_cow_overlay(c,0,8,buf));
    for(unsigned i=0;i<8*4096;i++)assert(buf[i]==0x10); /* uninitialized RAM hidden */
    budget=-1;assert(polaris_cow_put(c,3,2,input,ram,NULL));
    assert(c->used==2);clear(c);
    /* Compare randomized overlapping writes/readbacks to an independent full
     * image model. Base bytes never change. Cross hash bucket boundaries too. */
    const unsigned size=8192*4096u;
    uint8_t *base=malloc(size),*model=malloc(size);assert(base&&model);
    for(unsigned i=0;i<size;i++)base[i]=(uint8_t)(i*17u+(i>>12));
    memcpy(model,base,size);c->nblocks=8192;c->limit=8192;srand(19);
    for(unsigned step=0;step<500;step++) {
        unsigned n=1+rand()%256,lba=rand()%(8192-n+1),bytes=n*4096;
        memset(input,(uint8_t)step,bytes);
        assert(polaris_cow_put(c,lba,n,input,ram,NULL));
        memcpy(model+lba*4096,input,bytes);
        lba=rand()%(8192-n+1);memcpy(buf,base+lba*4096,bytes);
        assert(polaris_cow_overlay(c,lba,n,buf));assert(!memcmp(buf,model+lba*4096,bytes));
    }
    for(unsigned lba=0;lba<8192;lba+=256) {
        memcpy(buf,base+lba*4096,1<<20);assert(polaris_cow_overlay(c,lba,256,buf));
        assert(!memcmp(buf,model+lba*4096,1<<20));
    }
    for(unsigned i=0;i<size;i++)assert(base[i]==(uint8_t)(i*17u+(i>>12)));
    clear(c);free(c);free(base);free(model);free(buf);free(input);return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p/'test.c').write_text(source)
            subprocess.run(['cc', '-O1', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', '-I', str(ROOT/'tools'),
                            str(p/'test.c'), '-o', str(p/'test')], check=True)
            subprocess.run([str(p/'test')], check=True)


if __name__ == '__main__': unittest.main()
