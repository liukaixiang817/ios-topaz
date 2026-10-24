"""Actual request helper: I/O bypass counts and an independent byte-image model."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class RamIOTests(unittest.TestCase):
    def test_shipped_helper_matches(self):
        patch = (ROOT / 'xnu/profiles/polaris/0820-polaris-ram-io-fast-path.patch').read_text()
        header = patch.split('+++ b/bsd/dev/polaris_ram_io.h\n')[1]
        shipped = ''.join(line[1:] + '\n' for line in header.splitlines() if line.startswith('+'))
        self.assertEqual(shipped, (ROOT / 'tools/polaris-ram-io.h').read_text())

    def test_actual_helper_with_model_failures_and_sanitizers(self):
        source = r'''
#include "polaris-ram-io.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
enum { N=4096, BYTES=N*4096 };
struct base { unsigned calls; int error; uint8_t *image; };
static int allocations=-1;
static void *ram(size_t n, void *ctx) {
    (void)ctx; assert(n==16384);
    if (!allocations) return NULL;
    if (allocations>0) allocations--;
    void *p=malloc(n);assert(p);memset(p,0xa5,n);return p;
}
static int read_base(void *ctx,uint64_t physical,uint32_t blocks,void *buf) {
    struct base *b=ctx;b->calls++;
    assert(physical>=0x1000 && physical-0x1000<N && blocks<=N-(physical-0x1000));
    if(b->error) return b->error;
    memcpy(buf,b->image+(physical-0x1000)*4096,blocks*4096);return 0;
}
static void clear(struct polaris_cow *c) {
    for(unsigned i=0;i<c->used;i++)free(c->groups[i].data);
    memset(c,0,sizeof(*c));c->nblocks=N;c->limit=1024;
}
int main(void) {
    struct polaris_cow *c=calloc(1,sizeof(*c));assert(c);clear(c);
    uint8_t *base=malloc(BYTES),*model=malloc(BYTES),*bounce=malloc(1<<20),*data=malloc(1<<20);
    assert(base&&model&&bounce&&data);
    for(unsigned i=0;i<BYTES;i++)base[i]=(uint8_t)(i*13u+(i>>12));
    memcpy(model,base,BYTES);struct base b={.image=base};
    struct polaris_ram_request q={.logical=0,.physical=0x1000,.blocks=1,.bytes=4096,.data=data,.bounce=bounce};
    memset(data,0x42,4096);
    struct polaris_ram_result v=polaris_ram_io(c,&q,ram,NULL,read_base,&b);
    assert(v.status==POLARIS_RAM_OK && v.source==POLARIS_RAM_OVERWRITE && b.calls==0);
    q.read=true;memset(data,0,4096);v=polaris_ram_io(c,&q,NULL,NULL,read_base,&b);
    assert(v.status==POLARIS_RAM_OK && v.source==POLARIS_RAM_CACHED && b.calls==0);
    for(unsigned i=0;i<4096;i++)assert(data[i]==0x42);
    /* A hit on the first block plus miss on the second must copy nothing. */
    memset(bounce,0x91,8192);assert(!polaris_cow_copy_complete(c,0,2,bounce));
    for(unsigned i=0;i<8192;i++)assert(bounce[i]==0x91);
    q.read=false;q.skip=17;q.bytes=11;memset(data,0x33,11);
    v=polaris_ram_io(c,&q,ram,NULL,read_base,&b);
    assert(v.status==POLARIS_RAM_OK && v.source==POLARIS_RAM_CACHED && b.calls==0);
    q.read=true;q.skip=0;q.bytes=4096;v=polaris_ram_io(c,&q,NULL,NULL,read_base,&b);
    for(unsigned i=0;i<4096;i++)assert(data[i]==(i>=17&&i<28?0x33:0x42));
    /* Partial cold write reads/merges exactly once and retains untouched bytes. */
    q.logical=1;q.physical=0x1001;q.read=false;q.skip=4090;q.bytes=12;q.blocks=2;
    memset(data,0x66,12);v=polaris_ram_io(c,&q,ram,NULL,read_base,&b);
    assert(v.status==POLARIS_RAM_OK && v.source==POLARIS_RAM_BASE && b.calls==1);
    memcpy(model+4096+4090,data,12);
    q.read=true;q.skip=0;q.bytes=8192;v=polaris_ram_io(c,&q,NULL,NULL,read_base,&b);
    assert(v.source==POLARIS_RAM_CACHED && b.calls==1 && !memcmp(data,model+4096,8192));
    /* Failed base I/O cannot modify overlay or expose bounce/input garbage. */
    q.logical=30;q.physical=0x101e;q.blocks=1;q.bytes=19;q.skip=3;q.read=false;b.error=5;
    unsigned used=c->used;v=polaris_ram_io(c,&q,ram,NULL,read_base,&b);
    assert(v.status==POLARIS_RAM_BASE_ERROR && v.base_error==5 && c->used==used);
    assert(!polaris_cow_find(c,30/4));b.error=0;
    /* Reject spans before any base access or allocation. */
    struct polaris_ram_request valid=q;unsigned calls=b.calls;
    q.bytes=0;assert(polaris_ram_io(c,&q,ram,NULL,read_base,&b).status==POLARIS_RAM_INVALID);
    q=valid;q.blocks=257;assert(polaris_ram_io(c,&q,ram,NULL,read_base,&b).status==POLARIS_RAM_INVALID);
    q=valid;q.skip=4096;assert(polaris_ram_io(c,&q,ram,NULL,read_base,&b).status==POLARIS_RAM_INVALID);
    q=valid;q.logical=N;assert(polaris_ram_io(c,&q,ram,NULL,read_base,&b).status==POLARIS_RAM_INVALID);
    q=valid;q.blocks=2;q.physical=UINT64_MAX;assert(polaris_ram_io(c,&q,ram,NULL,read_base,&b).status==POLARIS_RAM_INVALID);
    assert(b.calls==calls);
    clear(c);c->limit=1;q=(struct polaris_ram_request){.logical=3,.physical=0x1003,.blocks=2,.bytes=8192,.data=data,.bounce=bounce};
    v=polaris_ram_io(c,&q,ram,NULL,read_base,&b);assert(v.status==POLARIS_RAM_FULL && b.calls==calls && c->used==0);
    clear(c);allocations=1;v=polaris_ram_io(c,&q,ram,NULL,read_base,&b);
    assert(v.status==POLARIS_RAM_FULL && c->used==1 && !c->groups[0].valid && b.calls==calls);
    allocations=-1;clear(c);memcpy(model,base,BYTES);uint8_t dirty[N]={0};srand(29);
    for(unsigned step=0;step<1000;step++) {
        unsigned bytes=1+rand()%65536,skip=rand()%4096,blocks=(skip+bytes+4095)/4096;
        unsigned lba=rand()%(N-blocks+1);bool read=(rand()%3)==0;
        if(step%5==0){skip=0;bytes=blocks*4096;read=false;}
        q=(struct polaris_ram_request){.logical=lba,.physical=lba+0x1000,.blocks=blocks,.skip=skip,.bytes=bytes,.read=read,.data=data,.bounce=bounce};
        bool cached=true;for(unsigned i=0;i<blocks;i++)cached&=!!dirty[lba+i];
        enum polaris_ram_source expected=!read&&!skip&&bytes==blocks*4096?POLARIS_RAM_OVERWRITE:cached?POLARIS_RAM_CACHED:POLARIS_RAM_BASE;
        calls=b.calls;memset(bounce,0xa9,blocks*4096);memset(data,(uint8_t)step,bytes);
        v=polaris_ram_io(c,&q,ram,NULL,read_base,&b);
        assert(v.status==POLARIS_RAM_OK && v.source==expected && b.calls-calls==(expected==POLARIS_RAM_BASE));
        if(read)assert(!memcmp(data,model+lba*4096+skip,bytes));
        else {memcpy(model+lba*4096+skip,data,bytes);for(unsigned i=0;i<blocks;i++)dirty[lba+i]=1;}
    }
    for(unsigned lba=0;lba<N;lba+=256){
        q=(struct polaris_ram_request){.logical=lba,.physical=lba+0x1000,.blocks=256,.bytes=1<<20,.read=true,.data=data,.bounce=bounce};
        v=polaris_ram_io(c,&q,NULL,NULL,read_base,&b);assert(v.status==POLARIS_RAM_OK);
        assert(!memcmp(data,model+lba*4096,1<<20));
    }
    for(unsigned i=0;i<BYTES;i++)assert(base[i]==(uint8_t)(i*13u+(i>>12)));
    clear(c);free(c);free(base);free(model);free(bounce);free(data);return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory)
            (p / 'io.c').write_text(source)
            subprocess.run(['/usr/bin/clang', '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                            '-I', str(ROOT / 'tools'), str(p / 'io.c'), '-o', str(p / 'io')], check=True)
            subprocess.run([str(p / 'io')], check=True)


if __name__ == '__main__':
    unittest.main()
