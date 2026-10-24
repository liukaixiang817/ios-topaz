"""A630 original HFI wire fixture and RAM ring safety; no GPU execution."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class A630HFITests(unittest.TestCase):
    def test_actual_abi_and_rings_under_sanitizers(self):
        source = r'''
#include "polaris-a630-hfi.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    assert(sizeof(struct a630_hfi_table)==168);
    assert(sizeof(struct a630_hfi_queue)==48);
    assert(offsetof(struct a630_hfi_queue,read_index)==40);
    assert(offsetof(struct a630_hfi_queue,write_index)==44);
    uint8_t *mem=malloc(A630_HFI_BYTES+16),*before=malloc(A630_HFI_BYTES+16);
    assert(mem && before);memset(mem,0xa5,A630_HFI_BYTES+16);
    memcpy(before,mem,A630_HFI_BYTES+16);
    assert(!a630_hfi_init(mem,A630_HFI_BYTES-1,0x60000000));
    assert(!a630_hfi_init(mem+1,A630_HFI_BYTES,0x60000000));
    assert(!a630_hfi_init(mem,A630_HFI_BYTES,0x60000001));
    assert(!a630_hfi_init(mem,A630_HFI_BYTES,0x5fffc000));
    assert(!a630_hfi_init(mem,A630_HFI_BYTES,0xffffc000));
    assert(!memcmp(mem,before,A630_HFI_BYTES+16));
    assert(a630_hfi_init(mem,A630_HFI_BYTES,0x60000000));
    /* Independent little-endian wire fixture derived from the original
     * polaris hfi_init: header6words, queues12words, IDs0/4/5,16Bguards. */
    const uint32_t wire[42]={0,42,6,12,3,3,
      1,0x600000a8,0xa00,1024,0,0,1,1,1,0,0,0,
      1,0x600010b8,0xa04,1024,0,0,1,1,1,0,0,0,
      1,0x600020c8,0x2805,1024,0,0,1,1,1,0,0,0};
    assert(!memcmp(mem,wire,sizeof(wire)));
    for(unsigned i=A630_HFI_BYTES;i<A630_HFI_BYTES+16;i++)assert(mem[i]==0xa5);
    struct a630_hfi_table *t=(struct a630_hfi_table *)mem;
    uint32_t message[255],out[255];
    assert(a630_hfi_header(1,2,0,0x123,&message[0]));
    assert(message[0]==0x12300201);
    uint32_t saved=message[0];
    assert(!a630_hfi_header(1,256,0,0,&message[0]));
    assert(!a630_hfi_header(1,0,0,0,&message[0]));
    assert(!a630_hfi_header(256,2,0,0,&message[0]));
    assert(!a630_hfi_header(1,2,3,0,&message[0]));
    assert(!a630_hfi_header(1,2,0,4096,&message[0]));assert(message[0]==saved);
    assert(a630_hfi_push(mem,A630_HFI_BYTES,0x60000000,message,1)==A630_HFI_PACKET);
    for(unsigned i=1;i<255;i++)message[i]=0x10000+i;
    assert(a630_hfi_header(1,255,0,7,&message[0]));
    for(unsigned i=0;i<4;i++)assert(a630_hfi_push(mem,A630_HFI_BYTES,0x60000000,message,255)==255);
    assert(t->q[0].write_index==1020);
    assert(a630_hfi_header(0,3,0,8,&message[0]));
    assert(a630_hfi_push(mem,A630_HFI_BYTES,0x60000000,message,3)==3);
    assert(t->q[0].write_index==1023);
    assert(a630_hfi_header(0,1,0,9,&message[0]));
    assert(a630_hfi_push(mem,A630_HFI_BYTES,0x60000000,message,1)==A630_HFI_FULL);
    t->q[0].read_index=100;
    assert(a630_hfi_header(1,3,0,10,&message[0]));
    assert(a630_hfi_push(mem,A630_HFI_BYTES,0x60000000,message,3)==3);
    assert(t->q[0].write_index==2);
    uint32_t *ring=(uint32_t *)(mem+a630_hfi_offset(0));
    assert(ring[1023]==message[0] && ring[0]==message[1] && ring[1]==message[2]);
    t->q[0].write_index=1024;
    assert(a630_hfi_push(mem,A630_HFI_BYTES,0x60000000,message,3)==A630_HFI_INVALID);
    t->q[0].write_index=2;t->q[0].start_addr++;
    assert(a630_hfi_push(mem,A630_HFI_BYTES,0x60000000,message,3)==A630_HFI_INVALID);
    t->q[0].start_addr--;
    for(unsigned q=1;q<=2;q++) {
        assert(a630_hfi_pop(mem,A630_HFI_BYTES,0x60000000,q,out,255)==0);
        struct a630_hfi_queue *desc=&t->q[q];
        ring=(uint32_t *)(mem+a630_hfi_offset(q));
        desc->read_index=1023;desc->write_index=2;
        assert(a630_hfi_header(126,3,2,0xabc,&ring[1023]));
        ring[0]=0x12300201;ring[1]=0;
        assert(a630_hfi_pop(mem,A630_HFI_BYTES,0x60000000,q,out,2)==A630_HFI_OUTPUT);
        assert(desc->read_index==1023);
        assert(a630_hfi_pop(mem,A630_HFI_BYTES,0x60000000,q,out,255)==3);
        assert(out[0]==0xabc2037e && out[1]==0x12300201 && out[2]==0);
        assert(desc->read_index==2);
        desc->read_index=0;desc->write_index=2;
        ring[0]=3u<<8;
        assert(a630_hfi_pop(mem,A630_HFI_BYTES,0x60000000,q,out,255)==A630_HFI_PACKET);
        ring[0]=0;
        assert(a630_hfi_pop(mem,A630_HFI_BYTES,0x60000000,q,out,255)==A630_HFI_PACKET);
        ring[0]=(15u<<16)|(1u<<8);
        assert(a630_hfi_pop(mem,A630_HFI_BYTES,0x60000000,q,out,255)==A630_HFI_PACKET);
        assert(desc->read_index==0);
        desc->read_index=1024;
        assert(a630_hfi_pop(mem,A630_HFI_BYTES,0x60000000,q,out,255)==A630_HFI_INVALID);
        desc->read_index=0;desc->queue_size=0xffffffff;
        assert(a630_hfi_pop(mem,A630_HFI_BYTES,0x60000000,q,out,255)==A630_HFI_INVALID);
        desc->queue_size=1024;
    }
    assert(a630_hfi_pop(mem,A630_HFI_BYTES,0x60000000,0,out,255)==A630_HFI_INVALID);
    assert(a630_hfi_pop(mem,A630_HFI_BYTES,0x60000000,3,out,255)==A630_HFI_INVALID);
    for(unsigned q=0;q<3;q++) {
        unsigned guard=a630_hfi_offset(q)+4096;
        for(unsigned n=0;n<16;n++)assert(mem[guard+n]==0);
    }
    for(unsigned i=A630_HFI_BYTES;i<A630_HFI_BYTES+16;i++)assert(mem[i]==0xa5);
    assert(a630_hfi_init(mem,A630_HFI_BYTES,0x7fffc000));
    free(mem);free(before);return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / 'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang', '-std=c11', '-O1', '-g',
                            '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                            '-I', str(ROOT / 'tools'), str(p / 'test.c'), '-o', str(p / 'test')], check=True)
            subprocess.run([str(p / 'test')], check=True)


if __name__ == '__main__':
    unittest.main()
