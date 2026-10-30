"""Own legacy SMEM allocation wire fixtures; no radio, firmware or device I/O."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = r'''
#include "polaris-glink-inventory.h"
#include <assert.h>
#include <string.h>
static uint8_t memory[65536];
static uint32_t calls,deny,race,forbidden;
static struct polaris_glink_workspace work;
static const uint32_t part=20480,span=32768,toc=61440;
static void put(uint32_t at,uint32_t value) {
 for(unsigned n=0;n<4;n++)memory[at+n]=(uint8_t)(value>>(8*n));
}
static void partition(uint32_t i,uint32_t at,uint32_t size,uint32_t hosts) {
 uint32_t t=toc+32+48*i;put(t,at);put(t+4,size);put(t+12,hosts);put(t+16,64);
 put(at,0x54525024);put(at+4,hosts);put(at+8,size);put(at+12,32);put(at+16,size);
}
static void entry(uint32_t at,uint32_t id,uint32_t size,uint32_t padding,uint32_t header_padding) {
 put(at,0xa5a5|(id<<16));put(at+4,size);put(at+8,padding|(header_padding<<16));
}
static void setup(void) {
 memset(memory,0,sizeof(memory));calls=deny=race=forbidden=0;
 put(92,0xc0000);put(192,1);put(toc,0x434f5424);put(toc+4,1);put(toc+8,3);
 partition(0,12288,4096,0xfffefffe);partition(1,part,span,0x00020000);
 partition(2,57344,2048,0x00030001);
 entry(part+32,478,32,0,0);entry(part+80,479,256,0,0);
 put(part+12,352);put(part+16,span-64-512);
 entry(part+span-64,480,512,0,48);
 /* Payloads deliberately contain invalid-header-looking bytes. The reader
  * below denies every payload read, so success cannot inspect a FIFO. */
 memset(memory+part+48,0x5a,32);memset(memory+part+96,0x6b,256);
 memset(memory+part+span-64-512,0x7c,512);
}
static bool metadata_read(void *context,uint32_t at,void *out,size_t n) {
 assert(context==memory);calls++;
 assert(at<=sizeof(memory)&&n<=sizeof(memory)-at);
 bool allowed=(at==0&&n==208)||(at>=toc&&n<=sizeof(memory)-at)||
   ((at==12288||at==part)&&n==32)||
   ((at==part+32||at==part+80||at==part+span-64||at==part+span-640)&&n==16);
 if(!allowed){forbidden++;return false;}
 if(calls==deny)return false;
 memcpy(out,memory+at,n);
 if(race&&at==part+32){memory[part+32+15]^=1;race=0;}
 return true;
}
int main(void) {
 struct polaris_smem_reader r={metadata_read,memory,sizeof(memory)};
 struct polaris_glink_layout out,sentinel;memset(&sentinel,0xa5,sizeof(sentinel));
 setup();assert(polaris_glink_inventory(&r,2,&out,&work));
 assert(out.remote==2&&out.partition==part&&out.partition_bytes==span&&out.headers==3);
 assert(out.descriptor.offset==part+48&&out.descriptor.bytes==32&&!out.descriptor.cached);
 assert(out.tx.offset==part+96&&out.tx.bytes==256&&!out.tx.cached);
 assert(out.rx.offset==part+span-576&&out.rx.bytes==512&&out.rx.cached);
 assert(!forbidden);unsigned operations=calls;uint8_t baseline[sizeof(memory)];memcpy(baseline,memory,sizeof(memory));
 for(unsigned i=1;i<=operations;i++) {
  setup();deny=i;out=sentinel;assert(!polaris_glink_inventory(&r,2,&out,&work));
  assert(!memcmp(&out,&sentinel,sizeof(out)));assert(!memcmp(memory,baseline,sizeof(memory)));
 }
 setup();race=1;out=sentinel;assert(!polaris_glink_inventory(&r,2,&out,&work));assert(!memcmp(&out,&sentinel,sizeof(out)));
 setup();assert(!polaris_glink_inventory(&r,0,&out,&work)&&!calls);
 assert(!polaris_glink_inventory(&r,10,&out,&work)&&!calls);
 assert(!polaris_glink_inventory(&r,3,&out,&work));assert(!forbidden); /* No APPS/3 allocation. */
 setup();put(part+80,0xa5a5|(478u<<16));assert(!polaris_glink_inventory(&r,2,&out,&work)); /* duplicate */
 setup();put(part+32+4,0xfffffff8u);assert(!polaris_glink_inventory(&r,2,&out,&work));
 setup();put(part+32+8,32);assert(!polaris_glink_inventory(&r,2,&out,&work));
 setup();put(part+32+8,1u<<16);assert(!polaris_glink_inventory(&r,2,&out,&work));
 setup();put(part+32+4,24);assert(!polaris_glink_inventory(&r,2,&out,&work));
 setup();put(part+12,353);assert(!polaris_glink_inventory(&r,2,&out,&work));
 setup();put(part+span-64+8,49u<<16);assert(!polaris_glink_inventory(&r,2,&out,&work));
 setup();put(part+span-64+4,span);assert(!polaris_glink_inventory(&r,2,&out,&work));
 setup();put(toc+32+48+8,1);assert(!polaris_glink_inventory(&r,2,&out,&work));
 setup();put(toc+32+48+32,64);assert(!polaris_glink_inventory(&r,2,&out,&work));
 /* Cached FIFO takes precedence over its separate uncached allocation, just
  * as own get_rx_fifo. Descriptor is always the uncached allocation. */
 setup();entry(part+span-640,479,128,0,48);put(part+16,span-768);
 assert(polaris_glink_inventory(&r,2,&out,&work));assert(out.tx.cached&&out.tx.bytes==128&&out.headers==4);
 setup();entry(part+span-640,478,128,0,48);put(part+16,span-768);
 assert(!polaris_glink_inventory(&r,2,&out,&work));
 uint32_t seed=19;
 for(unsigned i=0;i<10000;i++) {
  setup();seed=seed*1664525u+1013904223u;
  unsigned h=(seed>>8)%3,offsets[3]={part+32,part+80,part+span-64};
  uint32_t at=offsets[h]+(seed%16);memory[at]^=(uint8_t)(1u<<((seed>>16)&7));
  out=sentinel;bool ok=polaris_glink_inventory(&r,2,&out,&work);
  if(!ok)assert(!memcmp(&out,&sentinel,sizeof(out)));
  else {assert(out.descriptor.bytes==32);const struct polaris_glink_item *v[3]={&out.descriptor,&out.tx,&out.rx};
   for(unsigned j=0;j<3;j++)assert(v[j]->offset>=part+32&&v[j]->offset<=part+span&&v[j]->bytes<=part+span-v[j]->offset);
   assert(!forbidden);}
 }
 return 0;
}
'''


class GlinkInventory(unittest.TestCase):
    def test_real_wire_bounds_fallback_and_metadata_only_reads(self):
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            (d / 'test.c').write_text(SOURCE)
            subprocess.run(['/usr/bin/clang', '-std=c11', '-O1', '-g', '-Wall',
                            '-Wextra', '-Werror', '-fsanitize=address,undefined',
                            '-I' + str(ROOT / 'tools'), str(d / 'test.c'), '-o', str(d / 'test')], check=True)
            subprocess.run([str(d / 'test')], check=True)

    def test_aarch64_freestanding_caller_owned_workspace(self):
        with tempfile.TemporaryDirectory() as directory:
            d = Path(directory)
            (d / 'test.c').write_text('#include "polaris-glink-inventory.h"\n'
                'bool inspect(const struct polaris_smem_reader *r, unsigned h, '
                'struct polaris_glink_layout *o, struct polaris_glink_workspace *w) '
                '{ return polaris_glink_inventory(r,h,o,w); }\n')
            subprocess.run(['/usr/bin/clang', '-target', 'aarch64-none-elf', '-ffreestanding',
                            '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wframe-larger-than=1024',
                            '-I' + str(ROOT / 'tools'), '-c', str(d / 'test.c'), '-o', str(d / 'test.o')], check=True)


if __name__ == '__main__':
    unittest.main()
