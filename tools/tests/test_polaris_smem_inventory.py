"""Bounded original SMEM metadata snapshots; no remote DSP or hardware access."""
from pathlib import Path
import subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[2]


class SmemInventory(unittest.TestCase):
    def test_bounds_host_isolation_snapshot_races_and_read_failures(self):
        source=r'''
#include "polaris-smem-inventory.h"
#include <assert.h>
#include <string.h>
static uint8_t data[65536];static unsigned calls,deny,race,forbidden,change_after_first_partition;
static void put(uint32_t o,uint32_t v){for(unsigned n=0;n<4;n++)data[o+n]=(uint8_t)(v>>(n*8));}
static bool read_only(void*c,uint32_t o,void*out,size_t n){assert(c==data);calls++;
 assert(o<=sizeof(data)&&n<=sizeof(data)-o);if(o==32768){forbidden++;return false;} /* denied remote-only partition */
 if(calls==deny)return false;
 if(change_after_first_partition && calls==7)put(12288+12,64);
 memcpy(out,data+o,n);
 if(race&&calls==race)((uint8_t*)out)[0]^=1;
 return true;}
static void part(unsigned i,uint32_t offset,uint32_t bytes,uint32_t hosts){
 unsigned t=65536-4096+32+i*48;put(t,offset);put(t+4,bytes);put(t+12,hosts);put(t+16,64);
 put(offset,0x54525024);put(offset+4,hosts);put(offset+8,bytes);put(offset+12,32);put(offset+16,bytes);}
static void setup(void){memset(data,0,sizeof(data));calls=deny=race=forbidden=change_after_first_partition=0;
 put(92,0xc0000);put(192,1);put(65536-4096,0x434f5424);put(65536-4092,1);put(65536-4088,3);
 part(0,12288,4096,0xfffefffe);part(1,20480,4096,0x00020000);part(2,32768,4096,0x00030001);}
int main(void){static struct polaris_smem_workspace work;struct polaris_smem_inventory out,sentinel;memset(&sentinel,0xa5,sizeof(sentinel));
 struct polaris_smem_reader r={read_only,data,sizeof(data)};setup();
 assert(polaris_smem_inventory(&r,&out,&work));assert(out.version==0xc0000&&out.count==3&&out.accessible_count==2&&out.common_index==0);
 assert(out.parts[1].offset==20480&&out.parts[1].host1==2&&out.parts[1].accessible);
 assert(!out.parts[2].accessible);assert(!forbidden);unsigned operations=calls;uint8_t baseline[sizeof(data)];memcpy(baseline,data,sizeof(data));
 for(unsigned n=1;n<=operations;n++){setup();deny=n;out=sentinel;assert(!polaris_smem_inventory(&r,&out,&work));assert(!memcmp(&out,&sentinel,sizeof(out)));assert(!memcmp(data,baseline,sizeof(data)));}
 for(unsigned n=3;n<=operations;n++){setup();race=n;out=sentinel;assert(!polaris_smem_inventory(&r,&out,&work));assert(!memcmp(&out,&sentinel,sizeof(out)));}
 setup();change_after_first_partition=1;out=sentinel;assert(!polaris_smem_inventory(&r,&out,&work));assert(!memcmp(&out,&sentinel,sizeof(out)));
 setup();put(65536-4096+32+48+12,10u<<16);assert(!polaris_smem_inventory(&r,&out,&work));
 setup();put(65536-4096+32+48,8192);assert(!polaris_smem_inventory(&r,&out,&work)); /* legacy TOC is not a partition */
 setup();put(92,0xb0000);assert(polaris_smem_inventory(&r,&out,&work));
 setup();put(65536-4088,PSM_MAX_PARTS+1);assert(!polaris_smem_inventory(&r,&out,&work));
 setup();put(65536-4096+32+48,0xfffffff0);assert(!polaris_smem_inventory(&r,&out,&work));
 setup();put(65536-4096+32+48,4096);assert(!polaris_smem_inventory(&r,&out,&work));
 setup();put(20480+12,4097);assert(!polaris_smem_inventory(&r,&out,&work));
 setup();put(20480+16,16);assert(!polaris_smem_inventory(&r,&out,&work));
 setup();put(65536-4096+32+16,48);assert(!polaris_smem_inventory(&r,&out,&work));
 setup();put(12288+4,0x00020000);assert(!polaris_smem_inventory(&r,&out,&work));
 setup();put(65536-4096+32+12,0x00030001);assert(!polaris_smem_inventory(&r,&out,&work)); /* v12 no common */
 setup();uint32_t before=calls;r.bytes=1024;assert(!polaris_smem_inventory(&r,&out,&work)&&calls==before);r.bytes=sizeof(data);
 unsigned seed=13;
 for(unsigned n=0;n<10000;n++){
  setup();seed=seed*1664525u+1013904223u;unsigned off=(seed&1)?(65536-4096+seed%200):(12288+seed%32);
  data[off]^=1u<<((seed>>16)&7);out=sentinel;bool ok=polaris_smem_inventory(&r,&out,&work);
  if(ok) {for(unsigned i=0;i<out.count;i++)if(out.parts[i].bytes){assert(out.parts[i].offset<=61440&&out.parts[i].bytes<=61440-out.parts[i].offset);}}
  else {assert(!memcmp(&out,&sentinel,sizeof(out)));}
 }
 return 0;}
'''
        with tempfile.TemporaryDirectory() as directory:
            d=Path(directory);(d/'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(ROOT/'tools'),str(d/'test.c'),'-o',str(d/'test')],check=True)
            subprocess.run([str(d/'test')],check=True)


if __name__=='__main__':unittest.main()
