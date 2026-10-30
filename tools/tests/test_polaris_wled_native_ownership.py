"""Execute the exact FW archive containment/map predicate, with synthetic map
metadata. Does not establish any physical mapping or load a firmware image.
"""
from pathlib import Path
import unittest
from .test_polaris_gpu_lifetime import function
from .test_polaris_gpu_bootstrap import run

ROOT=Path(__file__).resolve().parents[2]


class ArchiveOwnership(unittest.TestCase):
    def test_exact_self_image_bounds_disjoint_bank_and_every_page_owner(self):
        body=function((ROOT/'shim/polaris/uefi-wled-native.h').read_text(),'static int wln_image_owned(')
        fixture='#include "'+str(ROOT/'shim/polaris/uefi-memory.h')+'"\n'+r'''
#include <assert.h>
#include <string.h>
static uint8_t wln_archive[8192*32] __attribute__((aligned(4096)));
static struct {uint64_t bytes,stride;struct efi_memory data[2];} map_snapshot;
static unsigned wln_archive_owned;
static uint64_t ram_base=0x1000;
#define POLARIS_RAM_BASE ram_base
#define POLARIS_RAM_SIZE 4096
static int overlap(uint64_t a,uint64_t n,uint64_t b,uint64_t z)
{return n&&z&&a<b+z&&b<a+n;}
static void report(const char *name,uint64_t v){(void)name;assert(v==1);}
''' + body + r'''
int main(void) {
 uint64_t begin=(uintptr_t)wln_archive;
 struct efi_loaded good={.base=(void *)(uintptr_t)(begin-4096),.bytes=sizeof(wln_archive)+8192,
  .code_type=1,.data_type=2};
 for(unsigned bad=0;bad<12;bad++) {
  struct efi_loaded image=good;ram_base=0x1000;wln_archive_owned=0;
  map_snapshot.bytes=sizeof(map_snapshot.data);map_snapshot.stride=sizeof(struct efi_memory);
  map_snapshot.data[0]=(struct efi_memory){.type=1,.physical=begin,.pages=32};
  map_snapshot.data[1]=(struct efi_memory){.type=2,.physical=begin+32*4096,.pages=32};
  if(bad==1)image.base=0;
  if(bad==2)image.bytes=0;
  if(bad==3)image.bytes=UINT64_MAX;
  if(bad==4)image.base=(void *)(uintptr_t)(begin+4096);
  if(bad==5)image.bytes=sizeof(wln_archive);
  if(bad==6)image.code_type=7;
  if(bad==7)image.data_type=7;
  if(bad==8)ram_base=begin+4096;
  if(bad==9)map_snapshot.data[1].physical+=4096;
  if(bad==10)map_snapshot.data[1].type=7;
  if(bad==11)map_snapshot.data[1].attributes=UINT64_C(1)<<63;
  if(!bad)assert(wln_image_owned(&image)&&wln_archive_owned==1);
  else assert(!wln_image_owned(&image)&&!wln_archive_owned);
 }
 assert(!wln_image_owned(0));return 0;
}
'''
        run(fixture)
        physical=fixture.replace('.code_type=1,.data_type=2','.code_type=3,.data_type=4').replace('.type=1,','.type=3,').replace('.type=2,','.type=4,')
        run('#define EFI_XNU_WLED_NATIVE_RUNTIME_PHYSICAL 1\n'+physical)


if __name__=='__main__':unittest.main()
