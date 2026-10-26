"""Real read-only EFI map validator: malformed maps and live upper-bank RAM."""
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[2]


class UEFIMemoryTests(unittest.TestCase):
 def test_real_map_bounds_overlaps_and_firmware_ownership(self):
  source=r'''
#include "uefi-memory.h"
#include <assert.h>
int main(void){struct polaris_efi_memory out={0};
 struct efi_memory m[3]={{7,0,0x180000000,0,16,0},{5,0,0x180010000,0,2,0},{2,0,0x180012000,0,4,0}};
 assert(polaris_efi_memory_check(m,sizeof(m),sizeof(m),sizeof(m[0]),&out));
 assert(out.descriptors==3&&out.conventional_pages==16&&out.upper_free_pages==16);
 assert(out.upper_live_pages==2&&out.upper_mapped_pages==22);
 assert(polaris_efi_range_owned(m,sizeof(m),40,0x180000000,0x10000,7));
 assert(!polaris_efi_range_owned(m,sizeof(m),40,0x180000000,0x16000,7));
 assert(polaris_efi_range_owned(m,sizeof(m),40,0x180012000,0x4000,2));
 assert(!polaris_efi_range_owned(m,sizeof(m),40,0x180012000,0x5000,2));
 assert(!polaris_efi_range_owned(m,sizeof(m),40,0x180000000,0,7));
 assert(!polaris_efi_range_owned(m,sizeof(m),40,UINT64_MAX-4095,8192,7));
 struct efi_memory owned[2]={{2,0,0x180008000,0,8,0},{2,0,0x180000000,0,8,0}};
 assert(polaris_efi_range_owned(owned,sizeof(owned),40,0x180000000,0x10000,2));
 owned[0].attributes=UINT64_C(0x8000000000000000);
 assert(!polaris_efi_range_owned(owned,sizeof(owned),40,0x180000000,0x10000,2));
 owned[0].attributes=0;owned[0].physical+=4096;
 assert(!polaris_efi_range_owned(owned,sizeof(owned),40,0x180000000,0x10000,2));
 assert(!polaris_efi_memory_check(0,sizeof(m),sizeof(m),40,&out));
 assert(!polaris_efi_memory_check(m,0,sizeof(m),40,&out));
 assert(!polaris_efi_memory_check(m,sizeof(m),sizeof(m)-1,40,&out));
 assert(!polaris_efi_memory_check(m,sizeof(m),sizeof(m),0,&out));
 assert(!polaris_efi_memory_check(m,sizeof(m),sizeof(m),39,&out));
 assert(!polaris_efi_memory_check(m,sizeof(m),sizeof(m),41,&out));
 assert(!polaris_efi_memory_check(m,sizeof(m),sizeof(m),8192,&out));
 m[2].physical-=4096;assert(!polaris_efi_memory_check(m,sizeof(m),sizeof(m),40,&out));m[2].physical+=4096;
 m[0].pages=0;assert(!polaris_efi_memory_check(m,sizeof(m),sizeof(m),40,&out));m[0].pages=16;
 m[2].physical++;assert(!polaris_efi_memory_check(m,sizeof(m),sizeof(m),40,&out));m[2].physical--;
 m[2].physical=UINT64_MAX-4095;m[2].pages=2;assert(!polaris_efi_memory_check(m,sizeof(m),sizeof(m),40,&out));
 struct efi_memory edge={7,0,0x17ffff000,0,2,0};
 assert(polaris_efi_memory_check(&edge,40,40,40,&out)&&out.upper_free_pages==1);
 edge.physical=0x27c89f000;assert(polaris_efi_memory_check(&edge,40,40,40,&out)&&out.upper_free_pages==1);
 edge.attributes=UINT64_C(0x8000000000000000);
 assert(polaris_efi_memory_check(&edge,40,40,40,&out)&&out.upper_free_pages==0&&out.upper_live_pages==1);
 edge.type=2;
 assert(polaris_efi_memory_check(&edge,40,40,40,&out)&&out.upper_live_pages==1);
 return 0;}
'''
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);(p/'test.c').write_text(source)
   subprocess.run(['/usr/bin/clang','-std=c11','-Wall','-Wextra','-Werror','-O1','-g',
                   '-fsanitize=address,undefined','-I',str(ROOT/'shim/polaris'),str(p/'test.c'),'-o',str(p/'test')],check=True)
   subprocess.run([str(p/'test')],check=True)


if __name__=='__main__':unittest.main()
