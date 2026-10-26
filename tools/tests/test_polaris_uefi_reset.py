"""Check the restricted PM8998 restart marker before hardware reset trials."""
from pathlib import Path
import subprocess
import tempfile
import unittest


class ResetMarker(unittest.TestCase):
    def test_mode_bits_readback_and_failure_rollback(self):
        root=Path(__file__).resolve().parents[2]
        source=r'''
#include "uefi-reset.h"
#include <assert.h>
static unsigned reads,writes,fail_read,fail_write,ignore_write;
static uint8_t reg;
static efi_status get(uint32_t device,uint32_t spare,uint8_t *value){
 assert(device==0&&spare==3);reads++;if(reads==fail_read)return EFI_ERROR|7;
 *value=reg;return 0;
}
static efi_status set(uint32_t device,uint32_t spare,uint8_t value,uint8_t mask){
 assert(device==0&&spare==3&&mask==0xfe);writes++;
 if(writes!=ignore_write)reg=(reg&~mask)|(value&mask);
 return writes==fail_write?EFI_ERROR|7:0;
}
static void init(uint8_t value){reg=value;reads=writes=fail_read=fail_write=ignore_write=0;}
int main(void){
 struct polaris_efi_pon p={0x10001,get,set};struct polaris_efi_reset_marker r;
 for(unsigned bit=0;bit<2;bit++){
  init(0xa0|bit);assert(polaris_efi_pon_marker(&p,2,&r));assert(reg==(4|bit));
  assert(reads==2&&writes==1&&r.before==(0xa0|bit)&&r.after==reg);
  assert(polaris_efi_pon_marker(&p,1,&r));assert(reg==(0x44|bit));
 }
 init(0x89);assert(!polaris_efi_pon_marker(&p,0,&r));assert(!reads&&!writes&&reg==0x89);
 assert(!polaris_efi_pon_marker(0,2,&r));p.revision=0x10002;
 assert(!polaris_efi_pon_marker(&p,2,&r));assert(!reads&&!writes);p.revision=0x10001;
 fail_read=1;assert(!polaris_efi_pon_marker(&p,2,&r));assert(!writes&&reg==0x89);
 init(0x89);fail_write=1;assert(!polaris_efi_pon_marker(&p,2,&r));assert(writes==2&&reg==0x89&&!r.restore_status);
 init(0x89);fail_read=2;assert(!polaris_efi_pon_marker(&p,2,&r));assert(writes==2&&reg==0x89);
 init(0x89);ignore_write=1;assert(!polaris_efi_pon_marker(&p,2,&r));assert(writes==2&&reg==0x89);
 init(0x89);ignore_write=1;fail_write=2;assert(!polaris_efi_pon_marker(&p,2,&r));assert(r.restore_status==(EFI_ERROR|7));
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            c=Path(d)/'marker.c';exe=Path(d)/'marker';c.write_text(source)
            subprocess.run(['/usr/bin/clang','-std=c11','-Wall','-Wextra','-Werror',
                            '-fsanitize=address,undefined','-I'+str(root/'shim/polaris'),
                            str(c),'-o',str(exe)],check=True)
            subprocess.run([str(exe)],check=True)


if __name__=='__main__':unittest.main()
