"""The host-loss recovery lease is opt-in to the running RAM kernel only."""
from pathlib import Path
import subprocess
import tempfile
import unittest


class RamLease(unittest.TestCase):
    def test_boundary_activity_once_invalid_clock_and_wrap(self):
        root=Path(__file__).resolve().parents[2]
        code=r'''
#include "uefi-ram-lease.h"
#include <assert.h>
int main(void){
 struct polaris_efi_ram_lease l={0};
 assert(!polaris_efi_ram_lease_expired(&l,UINT64_MAX,1));
 polaris_efi_ram_lease_activity(&l,12);assert(!l.active&&!l.last);
 l=(struct polaris_efi_ram_lease){.last=100,.active=1};
 assert(!polaris_efi_ram_lease_expired(&l,UINT64_MAX,0));
 assert(!polaris_efi_ram_lease_expired(&l,UINT64_MAX,UINT64_MAX));
 assert(!polaris_efi_ram_lease_expired(&l,100+1800*1000-1,1000));
 polaris_efi_ram_lease_activity(&l,100+1200*1000);
 assert(!polaris_efi_ram_lease_expired(&l,100+1800*1000,1000));
 assert(polaris_efi_ram_lease_expired(&l,100+3000*1000,1000));
 assert(!polaris_efi_ram_lease_expired(&l,100+4000*1000,1000));
 polaris_efi_ram_lease_activity(&l,100+4000*1000);
 assert(!polaris_efi_ram_lease_expired(&l,100+4000*1000,1000));
 l=(struct polaris_efi_ram_lease){.last=UINT64_MAX-100,.active=1};
 assert(!polaris_efi_ram_lease_expired(&l,100,1));
 assert(polaris_efi_ram_lease_expired(&l,1700,1));
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            source=Path(d)/'lease.c';exe=Path(d)/'lease';source.write_text(code)
            subprocess.run(['/usr/bin/clang','-std=c11','-Wall','-Wextra','-Werror',
                            '-fsanitize=address,undefined','-I'+str(root/'shim/polaris'),str(source),'-o',str(exe)],check=True)
            subprocess.run([str(exe)],check=True)


if __name__=='__main__':unittest.main()
