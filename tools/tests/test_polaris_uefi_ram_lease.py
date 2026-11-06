"""The host-loss recovery lease is opt-in to the running RAM kernel only."""
from pathlib import Path
import subprocess
import tempfile
import unittest


class RamLease(unittest.TestCase):
    def test_physical_default_never_expires_even_after_long_idle(self):
        root=Path(__file__).resolve().parents[2]
        code=r'''
#include "uefi-ram-lease.h"
#include <assert.h>
int main(void){
 struct polaris_efi_ram_lease l={.last=123,.active=1};
 const uint64_t times[]={0,123,1800,3600,86400,UINT64_MAX};
 const uint64_t frequencies[]={0,1,19200000,UINT64_MAX};
 assert(POLARIS_RAM_LEASE_SECONDS==0);
 for(unsigned t=0;t<6;t++)for(unsigned f=0;f<4;f++){
  assert(!polaris_efi_ram_lease_expired(&l,times[t],frequencies[f]));
  assert(l.active==1&&l.last==123&&!l.fired);
 }
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            source=Path(d)/'idle.c';exe=Path(d)/'idle';source.write_text(code)
            subprocess.run(['/usr/bin/clang','-std=c11','-Wall','-Wextra','-Werror',
                            '-fsanitize=address,undefined','-I'+str(root/'shim/polaris'),str(source),'-o',str(exe)],check=True)
            subprocess.run([str(exe)],check=True)

    def test_actual_idle_guard_polls_without_any_reset_dependency(self):
        root=Path(__file__).resolve().parents[2]
        source=(root/'shim/polaris/uefi-xnu.c').read_text()
        start=source.index('static void idle_guard(void *context)')
        end=source.index('\n#if EFI_XNU_GCD_MMIO_QUERY_AVAILABLE',start)
        actual=source[start:end]
        peer='''#include <assert.h>
#define POLARIS_RAM_LEASE_SECONDS 0
#define EFI_XNU_WLED_NATIVE_RUNTIME 1
static unsigned polls;
static void wln_poll(void){polls++;}
'''
        with tempfile.TemporaryDirectory() as d:
            src=Path(d)/'guard.c';exe=Path(d)/'guard'
            src.write_text(peer+actual+'\nint main(void){for(unsigned n=0;n<10000;n++)idle_guard(0);assert(polls==10000);return 0;}\n')
            subprocess.run(['/usr/bin/clang','-std=c11','-Wall','-Wextra','-Werror',
                            '-fsanitize=address,undefined',str(src),'-o',str(exe)],check=True)
            subprocess.run([str(exe)],check=True)

    def test_boundary_activity_once_invalid_clock_and_wrap(self):
        root=Path(__file__).resolve().parents[2]
        code=r'''
#define POLARIS_RAM_LEASE_SECONDS 1800u
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
