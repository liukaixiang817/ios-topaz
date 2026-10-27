import subprocess
import tempfile
from pathlib import Path
import unittest


class UEFICoreAdmission(unittest.TestCase):
    def test_single_declared_kernel_core_and_actual_affinity(self):
        root=Path(__file__).resolve().parents[2]
        source=r'''
#include "polaris-uefi-cpu.h"
#include <assert.h>
int main(void) {
 assert(polaris_uefi_cpu_allowed(1,0x100,1,0,0x100,0x81000100));
 assert(polaris_uefi_cpu_allowed(1,1,1,0,1,0x80000001));
 assert(polaris_uefi_cpu_allowed(1,0x700,1,0,0x700,0x81000700));
 assert(polaris_uefi_cpu_allowed(1,7,1,0,7,0x80000007));
 assert(!polaris_uefi_cpu_allowed(1,0x700,1,0,0x100,0x81000700));
 assert(!polaris_uefi_cpu_allowed(1,0x700,1,0,0x700,0x81000100));
 assert(polaris_uefi_cpu_allowed(1,0x700,2,0,0x700,0x81000700));
 assert(polaris_uefi_cpu_declared(1,0x700,2,1,0x600));
 assert(polaris_uefi_cpu_declared(1,7,2,1,6));
 assert(!polaris_uefi_cpu_declared(1,0x700,2,1,0));
 assert(!polaris_uefi_cpu_declared(1,0x700,2,1,0x100));
 assert(!polaris_uefi_cpu_declared(1,0x700,2,1,0x700));
 assert(!polaris_uefi_cpu_declared(1,0x100,2,1,0x200));
 assert(!polaris_uefi_cpu_allowed(1,0x700,2,1,0x600,0x81000600));
 assert(!polaris_uefi_cpu_allowed(1,0x700,3,0,0x700,0x81000700));
 assert(!polaris_uefi_cpu_allowed(1,7,1,0,0x700,0x81000700));
 assert(!polaris_uefi_cpu_allowed(0,0x100,1,0,0x100,0x81000100));
 assert(!polaris_uefi_cpu_allowed(2,0x100,1,0,0x100,0x81000100));
 assert(!polaris_uefi_cpu_allowed(1,0,1,0,0,0x81000000));
 assert(!polaris_uefi_cpu_allowed(1,0x200,1,0,0x200,0x81000200));
 assert(!polaris_uefi_cpu_allowed(1,0x100,2,0,0x100,0x81000100));
 assert(!polaris_uefi_cpu_allowed(1,0x100,1,1,0x100,0x81000100));
 assert(!polaris_uefi_cpu_allowed(1,0x100,1,0,0,0x81000100));
 assert(!polaris_uefi_cpu_allowed(1,0x100,1,0,0x100,0x81000000));
 assert(!polaris_uefi_cpu_allowed(1,0x100,1,0,0x100,0x81010100));
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            c=Path(d)/'test.c';exe=Path(d)/'test';c.write_text(source)
            subprocess.run(['/usr/bin/clang','-std=c11','-Wall','-Wextra','-Werror',
                            '-fsanitize=address,undefined','-I'+str(root/'tools'),str(c),'-o',str(exe)],check=True)
            subprocess.run([str(exe)],check=True)


if __name__=='__main__':unittest.main()
