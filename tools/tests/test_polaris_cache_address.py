"""The shipped XNU cache-sync function must retain physical addresses above4GiB."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PATCH = ROOT / 'xnu/profiles/polaris/0845-polaris-high-physical-cache-sync.patch'


def function(after):
    section = PATCH.read_text().split('+++ b/osfmk/arm/pmap/pmap.c\n', 1)[1]
    section = section.split('--- a/bsd/dev/polaris_a630.c', 1)[0]
    keep = (' ', '+') if after else (' ', '-')
    text = '\n'.join(line[1:] for line in section.splitlines()
                     if line and line[0] in keep and not line.startswith(('---', '+++')))
    match = re.search(r'void\npmap_sync_page_attributes_phys\(.*?\n\}', text, re.S)
    if not match:
        raise AssertionError('Actual shipped function missing from patch context')
    return match[0]


class CacheAddressTests(unittest.TestCase):
    def run_function(self, after):
        source = r'''
#include <stdint.h>
#include <stddef.h>
typedef uint32_t ppnum_t;
typedef uint64_t vm_offset_t;
#define PAGE_SHIFT 14
#define PAGE_SIZE 16384u
#define TRUE 1
#define ptoa_64(x) ((uint64_t)(x) << PAGE_SHIFT)
_Static_assert(sizeof(ppnum_t)==4,"32bit physical page numbers");
static uint64_t observed;
static unsigned count,length;
static int physical;
static void flush_dcache(vm_offset_t addr,unsigned bytes,int phys) {
    count++;observed=addr;length=bytes;physical=phys;
}
''' + function(after) + r'''
int main(void) {
    const uint64_t addresses[]={0,0x4000,0xffffc000,0x100000000ull,
        0x180004000ull,0x200004000ull,0x8ffffc000ull,0x123456780000ull};
    for(unsigned n=0;n<sizeof(addresses)/sizeof(addresses[0]);n++) {
        count=0;pmap_sync_page_attributes_phys((ppnum_t)(addresses[n]>>PAGE_SHIFT));
        if(count!=1||length!=16384||physical!=1||observed!=addresses[n])return 1;
    }
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            (path/'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang','-std=c11','-O1','-g','-Wall',
                            '-Wextra','-Werror','-fsanitize=address,undefined',
                            str(path/'test.c'),'-o',str(path/'test')],check=True)
            return subprocess.run([str(path/'test')],capture_output=True).returncode

    def test_actual_shipped_function_retains_high_addresses(self):
        self.assertEqual(self.run_function(True),0)

    def test_regression_detects_original_32bit_shift(self):
        self.assertEqual(self.run_function(False),1)


if __name__ == '__main__':
    unittest.main()
