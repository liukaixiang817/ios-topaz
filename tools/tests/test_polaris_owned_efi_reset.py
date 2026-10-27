"""Exercise the exact EFI sender/reset gate with the actual shared status ABI.

This host test does not prove a native shutdown or hardware persistence.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class OwnedEfiReset(unittest.TestCase):
    def test_no_RAW_or_RAM_DRAINED_permission_and_exact_SAFE_binding(self):
        original = (ROOT / 'shim/polaris/uefi-xnu.c').read_text()
        functions = original.split('static int shutdown_begin(', 1)[1].split('static void reset(', 1)[0]
        # Remove only the closing outer bridge conditional; function bodies are exact.
        functions = 'static int shutdown_begin(' + functions.replace('\n#endif\nstatic int prepare_reset', '\nstatic int prepare_reset', 1)
        source = r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "runtime-quiesce.h"
#define EFI_XNU_OWNED_TEST 1
#define EFI_XNU_DURABLE_GUARD 1
#define POLARIS_EFI_TEST_QEMU 1
#define EFI_XNU_SHUTDOWN_OFFSET 0
static struct polaris_shutdown_slot box;
#define POLARIS_RAM_BASE ((uintptr_t)&box)
static unsigned load_state=4;
static struct { struct { void *reset_system; } *runtime; } table, *system_table=&table;
static void bytes_zero(void *p,uint64_t n) { memset(p,0,n); }
static void clean(uintptr_t p,uint64_t n) { (void)p;(void)n; }
static int shutdown_status(void *c,const uint8_t **data,uint64_t *bytes) {
 (void)c;*data=(const void*)&box.kernel;*bytes=sizeof(box.kernel);return 1;
}
''' + functions + r'''
int main(void) {
 typeof(*table.runtime) rt={.reset_system=(void*)1};table.runtime=&rt;
 box.kernel.cookie=99;box.kernel.phase=POLARIS_Q_RUNNING;box.kernel.write_epoch=1;
 assert(!prepare_reset(0,1)&&!prepare_reset(0,2));
 assert(shutdown_begin(0,2));
 assert(box.firmware.cookie==99&&box.firmware.sequence==1&&box.firmware.mode==2);
 assert(!prepare_reset(0,2));
 box.kernel.sequence=1;box.kernel.mode=2;box.kernel.phase=POLARIS_Q_SEALED;
 box.kernel.capabilities=POLARIS_Q_RAM_DRAINED;
 assert(!shutdown_reset_ready(0,2)&&!prepare_reset(0,2));
 box.kernel.phase=POLARIS_Q_SAFE;box.kernel.flushed_epoch=1;
 box.kernel.capabilities=POLARIS_Q_SAFE_CAPABILITIES;
 assert(shutdown_reset_ready(0,2)&&prepare_reset(0,2));
 assert(!shutdown_reset_ready(0,1)&&!prepare_reset(0,1));
 for (unsigned bit=0;bit<64;bit++) {
  box.kernel.cookie^=UINT64_C(1)<<bit;assert(!prepare_reset(0,2));
  box.kernel.cookie^=UINT64_C(1)<<bit;
  box.kernel.flushed_epoch^=UINT64_C(1)<<bit;assert(!prepare_reset(0,2));
  box.kernel.flushed_epoch^=UINT64_C(1)<<bit;
 }
 for (unsigned bit=0;bit<32;bit++) {
  box.kernel.capabilities^=1u<<bit;assert(!prepare_reset(0,2));
  box.kernel.capabilities^=1u<<bit;
  box.kernel.error=1u<<bit;assert(!prepare_reset(0,2));box.kernel.error=0;
 }
 box.kernel.phase=POLARIS_Q_FAILED;box.kernel.error=5;
 assert(!prepare_reset(0,1)&&!prepare_reset(0,2));
 load_state=3;assert(prepare_reset(0,2)); /* Before CPU_ON no owned write can exist. */
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            (folder/'test.c').write_text(source)
            subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
                            '-I'+str(ROOT/'shim/polaris'),str(folder/'test.c'),'-o',str(folder/'test')], check=True)
            subprocess.run([str(folder/'test')], check=True)


if __name__ == '__main__':
    unittest.main()
