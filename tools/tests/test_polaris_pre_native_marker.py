"""Actual pre-native guards; marker hardware methods remain software leaves."""
from pathlib import Path
import subprocess
import tempfile
import unittest

from tools.tests.test_polaris_mss_word_trace import execute, function

ROOT = Path(__file__).resolve().parents[2]


class PreNativeMarkerTests(unittest.TestCase):
    def test_raw_boot_prefix_requires_completed_marker(self):
        loader = (ROOT/'shim/polaris/uefi-xnu.c').read_text()
        prefix = function(loader, 'static int prepare_boot(void *context)')
        prefix = prefix[:prefix.index('#if EFI_XNU_WIFI_NATIVE_RUNTIME_AVAILABLE')]
        execute(r'''
#include <assert.h>
#define EFI_XNU_WIFI_NATIVE_BOOTLOADER_MARKER 1
static unsigned load_state,native_marker_ready;
static struct {unsigned prepared,error;} native_marker_result;
''' + prefix + r'''
return 1;}
int main(void){
 for(load_state=0;load_state<6;load_state++){
 for(native_marker_ready=0;native_marker_ready<2;native_marker_ready++){
 for(unsigned prepared=0;prepared<2;prepared++){
 for(unsigned error=0;error<2;error++){
  native_marker_result.prepared=prepared;native_marker_result.error=error;
  assert(prepare_boot(0)==(load_state==2&&native_marker_ready&&prepared&&!error));
 }}}}
 return 0;
}
''')

    def test_actual_backend_stays_before_native_ownership_and_is_one_shot(self):
        loader = (ROOT/'shim/polaris/uefi-xnu.c').read_text()
        backend = function(loader, 'static int native_bootloader_marker(void *context)')
        execute('#include "'+str(ROOT/'shim/polaris/uefi-probe-reset.h')+'"\n'+r'''
#include <assert.h>
#include <string.h>
static unsigned load_state,wifi_native_prepared,wifi_native_boot_phase,wln_cpu_on_issued,
 native_marker_requested,native_marker_ready,original_service_unknown,archs,caches,arms;
static unsigned arch_ok=1,cache_ok=1,arm_ok=1,arm_attempted=1;
static struct ppr_result native_marker_result;
static struct polaris_efi_pon pon,*reset_pon=&pon;
static int new_original_unknown(void){return original_service_unknown;}
static int marker_arch(void*c,struct pawr_arch*a){(void)c;archs++;
 *a=(struct pawr_arch){4,0x81000000,0,1,0x80803518,0x13ffe89000,0,0,19200000,10};return arch_ok;}
static int marker_translate(void*c,unsigned w,struct pawr_translation*t){(void)c;(void)w;(void)t;assert(0);return 0;}
static int marker_reason_read(void*c,uint32_t*v){(void)c;(void)v;assert(0);return 0;}
static int marker_reason_write(void*c,uint32_t v){(void)c;(void)v;assert(0);return 0;}
static int cache_reset_protocol(void){caches++;return cache_ok;}
static int simulated_arm(struct ppr_result*r,const struct ppr_ops*o){
 arms++;assert(o->arch==marker_arch&&o->translate==marker_translate&&o->read_reason==marker_reason_read&&
  o->write_reason==marker_reason_write&&o->pon==&pon&&!o->reset_system);
 r->attempted=arm_attempted;r->prepared=arm_ok;r->error=arm_ok?0:3;return arm_ok;
}
static void report(const char*s,uint64_t v){(void)s;(void)v;}
#define ppr_arm_marker simulated_arm
''' + backend + r'''
static void init(void){load_state=2;wifi_native_prepared=wifi_native_boot_phase=wln_cpu_on_issued=0;
 native_marker_requested=native_marker_ready=original_service_unknown=archs=caches=arms=0;
 arch_ok=cache_ok=arm_ok=arm_attempted=1;memset(&native_marker_result,0,sizeof(native_marker_result));}
int main(void){
 for(unsigned state=0;state<6;state++)for(unsigned bits=0;bits<32;bits++){
  init();load_state=state;wifi_native_prepared=bits&1;wifi_native_boot_phase=(bits>>1)&1;
  wln_cpu_on_issued=(bits>>2)&1;native_marker_requested=(bits>>3)&1;original_service_unknown=(bits>>4)&1;
  if(state==2&&!bits)continue;
  assert(!native_bootloader_marker(0)&&!archs&&!caches&&!arms);
 }
 init();assert(native_bootloader_marker(0)&&native_marker_requested&&native_marker_ready&&arms==1);
 assert(!native_bootloader_marker(0)&&arms==1&&caches==1);
 init();arch_ok=0;assert(!native_bootloader_marker(0)&&!caches&&!arms);
 init();cache_ok=0;assert(!native_bootloader_marker(0)&&caches==1&&!arms);
 init();arm_ok=0;assert(!native_bootloader_marker(0)&&original_service_unknown&&!native_marker_ready&&arms==1);
 assert(!native_bootloader_marker(0)&&arms==1);
 init();arm_ok=arm_attempted=0;assert(!native_bootloader_marker(0)&&!original_service_unknown&&arms==1);
 return 0;
}
''')

    def test_builder_refuses_marker_outside_fault_diagnostic(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            for extra, message in [([], 'requires --wifi-native-fault-hold'),
                                   (['--wifi-native-fault-hold'], 'requires firmware-only native-ready')]:
                command = ['python3', str(ROOT/'tools/build-polaris-uefi-xnu.py'),
                           '--zig', str(path/'missing-zig'), '--kernel', str(path/'missing-kernel'), '--payload', str(path/'missing-payload'),
                           '--output', str(path/'output'), '--wifi-native-bootloader-marker', *extra]
                result = subprocess.run(command, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertFalse((path/'output').exists())


if __name__ == '__main__':
    unittest.main()
