"""Actual publisher must preserve native failures before optional hardware."""
from pathlib import Path
import unittest
from tools.tests.test_polaris_mss_word_trace import execute, function

ROOT = Path(__file__).resolve().parents[2]


class NativeProgressPublicationTests(unittest.TestCase):
    def test_actual_publisher_records_errors_before_optional_sample(self):
        source = (ROOT/'shim/polaris/uefi-xnu.c').read_text()
        fields = function(source, 'static void wifi_native_fault_progress_fields(void)')
        publish = function(source, 'static int wifi_native_fault_publish(unsigned force)')
        execute('#include "'+str(ROOT/'shim/polaris/uefi-wifi-native-fault.h')+'"\n'+
                '#include "'+str(ROOT/'shim/polaris/uefi-apps-watchdog-native-readonly.h')+'"\n'+r'''
#include <assert.h>
#include <setjmp.h>
#include <string.h>
#define EFI_XNU_WIFI_NATIVE_WATCHDOG_READONLY 1
/* Field-only model; actual production ARM layouts/objects are checked separately. */
struct pwns_parent {
 unsigned attempted,phase,unknown,error;uint64_t turns;
 struct {unsigned attempted,error,held,unknown;uint64_t opening,last;}owner;
 struct {unsigned attempted,pages,segments,error,ready;uint64_t opening;unsigned segment[28];}copy;
 struct {unsigned attempted,phase,error;struct {uint64_t opening;unsigned phase,step;}modem;}auth;
 struct pawn_state watchdog;
};
static struct pwns_parent wifi_native_parent;
static struct pfnf_record wifi_native_fault;
static unsigned wifi_native_boot_phase=5,cleans,samples,fail_clean,sample_ok,hang;
static jmp_buf stop;
static int wifi_native_fault_clean(uint64_t address,uint64_t bytes){
 assert(bytes&&bytes<=4096);cleans++;
 if(cleans==10){
  assert(address==(uintptr_t)&wifi_native_fault&&bytes==sizeof(wifi_native_fault));
  assert(wifi_native_fault.parent_error==wifi_native_parent.error&&
   wifi_native_fault.parent_unknown==wifi_native_parent.unknown&&
   wifi_native_fault.owner_error==wifi_native_parent.owner.error&&
   wifi_native_fault.copy_error==wifi_native_parent.copy.error&&
   wifi_native_fault.copy_pages==874);
 }
 if(cleans==11)assert(address==(uintptr_t)&wifi_native_parent.watchdog);
 return cleans!=fail_clean;
}
static int wifi_native_watchdog_sample(void){
 assert(cleans==10&&!wifi_native_parent.error&&!wifi_native_parent.unknown&&
  !wifi_native_parent.owner.error&&!wifi_native_parent.owner.unknown&&
  !wifi_native_parent.copy.error&&!wifi_native_parent.auth.error);
 samples++;if(hang)longjmp(stop,1);
 wifi_native_parent.watchdog.result.error=sample_ok?0:6;return sample_ok;
}
''' + fields + publish + r'''
static void init(void){
 memset(&wifi_native_parent,0,sizeof(wifi_native_parent));memset(&wifi_native_fault,0,sizeof(wifi_native_fault));
 wifi_native_parent.phase=19;wifi_native_parent.turns=1000;wifi_native_parent.copy.pages=874;
 wifi_native_fault.armed=1;cleans=samples=fail_clean=hang=0;sample_ok=1;
}
int main(void){
 init();assert(wifi_native_fault_publish(1)&&cleans==11&&samples==1);
 for(unsigned flag=0;flag<6;flag++){
  init();switch(flag){case 0:wifi_native_parent.error=5;break;case 1:wifi_native_parent.unknown=1;break;
  case 2:wifi_native_parent.owner.error=3;break;case 3:wifi_native_parent.owner.unknown=1;break;
  case 4:wifi_native_parent.copy.error=11;break;case 5:wifi_native_parent.auth.error=8;break;}
  assert(!wifi_native_fault_publish(1)&&cleans==11&&!samples&&wifi_native_parent.watchdog.result.error==8);
 }
 init();sample_ok=0;assert(!wifi_native_fault_publish(1)&&cleans==11&&samples==1);
 wifi_native_parent.error=5;wifi_native_parent.unknown=1;cleans=samples=0;
 assert(!wifi_native_fault_publish(1)&&cleans==11&&!samples&&wifi_native_parent.watchdog.result.error==6);
 init();hang=1;if(!setjmp(stop)){wifi_native_fault_publish(1);assert(0);}
 assert(cleans==10&&samples==1&&wifi_native_fault.copy_pages==874&&wifi_native_fault.parent_phase==19);
 for(unsigned n=1;n<=11;n++){
  init();fail_clean=n;assert(!wifi_native_fault_publish(1));assert(cleans==n&&samples==(n==11));
 }
 init();wifi_native_fault.armed=0;assert(!wifi_native_fault_publish(1)&&!cleans&&!samples);
 init();wifi_native_fault.entered=1;assert(!wifi_native_fault_publish(1)&&!cleans&&!samples);
 return 0;
}
''')


if __name__ == '__main__':
    unittest.main()
