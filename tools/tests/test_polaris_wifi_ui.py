"""Actual loader UI service + WLED runtime/mailbox on a SOFTWARE PMIC.

CPU exclusion is separately tested by polaris-wifi-ui-window-test.c. No phone,
physical PMIC, button hardware or whole-image admission is claimed here.
"""
from pathlib import Path
import unittest
from .test_polaris_gpu_lifetime import function
from .test_polaris_gpu_bootstrap import run
from .test_polaris_wled_runtime import H

ROOT = Path(__file__).resolve().parents[2]


def source():
    wled = (ROOT / 'shim/polaris/uefi-wled-native.h').read_text()
    loader = (ROOT / 'shim/polaris/uefi-xnu.c').read_text()
    return H + r'''
#define wln_power p
#define wln_runtime r
#define wln_firmware fw
static unsigned wln_started,wln_advertised,wln_closing_mode,wln_error_reported;
static unsigned wln_receipt_issued,buttons_terminal,log_overflow,button_polls;
static unsigned load_state=4;
static int cpu_status;
static uint64_t wln_cookie,wln_last_poll,wln_native_cookie;
static uint32_t wln_native_sequence;
static struct polaris_wled_slot slot;
enum {PWNU_PREPARE=1,PWNU_POLL,PWNU_CLOSE,PWNU_SEAL};
static volatile struct polaris_wled_slot *wln_slot(void){return &slot;}
static uint64_t buttons_us(void*x){(void)x;return f.time;}
static void clean(uintptr_t p,uint64_t z){assert(p==(uintptr_t)&slot.firmware&&z==128);}
static void invalidate(uintptr_t p,uint64_t z){assert(p==(uintptr_t)&slot.native&&z==128);}
static void bytes_copy(void*p,const void*q,uint64_t z){memcpy(p,q,z);}
static void report(const char*s,uint64_t n){(void)s;(void)n;}
static void wln_sync_history(void){} /* Journal encoding is tested separately. */
static int buttons_prepare(void){return !buttons_terminal;}
static void buttons_poll(void){button_polls++;}
static int wln_begin(void){return wln_started;} /* Preparation has separate admission tests. */
''' + '\n'.join(function(wled, n) for n in (
        'static void wln_publish(', 'static int wln_close(',
        'static void wln_poll(', 'static int wln_reset_ready(')) + '\n' + '\n'.join(
            function(loader, n) for n in ('static int wifi_native_ui_healthy(', 'static int pwnu_service(')) + r'''
static void setup_ui(void){
 begin(8192,1);memset(&slot,0,sizeof(slot));wln_started=wln_advertised=1;
 wln_cookie=fw.cookie;wln_last_poll=wln_native_cookie=wln_native_sequence=0;
 wln_closing_mode=wln_error_reported=wln_receipt_issued=buttons_terminal=log_overflow=button_polls=0;
 load_state=4;cpu_status=0;
}
static int service(unsigned op){f.time+=10000;return pwnu_service(op,0,0);}
'''


class WifiUi(unittest.TestCase):
    def test_actual_service_restores_from_each_power_phase_and_seals_exact_token(self):
        run(source() + r'''
int main(void){
 for(unsigned phase=PWP_ON;phase<=PWP_VERIFY_ON;phase++){
  setup_ui();assert(service(PWNU_PREPARE)==1);
  if(phase!=PWP_ON){
   assert(pwr_request(&r,1,false)==PWR_ACCEPTED);
   for(unsigned k=0;k<64&&p.phase!=phase;k++){
    if(p.phase==PWP_OFF&&!r.pending&&phase>PWP_OFF)assert(pwr_request(&r,2,true)==PWR_ACCEPTED);
    f.time+=1000;assert(pwr_poll(&r));
   }assert(p.phase==phase);
  }
  assert(!pwnu_service(PWNU_SEAL,77,1));
  int result=1;
  for(unsigned k=0;k<128&&result==1;k++)result=service(PWNU_CLOSE);
  assert(result==2&&r.closing&&!r.pending&&!fw.pending&&p.actual_on&&button_polls);
  unsigned before=r.count;
  assert(pwnu_service(PWNU_SEAL,77,1)==1&&r.sealed&&r.count==before+4);
  assert(wln_native_cookie==77&&wln_native_sequence==1);
  assert(!pwnu_service(PWNU_SEAL,78,1)&&!pwnu_service(PWNU_SEAL,77,2));
 }
 return 0;
}
''')

    def test_real_pending_mailbox_off_request_is_drained_before_close_ready(self):
        run(source() + r'''
int main(void){
 setup_ui();assert(pwm_native_intent(&n,false));
 assert(pwm_native_next(&n,++f.time,&slot.native));
 assert(service(PWNU_POLL)==1&&fw.pending&&r.pending);
 assert(service(PWNU_CLOSE)==1&&r.closing&&fw.pending);
 int result=1;
 for(unsigned k=0;k<128&&result==1;k++)result=service(PWNU_CLOSE);
 assert(result==2&&!fw.pending&&!r.pending&&p.actual_on&&slot.firmware.sequence==1);
 assert(pwnu_service(PWNU_SEAL,77,1)==1);
 return 0;
}
''')

    def test_real_pmic_timeout_and_fault_prevent_restoration_and_seal(self):
        run(source() + r'''
int main(void){
 for(unsigned fault=0;fault<2;fault++){
  setup_ui();assert(pwm_native_intent(&n,false));assert(pwm_native_next(&n,++f.time,&slot.native));
  f.pulse=0;if(fault)f.post_fault=2;else {f.fail_write=1;f.status=0;}
  int result=1;
  for(unsigned k=0;k<128&&result;k++)result=service(PWNU_POLL);
  assert(!result&&(p.error||r.error||fw.error));unsigned writes=f.writes;
  assert(!service(PWNU_CLOSE)&&!pwnu_service(PWNU_SEAL,77,1)&&f.writes==writes);
 }
 return 0;
}
''')


if __name__ == '__main__':
    unittest.main()
