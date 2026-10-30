"""Real native adapter byte publication with cache calls instrumented in RAM.
The kernel TU separately compiles privileged cache instructions. These host
tests do not execute those instructions or emulate a display/PMIC/USB device.
"""
from pathlib import Path
import unittest
from .test_polaris_gpu_bootstrap import run
from .test_polaris_wled_status import OEM_H

ROOT=Path(__file__).resolve().parents[2]
H=OEM_H+'#include "'+str(ROOT/'tools/polaris-wled-native.h')+'"\n'+r'''
static struct polaris_wled_slot slot;
static struct polaris_wled_native_adapter adapter;
static unsigned invalidates,cleans;
static uint64_t clean_seq[16],clean_on[16],clean_cookie[16],clean_frame[16];
static void cache(void *line,bool clean) {
 assert(line==(clean?(void *)&slot.native:(void *)&slot.firmware));
 if(!clean){invalidates++;return;}
 assert(cleans<16);unsigned k=cleans++;
 clean_seq[k]=slot.native.sequence;clean_on[k]=slot.native.on;
 clean_cookie[k]=slot.native.cookie;clean_frame[k]=slot.native.frame;
}
void begin(void) {
 memset(&adapter,0,sizeof(adapter));memset(&slot,0,sizeof(slot));cleans=invalidates=0;
 slot.firmware=(struct polaris_wled_ack){.cookie=0xabc123,.on=1,.completed_us=100,
  .records=2,.ready=PWM_READY};
 assert(pwn_init(&adapter,&slot,cache,true));
 assert(cleans==2&&!clean_cookie[0]&&clean_cookie[1]==PWM_NATIVE_START);
 assert(clean_seq[0]==0&&clean_seq[1]==0&&clean_on[0]==1&&clean_on[1]==1);
 assert(pwm_native_start_ready(&slot.native));cleans=0;
 assert(pwn_exchange(&adapter,true,100));
 assert(adapter.state.cookie==0xabc123&&!cleans&&invalidates==1);
}
void reply(uint64_t seq,bool on,uint64_t count,uint64_t now) {
 slot.firmware.on=on;slot.firmware.records=count;slot.firmware.completed_us=now;
 __atomic_store_n(&slot.firmware.sequence,seq,__ATOMIC_RELEASE);
}
'''


class NativeWledAdapter(unittest.TestCase):
    def test_request_body_clean_precedes_release_sequence_and_ack_cannot_republish(self):
        run(H+r'''
int main(void) {
 begin();assert(pwn_exchange(&adapter,false,101));
 assert(cleans==2&&clean_seq[0]==0&&clean_seq[1]==1);
 for(unsigned k=0;k<2;k++)assert(clean_cookie[k]==0xabc123&&!clean_on[k]&&!clean_frame[k]);
 assert(adapter.state.inflight&&!pwn_needs_frame(&adapter));
 assert(pwn_exchange(&adapter,false,102)&&cleans==2);
 reply(1,false,12,200);assert(pwn_exchange(&adapter,false,103)&&cleans==2);
 assert(!adapter.state.actual_on&&!adapter.state.inflight);
 assert(pwn_exchange(&adapter,false,104)&&cleans==2);return 0;
}
''')

    def test_old_sequence_can_have_next_body_but_cannot_ack_it_before_last_store(self):
        run(H+r'''
int main(void) {
 begin();assert(pwn_exchange(&adapter,false,101));
 slot.firmware.on=0;slot.firmware.records=12;slot.firmware.completed_us=200;
 assert(pwn_exchange(&adapter,true,102));
 assert(adapter.state.actual_on&&adapter.state.inflight&&!adapter.state.error);
 assert(pwn_presented(&adapter)); /* Synthetic actual-copy callback BEFORE OFF ACK. */
 __atomic_store_n(&slot.firmware.sequence,1,__ATOMIC_RELEASE);
 assert(pwn_exchange(&adapter,true,103));
 assert(!adapter.state.actual_on&&!adapter.state.inflight&&pwn_needs_frame(&adapter));
 assert(slot.native.sequence==1&&cleans==2);
 assert(pwn_presented(&adapter)&&pwn_exchange(&adapter,true,104));
 assert(slot.native.sequence==2&&slot.native.on==1&&slot.native.frame==2);
 assert(cleans==4&&clean_seq[2]==1&&clean_seq[3]==2);
 reply(2,true,26,300);assert(pwn_exchange(&adapter,true,105));
 assert(adapter.state.actual_on&&!pwn_needs_frame(&adapter));return 0;
}
''')

    def test_wrong_session_or_reserved_byte_never_publishes_an_on_request(self):
        run(H+r'''
int main(void) {
 for(unsigned bad=0;bad<74;bad++) {
  begin();assert(pwn_exchange(&adapter,false,101));reply(1,false,12,200);
  if(bad<72)slot.firmware.reserved[bad]=1;
  if(bad==72)slot.firmware.cookie++;
  if(bad==73)slot.firmware.ready++;
  assert(!pwn_exchange(&adapter,true,102)&&adapter.state.error&&cleans==2);
  assert(!pwn_presented(&adapter)&&!pwn_exchange(&adapter,true,103)&&cleans==2);
 }return 0;
}
''')

    def test_no_firmware_advertisement_times_out_and_default_off_touches_nothing(self):
        run(H+r'''
int main(void) {
 memset(&adapter,0,sizeof(adapter));memset(&slot,0,sizeof(slot));
 assert(pwn_init(&adapter,&slot,cache,false));
 assert(!pwn_exchange(&adapter,false,1)&&!pwn_presented(&adapter)&&!invalidates&&!cleans);
 assert(pwn_init(&adapter,&slot,cache,true));
 assert(cleans==2&&pwm_native_start_ready(&slot.native));cleans=0;
 assert(!pwn_exchange(&adapter,false,1)&&!adapter.state.error&&!cleans);
 assert(!pwn_exchange(&adapter,false,1+PWM_TIMEOUT_US)&&adapter.state.error==PWM_E_TIMEOUT);
 assert(!pwn_exchange(&adapter,true,2+PWM_TIMEOUT_US)&&!cleans);
 return 0;
}
''')

    def test_coupled_adapter_and_real_sequencer_only_ack_after_hardware_fixture_readback(self):
        run(H+r'''
int main(void) {
 struct fake f;struct polaris_wled_read_bus b;struct polaris_wled_power p;
 begin();oem_start(&f,&b,&p,1);
 assert(pwn_exchange(&adapter,false,f.time));
 assert(pwp_request(&p,slot.native.sequence,slot.native.on));until_ack(&f,&p,1);
 assert(!p.actual_on&&!p.error&&p.issued==p.completed&&p.completed==2);
 reply(1,p.actual_on,p.witness.count,f.time);
 assert(pwn_exchange(&adapter,true,f.time)&&pwn_needs_frame(&adapter));
 assert(pwn_presented(&adapter)&&pwn_exchange(&adapter,true,++f.time));
 assert(pwp_request(&p,slot.native.sequence,slot.native.on));until_ack(&f,&p,2);
 assert(pwp_restored(&p)&&!p.error&&p.issued==4&&p.completed==4);
 reply(2,p.actual_on,p.witness.count,f.time);
 assert(pwn_exchange(&adapter,true,f.time)&&adapter.state.actual_on);
 assert(f.ovp_time-f.enable_time>=10000&&p.witness.fault_or==1);
 return 0;
}
''')


if __name__=='__main__':unittest.main()
