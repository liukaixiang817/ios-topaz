"""A nonzero fault remains evidence; the observer can never arm a writer."""
from pathlib import Path
import unittest
from .test_polaris_wled_readonly import H
from .test_polaris_gpu_bootstrap import run

ROOT = Path(__file__).resolve().parents[2]
W = H + '#include "' + str(ROOT / 'shim/polaris/uefi-wled-fault-watch.h') + '"\n' + r'''
static void pulse_read(void *ctx,uint32_t offset,uint32_t word) {
 cmd(ctx,offset,word);struct fake *f=ctx;
 /* Explicit SOFTWARE trace: each read of FAULT alternates 1,0. This is not
  * an assertion about physical PMI8998 clearing behavior. */
 if(((word>>4)&255)==8)f->pmic[0][8]^=1;
}
static void watch_setup(struct fake *f,struct polaris_wled_read_bus *b,
 struct polaris_wled_fault_watch *w) {
 init(f,b);memset(w,0,sizeof(*w));assert(pw_map(b));
 b->fault=PW_E_CHANGED;b->read_command=pulse_read;
 f->pmic[0][8]=0;f->pmic[0][0x10]=2;f->pmic[0][0x46]=0x80;
 polaris_wled_fault_watch_start(w,b,now);assert(w->started&&!w->done);
}
static inline void drive(struct fake *f,struct polaris_wled_fault_watch *w) {
 for(unsigned n=0;n<40&&!w->done;n++){f->time+=10001;polaris_wled_fault_watch_poll(w);}
 assert(w->done);
}
'''


class WledFaultWatch(unittest.TestCase):
    def test_pulses_raw_pairs_timing_and_original_failure_are_preserved(self):
        run(W + r'''
int main(void) {
 struct fake f;struct polaris_wled_read_bus b;struct polaris_wled_fault_watch w;
 watch_setup(&f,&b,&w);uint8_t old[2][256];memcpy(old,f.pmic,sizeof(old));
 drive(&f,&w);assert(!w.error&&w.count==32&&w.bus.reads==128&&f.commands==128);
 assert(w.fault_or==1&&w.rt_or==2&&!w.enable_xor&&w.partial_valid==15);
 for(unsigned n=0;n<32;n++) {
  assert(w.samples[n].first==1&&w.samples[n].after==0&&w.samples[n].rt==2&&w.samples[n].enable==0x80);
  assert(w.samples[n].ended_us>=w.samples[n].began_us);
  if(n)assert(w.samples[n].began_us-w.samples[n-1].ended_us>=10000);
 }
 assert(b.fault==PW_E_CHANGED&&!b.reads);assert(!memcmp(old,f.pmic,sizeof(old)));
 unsigned calls=f.commands;polaris_wled_fault_watch_poll(&w);assert(calls==f.commands);
 return 0;
}
''')

    def test_each_read_failure_stops_and_keeps_even_partial_fault(self):
        run(W + r'''
int main(void) {
 for(unsigned n=1;n<=128;n++) {
  struct fake f;struct polaris_wled_read_bus b;struct polaris_wled_fault_watch w;
  watch_setup(&f,&b,&w);f.fail_command=n;drive(&f,&w);
  assert(w.error==PW_E_RESPONSE&&f.commands==n&&b.fault==PW_E_CHANGED);
  assert(w.count==(n-1)/4);
  if((n-1)%4)assert(w.fault_or==1&&w.partial_valid&1&&w.partial.first==1);
  unsigned calls=f.commands;for(unsigned j=0;j<10;j++)polaris_wled_fault_watch_poll(&w);
  assert(calls==f.commands);
 }
 return 0;
}
''')

    def test_late_clock_owner_change_and_prior_transport_error_cannot_be_clean(self):
        run(W + r'''
int main(void) {
 struct fake f;struct polaris_wled_read_bus b;struct polaris_wled_fault_watch w;
 watch_setup(&f,&b,&w);drive(&f,&w);assert(w.count==32&&!w.error);
 watch_setup(&f,&b,&w);f.time+=2000001;polaris_wled_fault_watch_poll(&w);
 assert(w.done&&w.error==PW_E_TIME&&!f.commands&&!w.count);
 watch_setup(&f,&b,&w);f.backward=1;f.time=w.started-1;polaris_wled_fault_watch_poll(&w);
 assert(w.done&&w.error==PW_E_TIME&&!f.commands);
 watch_setup(&f,&b,&w);f.frozen=1;
 for(unsigned n=0;n<4100&&!w.done;n++)polaris_wled_fault_watch_poll(&w);
 assert(w.done&&w.error==PW_E_TIME&&w.count<=1&&f.commands<=4);
 watch_setup(&f,&b,&w);f.owners[7]=3;polaris_wled_fault_watch_poll(&w);
 assert(w.done&&w.error==PW_E_MAPPING&&!f.commands);
 init(&f,&b);assert(pw_map(&b));memset(&w,0,sizeof(w));b.fault=PW_E_RESPONSE;
 polaris_wled_fault_watch_start(&w,&b,now);assert(w.done&&w.error&&!f.commands);
 return 0;
}
''')


if __name__ == '__main__':
    unittest.main()
