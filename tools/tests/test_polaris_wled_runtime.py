"""Offline runtime policies coupled to the real PWP sequencer and a SOFTWARE
PMIC. No EFI runtime integration, panel/PMIC simulation, cache or USB claim.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest
from .test_polaris_gpu_bootstrap import run
from .test_polaris_wled_status import OEM_H

ROOT = Path(__file__).resolve().parents[2]
H = (OEM_H.replace('f->writes<16', 'f->writes<4096').replace('[16]', '[4096]')
     + '#include "' + str(ROOT/'shim/polaris/uefi-wled-runtime.h') + '"\n'
     + '#include "' + str(ROOT/'tools/polaris-wled-mailbox.h') + '"\n' + r'''
#include <stdlib.h>
static struct fake f;
static struct polaris_wled_read_bus b;
static struct polaris_wled_power p;
static struct polaris_wled_runtime r;
static struct polaris_wled_native n;
static struct polaris_wled_firmware fw;
static struct polaris_wled_runtime_record archive[8192];
static void begin(unsigned capacity,unsigned pulse) {
 memset(&r,0,sizeof(r));memset(&n,0,sizeof(n));memset(&fw,0,sizeof(fw));
 memset(archive,0xa5,sizeof(archive));oem_start(&f,&b,&p,pulse);
 assert(pwr_init(&r,&p,archive,capacity)&&r.count==2);
 struct polaris_wled_ack ready;
 assert(pwm_firmware_init(&fw,0x123456789abcdef0,r.count,f.time,&ready));
 assert(pwm_native_init(&n,&ready,f.time));
}
static void drive(void) {
 for(unsigned k=0;k<64&&r.pending;k++) {
  unsigned before=f.writes;f.time+=1000;
  assert(pwr_poll(&r));assert(f.writes<=before+1);
 }assert(!r.pending&&!p.error&&!p.uncertain);
}
static void complete(struct polaris_wled_ack *out) {
 assert(pwm_firmware_complete(&fw,p.actual_on,!p.error&&!p.uncertain&&
  !r.pending&&p.request==p.acknowledged,r.count,f.time,out));
 assert(pwm_native_ack(&n,out,f.time));
}
void target(bool on) {
 struct polaris_wled_request request;
 assert(pwm_native_intent(&n,on));
 if(on)assert(pwm_native_presented(&n,n.last_frame+1));
 assert(pwm_native_next(&n,++f.time,&request));
 assert(pwm_firmware_request(&fw,&request));
 assert(pwr_request(&r,request.sequence,on)==PWR_ACCEPTED);
 drive();struct polaris_wled_ack ack;complete(&ack);
 assert(p.actual_on==on&&n.actual_on==on&&fw.actual_on==on);
}
''')


class WledRuntime(unittest.TestCase):
    def test_200_cycles_preserve_all_raw_records_beyond_old_64_limit(self):
        run(H+r'''
int main(void) {
 begin(8192,1);
 for(unsigned cycle=0;cycle<200;cycle++) {
  unsigned before=r.count;target(false);
  assert(r.count==before+10&&p.witness.count<=PWS_RECORDS);
  struct polaris_wled_runtime_record prefix[12];
  memcpy(prefix,archive+before,10*sizeof(*prefix));
  target(true);assert(r.count==before+24&&!p.witness.count&&!r.copied);
  assert(!memcmp(prefix,archive+before,10*sizeof(*prefix)));
  assert(p.status_policy==PWP_OEM_STATUS_WITNESS&&!r.error&&!p.error);
 }
 assert(f.writes==800&&r.count==4802&&p.request==400&&p.acknowledged==400);
 assert(p.witness.fault_or==1&&p.witness.rt_or==1);
 uint64_t last=0;unsigned highs=0,lows=0;
 for(unsigned k=0;k<r.count;k++) {
  const struct polaris_wled_runtime_record *x=&archive[k];
  assert(x->raw.valid==3&&x->raw.began_us>=last&&x->raw.ended_us>x->raw.began_us);
  assert(x->sequence<=400);last=x->raw.ended_us;
  highs+=x->raw.fault==1;lows+=x->raw.fault==0;
 }assert(highs&&lows&&p.witness.previous_us>=last);
 f.pmic[0][8]=f.pmic[0][0x10]=0;assert(!memcmp(f.original,f.pmic,sizeof(f.pmic)));
 assert(pwm_firmware_close(&fw)&&pwr_close(&r)&&pwr_seal(&r));
 assert(r.final_first==4804&&r.final_last==4806&&r.count==4806);
 assert(!pwr_seal(&r)&&!pwr_poll(&r)&&!pwm_firmware_request(&fw,
  &(struct polaris_wled_request){.cookie=fw.cookie,.sequence=401}));
 return 0;
}
''')

    def test_capacity_refuses_before_off_and_preserves_final_read_reserve(self):
        run(H+r'''
int main(void) {
 begin(64,1);target(false);target(true);target(false);target(true);
 assert(r.count==50&&p.actual_on&&f.writes==8);
 struct polaris_wled_runtime_record saved[50];memcpy(saved,archive,sizeof(saved));
 struct polaris_wled_request q;struct polaris_wled_ack ack;
 assert(pwm_native_intent(&n,false)&&pwm_native_next(&n,++f.time,&q));
 assert(pwm_firmware_request(&fw,&q));
 assert(pwr_request(&r,q.sequence,false)==PWR_CAPACITY);
 assert(r.exhausted&&!r.error&&!p.error&&p.actual_on&&f.writes==8);
 assert(pwm_firmware_capacity(&fw,r.count,++f.time,&ack));
 assert(ack.on==1&&ack.error==PWM_E_CAPACITY);
 assert(!pwm_native_ack(&n,&ack,f.time)&&n.error==PWM_E_CAPACITY&&n.actual_on);
 assert(!pwm_native_next(&n,++f.time,&q));
 assert(pwr_request(&r,p.request+1,false)==PWR_CAPACITY);
 assert(pwm_firmware_close(&fw)&&pwr_close(&r)&&pwr_seal(&r));
 assert(r.count==54&&f.writes==8&&!memcmp(saved,archive,sizeof(saved)));
 assert(r.final_first==52&&r.final_last==54&&p.witness.fault_or==1);
 return 0;
}
''')

    def test_latest_intent_waits_for_ack_and_a_new_post_ack_panel_frame(self):
        run(H+r'''
int main(void) {
 begin(64,0);struct polaris_wled_request q,untouched;
 memset(&untouched,0xa5,sizeof(untouched));
 assert(pwm_native_presented(&n,1)&&pwm_native_intent(&n,false));
 assert(pwm_native_next(&n,++f.time,&q)&&pwm_firmware_request(&fw,&q));
 assert(pwr_request(&r,q.sequence,false)==PWR_ACCEPTED);
 assert(pwm_native_intent(&n,true)&&pwm_native_presented(&n,2));
 struct polaris_wled_request copy=untouched;
 assert(!pwm_native_next(&n,++f.time,&copy)&&!memcmp(&copy,&untouched,sizeof(copy)));
 drive();struct polaris_wled_ack ack;complete(&ack);
 assert(n.desired_on&&!n.actual_on&&n.off_frame==2);
 assert(!pwm_native_next(&n,++f.time,&copy)); /* Old/caller-prepared frame refused. */
 assert(pwm_native_presented(&n,3)&&pwm_native_next(&n,++f.time,&q));
 assert(q.on==1&&q.frame==3&&q.sequence==2&&pwm_firmware_request(&fw,&q));
 assert(pwr_request(&r,q.sequence,true)==PWR_ACCEPTED);
 assert(pwm_native_intent(&n,false));drive();complete(&ack);
 assert(n.actual_on&&!n.desired_on&&pwm_native_next(&n,++f.time,&q));
 assert(q.sequence==3&&!q.on);return 0;
}
''')

    def test_terminal_restore_at_each_phase_without_forging_a_native_on_ack(self):
        run(H+r'''
int main(void) {
 for(unsigned phase=PWP_ON;phase<=PWP_VERIFY_ON;phase++) {
  begin(64,1);
  if(phase!=PWP_ON) {
   assert(pwr_request(&r,1,false)==PWR_ACCEPTED);
   for(unsigned k=0;k<64&&p.phase!=phase;k++) {
    if(p.phase==PWP_OFF&&!r.pending&&phase>PWP_OFF)
     assert(pwr_request(&r,2,true)==PWR_ACCEPTED);
    f.time+=1000;assert(pwr_poll(&r));
   }assert(p.phase==phase);
  }
  assert(pwm_firmware_close(&fw)&&pwr_close(&r));
  unsigned writes=f.writes;
  assert(pwr_request(&r,p.request+1,false)==PWR_REFUSED&&f.writes==writes);
  for(unsigned k=0;k<128&&(r.pending||!p.actual_on);k++) {
   f.time+=1000;assert(pwr_poll(&r));
  }
  assert(!r.pending&&p.actual_on&&!n.inflight&&n.sequence==0);
  unsigned before=r.count;assert(pwr_seal(&r));
  assert(r.count==before+4&&r.final_first==before+2&&r.final_last==before+4);
  assert(p.issued==p.completed&&!p.uncertain&&f.writes<=4);
  assert(!pwr_seal(&r)&&!pwr_close(&r)&&!pwr_poll(&r));
 }
 return 0;
}
''')

    def test_every_serious_status_after_each_write_keeps_partial_raw_and_blocks_seal(self):
        run(H+r'''
int main(void) {
 for(unsigned bank=0;bank<2;bank++)for(unsigned bit=1;bit<8;bit++)
 for(unsigned command=1;command<=4;command++) {
  begin(64,0);assert(pwr_request(&r,1,false)==PWR_ACCEPTED);
  while(f.writes<command-1&&f.writes<2){f.time+=1000;assert(pwr_poll(&r));}
  if(command>=3) {drive();assert(pwr_request(&r,2,true)==PWR_ACCEPTED);
   while(f.writes<command-1){f.time+=1000;assert(pwr_poll(&r));}}
  if(bank)f.post_rt=1u<<bit;else f.post_fault=1u<<bit;
  for(unsigned k=0;k<64&&!p.error;k++){f.time+=1000;(void)pwr_poll(&r);}
  assert(p.error==PWS_E_STATUS&&p.uncertain&&f.writes==command);
  assert(p.completed==command&&!pwr_seal(&r)&&!pwr_close(&r));
  const struct polaris_wled_status_record *raw=&archive[r.count-1].raw;
  assert((bank?raw->rt:raw->fault)==(1u<<bit)&&raw->valid==(bank?3:1));
  struct polaris_wled_runtime_record saved[64];memcpy(saved,archive,r.count*sizeof(*saved));
  for(unsigned k=0;k<100;k++)assert(!pwr_poll(&r));
  assert(f.writes==command&&!memcmp(saved,archive,r.count*sizeof(*saved)));
 }
 return 0;
}
''')

    def test_every_cycle_and_terminal_observer_read_failure_is_retained_without_retry(self):
        run(H+r'''
int main(void) {
 begin(64,0);unsigned start=f.read_count;
 target(false);target(true);assert(pwr_close(&r)&&pwr_seal(&r));
 unsigned reads=f.read_count-start;assert(reads==448);
 for(unsigned fail=1;fail<=reads;fail++) {
  begin(64,0);f.fail_read=f.read_count+fail;
  assert(pwr_request(&r,1,false)==PWR_ACCEPTED);
  for(unsigned k=0;k<64&&r.pending&&!p.error;k++){f.time+=1000;(void)pwr_poll(&r);}
  if(!p.error) {
   assert(pwr_request(&r,2,true)==PWR_ACCEPTED);
   for(unsigned k=0;k<64&&r.pending&&!p.error;k++){f.time+=1000;(void)pwr_poll(&r);}
  }
  if(!p.error){assert(pwr_close(&r));assert(!pwr_seal(&r));}
  assert(p.error&&!r.sealed&&r.count<=64);
  assert(p.witness.count==r.copied); /* Even the failing partial record copied. */
  unsigned writes=f.writes;for(unsigned k=0;k<32;k++)assert(!pwr_poll(&r));
  assert(f.writes==writes&&!pwr_seal(&r));
 }return 0;
}
''')

    def test_unknown_completion_owner_and_static_change_never_retry_or_reset(self):
        run(H+r'''
int main(void) {
 for(unsigned failed=1;failed<=4;failed++)for(unsigned status_code=0;status_code<16;status_code++) {
  if(status_code==1)continue;begin(64,0);
  assert(pwr_request(&r,1,false)==PWR_ACCEPTED);
  if(failed>=3){drive();assert(pwr_request(&r,2,true)==PWR_ACCEPTED);}
  f.fail_write=failed;f.status=status_code;
  for(unsigned k=0;k<64&&!p.error;k++){f.time+=1000;(void)pwr_poll(&r);}
  assert(p.error&&p.uncertain&&f.writes==failed&&p.completed==failed-1);
  assert(!pwr_close(&r)&&!pwr_seal(&r));
 }
 for(unsigned bad=0;bad<5;bad++) {
  begin(64,0);assert(pwr_request(&r,1,false)==PWR_ACCEPTED);
  if(bad==0)f.foreign_owner=1;if(bad==1)f.bad_map=1;if(bad==2)f.bad_version=1;
  if(bad==3)f.pmic[0][0x5a]^=1;if(bad==4)f.pmic[1][0x57]^=1;
  for(unsigned k=0;k<64&&!p.error;k++){f.time+=1000;(void)pwr_poll(&r);}
  assert(p.error&&!f.writes&&!pwr_close(&r)&&!pwr_seal(&r));
 }return 0;
}
''')

    def test_all_request_reserved_bits_and_bad_fields_fail_before_backend_write(self):
        run(H+r'''
int main(void) {
 for(unsigned byte=0;byte<96;byte++)for(unsigned bit=0;bit<8;bit++) {
  begin(64,0);struct polaris_wled_request q;
  assert(pwm_native_intent(&n,false)&&pwm_native_next(&n,++f.time,&q));
  q.reserved[byte]=1u<<bit;assert(!pwm_firmware_request(&fw,&q)&&fw.error&&!f.writes);
 }
 for(unsigned bad=0;bad<7;bad++) {
  begin(64,0);struct polaris_wled_request q;
  assert(pwm_native_intent(&n,false)&&pwm_native_next(&n,++f.time,&q));
  if(bad==0)q.cookie++;if(bad==1)q.sequence=0;if(bad==2)q.sequence++;
  if(bad==3)q.on=2;if(bad==4)q.on=1;
  if(bad==5)fw.pending=true;if(bad==6)fw.sequence=UINT64_MAX;
  assert(!pwm_firmware_request(&fw,&q)&&fw.error&&!f.writes);
 }
 begin(64,0);target(false);
 struct polaris_wled_request q={.cookie=fw.cookie,.sequence=2,.on=1,.frame=fw.off_frame};
 assert(!pwm_firmware_request(&fw,&q)&&fw.error==PWM_E_FRAME&&f.writes==2);
 return 0;
}
''')

    def test_every_ack_reserved_bit_stale_session_wrong_state_and_late_reply_are_sticky(self):
        run(H+r'''
int main(void) {
 for(unsigned byte=0;byte<72;byte++)for(unsigned bit=0;bit<8;bit++) {
  begin(64,0);struct polaris_wled_request q;struct polaris_wled_ack a;
  assert(pwm_native_intent(&n,false)&&pwm_native_next(&n,++f.time,&q));
  assert(pwm_firmware_request(&fw,&q)&&pwr_request(&r,q.sequence,false)==PWR_ACCEPTED);
  drive();assert(pwm_firmware_complete(&fw,false,true,r.count,f.time,&a));
  a.reserved[byte]=1u<<bit;
  assert(!pwm_native_ack(&n,&a,f.time)&&n.error&&n.inflight&&n.actual_on);
 }
 for(unsigned bad=0;bad<12;bad++) {
  begin(64,0);struct polaris_wled_request q;struct polaris_wled_ack a;
  assert(pwm_native_intent(&n,false)&&pwm_native_next(&n,++f.time,&q));
  assert(pwm_firmware_request(&fw,&q)&&pwr_request(&r,q.sequence,false)==PWR_ACCEPTED);
  drive();assert(pwm_firmware_complete(&fw,false,true,r.count,f.time,&a));
  if(bad==0)a.cookie++;if(bad==1)a.sequence--;if(bad==2)a.sequence++;
  if(bad==3)a.on=1;if(bad==4)a.on=2;if(bad==5)a.error=1;if(bad==6)a.ready++;
  if(bad==7)a.completed_us=n.firmware_us;if(bad==8)a.records=n.records;
  if(bad==9)f.time=n.sent_us+PWM_TIMEOUT_US;
  if(bad==10)f.time=n.last_us-1;if(bad==11)a.completed_us=0;
  assert(!pwm_native_ack(&n,&a,f.time)&&n.error&&n.inflight&&n.actual_on);
  assert(!pwm_native_next(&n,++f.time,&q)&&!pwm_native_tick(&n,f.time));
 }
 begin(64,0);struct polaris_wled_request q;
 assert(pwm_native_intent(&n,false)&&pwm_native_next(&n,++f.time,&q));
 assert(pwm_native_tick(&n,n.sent_us+PWM_TIMEOUT_US-1));
 assert(!pwm_native_tick(&n,n.sent_us+PWM_TIMEOUT_US)&&n.error==PWM_E_TIMEOUT);
 assert(!f.writes&&n.inflight&&n.actual_on);
 begin(64,0);
 for(unsigned k=0;k<4095;k++)assert(pwm_native_tick(&n,n.last_us));
 assert(!pwm_native_tick(&n,n.last_us)&&n.error==PWM_E_CLOCK);
 return 0;
}
''')

    def test_backend_evidence_failure_cannot_publish_a_success_ack(self):
        run(H+r'''
int main(void) {
 for(unsigned bad=0;bad<6;bad++) {
  begin(64,0);struct polaris_wled_request q;struct polaris_wled_ack a,old;
  memset(&a,0xa5,sizeof(a));old=a;
  assert(pwm_native_intent(&n,false)&&pwm_native_next(&n,++f.time,&q));
  assert(pwm_firmware_request(&fw,&q));
  if(bad==5)fw.pending=false;
  assert(!pwm_firmware_complete(&fw,bad==0,bad!=1,bad==2?0:bad==3?fw.records:12,
   bad==4?fw.last_us:++f.time,&a));
  assert(fw.error==PWM_E_BACKEND&&!memcmp(&old,&a,sizeof(a))&&!f.writes);
 }return 0;
}
''')

    def test_fresh_storage_alias_alignment_and_bad_sequence_refuse_without_reinitializing(self):
        run(H+r'''
int main(void) {
 begin(64,0);unsigned reads=f.read_count;
 struct polaris_wled_runtime other={0};
 assert(!pwr_init(&other,&p,archive,63));
 assert(!pwr_init(&other,&p,archive,PWR_MAX_RECORDS+1));
 assert(!pwr_init(&other,&p,(void *)((uint8_t *)archive+1),64));
 assert(!pwr_init(&other,&p,(void *)&p,64));
 assert(!pwr_init((void *)&p,&p,archive,64));
 assert(!pwr_init(&r,&p,archive,64)&&f.read_count==reads&&!f.writes);
 assert(pwr_request(&r,2,false)==PWR_REFUSED&&r.error==PWR_E_REQUEST);
 assert(!pwr_close(&r)&&!pwr_seal(&r)&&!f.writes);
 begin(64,0);assert(pwr_request(&r,1,false)==PWR_ACCEPTED);
 assert(pwr_request(&r,2,true)==PWR_REFUSED&&r.error==PWR_E_REQUEST&&!f.writes);
 return 0;
}
''')

    def test_aarch64_freestanding_and_cpp_wire_abi_compile_without_environment_stubs(self):
        source = ('#include "'+str(ROOT/'shim/polaris/uefi-wled-runtime.h')+'"\n'
                  '#include "'+str(ROOT/'tools/polaris-wled-mailbox.h')+'"\n'
                  'bool poll(struct polaris_wled_runtime *r) {return pwr_poll(r);}\n'
                  'bool seal(struct polaris_wled_runtime *r) {return pwr_seal(r);}\n')
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'probe.c'
            path.write_text(source)
            subprocess.run(['/usr/bin/clang', '-target', 'aarch64-none-elf', '-ffreestanding',
                            '-O2', '-Wall', '-Wextra', '-Werror', '-fstack-usage', '-c', str(path),
                            '-o', str(Path(d)/'probe.o')], check=True)
            cpp = Path(d)/'probe.cpp'
            cpp.write_text('#include "'+str(ROOT/'tools/polaris-wled-mailbox.h')+'"\n'
                           'bool next(polaris_wled_native *n,polaris_wled_request *out)'
                           '{return pwm_native_next(n,1,out);}\n')
            subprocess.run(['/usr/bin/clang++', '-target', 'arm64-apple-macos14', '-ffreestanding',
                            '-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror', '-c', str(cpp),
                            '-o', str(Path(d)/'probe-cpp.o')], check=True)


if __name__ == '__main__':
    unittest.main()
