"""Actual bounded WLED sequencer with explicit synthetic PMIC semantics.

This checks register scope and failures, not physical darkness or SD845 MMIO.
"""
from pathlib import Path
import unittest
from .test_polaris_gpu_bootstrap import run

ROOT = Path(__file__).resolve().parents[2]
H = '#include "' + str(ROOT/'shim/polaris/uefi-wled-power.h') + '"\n' + r'''
#include <assert.h>
#include <string.h>
struct fake {
 uint8_t pmic[2][256], original[2][256];
 uint64_t time, enable_time, ovp_time;
 uint32_t read_cmd, read_off, read_count, writes, status, last_off;
 unsigned foreign_owner, bad_map, bad_version, fail_read, fail_write, drop_write;
 unsigned backward, frozen, freeze_after_issue, mutate_after_issue;
 uint32_t offsets[16],commands[16],data[16];
};
static uint64_t clock_us(void *ctx) {
 struct fake*f=ctx;if(f->backward)return f->time--;return f->frozen?f->time:++f->time;
}
static uint32_t read_reg(void *ctx,unsigned bank,uint32_t off) {
 struct fake*f=ctx;
 if(bank==PW_CORE) {
  if(!off)return f->bad_version?0x60000000:0x50000000;
  assert(off>=0x900&&off<0x1100&&!(off&3));unsigned apid=(off-0x900)/4;
  return apid==253?(f->bad_map?0x0103da00:0x0103d800):apid==254?0x0103d900:0;
 }
 if(bank==PW_CONFIG) {
  assert(off==0x700+253*4||off==0x700+254*4);return f->foreign_owner;
 }
 assert(bank==PW_OBSERVER);
 uint32_t local=off-f->read_off;
 if(local==8)return f->fail_read&&f->read_count==f->fail_read?2:1;
 assert(local==0x18||local==0x1c);
 unsigned k=f->read_off==253*0x80?0:1,reg=(f->read_cmd>>4)&255;
 uint32_t value=0;for(unsigned n=0;n<4;n++) {
  unsigned at=reg+n+(local==0x1c?4:0);if(at<256)value|=(uint32_t)f->pmic[k][at]<<(n*8);
 }return value;
}
static void read_command(void *ctx,uint32_t off,uint32_t cmd) {
 struct fake*f=ctx;assert(off==253*0x80||off==254*0x80);
 assert(cmd>>27==1&&!(cmd&0x07fff008));f->read_off=off;f->read_cmd=cmd;f->read_count++;
}
static void issue(void *ctx,uint32_t off,uint32_t cmd,uint32_t data) {
 struct fake*f=ctx;assert(off==0xfd0000&&!(cmd>>27)&&f->writes<16);
 unsigned i=f->writes++;f->offsets[i]=off;f->commands[i]=cmd;f->data[i]=data;f->last_off=off;
 /* Validate every bus command independently of the production allowlist. */
 assert((cmd==0x460&&(data==0||data==0x80))||
        (cmd==0x160&&data==2)||(cmd==0x141&&data==0x0202));
 if(f->freeze_after_issue)f->frozen=1;
 if(f->mutate_after_issue)f->pmic[1][0x57]^=1;
 if(f->drop_write)return;
 if(cmd==0x460){f->pmic[0][0x46]=(uint8_t)data;if(data)f->enable_time=f->time;}
 else if(cmd==0x160)f->pmic[0][0x15]&=~2u;
 else {assert(f->time-f->enable_time>=10000);f->pmic[0][0x15]|=2;f->ovp_time=f->time;}
}
static uint32_t status(void *ctx,uint32_t off) {
 struct fake*f=ctx;assert(off==f->last_off+8);
 return f->fail_write==f->writes?f->status:1;
}
static void setup(struct fake*f,struct polaris_wled_read_bus*b,struct polaris_wled_power*p) {
 memset(f,0,sizeof(*f));memset(b,0,sizeof(*b));memset(p,0,sizeof(*p));f->time=1;
 const uint8_t ctrl[8]={0,3,1,3,0x17,0x10,0,0},sink[8]={1,1,0,1,0x17,0x11,0,0};
 const uint8_t config[6]={0xf0,0x0f,0,0,0x4c,3},string[9]={0x80,2,8,0,0,0,0x80,0xff,7};
 memcpy(f->pmic[0],ctrl,8);memcpy(f->pmic[1],sink,8);f->pmic[0][0x46]=0x80;
 f->pmic[0][0x15]=2;f->pmic[0][0x5a]=0x80;f->pmic[0][0x5b]=0x84;
 memcpy(f->pmic[1]+0x46,config,6);
 for(unsigned n=0;n<4;n++)memcpy(f->pmic[1]+0x50+0x10*n,string,9);
 memcpy(f->original,f->pmic,sizeof(f->pmic));
 b->context=f;b->read=read_reg;b->read_command=read_command;b->now_us=clock_us;
 p->write_context=f;p->issue=issue;p->status=status;
}
void start(struct fake*f,struct polaris_wled_read_bus*b,struct polaris_wled_power*p) {
 setup(f,b,p);struct polaris_wled_snapshot s;assert(polaris_wled_inventory(b,&s));
 assert(pwp_init(p,b,&s,false)&&pwp_restored(p)&&f->writes==0);
}
void until_ack(struct fake*f,struct polaris_wled_power*p,uint64_t seq) {
 for(unsigned n=0;n<32&&p->acknowledged!=seq;n++) {
  unsigned before=f->writes;f->time+=1000;assert(pwp_poll(p));assert(f->writes<=before+1);
 }assert(p->acknowledged==seq&&!p->uncertain);
}
'''

class WledPower(unittest.TestCase):
    def test_off_on_exact_saved_state_and_cooperative_softstart(self):
        run(H+r'''
int main(void){struct fake f;struct polaris_wled_read_bus b;struct polaris_wled_power p;start(&f,&b,&p);
 assert(pwp_request(&p,1,false));until_ack(&f,&p,1);assert(!p.actual_on&&!pwp_restored(&p));
 assert(f.writes==2&&p.issued==2&&p.completed==2&&f.commands[0]==0x460&&f.commands[1]==0x160);
 assert(!f.pmic[0][0x46]&&!f.pmic[0][0x15]);
 uint8_t off[2][256];memcpy(off,f.pmic,sizeof(off));off[0][0x46]=0x80;off[0][0x15]=2;
 assert(!memcmp(off,f.original,sizeof(off)));assert(pwp_request(&p,2,true));until_ack(&f,&p,2);
 assert(f.writes==4&&pwp_restored(&p)&&!memcmp(f.original,f.pmic,sizeof(f.pmic)));
 assert(f.commands[2]==0x460&&f.commands[3]==0x141&&f.ovp_time-f.enable_time>=10000);
 for(unsigned n=0;n<100;n++)assert(pwp_poll(&p));assert(f.writes==4);
 return 0;}
''')

    def test_all_initial_bytes_owner_map_version_and_dt_fail_before_writes(self):
        run(H+r'''
int main(void){struct fake f;struct polaris_wled_read_bus b;struct polaris_wled_power p;
 for(unsigned n=0;n<sizeof(struct polaris_wled_snapshot);n++)for(unsigned bit=0;bit<8;bit++){
  setup(&f,&b,&p);struct polaris_wled_snapshot s;assert(polaris_wled_inventory(&b,&s));
  ((uint8_t*)&s)[n]^=1u<<bit;assert(!pwp_init(&p,&b,&s,false)&&!f.writes);
 }
 for(unsigned bad=0;bad<4;bad++){
  setup(&f,&b,&p);struct polaris_wled_snapshot s;assert(polaris_wled_inventory(&b,&s));
  if(bad==0)f.foreign_owner=1;if(bad==1)f.bad_map=1;if(bad==2)f.bad_version=1;
  assert(!pwp_init(&p,&b,&s,bad==3)&&!f.writes);
 }return 0;}
''')

    def test_write_timeouts_errors_readback_mismatch_are_sticky_and_never_retried(self):
        run(H+r'''
int main(void){struct fake f;struct polaris_wled_read_bus b;struct polaris_wled_power p;
 for(unsigned failed=1;failed<=4;failed++)for(unsigned state=0;state<16;state++){
  if(state==1)continue;start(&f,&b,&p);f.fail_write=failed;f.status=state;
  assert(pwp_request(&p,1,false));if(failed>=3){until_ack(&f,&p,1);assert(pwp_request(&p,2,true));}
  for(unsigned n=0;n<32&&!p.error;n++){f.time+=1000;(void)pwp_poll(&p);}
  assert(p.error&&p.uncertain&&f.writes==failed&&p.completed==failed-1&&!pwp_restored(&p));
  unsigned writes=f.writes;for(unsigned n=0;n<100;n++)assert(!pwp_poll(&p));
  assert(!pwp_request(&p,3,true)&&f.writes==writes);
 }
 for(unsigned bad=0;bad<3;bad++){
  start(&f,&b,&p);if(bad==0)f.drop_write=1;if(bad==1)f.mutate_after_issue=1;
  if(bad==2){f.fail_write=1;f.status=0;f.freeze_after_issue=1;}
  assert(pwp_request(&p,1,false));assert(pwp_poll(&p));assert(!pwp_poll(&p));
  assert(p.error&&p.uncertain&&f.writes==1&&!pwp_restored(&p));
 }return 0;}
''')

    def test_changed_live_configuration_and_every_observer_failure_deny_next_write(self):
        run(H+r'''
int main(void){struct fake f;struct polaris_wled_read_bus b;struct polaris_wled_power p;
 for(unsigned fail=1;fail<=32;fail++){
  start(&f,&b,&p);f.fail_read=f.read_count+fail;
  assert(pwp_request(&p,1,false)&&pwp_poll(&p));assert(!pwp_poll(&p));
  assert(p.error&&!f.writes&&!pwp_restored(&p));
 }
 for(unsigned bad=0;bad<5;bad++){
  start(&f,&b,&p);assert(pwp_request(&p,1,false)&&pwp_poll(&p));
  if(bad==0)f.foreign_owner=1;if(bad==1)f.bad_map=1;if(bad==2)f.bad_version=1;
  if(bad==3)f.pmic[0][0x5a]^=1;if(bad==4)f.pmic[1][0x57]^=1;
  assert(!pwp_poll(&p)&&!f.writes&&p.error);
 }return 0;}
''')

    def test_rapid_latest_desired_coalesces_without_early_ack_or_skipping_softstart(self):
        run(H+r'''
int main(void){struct fake f;struct polaris_wled_read_bus b;struct polaris_wled_power p;
 for(unsigned change_phase=PWP_OFF_MODULE;change_phase<=PWP_VERIFY_ON;change_phase++){
  start(&f,&b,&p);assert(pwp_request(&p,1,false));
  for(unsigned n=0;n<64&&p.phase!=change_phase;n++){
   if(p.phase==PWP_OFF)assert(pwp_request(&p,p.request+1,true));
   f.time+=1000;assert(pwp_poll(&p));
  }
  assert(p.phase==change_phase);uint64_t seq=p.request+1;
  assert(pwp_request(&p,seq,true));until_ack(&f,&p,seq);assert(pwp_restored(&p));
  assert(!memcmp(f.original,f.pmic,sizeof(f.pmic)));
 }
 start(&f,&b,&p);assert(pwp_request(&p,1,false)&&pwp_request(&p,2,true));
 until_ack(&f,&p,2);assert(!f.writes);return 0;}
''')

    def test_bad_sequence_clock_and_out_of_phase_direct_calls_stop(self):
        run(H+r'''
int main(void){struct fake f;struct polaris_wled_read_bus b;struct polaris_wled_power p;
 for(unsigned bad=0;bad<4;bad++){
  start(&f,&b,&p);
  if(bad==0)assert(!pwp_request(&p,0,false));
  if(bad==1)assert(!pwp_request(&p,2,false));
  if(bad==2){p.previous_us=f.time+2;assert(!pwp_poll(&p));}
  if(bad==3)assert(!pwp_write(&p,PWP_ENABLE_MODULE));
  assert(p.error&&!f.writes&&!pwp_restored(&p));
 }
 start(&f,&b,&p);assert(pwp_request(&p,1,false));until_ack(&f,&p,1);
 assert(pwp_request(&p,2,true));while(p.phase!=PWP_SOFTSTART)assert(pwp_poll(&p));
 f.frozen=1;unsigned writes=f.writes;for(unsigned n=0;n<4096&&!p.error;n++)(void)pwp_poll(&p);
 assert(p.error&&!pwp_restored(&p)&&f.writes==writes);
 return 0;}
''')

if __name__ == '__main__':
    unittest.main()
