"""Owned CX interval, reset-held clock activation and every cleanup failure."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class A630ClockTests(unittest.TestCase):
    def test_reset_ownership_clock_gates_and_restoration(self):
        source = r'''
#include "polaris-a630-probe.h"
#include "polaris-a630-power.h"
#include "polaris-a630-clock.h"
#include <assert.h>
struct mock {
 uint32_t reg[5],cfg,hw,gx,gx_gmu,ahb,cx;
 unsigned reads,writes,waits,fail_read,fail_write,stall_root,stall_gmu,stall_disable,clock_reads;
 unsigned cx_cycled,collapsed,ack_delay,drop_index,live_zero_reset;
 unsigned pending[5];uint32_t pending_value[5];
 struct a630_clock_snapshot clock;
};
static int index_of(uint32_t off){for(int i=0;i<5;i++)if(off==a630_clock_offsets[i])return i;return -1;}
static void apply(struct mock *m,int i,uint32_t value){
 m->reg[i]=value;
 if(i<4){
  bool on=!!(value&a630_clock_masks[i]);
  bool stuck=on?((i==2&&m->stall_root)||(i==3&&m->stall_gmu)):m->stall_disable;
  if(!stuck){if(on)m->reg[i]&=~A630_POWER_ON;else m->reg[i]|=A630_POWER_ON;}
 }
}
static bool rd(void *p,unsigned region,uint32_t off,uint32_t *v){
 struct mock *m=p;if(++m->reads==m->fail_read)return false;
 if(region==0){assert(off==0x71004);*v=m->ahb;return true;}
 assert(region==1); /* No GMU, GPU, SMMU or firmware read. */
 if(off==A630_CX_STATUS)*v=m->hw;
 else if(off==A630_CX_REQUEST)*v=m->cx;
 else if(off==0x100c)*v=m->gx;
 else if(off==0x1064)*v=m->gx_gmu;
 else if(off==0x1124)*v=m->cfg;
 else{int i=index_of(off);assert(i>=0&&!m->collapsed);m->clock_reads++;
  if(m->pending[i]&&!--m->pending[i])apply(m,i,m->pending_value[i]);
  *v=(m->live_zero_reset&&i==4&&
       ((m->live_zero_reset==1&&m->clock.step==9)||(m->live_zero_reset==2&&m->clock.step==10)))?0:m->reg[i];}
 return true;
}
static bool wr(void *p,unsigned region,uint32_t off,uint32_t value){
 struct mock *m=p;assert(region==1);m->writes++;
 if(off==A630_CX_REQUEST){
  assert(((value^m->cx)&~1u)==0);m->cx=value;
  if(value&1){m->hw&=~A630_POWER_ON;m->collapsed=1;}
  else{m->hw|=A630_POWER_ON;m->cx_cycled=1;}
 }else{
  int i=index_of(off);assert(i>0&&(m->hw&A630_POWER_ON)&&!m->collapsed);
  assert(((value^m->reg[i])&~a630_clock_masks[i])==0);
  if(i<4)assert(m->reg[4]&1); /* Reset before any clock write. */
  if(i==4&&!(value&1))assert((m->reg[2]&A630_POWER_ON)&&(m->reg[3]&A630_POWER_ON));
  if(m->drop_index!=(unsigned)i+1){
   if(m->ack_delay){m->pending[i]=m->ack_delay;m->pending_value[i]=value;}
   else apply(m,i,value);
  }
 }
 return m->writes!=m->fail_write; /* Fail after a posted write. */
}
static void wait_us(void *p,uint32_t us){assert(us==1);((struct mock*)p)->waits++;}
static struct mock fresh(void){return (struct mock){.reg={0,0x80000000,0x80000200,0x80004220,0},
 .cfg=1,.hw=0x80005ff4,.gx_gmu=0x80000000,.cx=0x222000};}
static unsigned trial(struct mock *m){return a630_clock_trial(true,true,rd,wr,wait_us,m,&m->clock);}
static void clock_hook(void *p){struct mock *m=p;assert(m->hw&A630_POWER_ON);trial(m);}
static bool held_hook(void *p){struct mock *m=p;
 assert(m->hw&A630_POWER_ON);assert(m->reg[4]&1);
 assert(!(m->reg[1]&A630_POWER_ON)&&!(m->reg[2]&A630_POWER_ON)&&!(m->reg[3]&A630_POWER_ON));
 return false;}
int main(void){
 struct mock m=fresh();struct a630_clock_snapshot s;
 assert(a630_clock_trial(false,true,rd,wr,wait_us,&m,&s)==A630_CLK_DISABLED&&!m.reads);
 assert(a630_clock_trial(true,false,rd,wr,wait_us,&m,&s)==A630_CLK_DISABLED&&!m.reads);
 for(unsigned refusal=0;refusal<12;refusal++){
  m=fresh();switch(refusal){
   case 0:m.ahb=A630_POWER_ON;break;case 1:m.hw=0;break;
   case 2:m.gx=A630_POWER_ON;break;case 3:m.gx_gmu|=1;break;
   case 4:m.cfg|=0x500;break;case 5:m.cfg|=0x100000;break;
   case 6:m.cfg=2;break;case 7:m.reg[2]|=1;break;
   case 8:m.reg[2]&=~A630_POWER_ON;break;case 9:m.reg[3]|=1;break;
   case 10:m.reg[1]|=2;break;case 11:m.reg[4]=1;break;
  }
  assert(trial(&m)==A630_CLK_REFUSED&&!m.writes);
 }
 m=fresh();assert(trial(&m)==A630_CLK_READY_RESTORED);
 assert(!(m.clock.changed&1)&&m.clock.before[0]==0&&m.clock.live[0]==0&&m.clock.after[0]==0);
 assert(m.clock.restored&&m.reg[2]==0x80000200&&m.reg[3]==0x80004220&&!m.reg[4]);
 assert(!(m.clock.live[2]&A630_POWER_ON)&&!(m.clock.live[3]&A630_POWER_ON)&&(m.clock.live[4]&1));
 unsigned reads=m.reads,writes=m.writes;
 m=fresh();assert(a630_clock_trial_with_hook(true,true,rd,wr,wait_us,&m,&m.clock,held_hook,&m)==A630_CLK_READY_RESET_HELD);
 assert(m.clock.reset_retained&&!m.clock.restored&&m.reg[4]==1);
 assert(m.reg[2]==0x80000200&&m.reg[3]==0x80004220);
 m=fresh();m.live_zero_reset=2;
 assert(a630_clock_trial_with_hook(true,true,rd,wr,wait_us,&m,&m.clock,held_hook,&m)==A630_CLK_RESTORE_FAILED);
 assert(m.clock.reset_retained&&m.clock.failed_expected==1&&m.clock.failed_value==0&&m.clock.failed_offset==0x111c);
 m=fresh();m.stall_disable=1;
 assert(a630_clock_trial_with_hook(true,true,rd,wr,wait_us,&m,&m.clock,held_hook,&m)==A630_CLK_RESTORE_FAILED);
 assert(m.reg[4]==1&&!m.clock.restored);
 /* AON is not in the phone's GMU consumer clock list. A zero, off or
  * hardware-controlled observation must never lead to an AON write or
  * suppress verification of the clocks the GMU actually consumes. */
 for(unsigned aon=0;aon<4;aon++){
  m=fresh();m.reg[0]=((aon&1)?A630_POWER_ON:0)|((aon&2)?2u:0);
  assert(trial(&m)==A630_CLK_READY_RESTORED&&m.clock.restored);
  assert(!(m.clock.changed&1)&&m.reg[0]==m.clock.before[0]);
 }
 for(unsigned fail=1;fail<=reads;fail++){
  m=fresh();m.fail_read=fail;unsigned e=trial(&m);
  assert(e==A630_CLK_IO||e==A630_CLK_RESTORE_FAILED);
  assert(!m.clock.changed||m.clock.restored||e==A630_CLK_RESTORE_FAILED);
 }
 for(unsigned fail=1;fail<=writes;fail++){
  m=fresh();m.fail_write=fail;unsigned e=trial(&m);
  assert(e==A630_CLK_IO||e==A630_CLK_RESTORE_FAILED);
  assert(!m.clock.changed||m.clock.restored||e==A630_CLK_RESTORE_FAILED);
 }
 /* Successful delayed requests must not be classified as I/O failure. */
 for(unsigned delay=1;delay<=500;delay+=499){
  m=fresh();m.ack_delay=delay;assert(trial(&m)==A630_CLK_READY_RESTORED);
  assert(m.clock.restored&&!m.clock.failed_op&&m.clock.request_polls>=delay);
 }
 m=fresh();m.ack_delay=501;assert(trial(&m)==A630_CLK_RESTORE_FAILED&&!m.clock.restored);
 assert(m.clock.failed_step==2&&m.clock.failed_op==3&&m.clock.failed_offset==0x111c);
 for(unsigned drop=2;drop<=5;drop++){
  m=fresh();m.drop_index=drop;assert(trial(&m)==A630_CLK_REQUEST_TIMEOUT&&m.clock.restored);
  assert(m.clock.failed_op==3&&m.clock.failed_offset==a630_clock_offsets[drop-1]);
 }
 m=fresh();m.live_zero_reset=1;assert(trial(&m)==A630_CLK_STATE_CHANGED&&m.clock.restored);
 assert(m.clock.failed_step==9&&m.clock.failed_op==5&&m.clock.failed_offset==0x111c);
 m=fresh();m.fail_write=1;m.fail_read=12;assert(trial(&m)==A630_CLK_RESTORE_FAILED);
 assert(m.clock.failed_step==2&&m.clock.failed_op==2&&m.clock.failed_offset==0x111c);
 m=fresh();m.stall_root=1;assert(trial(&m)==A630_CLK_ROOT_TIMEOUT&&m.clock.restored&&m.clock.polls>=500);
 assert(m.clock.failed_step==6&&m.clock.failed_op==4&&m.clock.failed_offset==0x1120);
 m=fresh();m.stall_gmu=1;assert(trial(&m)==A630_CLK_BRANCH_TIMEOUT&&m.clock.restored&&m.clock.polls>=500);
 m=fresh();m.stall_disable=1;assert(trial(&m)==A630_CLK_RESTORE_FAILED&&!m.clock.restored&&(m.reg[4]&1));
 m=fresh();m.cx=0x222001;m.hw=0x5ff4;struct a630_power_snapshot power;
 assert(a630_power_trial_with_hook(true,true,rd,wr,wait_us,&m,&power,clock_hook,&m)==A630_POWER_ON_REQUEST_RESTORED);
 assert(power.request_restored&&m.cx==0x222001&&m.cx_cycled&&m.collapsed);
 assert(m.clock.result==A630_CLK_READY_RESTORED&&m.clock.restored);
 m=fresh();m.cx=0x222001;unsigned before=m.clock_reads;
 assert(a630_power_trial_with_hook(true,false,rd,wr,wait_us,&m,&power,clock_hook,&m)==A630_POWER_DISABLED);
 assert(m.clock_reads==before&&!m.reads&&!m.writes);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / 'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang', '-std=c11', '-O1', '-g',
                            '-fsanitize=address,undefined', '-I', str(ROOT / 'tools'),
                            str(p / 'test.c'), '-o', str(p / 'test')], check=True)
            subprocess.run([str(p / 'test')], check=True)


if __name__ == '__main__':
    unittest.main()
