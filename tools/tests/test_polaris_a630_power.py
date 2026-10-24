"""Bounded original CX request, refusal boundaries and honest cleanup status."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class A630PowerTests(unittest.TestCase):
    def test_request_only_enable_observation_and_restore(self):
        source = r'''
#include "polaris-a630-probe.h"
#include "polaris-a630-power.h"
#include <assert.h>
struct mock {
 unsigned calls,writes,waits,polls,ack,fail_read,fail_write,other_vote;
 uint32_t cfg,request,hw,gx,values[2];
};
static bool rd(void *p,unsigned region,uint32_t off,uint32_t *v){
 struct mock *m=p;if(++m->calls==m->fail_read)return false;
 if(region==0){assert(off==0x71004);*v=m->cfg;return true;}
 assert(region==1 && !(m->cfg&A630_POWER_ON));
 if(off==A630_CX_REQUEST)*v=m->request;
 else if(off==A630_CX_STATUS){
  if(!(m->request&A630_COLLAPSE) && m->ack && ++m->polls>=m->ack)m->hw|=A630_POWER_ON;
  *v=m->hw;
 }else{assert(off==0x100c);*v=m->gx;}
 return true;
}
static bool wr(void *p,unsigned region,uint32_t off,uint32_t value){
 struct mock *m=p;assert(region==1&&off==A630_CX_REQUEST&&m->writes<2);
 assert(((value^m->request)&~A630_COLLAPSE)==0);
 m->values[m->writes++]=value;m->request=value;
 if((value&A630_COLLAPSE)&&!m->other_vote)m->hw&=~A630_POWER_ON;
 return m->writes!=m->fail_write;
}
static void wait_us(void *p,uint32_t us){assert(us==1);((struct mock*)p)->waits++;}
static struct mock fresh(void){return (struct mock){.request=0x222001,.hw=0x5ff4,.ack=2};}
static unsigned trial(struct mock *m,struct a630_power_snapshot *s){return a630_power_trial(true,true,rd,wr,wait_us,m,s);}
static bool retain(void *p){(void)p;return false;}
int main(void){
 struct a630_power_snapshot s;struct mock m=fresh();
 assert(a630_power_trial(false,true,rd,wr,wait_us,&m,&s)==A630_POWER_DISABLED&&!m.calls);
 assert(a630_power_trial(true,false,rd,wr,wait_us,&m,&s)==A630_POWER_DISABLED&&!m.calls);
 m.cfg=A630_POWER_ON;assert(trial(&m,&s)==A630_POWER_AHB_OFF&&m.calls==1&&!m.writes);
 m=fresh();m.hw|=A630_POWER_ON;assert(trial(&m,&s)==A630_POWER_ALREADY_ON&&!m.writes);
 for(unsigned refusal=0;refusal<4;refusal++){
  m=fresh();if(refusal==0)m.request|=A630_HW_CONTROL;
  else if(refusal==1)m.request&=~A630_COLLAPSE;
  else if(refusal==2)m.gx=A630_POWER_ON;else m.request|=A630_SW_OVERRIDE;
  assert(trial(&m,&s)==A630_POWER_REFUSED&&!m.writes);
 }
 for(unsigned vote=0;vote<2;vote++){
  m=fresh();m.other_vote=vote;
  assert(trial(&m,&s)==A630_POWER_ON_REQUEST_RESTORED);
  assert(s.changed&&s.request_restored&&(s.on_hw&A630_POWER_ON)&&s.polls==2);
  assert(m.writes==2&&m.values[0]==0x222000&&m.values[1]==0x222001);
  assert(s.after==s.before&&s.before_hw==0x5ff4);
  assert(!!(s.after_hw&A630_POWER_ON)==!!vote);
 }
 m=fresh();m.ack=0;assert(trial(&m,&s)==A630_POWER_TIMEOUT);
 assert(s.polls==500&&s.request_restored&&m.request==0x222001);
 m=fresh();m.ack=500;assert(trial(&m,&s)==A630_POWER_ON_REQUEST_RESTORED&&s.polls==500);
 for(unsigned fail=1;fail<=9;fail++){
  m=fresh();m.fail_read=fail;unsigned e=trial(&m,&s);
  assert(e==A630_POWER_IO||e==A630_POWER_RESTORE_FAILED);
  assert(!s.changed||s.request_restored||e==A630_POWER_RESTORE_FAILED);
 }
 m=fresh();m.fail_write=1;assert(trial(&m,&s)==A630_POWER_IO&&s.request_restored);
 m=fresh();m.fail_write=2;assert(trial(&m,&s)==A630_POWER_RESTORE_FAILED&&!s.request_restored);
 m=fresh();assert(a630_power_trial_with_lifetime(true,true,rd,wr,wait_us,&m,&s,0,&m,retain)==A630_POWER_RESOURCES_HELD);
 assert(s.resources_retained&&!s.request_restored&&m.writes==1&&m.request==0x222000);
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
