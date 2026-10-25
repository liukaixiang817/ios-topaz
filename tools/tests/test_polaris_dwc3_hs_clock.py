"""Original HS PIPE/UTMI sequence, readback boundaries and safe retention."""
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[2]

class Dwc3HSClockTests(unittest.TestCase):
    def test_source_sequence_and_failure_retention(self):
        source = r'''
#include "polaris-dwc3-command.h"
#include "polaris-dwc3-hs-clock.h"
#include <assert.h>
#include <string.h>
struct model {uint32_t q,g,d,s,cmd[6],reads,writes,log[16],ignore,delay,pending,value,settles,pipe,pipe_writes,pipe_ignore,pipe_delay,pipe_pending,pipe_value;};
static uint32_t qr(void *p,uint32_t off){struct model *m=p;assert(off==8);m->reads++;
 if(m->pending&&!--m->pending)m->q=m->value;return m->q;}
static void qw(void *p,uint32_t off,uint32_t v){struct model *m=p;assert(off==8);
 assert(!((m->q^v)&~PDWC3_HS_MASK));assert(m->writes<16);m->log[m->writes++]=v;
 if(m->writes==m->ignore)return;m->value=v;if(m->delay)m->pending=m->delay;else m->q=v;}
static uint32_t cr(void *p,uint32_t off){struct model *m=p;m->reads++;
 if(off==PDWC3_HS_PIPE){if(m->pipe_pending&&!--m->pipe_pending)m->pipe=m->pipe_value;return m->pipe;}
 if(off==0xc110)return m->g;if(off==0xc704)return m->d;if(off==0xc70c)return m->s;
 assert(off>=0xc80c&&off<=0xc85c&&(off&15)==12);return m->cmd[(off-0xc80c)/16];}
static void cw(void *p,uint32_t off,uint32_t v){struct model *m=p;
 assert(off==PDWC3_HS_PIPE&&!((v^m->pipe)&~PDWC3_HS_PIPE_SUSPHY));
 m->pipe_writes++;if(m->pipe_writes==m->pipe_ignore)return;
 m->pipe_value=v;if(m->pipe_delay)m->pipe_pending=m->pipe_delay;else m->pipe=v;}
static void wait_us(void *p,uint32_t us){struct model *m=p;assert(us==1||us==2);if(us==2)m->settles++;}
static void reset(struct model *m){memset(m,0,sizeof(*m));m->q=0x80000024;m->g=0x112001;m->s=1u<<22;m->pipe=0x03080002;}
int main(void){struct model m;struct pdwc3_hs_clock s;
 struct pdwc3_io qs={&m,qr,qw,wait_us},core={&m,cr,cw,wait_us};
 reset(&m);assert(polaris_dwc3_hs_clock_begin(&qs,&core,false,&s)==PDWC3_HS_UNSAFE&&!m.reads);
 assert(polaris_dwc3_hs_clock_begin(0,&core,true,&s)==PDWC3_HS_ARGUMENT);
 for(unsigned n=0;n<6;n++){
  reset(&m);if(n==0)m.d=1u<<31;if(n==1)m.d=1u<<30;if(n==2)m.s=0;
  if(n==3)m.g=0x111001;if(n==4)m.g|=1u<<11;if(n==5)m.q|=1u<<8;
  assert(polaris_dwc3_hs_clock_begin(&qs,&core,true,&s)==PDWC3_HS_UNSAFE&&!m.writes);
 }
 for(unsigned ep=0;ep<6;ep++){
  reset(&m);m.cmd[ep]=0x402;
  assert(polaris_dwc3_hs_clock_begin(&qs,&core,true,&s)==PDWC3_HS_BUSY&&!m.writes);
  assert(s.busy_ep==ep&&s.busy_command==0x402);
 }
 reset(&m);assert(!polaris_dwc3_hs_clock_begin(&qs,&core,true,&s));
 assert(s.stage==5&&s.live==0x8000002d&&s.polls==3&&m.settles==3);
 assert(m.writes==3&&m.log[0]==0x80000124&&m.log[1]==0x8000012d&&m.log[2]==0x8000002d);
 m.q|=1u<<20;
 assert(polaris_dwc3_hs_clock_restore(&qs,&core,&s)&&s.restored);
 assert(m.q==0x80100024&&m.settles==6&&m.writes==6);
 reset(&m);m.q|=9;assert(!polaris_dwc3_hs_clock_begin(&qs,&core,true,&s));
 assert(!s.changed&&m.pipe_writes==1&&!m.writes&&polaris_dwc3_hs_clock_restore(&qs,&core,&s));
 for(unsigned n=1;n<=3;n++){
  reset(&m);m.ignore=n;
  assert(polaris_dwc3_hs_clock_begin(&qs,&core,true,&s)==PDWC3_HS_ACK&&s.stage==n);
  assert(s.polls==999+n);m.ignore=0;
  assert(polaris_dwc3_hs_clock_restore(&qs,&core,&s)&&s.restored&&m.q==0x80000024);
 }
 for(unsigned n=4;n<=6;n++){
  reset(&m);assert(!polaris_dwc3_hs_clock_begin(&qs,&core,true,&s));m.ignore=n;
  assert(!polaris_dwc3_hs_clock_restore(&qs,&core,&s)&&!s.restored&&s.restore_error==PDWC3_HS_ACK);
  m.ignore=0;assert(polaris_dwc3_hs_clock_restore(&qs,&core,&s)&&s.restored&&m.q==0x80000024);
 }
 for(unsigned ep=0;ep<6;ep++){
  reset(&m);assert(!polaris_dwc3_hs_clock_begin(&qs,&core,true,&s));m.cmd[ep]=0x402;
  assert(!polaris_dwc3_hs_clock_restore(&qs,&core,&s)&&s.restore_error==PDWC3_HS_BUSY);
  assert(m.writes==3&&m.q==0x8000002d&&!s.restored);m.cmd[ep]=0;
  assert(polaris_dwc3_hs_clock_restore(&qs,&core,&s)&&m.q==0x80000024);
 }
 for(unsigned n=1;n<=1000;n+=999){
  reset(&m);m.delay=n;assert(!polaris_dwc3_hs_clock_begin(&qs,&core,true,&s));
  assert(s.polls==3*n);assert(polaris_dwc3_hs_clock_restore(&qs,&core,&s)&&s.restore_polls==3*n);
 }
 reset(&m);m.delay=1001;assert(polaris_dwc3_hs_clock_begin(&qs,&core,true,&s)==PDWC3_HS_ACK);
 m.delay=0;assert(polaris_dwc3_hs_clock_restore(&qs,&core,&s)&&s.restored);
 /* PIPE suspension is owned independently of the UTMI mux. */
 reset(&m);assert(!polaris_dwc3_hs_clock_begin(&qs,&core,true,&s));
 assert(s.pipe_before==0x03080002&&s.pipe_live==0x030a0002&&s.pipe_changed);
 m.pipe|=1u<<20;assert(polaris_dwc3_hs_clock_restore(&qs,&core,&s));
 assert(m.pipe==0x03180002); /* unrelated concurrent bit preserved */
 reset(&m);m.pipe|=PDWC3_HS_PIPE_SUSPHY;
 assert(!polaris_dwc3_hs_clock_begin(&qs,&core,true,&s)&&!s.pipe_changed&&!m.pipe_writes);
 assert(polaris_dwc3_hs_clock_restore(&qs,&core,&s)&&!m.pipe_writes);
 reset(&m);m.pipe_ignore=1;
 assert(polaris_dwc3_hs_clock_begin(&qs,&core,true,&s)==PDWC3_HS_ACK&&s.stage==4&&s.pipe_polls==1000);
 m.pipe_ignore=0;assert(polaris_dwc3_hs_clock_restore(&qs,&core,&s)&&m.pipe==0x03080002);
 reset(&m);assert(!polaris_dwc3_hs_clock_begin(&qs,&core,true,&s));m.pipe_ignore=2;
 assert(!polaris_dwc3_hs_clock_restore(&qs,&core,&s)&&s.restore_error==PDWC3_HS_ACK);
 m.pipe_ignore=0;assert(polaris_dwc3_hs_clock_restore(&qs,&core,&s));
 for(unsigned n=1;n<=1000;n+=999){
  reset(&m);m.pipe_delay=n;assert(!polaris_dwc3_hs_clock_begin(&qs,&core,true,&s)&&s.pipe_polls==n);
  assert(polaris_dwc3_hs_clock_restore(&qs,&core,&s)&&s.pipe_restore_polls==n);
 }
 for(unsigned ep=0;ep<6;ep++){
  reset(&m);assert(!polaris_dwc3_hs_clock_begin(&qs,&core,true,&s));m.cmd[ep]=0x402;
  assert(!polaris_dwc3_hs_clock_restore(&qs,&core,&s)&&m.pipe_writes==1&&m.pipe==0x030a0002);
 }
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory); (p/'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror',
                            '-fsanitize=address,undefined','-I',str(ROOT/'tools'),str(p/'test.c'),'-o',str(p/'test')],check=True)
            subprocess.run([str(p/'test')],check=True)

if __name__ == '__main__': unittest.main()
