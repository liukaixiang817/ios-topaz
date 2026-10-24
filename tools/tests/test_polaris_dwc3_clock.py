"""Polaris DT clock-gating quirk: masked ownership and command-safe rollback."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class Dwc3ClockTests(unittest.TestCase):
    def test_ack_ownership_halted_and_busy_command_boundaries(self):
        source = r'''
#include "polaris-dwc3-command.h"
#include "polaris-dwc3-clock.h"
#include <assert.h>
#include <string.h>
struct model {
 uint32_t gctl,dctl,dsts,cmd[6],reads,writes,waits;
 uint32_t delay,pending,request,ignore;
};
static uint32_t read_io(void *p,uint32_t off) {
 struct model *m=p;m->reads++;
 if(off==0xc110) {
  if(m->pending && --m->pending==0)m->gctl=m->request;
  return m->gctl;
 }
 if(off==0xc704)return m->dctl;
 if(off==0xc70c)return m->dsts;
 assert(off>=0xc80c && off<=0xc85c && (off-0xc80c)%16==0);
 return m->cmd[(off-0xc80c)/16];
}
static void write_io(void *p,uint32_t off,uint32_t value) {
 struct model *m=p;m->writes++;assert(off==0xc110);
 assert(!((value^m->gctl)&~1u));
 if(m->ignore)return;
 m->request=value;
 if(m->delay)m->pending=m->delay;else m->gctl=value;
}
static void wait_io(void *p,uint32_t us) {struct model *m=p;assert(us==1);m->waits++;}
static void init(struct model *m) {memset(m,0,sizeof(*m));m->gctl=0x112000;m->dsts=1u<<22;}
int main(void) {
 struct model m;struct pdwc3_gate s;
 struct pdwc3_io io={&m,read_io,write_io,wait_io};
 init(&m);assert(polaris_dwc3_clock_begin(0,true,&s)==PDWC3_GATE_ARGUMENT);
 assert(polaris_dwc3_clock_begin(&io,true,0)==PDWC3_GATE_ARGUMENT);
 assert(polaris_dwc3_clock_begin(&io,false,&s)==PDWC3_GATE_UNSAFE);
 assert(!m.reads&&!m.writes&&!s.attempted);
 for(unsigned n=0;n<5;n++) {
  init(&m);
  if(n==0)m.dctl=1u<<31;if(n==1)m.dctl=1u<<30;
  if(n==2)m.dsts=0;if(n==3)m.gctl=(m.gctl&~0x3000u)|0x1000;
  if(n==4)m.gctl|=1u<<11;
  assert(polaris_dwc3_clock_begin(&io,true,&s)==PDWC3_GATE_UNSAFE);
  assert(s.start_error==PDWC3_GATE_UNSAFE&&!m.writes);
 }
 init(&m);assert(!polaris_dwc3_clock_begin(&io,true,&s));
 assert(m.gctl==0x112001 && s.changed && m.writes==1 && s.polls==1);
 m.gctl|=1u<<23; /* unrelated live field must survive rollback */
 assert(!polaris_dwc3_clock_restore(&io,&s));
 assert(s.restored && !s.error && m.gctl==(0x112000|(1u<<23)) && m.writes==2);
 init(&m);m.gctl|=1;
 assert(!polaris_dwc3_clock_begin(&io,true,&s));assert(!s.changed&&!m.writes);
 m.cmd[0]=0x402;assert(!polaris_dwc3_clock_restore(&io,&s));
 assert(s.restored&&m.gctl==0x112001&&!m.writes);
 for(unsigned n=0;n<6;n++) {
  init(&m);assert(!polaris_dwc3_clock_begin(&io,true,&s));m.cmd[n]=0x402;
  assert(polaris_dwc3_clock_restore(&io,&s)==PDWC3_GATE_COMMAND_ACTIVE);
  assert(!s.restored&&m.gctl==0x112001&&m.writes==1);
  assert(s.busy_ep==n&&s.busy_command==0x402);
  m.cmd[n]=0;assert(!polaris_dwc3_clock_restore(&io,&s));
  assert(s.restored&&!s.error&&m.gctl==0x112000&&m.writes==2);
 }
 for(unsigned n=0;n<2;n++) {
  init(&m);assert(!polaris_dwc3_clock_begin(&io,true,&s));
  if(n==0)m.dctl=1u<<31;else m.dsts=0;
  assert(polaris_dwc3_clock_restore(&io,&s)==PDWC3_GATE_UNSAFE);
  assert(!s.restored&&m.writes==1&&(m.gctl&1));
 }
 const unsigned delayed[2]={1,1000};
 for(unsigned n=0;n<2;n++) {
  init(&m);m.delay=delayed[n];assert(!polaris_dwc3_clock_begin(&io,true,&s));
  assert(s.polls==delayed[n]&&(m.gctl&1));
  assert(!polaris_dwc3_clock_restore(&io,&s));
  assert(s.restore_polls==delayed[n]&&s.restored&&!(m.gctl&1));
 }
 init(&m);m.ignore=1;
 assert(polaris_dwc3_clock_begin(&io,true,&s)==PDWC3_GATE_ACK_TIMEOUT);
 assert(s.polls==1000&&s.start_error==PDWC3_GATE_ACK_TIMEOUT);
 m.ignore=0;assert(!polaris_dwc3_clock_restore(&io,&s));
 assert(s.restored&&s.error==PDWC3_GATE_ACK_TIMEOUT&&!(m.gctl&1));
 init(&m);assert(!polaris_dwc3_clock_begin(&io,true,&s));m.ignore=1;
 assert(polaris_dwc3_clock_restore(&io,&s)==PDWC3_GATE_RESTORE_TIMEOUT);
 assert(!s.restored&&s.restore_polls==1000&&(m.gctl&1));
 init(&m);m.delay=1001;
 assert(polaris_dwc3_clock_begin(&io,true,&s)==PDWC3_GATE_ACK_TIMEOUT);
 assert(s.polls==1000);m.delay=0;
 assert(!polaris_dwc3_clock_restore(&io,&s)&&s.restored);
 init(&m);assert(!polaris_dwc3_clock_begin(&io,true,&s));
 assert(!polaris_dwc3_clock_restore(&io,&s)&&s.restored);
 /* A repeated failed cleanup must clear the previous restored flag. */
 m.dctl=1u<<31;
 assert(polaris_dwc3_clock_restore(&io,&s)==PDWC3_GATE_UNSAFE&&!s.restored);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang', '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                            '-I', str(ROOT / 'tools'), str(path / 'test.c'), '-o', str(path / 'test')], check=True)
            subprocess.run([str(path / 'test')], check=True)


if __name__ == '__main__':
    unittest.main()
