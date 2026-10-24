"""Exercise the real HS request helper, including rollback while halted."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class Dwc3SessionTests(unittest.TestCase):
    def test_hs_ownership_acknowledgement_and_halted_rollback(self):
        source = r'''
#include "polaris-dwc3-command.h"
#include "polaris-dwc3-session.h"
#include <assert.h>
struct mock { uint32_t value,pending_value;unsigned reads,writes,waits,delay,pending,drop; };
static uint32_t rd(void *p,uint32_t off){
 struct mock *m=p;assert(off==0x10);m->reads++;
 if(m->pending&&!--m->pending)m->value=m->pending_value;
 return m->value;
}
static void wr(void *p,uint32_t off,uint32_t value){
 struct mock *m=p;assert(off==0x10); /* Never SS0x30, PHY, DWC3 or a clock. */
 assert(!((m->value^value)&~PDWC3_SESSION_MASK));m->writes++;
 if(m->drop)return;
 if(m->delay){m->pending=m->delay;m->pending_value=value;}
 else m->value=value;
}
static void wait_us(void *p,uint32_t us){assert(us==1);((struct mock*)p)->waits++;}
int main(void){
 const uint32_t bits[4]={0,1u<<20,1u<<28,PDWC3_SESSION_MASK};
 struct pdwc3_session s;struct mock m={0};struct pdwc3_io io={&m,rd,wr,wait_us};
 assert(polaris_dwc3_session_begin(0,&s)==PDWC3_SESSION_ARGUMENT&&!m.reads);
 assert(polaris_dwc3_session_begin(&io,0)==PDWC3_SESSION_ARGUMENT&&!m.reads);
 for(unsigned n=0;n<4;n++){
  m=(struct mock){.value=bits[n]|0x24002};uint32_t before=m.value;
  assert(polaris_dwc3_session_begin(&io,&s)==PDWC3_SESSION_OK);
  assert(s.changed==(PDWC3_SESSION_MASK&~before));
  assert((m.value&PDWC3_SESSION_MASK)==PDWC3_SESSION_MASK);
  assert(m.writes==(n==3?0u:1u));
  m.value^=0x80; /* An unrelated live change must survive rollback. */
  assert(polaris_dwc3_session_restore(&io,&s,true)==PDWC3_SESSION_OK&&s.restored);
  assert(m.value==(before^0x80));
 }
 for(unsigned delay=1;delay<=1000;delay+=999){
  m=(struct mock){.delay=delay};
  assert(polaris_dwc3_session_begin(&io,&s)==PDWC3_SESSION_OK);
  assert(s.polls==delay);
  assert(polaris_dwc3_session_restore(&io,&s,true)==PDWC3_SESSION_OK);
  assert(s.restored&&s.restore_polls==delay&&!m.value);
 }
 m=(struct mock){.drop=1};
 assert(polaris_dwc3_session_begin(&io,&s)==PDWC3_SESSION_TIMEOUT&&s.polls==1000);
 assert(polaris_dwc3_session_restore(&io,&s,true)==PDWC3_SESSION_OK&&s.restored);
 assert(s.error==PDWC3_SESSION_TIMEOUT&&s.start_error==PDWC3_SESSION_TIMEOUT);
 /* A later rollback failure must not erase the original activation error. */
 m.value=PDWC3_SESSION_MASK;
 assert(polaris_dwc3_session_restore(&io,&s,true)==PDWC3_SESSION_RESTORE_TIMEOUT);
 assert(s.error==PDWC3_SESSION_RESTORE_TIMEOUT&&s.start_error==PDWC3_SESSION_TIMEOUT);
 assert(!s.restored&&s.restore_polls==1000);
 m=(struct mock){0};assert(!polaris_dwc3_session_begin(&io,&s));
 unsigned writes=m.writes,reads=m.reads;
 assert(polaris_dwc3_session_restore(&io,&s,false)==PDWC3_SESSION_NOT_HALTED);
 assert(!s.restored&&m.writes==writes&&m.reads==reads);
 m=(struct mock){0};assert(!polaris_dwc3_session_begin(&io,&s));m.drop=1;
 assert(polaris_dwc3_session_restore(&io,&s,true)==PDWC3_SESSION_RESTORE_TIMEOUT);
 assert(!s.restored&&s.restore_polls==1000&&m.value==PDWC3_SESSION_MASK);
 m=(struct mock){0};assert(!polaris_dwc3_session_begin(&io,&s));m.delay=1001;
 assert(polaris_dwc3_session_restore(&io,&s,true)==PDWC3_SESSION_RESTORE_TIMEOUT);
 assert(!s.restored&&s.restore_polls==1000);
 /* A request already set by somebody else is never taken over or rewritten. */
 m=(struct mock){.value=PDWC3_SESSION_MASK};assert(!polaris_dwc3_session_begin(&io,&s));
 m.value&=~(1u<<20);assert(!polaris_dwc3_session_restore(&io,&s,true));
 assert(!m.writes&&m.value==(1u<<28)&&s.restored);
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
