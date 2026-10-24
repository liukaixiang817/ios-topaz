"""Original Qualcomm RAM master clock requests and busy-command retention."""
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[2]

class Dwc3RAMClockTests(unittest.TestCase):
    def test_masked_request_and_all_ack_boundaries(self):
        source = r'''
#include "polaris-dwc3-command.h"
#include "polaris-dwc3-hs-clock.h"
#include "polaris-dwc3-ram-clock.h"
#include <assert.h>
#include <string.h>
struct model {uint32_t q,g,d,s,cmd[6],reads,writes,ignore,delay,pending,value;};
static uint32_t qr(void *p,uint32_t off){struct model *m=p;assert(off==0x28);m->reads++;
 if(m->pending&&!--m->pending)m->q=m->value;return m->q;}
static void qw(void *p,uint32_t off,uint32_t v){struct model *m=p;assert(off==0x28);
 assert(!((m->q^v)&~0x18u));m->writes++;
 if(m->ignore)return;m->value=v;if(m->delay)m->pending=m->delay;else m->q=v;}
static uint32_t cr(void *p,uint32_t off){struct model *m=p;m->reads++;
 if(off==0xc110)return m->g;if(off==0xc704)return m->d;if(off==0xc70c)return m->s;
 assert(off>=0xc80c&&off<=0xc85c&&(off&15)==12);return m->cmd[(off-0xc80c)/16];}
static void cw(void *p,uint32_t off,uint32_t v){(void)p;(void)off;(void)v;assert(0);}
static void wait_us(void *p,uint32_t us){(void)p;assert(us==1);}
static void reset(struct model *m){memset(m,0,sizeof(*m));m->q=0x80000084;m->g=0x112001;m->s=1u<<22;}
int main(void){struct model m;struct pdwc3_ram_clock s;
 struct pdwc3_io qs={&m,qr,qw,wait_us},core={&m,cr,cw,wait_us};
 reset(&m);assert(polaris_dwc3_ram_clock_begin(&qs,&core,false,&s)==PDWC3_RAM_UNSAFE&&!m.reads);
 assert(polaris_dwc3_ram_clock_begin(0,&core,true,&s)==PDWC3_RAM_ARGUMENT);
 for(unsigned n=0;n<5;n++){
  reset(&m);if(n==0)m.d=1u<<31;if(n==1)m.d=1u<<30;if(n==2)m.s=0;
  if(n==3)m.g=0x111001;if(n==4)m.g|=1u<<11;
  assert(polaris_dwc3_ram_clock_begin(&qs,&core,true,&s)==PDWC3_RAM_UNSAFE&&!m.writes);
 }
 const unsigned initial[]={0,8,16,24};
 for(unsigned n=0;n<4;n++){
  reset(&m);m.q|=initial[n];uint32_t before=m.q;
  assert(!polaris_dwc3_ram_clock_begin(&qs,&core,true,&s));
  assert(s.stage==3&&s.changed==(24u&~initial[n])&&m.q==(before|24));
  assert(m.writes==(n==3?0u:1u));m.q|=1u<<20;
  assert(polaris_dwc3_ram_clock_restore(&qs,&core,&s)&&s.restored);
  assert(m.q==(before|(1u<<20)));
 }
 for(unsigned ep=0;ep<6;ep++){
  reset(&m);m.cmd[ep]=0x402;
  assert(polaris_dwc3_ram_clock_begin(&qs,&core,true,&s)==PDWC3_RAM_BUSY&&!m.writes);
  assert(s.busy_ep==ep&&s.busy_command==0x402);
  reset(&m);assert(!polaris_dwc3_ram_clock_begin(&qs,&core,true,&s));m.cmd[ep]=0x402;
  assert(!polaris_dwc3_ram_clock_restore(&qs,&core,&s)&&s.restore_error==PDWC3_RAM_BUSY);
  assert(!s.restored&&m.writes==1&&m.q==0x8000009c);m.cmd[ep]=0;
  assert(polaris_dwc3_ram_clock_restore(&qs,&core,&s)&&m.q==0x80000084);
 }
 const unsigned delay[]={1,1000};
 for(unsigned n=0;n<2;n++){
  reset(&m);m.delay=delay[n];assert(!polaris_dwc3_ram_clock_begin(&qs,&core,true,&s));
  assert(s.polls==delay[n]);assert(polaris_dwc3_ram_clock_restore(&qs,&core,&s)&&s.restore_polls==delay[n]);
 }
 reset(&m);m.ignore=1;
 assert(polaris_dwc3_ram_clock_begin(&qs,&core,true,&s)==PDWC3_RAM_ACK&&s.polls==1000);
 m.ignore=0;assert(polaris_dwc3_ram_clock_restore(&qs,&core,&s)&&s.restored&&m.q==0x80000084);
 reset(&m);assert(!polaris_dwc3_ram_clock_begin(&qs,&core,true,&s));m.ignore=1;
 assert(!polaris_dwc3_ram_clock_restore(&qs,&core,&s)&&s.restore_error==PDWC3_RAM_ACK&&!s.restored);
 m.ignore=0;assert(polaris_dwc3_ram_clock_restore(&qs,&core,&s)&&m.q==0x80000084);
 reset(&m);m.delay=1001;assert(polaris_dwc3_ram_clock_begin(&qs,&core,true,&s)==PDWC3_RAM_ACK);
 m.delay=0;assert(polaris_dwc3_ram_clock_restore(&qs,&core,&s)&&m.q==0x80000084);
 reset(&m);assert(!polaris_dwc3_ram_clock_begin(&qs,&core,true,&s));m.d=1u<<31;
 assert(!polaris_dwc3_ram_clock_restore(&qs,&core,&s)&&s.restore_error==PDWC3_RAM_UNSAFE);
 assert(m.writes==1&&m.q==0x8000009c);m.d=0;
 assert(polaris_dwc3_ram_clock_restore(&qs,&core,&s)&&m.q==0x80000084);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory);(p/'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror',
                            '-fsanitize=address,undefined','-I',str(ROOT/'tools'),str(p/'test.c'),'-o',str(p/'test')],check=True)
            subprocess.run([str(p/'test')],check=True)

if __name__ == '__main__': unittest.main()
