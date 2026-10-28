"""Real consumer policy, not a physical key or user-space consumption proof."""
from pathlib import Path
import unittest
from .test_polaris_gpu_bootstrap import run
ROOT=Path(__file__).resolve().parents[2]
H='#include "'+str(ROOT/'tools/polaris-uefi-buttons.h')+'"\n'


class ButtonWireTests(unittest.TestCase):
    def test_exact_edges_independent_hold_heartbeat_and_expiry(self):
        run(H+r'''
#include <assert.h>
int main(void){struct polaris_button_consumer s={0};struct polaris_button_delivery d;
 assert(polaris_button_wire_apply(&s,1,0,10,0,true,100,&d)&&!d.changed);
 assert(polaris_button_wire_apply(&s,2,1,20,0,true,200,&d)&&d.changed==1&&d.pressed==1);
 assert(polaris_button_wire_apply(&s,3,7,30,0,true,300,&d)&&d.changed==6&&d.pressed==7);
 for(unsigned n=4;n<=100;n++){
  assert(polaris_button_wire_apply(&s,n,7,n*10,0,true,n*100,&d)&&!d.changed);
  assert(polaris_button_wire_expire(&s,n*100+749999,&d)&&!d.changed);
 }
 assert(!polaris_button_wire_expire(&s,10000+750000,&d)&&d.changed==7&&!d.pressed&&s.error==3);
 assert(!polaris_button_wire_apply(&s,101,7,2000,0,true,1000000,&d)&&!d.changed);
 return 0;}
''')

    def test_bad_first_press_and_noncanonical_or_failed_snapshots_sticky(self):
        run(H+r'''
#include <assert.h>
int main(void){struct polaris_button_consumer s={0};struct polaris_button_delivery d;
 assert(!polaris_button_wire_apply(&s,1,1,10,0,true,100,&d)&&!d.changed&&s.error==1);
 for(unsigned kind=0;kind<10;kind++){
  s=(struct polaris_button_consumer){0};
  assert(polaris_button_wire_apply(&s,1,0,10,0,true,100,&d));
  assert(polaris_button_wire_apply(&s,2,5,20,0,true,200,&d));
  uint64_t req=kind==0?4:kind==1?2:3,bits=kind==2?8:kind==9?0:5;
  uint64_t sample=kind==3?20:30,now=kind==4?200:kind==5?0:300;
  uint64_t err=kind==7?9:kind>=8?1:0;
  assert(!polaris_button_wire_apply(&s,req,bits,sample,err,kind!=6,now,&d));
  assert(d.changed==5&&!d.pressed&&s.error==(kind==9?2:1));
  assert(!polaris_button_wire_expire(&s,1000000,&d)&&!d.changed);
 }
 s=(struct polaris_button_consumer){.sequence=UINT32_MAX,.sampled_us=1,.received_us=1,.pressed=3};
 assert(!polaris_button_wire_apply(&s,UINT64_C(1)+UINT32_MAX,0,2,0,true,2,&d)&&d.changed==3);
 return 0;}
''')


if __name__=='__main__':unittest.main()
