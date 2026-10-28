"""Real pure button filter, not PMIC reads or physical key/HID success."""
from pathlib import Path
import unittest
from .test_polaris_gpu_bootstrap import run
ROOT=Path(__file__).resolve().parents[2]
H='#include "'+str(ROOT/'tools/polaris-buttons.h')+'"\n'


class ButtonPolicyTests(unittest.TestCase):
    def test_original_pon_masks_and_active_low_GPIO(self):
        run(H+r'''
#include <assert.h>
int main(void){
 assert(polaris_button_levels(0,1)==0);
 assert(polaris_button_levels(1,1)==1);
 assert(polaris_button_levels(2,1)==4);
 assert(polaris_button_levels(0,0)==2);
 assert(polaris_button_levels(3,0)==7);
 for(unsigned p=0;p<256;p++) { for(unsigned g=0;g<256;g++){
  unsigned result=polaris_button_levels(p,g);assert(!(result&~7));
  assert(!!(result&1)==!!(p&1));assert(!!(result&4)==!!(p&2));
  assert(!!(result&2)==!(g&1));
 }}
 return 0;}
''')

    def test_initially_held_needs_real_release_and_bounce_cannot_press(self):
        run(H+r'''
#include <assert.h>
int main(void){struct polaris_button_filter s={0};struct polaris_button_change c;
 assert(polaris_button_sample(&s,1,true,7,&c)&&!c.changed);
 for(unsigned n=1;n<100;n++){
  assert(polaris_button_sample(&s,1+n*20000,true,7,&c)&&!c.changed&&!s.stable);
 }
 assert(polaris_button_sample(&s,2000001,true,0,&c)&&!c.changed);
 assert(polaris_button_sample(&s,2015000,true,0,&c)&&!s.seen_released);
 assert(polaris_button_sample(&s,2015001,true,0,&c)&&s.seen_released==7);
 for(unsigned key=0;key<3;key++){
  uint64_t t=3000000+key*100000;unsigned m=1u<<key;
  assert(polaris_button_sample(&s,t,true,m,&c)&&!c.changed);
  assert(polaris_button_sample(&s,t+1000,true,0,&c)&&!c.changed);
  assert(polaris_button_sample(&s,t+2000,true,m,&c)&&!c.changed);
  assert(polaris_button_sample(&s,t+16999,true,m,&c)&&!c.changed);
  assert(polaris_button_sample(&s,t+17000,true,m,&c)&&c.changed==m&&c.pressed==m);
  assert(polaris_button_sample(&s,t+18000,true,m,&c)&&!c.changed);
  assert(polaris_button_sample(&s,t+20000,true,0,&c)&&!c.changed);
  assert(polaris_button_sample(&s,t+35000,true,0,&c)&&c.changed==m&&!c.pressed);
 }return 0;}
''')

    def test_failed_sample_releases_only_delivered_keys_and_never_resumes(self):
        run(H+r'''
#include <assert.h>
int main(void){
 for(unsigned fault=0;fault<5;fault++){
  struct polaris_button_filter s={0};struct polaris_button_change c;
  assert(polaris_button_sample(&s,1,true,0,&c));
  assert(polaris_button_sample(&s,15001,true,0,&c));
  assert(polaris_button_sample(&s,16001,true,5,&c));
  assert(polaris_button_sample(&s,31001,true,5,&c)&&c.changed==5);
  uint64_t now=fault==1?0:fault==2?31000:fault==3?31001:32000;
  assert(!polaris_button_sample(&s,now,fault!=0,fault==4?8:5,&c));
  assert(s.fault&&c.changed==5&&!c.pressed&&!s.stable);
  assert(!polaris_button_sample(&s,100000,true,7,&c)&&!c.changed&&!c.pressed);
 }
 struct polaris_button_filter s={0};struct polaris_button_change c;
 assert(!polaris_button_sample(&s,0,false,7,&c)&&!c.changed);
 assert(!polaris_button_sample(0,1,true,0,&c));return 0;}
''')

    def test_independent_held_key_and_clock_near_integer_end(self):
        run(H+r'''
#include <assert.h>
int main(void){struct polaris_button_filter s={0};struct polaris_button_change c;
 uint64_t t=UINT64_MAX-100000;
 assert(polaris_button_sample(&s,t,true,4,&c));
 assert(polaris_button_sample(&s,t+15000,true,4,&c)&&s.seen_released==3&&!s.stable);
 assert(polaris_button_sample(&s,t+16000,true,7,&c));
 assert(polaris_button_sample(&s,t+31000,true,7,&c)&&c.changed==3&&c.pressed==3);
 assert(polaris_button_sample(&s,UINT64_MAX,true,7,&c)&&!c.changed);
 assert(!polaris_button_sample(&s,1,true,0,&c)&&s.fault&&c.changed==3);
 return 0;}
''')


if __name__=='__main__':unittest.main()
