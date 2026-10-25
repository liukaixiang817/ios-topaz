"""Presentation interval keeps its requested limit and caps outlier backoff."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class DisplayCadenceTests(unittest.TestCase):
    def test_frame_budget_and_integer_limits(self):
        source = r'''
#include "polaris-display-cadence.h"
#include <assert.h>
int main(void){
 assert(polaris_fb_interval_us(20,10458)==50000);
 assert(polaris_fb_interval_us(20,40000)==160000);
 assert(polaris_fb_interval_us(20,60000)==200000);
 assert(polaris_fb_interval_us(20,UINT32_MAX)==200000);
 assert(polaris_fb_interval_us(0,0)==100000);
 assert(polaris_fb_interval_us(60,0)==33334);
 assert(polaris_fb_interval_us(1,UINT32_MAX)==1000000);
 for(unsigned hz=1;hz<300;hz++)for(unsigned us=0;us<100000;us+=97){
  uint32_t limit=hz>30?30:hz,base=(1000000u+limit-1)/limit;
  uint32_t value=polaris_fb_interval_us(hz,us);
  assert(value>=base&&value>0);
  assert(value<=200000||value==base);
  if(us<=50000)assert(value>=us*4);
 }
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


    def test_gpu_budget_and_work_accounted_tick_never_spin(self):
        source = r'''
#include "polaris-display-cadence.h"
#include <assert.h>
int main(void){
 assert(polaris_fb_gpu_interval_us(60,0)==16667);
 assert(polaris_fb_gpu_interval_us(60,9977)==19954);
 assert(polaris_fb_gpu_interval_us(60,40000)==80000);
 assert(polaris_fb_gpu_interval_us(60,UINT32_MAX)==200000);
 assert(polaris_fb_gpu_tick_us(0)==16667&&polaris_fb_gpu_tick_us(9977)==6690);
 assert(polaris_fb_gpu_tick_us(15667)==1000&&polaris_fb_gpu_tick_us(UINT32_MAX)==1000);
 for(unsigned hz=1;hz<300;hz++)for(unsigned cost=0;cost<200000;cost+=97){
  unsigned cap=hz>60?60:hz,base=(1000000u+cap-1)/cap;
  unsigned value=polaris_fb_gpu_interval_us(hz,cost);
  assert(value>=base&&(value<=200000||value==base));
  if(cost<=100000)assert(value>=cost*2);
  assert(polaris_fb_gpu_tick_us(cost)>=1000&&polaris_fb_gpu_tick_us(cost)<=16667);
 }
 return 0;}
'''
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang','-std=c11','-O1','-g','-fsanitize=address,undefined',
                            '-I',str(ROOT/'tools'),str(p/'test.c'),'-o',str(p/'test')],check=True)
            subprocess.run([str(p/'test')],check=True)


if __name__ == '__main__':
    unittest.main()
