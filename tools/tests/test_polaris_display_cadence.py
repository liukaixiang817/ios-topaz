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


if __name__ == '__main__':
    unittest.main()
