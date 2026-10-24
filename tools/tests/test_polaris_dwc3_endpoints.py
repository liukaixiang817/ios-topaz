"""Actual HS endpoint helper: resource order, exact parameters, stop on failure."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class Dwc3EndpointsTests(unittest.TestCase):
    def test_resource_allocation_precedes_configuration(self):
        source = r'''
#include "polaris-dwc3-endpoints.h"
#include <assert.h>
struct mock {unsigned calls,fail;uint32_t command[12][5];};
static int cmd(void *p,unsigned ep,uint32_t c,uint32_t p0,uint32_t p1,uint32_t p2){
 struct mock *m=p;unsigned n=m->calls++;assert(n<12);
 m->command[n][0]=ep;m->command[n][1]=c;m->command[n][2]=p0;
 m->command[n][3]=p1;m->command[n][4]=p2;return m->calls==m->fail?-1:0;
}
int main(void){
 struct mock m={0};assert(polaris_dwc3_ep0(cmd,&m)==0&&m.calls==9);
 assert(m.command[0][0]==0&&m.command[0][1]==9&&!m.command[0][2]);
 for(unsigned i=1;i<=6;i++)assert(m.command[i][0]==i-1&&m.command[i][1]==2&&m.command[i][2]==1&&!m.command[i][3]);
 for(unsigned ep=0;ep<2;ep++){
  uint32_t *c=m.command[7+ep];assert(c[0]==ep&&c[1]==1&&c[2]==(64u<<3));
  assert(c[3]==((1u<<8)|(1u<<10)|(ep<<25))&&!c[4]);
 }
 for(unsigned fail=1;fail<=9;fail++){m=(struct mock){.fail=fail};assert(polaris_dwc3_ep0(cmd,&m)==-1&&m.calls==fail);}
 assert(polaris_dwc3_ep0(0,&m)==-1);
 m=(struct mock){0};assert(!polaris_dwc3_ecm(cmd,&m)&&m.calls==3);
 assert(m.command[0][0]==2&&m.command[1][0]==3&&m.command[2][0]==5);
 for(unsigned i=0;i<3;i++)assert(m.command[i][1]==1); /* No second DEPSTARTCFG/resource. */
 assert(m.command[0][2]==((2u<<1)|(512u<<3)));
 assert(m.command[1][2]==((2u<<1)|(512u<<3)|(1u<<17)));
 assert(m.command[2][2]==((3u<<1)|(16u<<3)|(2u<<17)));
 for(unsigned fail=1;fail<=3;fail++){m=(struct mock){.fail=fail};assert(polaris_dwc3_ecm(cmd,&m)==-1&&m.calls==fail);}
 assert(polaris_dwc3_ecm(0,&m)==-1);
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
