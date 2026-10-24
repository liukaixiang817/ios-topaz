"""Original SDM845 source/rate admission and reversible bus requests."""
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[2]

class A630BusTests(unittest.TestCase):
    def test_rate_ownership_and_unwind(self):
        source = r'''
#include "polaris-a630-probe.h"
#include "polaris-a630-power.h"
#include "polaris-a630-bus.h"
#include <assert.h>
#include <string.h>
struct model {uint32_t r[2][0x90000/4],saved[2][0x90000/4];unsigned op,fail,writes;bool held,stuck;};
static struct model m;
static bool op(struct model *x){return ++x->op!=x->fail;}
static bool held(void *x){return ((struct model*)x)->held;}
static bool rd(void *ctx,unsigned b,uint32_t o,uint32_t *v){struct model *x=ctx;assert(b<2&&o<0x90000);if(!op(x))return false;*v=x->r[b][o/4];return true;}
static bool wr(void *ctx,unsigned b,uint32_t o,uint32_t v){
 struct model *x=ctx;assert(x->held);assert((b==0&&(o==0x52004||o==0x44038||o==0x7100c||o==0x71018))||(b==1&&(o==0x1120||o==0x1124)));
 x->writes++;x->r[b][o/4]=v;
 if(b==0&&o!=0x52004&&!x->stuck)x->r[b][o/4]=(v&1)?v&~0x80000000u:v|0x80000000u;
 if(b==1&&o==0x1120&&!x->stuck)x->r[b][o/4]&=~1u;
 return op(x);
}
static void wait_us(void *ctx,uint32_t us){(void)ctx;assert(us==1||us==10||us==500);}
static const struct a630_bus_io io={rd,wr,wait_us,held,&m};
static void reset(void){
 memset(&m,0,sizeof(m));m.held=true;
 m.r[0][0]=0xc0100001;m.r[0][1]=31;m.r[0][3]=0x103;m.r[0][0x2c/4]=1;m.r[0][0x38/4]=0x4000;
 m.r[0][0x52004/4]=0x123;m.r[0][0x44038/4]=0x80004000;
 m.r[0][0x7100c/4]=0x80004220;m.r[0][0x71018/4]=0x80000001;
 m.r[1][0x1120/4]=2;m.r[1][0x1124/4]=1;
 memcpy(m.saved,m.r,sizeof(m.r));
}
static void restored(void){
 for(unsigned b=0;b<2;b++)for(unsigned n=0;n<0x90000/4;n++){
  uint32_t mask=(b==0&&(n==0x44038/4||n==0x7100c/4||n==0x71018/4))?0x7fffffff:0xffffffff;
  assert(!((m.r[b][n]^m.saved[b][n])&mask));
 }
}
int main(void){struct a630_bus_snapshot s;
 reset();assert(a630_bus_begin(false,&io,&s)==A630_BUS_DISABLED&&!m.op);
 m.held=false;assert(a630_bus_begin(true,&io,&s)==A630_BUS_LEASE&&!m.op);
 reset();assert(a630_bus_begin(true,&io,&s)==A630_BUS_READY);unsigned count=m.op;
 assert(m.r[1][0x1124/4]==0x602&&m.r[0][0x52004/4]==0x10123);
 assert(m.r[0][0x44038/4]==0x4001&&m.r[0][0x7100c/4]==0x4221&&m.r[0][0x71018/4]==1);
 assert(a630_bus_end(&io,&s)&&s.restored);restored();
 for(unsigned fail=1;fail<=count;fail++){
  reset();m.fail=fail;assert(a630_bus_begin(true,&io,&s)==A630_BUS_IO);
  m.fail=0;assert(a630_bus_end(&io,&s));restored();assert(s.error==A630_BUS_IO);
 }
 reset();assert(a630_bus_begin(true,&io,&s)==A630_BUS_READY);
 m.op=0;assert(a630_bus_end(&io,&s));unsigned cleanup=m.op;
 for(unsigned fail=1;fail<=cleanup;fail++){
  reset();assert(a630_bus_begin(true,&io,&s)==A630_BUS_READY);
  m.op=0;m.fail=fail;assert(!a630_bus_end(&io,&s)&&s.restore_error&&!s.restored);
  m.fail=0;assert(a630_bus_end(&io,&s));restored();
 }
 for(unsigned n=0;n<5;n++){
  reset();const unsigned offs[]={0,4,0xc,0x2c,0x38};m.r[0][offs[n]/4]=0;
  assert(a630_bus_begin(true,&io,&s)==A630_BUS_PLL&&!m.writes);
 }
 reset();m.stuck=true;assert(a630_bus_begin(true,&io,&s)==A630_BUS_TIMEOUT);
 assert(s.offset==0x44038&&s.polls==500);m.stuck=false;assert(a630_bus_end(&io,&s));restored();
 reset();assert(a630_bus_begin(true,&io,&s)==A630_BUS_READY);m.held=false;
 unsigned writes=m.writes;assert(!a630_bus_end(&io,&s)&&m.writes==writes);return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory);(p/'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror',
                            '-fsanitize=address,undefined','-I',str(ROOT/'tools'),str(p/'test.c'),'-o',str(p/'test')],check=True)
            subprocess.run([str(p/'test')],check=True)

if __name__ == '__main__':unittest.main()
