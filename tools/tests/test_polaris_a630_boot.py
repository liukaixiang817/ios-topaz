"""Fresh A630 GMU boot ACK and every posted-write/cleanup failure boundary."""
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[2]

class A630BootTests(unittest.TestCase):
    def test_fresh_firmware_ack_and_containment(self):
        source=r'''
#include "polaris-a630-probe.h"
#include "polaris-a630-power.h"
#include "polaris-a630-boot.h"
#include <assert.h>
#include <string.h>
static uint32_t gmu[0x30000/4],pdc[0x300000/4],original[48];
struct model {unsigned op,fail,writes,releases,waits;bool held,timeout;uint32_t bcr,gx;};
static struct model m;
static bool owned(void *x){return ((struct model*)x)->held;}
static bool op(struct model *x){return ++x->op!=x->fail;}
static uint32_t *reg(unsigned b,uint32_t o){
 assert(!(o&3));if(b==1){assert(o==0x111c||o==0x100c);return o==0x111c?&m.bcr:&m.gx;}
 assert((b==2&&o<0x30000)||(b==4&&o<0x300000));return b==2?&gmu[o/4]:&pdc[o/4];
}
static bool rd(void *ctx,unsigned b,uint32_t o,uint32_t *v){if(!op(ctx))return false;*v=*reg(b,o);return true;}
static bool wr(void *ctx,unsigned b,uint32_t o,uint32_t v){
 struct model *x=ctx;assert(x->held);x->writes++;*reg(b,o)=v;
 if(b==2&&o==0x14000&&!v){
  x->releases++;
  /* Literal original values: TCM boot2, original compressed chipid,
   * source-specific fence/bus offsets; never enable HFI or GX here. */
  assert(gmu[0x14004/4]==2&&gmu[0x14614/4]==0x60000000);
  assert(gmu[0x14610/4]==1&&gmu[0x14608/4]==0x06030100);
  assert(gmu[0x24c44/4]==0x80a008a0&&gmu[0x1303c/4]==1);
  assert(gmu[0x14300/4]==0x09c40400&&!(gmu[0x14618/4]&1));
  assert(pdc[0x8576c/4]==2&&pdc[0x855dc/4]==1);
  assert((pdc[0x84500/4]&0x80000001)==0x80000001);
  if(!x->timeout)gmu[0x14070/4]=0xbabeface;
 }
 return op(x);
}
static void wait_us(void *ctx,uint32_t us){struct model *x=ctx;assert(us==1||us==20);x->waits++;}
static bool sync_io(void *ctx){return op(ctx);}
static const struct a630_boot_io io={rd,wr,wait_us,owned,sync_io,&m};
static void reset(void){
 memset(&m,0,sizeof(m));memset(gmu,0,sizeof(gmu));memset(pdc,0,sizeof(pdc));m.held=true;
 for(unsigned n=0;n<48;n++){const struct a630_boot_register *r=&a630_boot_profile[n];
  original[n]=0x5a000000+n;*reg(r->bank,r->offset)=original[n];
 }
 gmu[0x14000/4]=1;
}
static void restored(void){
 assert(m.bcr==1&&gmu[0x14000/4]==1);
 for(unsigned n=0;n<48;n++){const struct a630_boot_register *r=&a630_boot_profile[n];
  assert(!((*reg(r->bank,r->offset)^original[n])&r->mask));
 }
}
int main(void){struct a630_boot_snapshot s;
 reset();m.held=false;assert(!a630_boot_configure(&io,&s)&&s.error==A630_BOOT_LEASE&&!m.writes);
 reset();gmu[0x14600/4]=1;assert(!a630_boot_configure(&io,&s)&&s.error==A630_BOOT_RUNNING&&!m.writes);
 reset();gmu[0x14070/4]=0xbabeface;assert(!a630_boot_configure(&io,&s)&&!m.writes);
 reset();assert(a630_boot_configure(&io,&s));assert(s.stage==3&&!m.releases);
 unsigned config=m.op;assert(a630_boot_start(&io,&s)&&s.fw==0xbabeface&&m.releases==1);
 unsigned all=m.op;assert(s.error==A630_BOOT_READY&&s.started);
 assert(a630_boot_stop(&io,&s)&&s.stopped&&s.restored);restored();
 for(unsigned fail=1;fail<=all;fail++){
  reset();m.fail=fail;bool configured=a630_boot_configure(&io,&s);
  if(configured)assert(!a630_boot_start(&io,&s));else assert(fail<=config);
  assert(s.error==A630_BOOT_IO);unsigned first=s.error,offset=s.failed_offset;
  m.fail=0;assert(a630_boot_stop(&io,&s));assert(first==s.error&&offset==s.failed_offset);
  /* No profile changes until every snapshot has been saved. */
  if(s.changed)restored();
 }
 reset();assert(a630_boot_configure(&io,&s));assert(a630_boot_start(&io,&s));
 m.op=0;assert(a630_boot_stop(&io,&s));unsigned cleanup=m.op;
 for(unsigned fail=1;fail<=cleanup;fail++){
  reset();assert(a630_boot_configure(&io,&s));assert(a630_boot_start(&io,&s));
  m.op=0;m.fail=fail;assert(!a630_boot_stop(&io,&s)&&!s.restored&&s.restore_error);
  m.fail=0;assert(a630_boot_stop(&io,&s));restored();assert(s.error==A630_BOOT_READY);
 }
 reset();m.timeout=true;assert(a630_boot_configure(&io,&s));assert(!a630_boot_start(&io,&s));
 assert(s.error==A630_BOOT_TIMEOUT&&s.failed_offset==0x14070&&s.polls==10000);
 assert(!s.fw&&m.releases==1);assert(a630_boot_stop(&io,&s));restored();
 reset();assert(a630_boot_configure(&io,&s));assert(a630_boot_start(&io,&s));
 m.held=false;unsigned writes=m.writes;assert(!a630_boot_stop(&io,&s)&&!s.stopped&&m.writes==writes);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory);(p/'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror',
                            '-fsanitize=address,undefined','-I',str(ROOT/'tools'),str(p/'test.c'),'-o',str(p/'test')],check=True)
            subprocess.run([str(p/'test')],check=True)

if __name__ == '__main__':unittest.main()
