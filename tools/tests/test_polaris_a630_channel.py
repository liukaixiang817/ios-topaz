"""A630 original HFI register order, cold ACKs and failure containment."""
from pathlib import Path
import subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[2]
class A630ChannelTests(unittest.TestCase):
 def test_hfi_handshake_and_failure_boundaries(self):
  source=r'''
#include "polaris-a630-probe.h"
#include "polaris-a630-power.h"
#include "polaris-a630-channel.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
static uint32_t regs[0x30000/4];
static void *memory;
struct model {unsigned op,fail,writes,waits,doorbells;bool held,oob_stuck,sptp_stuck,hfi_stuck,queue_stuck,bad_seq,bad_id,async_msg;unsigned fw_error,bad_version;uint32_t gx,bcr;};
static struct model m;
static bool op(void){return ++m.op!=m.fail;}
static bool owned(void *x){assert(x==&m);return m.held;}
static bool rd(void *x,unsigned bank,uint32_t off,uint32_t *v){assert(x==&m);if(!op())return false;
 if(bank==1){assert(off==0x100c||off==0x111c);*v=off==0x100c?m.gx:m.bcr;}
 else {assert(bank==2&&off<0x30000&&!(off&3));*v=regs[off/4];}return true;
}
static void response(uint32_t h,unsigned id,unsigned words,uint32_t error,uint32_t value){
 struct a630_hfi_table *t=memory;struct a630_hfi_queue *q=&t->q[1];
 uint32_t *r=(uint32_t*)((unsigned char*)memory+a630_hfi_offset(1));uint32_t data[4];
 assert(a630_hfi_header(id,words,id==101?1:2,0,&data[0]));data[1]=h;data[2]=error;data[3]=value;
 for(unsigned n=0;n<words;n++){r[q->write_index]=data[n];q->write_index=(q->write_index+1)%1024;}
}
static bool wr(void *x,unsigned bank,uint32_t off,uint32_t v){assert(x==&m&&m.held);m.writes++;bool ok=op();
 if(bank==1){assert(off==0x100c);m.gx=v;return ok;}
 assert(bank==2&&off<0x30000&&!(off&3));regs[off/4]=v;
 if(off==A630_CH_INTR_CLEAR)regs[A630_CH_INTR_INFO/4]&=~v;
 if(off==A630_CH_INTR_SET&&v==(1u<<22)&&!m.oob_stuck){
  regs[A630_CH_INTR_INFO/4]|=1u<<30;
  if(regs[A630_CH_BOOT_OPTION/4]==0){assert(regs[A630_CH_GX_VOTE/4]==3&&regs[A630_CH_MX_VOTE/4]==3);m.gx|=1u<<31;}
  else {assert(regs[A630_CH_GX_VOTE/4]==0&&regs[A630_CH_MX_VOTE/4]==0);m.gx&=~(1u<<31);regs[A630_CH_POWER_STATE/4]=15;regs[A630_CH_SPTP_STATUS/4]|=0xc0;}
 }
 if(off==A630_CH_SPTP_CONTROL&&!m.sptp_stuck)regs[A630_CH_SPTP_STATUS/4]=v==0x778000?8:4;
 if(off==A630_CH_HFI_INIT&&!m.hfi_stuck)regs[A630_CH_HFI_STATUS/4]=1;
 if(off==A630_CH_INTR_SET&&v==1){
  m.doorbells++;assert(regs[A630_CH_HFI_STATUS/4]==1);
  struct a630_hfi_table *t=memory;struct a630_hfi_queue *q=&t->q[0];
  uint32_t *r=(uint32_t*)((unsigned char*)memory+a630_hfi_offset(0));uint32_t h=r[q->read_index];unsigned id=h&255,size=(h>>8)&255;
  assert(id==0||id==1);assert(size==(id==0?5:2));
  if(id==0){assert(r[(q->read_index+1)%1024]==0&&r[(q->read_index+2)%1024]==0x60004000&&r[(q->read_index+3)%1024]==16384&&r[(q->read_index+4)%1024]==1);}
  else assert(r[(q->read_index+1)%1024]==0x10010000);
  if(!m.queue_stuck){q->read_index=q->write_index;if(m.async_msg&&id==0)response(h,101,2,0,0);
   if(m.bad_seq)h^=1u<<20;if(m.bad_id)h^=1;
   response(h,126,id==0?3:4,m.fw_error,m.bad_version?0x20000000:0x10010005);regs[A630_CH_INTR_INFO/4]|=1;}
 }
 return ok;
}
static bool sync_io(void *x){assert(x==&m);return op();}
static void wait_io(void *x,uint32_t us){assert(x==&m&&(us==10||us==50));m.waits++;}
static const struct a630_channel_io io={owned,rd,wr,sync_io,wait_io,&m};
static void reset(void){memset(&m,0,sizeof(m));memset(regs,0,sizeof(regs));m.held=true;regs[0x14070/4]=0xbabeface;regs[A630_CH_SPTP_STATUS/4]=0xc4;m.gx=0x222001;assert(a630_hfi_init(memory,16384,0x60000000));}
static bool finish(struct a630_channel_snapshot *s){bool a=a630_channel_slumber(&io,s);m.bcr=1;regs[0x14000/4]=1;return a&&a630_channel_restore(&io,s);}
int main(void){memory=aligned_alloc(16384,16384);assert(memory);struct a630_channel_snapshot s;
 reset();assert(!a630_channel_probe(false,true,&io,memory,&s)&&!m.op&&!m.writes);
 reset();assert(!a630_channel_probe(true,false,&io,memory,&s)&&s.error==A630_CH_ARGUMENT&&!m.op);
 reset();m.held=false;assert(!a630_channel_probe(true,true,&io,memory,&s)&&s.error==A630_CH_LEASE&&!m.writes);
 reset();regs[0x14070/4]=0;assert(!a630_channel_probe(true,true,&io,memory,&s)&&s.error==A630_CH_RUNNING&&!m.writes);
 reset();assert(a630_channel_probe(true,true,&io,memory,&s));unsigned startup=m.op;
 assert(s.stage==7&&s.acks==2&&s.commands==2&&s.version==0x10010005&&s.gx_requested&&s.sptp_requested&&s.hfi_requested);
 assert(finish(&s)&&s.slumber&&s.restored&&!s.restore_error);assert(m.gx==0x222001&&regs[A630_CH_INTR_MASK/4]==0);
 for(unsigned fail=1;fail<=startup;fail++){
  reset();m.fail=fail;assert(!a630_channel_probe(true,true,&io,memory,&s));assert(s.error==A630_CH_IO&&s.start_error==A630_CH_IO);
  m.fail=0;unsigned first=s.error;bool clean=finish(&s);assert(s.error==first);if(!clean)assert(s.restore_error);
 }
 reset();assert(a630_channel_probe(true,true,&io,memory,&s));m.op=0;assert(finish(&s));unsigned cleanup=m.op;
 for(unsigned fail=1;fail<=cleanup;fail++){
  reset();assert(a630_channel_probe(true,true,&io,memory,&s));m.op=0;m.fail=fail;
  assert(!finish(&s)&&s.restore_error&&s.error==A630_CH_READY);
 }
 reset();m.oob_stuck=true;assert(!a630_channel_probe(true,true,&io,memory,&s)&&s.error==A630_CH_TIMEOUT&&s.stage==2);assert(!finish(&s)&&!s.restored);
 reset();m.sptp_stuck=true;assert(!a630_channel_probe(true,true,&io,memory,&s)&&s.error==A630_CH_TIMEOUT&&s.stage==3);
 reset();m.hfi_stuck=true;assert(!a630_channel_probe(true,true,&io,memory,&s)&&s.error==A630_CH_TIMEOUT&&s.stage==4);
 reset();m.queue_stuck=true;assert(!a630_channel_probe(true,true,&io,memory,&s)&&s.error==A630_CH_TIMEOUT&&s.stage==5&&!s.acks);
 reset();m.bad_seq=true;assert(!a630_channel_probe(true,true,&io,memory,&s)&&s.error==A630_CH_PROTOCOL&&!s.acks);
 reset();m.bad_id=true;assert(!a630_channel_probe(true,true,&io,memory,&s)&&s.error==A630_CH_PROTOCOL&&!s.acks);
 reset();m.fw_error=3;assert(!a630_channel_probe(true,true,&io,memory,&s)&&s.error==A630_CH_FW_ERROR&&!s.acks&&s.actual==3);
 reset();m.bad_version=1;assert(!a630_channel_probe(true,true,&io,memory,&s)&&s.error==A630_CH_PROTOCOL&&s.acks==1);
 reset();m.async_msg=true;assert(a630_channel_probe(true,true,&io,memory,&s)&&s.async_messages==1&&s.acks==2);assert(finish(&s));
 reset();assert(a630_channel_probe(true,true,&io,memory,&s));unsigned writes=m.writes;m.held=false;assert(!finish(&s)&&m.writes==writes&&!s.restored);
 free(memory);return 0;
}
'''
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);(p/'test.c').write_text(source)
   subprocess.run(['/usr/bin/clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I',str(ROOT/'tools'),str(p/'test.c'),'-o',str(p/'test')],check=True)
   subprocess.run([str(p/'test')],check=True)
if __name__=='__main__':unittest.main()
