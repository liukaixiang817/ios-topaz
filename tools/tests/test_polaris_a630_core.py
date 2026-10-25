"""A630 native DCVS, strict PAS authentication and real-command proof boundaries.
Models are protocol/failure tests, never evidence of physical GPU execution.
"""
from pathlib import Path
import subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[2]
def run(source):
 with tempfile.TemporaryDirectory() as directory:
  p=Path(directory);(p/'test.c').write_text(source)
  subprocess.run(['/usr/bin/clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I',str(ROOT/'tools'),str(p/'test.c'),'-o',str(p/'test')],check=True)
  subprocess.run([str(p/'test')],check=True)
class A630CoreTests(unittest.TestCase):
 def test_pm4_wire_headers_with_independent_parity(self):
  run(r'''
#include "polaris-a630-core.h"
#include <assert.h>
int main(void){
 const unsigned counts[]={0,1,7,8,1023,16383};
 for(unsigned op=0;op<128;op++)for(unsigned i=0;i<6;i++){
  unsigned n=counts[i],h=a630_core_pkt7(op,n);
  assert((h&0x3fff)==n&&((h>>16)&127)==op);
  assert(__builtin_parity(h&0xffff)==1&&__builtin_parity((h>>16)&255)==1);
 }
 for(unsigned reg=0;reg<0x40000;reg+=257){
  unsigned h=a630_core_pkt4(reg,1);assert(((h>>8)&0x3ffff)==reg&&(h&127)==1);
  assert(__builtin_parity(h&255)==1&&(__builtin_parity(reg)^((h>>27)&1))==1);
 }
 assert(a630_core_pkt7(0x48,8)==0x70c80008&&a630_core_pkt7(0x3d,3)==0x703d8003&&a630_core_pkt7(0x66,1)==0x70e60001);
 return 0;}
''')
 def test_actual_adapter_secure_shutdown_lifetime(self):
  text=(ROOT/'tools/polaris-a630.c').read_text()
  start=text.index('static void a630_core_attempt(struct a630_io *io)')
  body=text[start:text.index('\n}\n',start)+3]
  run(r'''
#include "polaris-a630-images.h"
#include "polaris-a630-zap.h"
#include "polaris-a630-core.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
struct a630_io {bool core_lease;};
static unsigned mode,seq,starts,cores,stops;
static struct a630_image a630_images[6];
static uintptr_t a630_dma;static uint64_t a630_dma_physical=0x187640000;
static bool a630_core_dma_ready=true;
static struct a630_zap_snapshot a630_zap_saved;static struct a630_core_snapshot a630_core_saved;
static bool a630_core_owned(void*x){return ((struct a630_io*)x)->core_lease;}
static int32_t a630_scm_call(void*x,uint32_t a,uint32_t b,uint64_t c,uint64_t d,uint64_t e,uint64_t*f){(void)x;(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;return 0;}
static bool a630_zap_publish(void*x){return a630_core_owned(x);}
static bool a630_zap_segment(void*x,const uint8_t*d,uint32_t n){(void)d;(void)n;return a630_core_owned(x);}
static bool a630_core_read(void*x,uint32_t w,uint32_t*v){(void)w;(void)v;return a630_core_owned(x);}
static bool a630_core_write(void*x,uint32_t w,uint32_t v){(void)w;(void)v;return a630_core_owned(x);}
static bool a630_gmu_sync(void*x){return a630_core_owned(x);}
static void a630_delay_us(void*x,uint32_t n){(void)x;(void)n;}
static bool start_zap(bool yes,const struct a630_zap_io*io,const struct a630_image*im,uint64_t pa,struct a630_zap_snapshot*z){
 assert(yes&&io->owned(io->ctx)&&im==a630_images&&pa==0x187680000&&++seq==1);starts++;
 if(mode<=2){z->authenticated=1;z->signature=1;z->region=1;z->stage=7;z->error=A630_ZAP_READY;return true;}
 z->stage=mode==3?1:mode==4?4:3;z->signature=mode==4;z->error=mode==6?A630_ZAP_SECURE:A630_ZAP_TRANSPORT;return false;}
static bool run_core(bool a,bool b,bool c,const struct a630_core_io*io,uint32_t*ring,volatile uint32_t*scratch,volatile uint32_t*target,struct a630_core_snapshot*s){
 assert(a&&b&&c&&io->owned(io->ctx)&&++seq==2);assert((uintptr_t)ring==a630_dma+0x30000&&(uintptr_t)scratch==a630_dma+0x38000&&(uintptr_t)target==a630_dma+0x3c000);cores++;
 s->keep_live=mode==1;s->halted=mode!=1;return mode!=1;}
static bool stop_zap(const struct a630_zap_io*io,struct a630_zap_snapshot*z){
 assert(io->owned(io->ctx)&&a630_core_saved.halted&&++seq==3);stops++;z->shutdown=mode!=2;return mode!=2;}
#define a630_zap_start start_zap
#define a630_core_run run_core
#define a630_zap_stop stop_zap
'''+body+r'''
int main(void){a630_dma=(uintptr_t)aligned_alloc(16384,0x44000);assert(a630_dma);
 for(mode=0;mode<7;mode++){
  struct a630_io io={0};seq=starts=cores=stops=0;memset(&a630_zap_saved,0,sizeof(a630_zap_saved));memset(&a630_core_saved,0,sizeof(a630_core_saved));
  a630_core_attempt(&io);assert(!io.core_lease&&starts==1);
  assert(cores==(mode<=2));assert(stops==(mode==0||mode==2));
  assert(a630_core_saved.keep_live==(mode==1||mode==2||mode==4||mode==5));
  if(mode==0)assert(a630_zap_saved.shutdown&&a630_core_saved.halted);
 }free((void*)a630_dma);return 0;}
''')
 def test_actual_adapter_high_pa_dma_and_isolation(self):
  import re
  text=(ROOT/'tools/polaris-a630.c').read_text()
  start=text.index('static bool a630_prepare_dma(void)')
  body=text[start:text.index('\n}\n',start)+3]
  run(r'''
#include "polaris-a630-hfi.h"
#include "polaris-a630-images.h"
#include "polaris-a630-mmu.h"
#include "polaris-a630-core.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
typedef uintptr_t vm_offset_t;typedef uintptr_t addr64_t;typedef uint64_t ppnum_t;
#define PAGE_SIZE 16384u
#define PAGE_MASK 16383u
#define KMA_DATA 1
#define KMA_ZERO 2
#define KMA_PERMANENT 4
#define VM_KERN_MEMORY_IOKIT 0
#define KERN_SUCCESS 0
#define VM_WIMG_WCOMB 7u
#define VM_WIMG_MASK 7u
#define ptoa_64(p) ((uint64_t)(p)<<14)
static unsigned kernel_map,kernel_pmap,a630_mode=9,a630_dma_bytes,a630_dma_ready,a630_nc_pages,a630_core_dma_ready;
static vm_offset_t a630_dma;static uint64_t a630_dma_physical;
static struct a630_mmu a630_tables,a630_core_tables;static struct a630_image a630_images[6];
static unsigned attrs[32],alloc_fail,bad_phys;
static int kmem_alloc_contig(unsigned map,vm_offset_t *out,size_t n,unsigned mask,unsigned a,unsigned b,unsigned flags,unsigned tag){
 (void)map;(void)a;(void)b;(void)tag;assert(mask==PAGE_MASK&&flags==7&&n==0x44000);
 if(alloc_fail)return 1;*out=(vm_offset_t)aligned_alloc(PAGE_SIZE,n);assert(*out);memset((void*)*out,0,n);return 0;}
static ppnum_t pmap_find_phys(unsigned map,addr64_t va){(void)map;assert(va>=a630_dma&&va<a630_dma+a630_dma_bytes);return (UINT64_C(0x187640000)+(va-a630_dma)+(bad_phys&&va!=a630_dma?PAGE_SIZE:0))>>14;}
static void pmap_set_cache_attributes(ppnum_t pn,unsigned attr){unsigned i=(unsigned)((ptoa_64(pn)-UINT64_C(0x187640000))/PAGE_SIZE);assert(i<32);attrs[i]=attr;}
static unsigned pmap_cache_attributes(ppnum_t pn){unsigned i=(unsigned)((ptoa_64(pn)-UINT64_C(0x187640000))/PAGE_SIZE);assert(i<32);return attrs[i];}
'''+body+r'''
int main(void){unsigned char sqe[31980]={0},mdt[6684]={0};for(unsigned i=4;i<sizeof(sqe);i++)sqe[i]=(unsigned char)i;
 a630_images[1]=(struct a630_image){sqe,sizeof(sqe)};a630_images[2]=(struct a630_image){mdt,sizeof(mdt)};
 assert(a630_prepare_dma()&&a630_dma_ready&&a630_core_dma_ready&&a630_nc_pages==2);
 assert(a630_dma_physical==UINT64_C(0x187640000)&&a630_tables.capacity==16&&a630_core_tables.capacity==16);
 for(unsigned i=0;i<0x44000/PAGE_SIZE;i++)assert(attrs[i]==(i<8?0:VM_WIMG_WCOMB));
 assert(!memcmp((void*)(a630_dma+0x28000),sqe+4,sizeof(sqe)-4));
 const uint32_t spans[4][3]={{A630_CORE_SQE,0x28000,0x8000},{A630_CORE_RING,0x30000,0x8000},{A630_CORE_SCRATCH,0x38000,0x4000},{A630_CORE_TARGET,0x3c000,0x4000}};
 uint64_t physical,pte;
 for(unsigned k=0;k<4;k++)for(unsigned n=0;n<spans[k][2];n+=4096){
  assert(a630_mmu_lookup(&a630_core_tables,spans[k][0]+n,&physical,&pte)==A630_MMU_OK);
  assert(physical==a630_dma_physical+spans[k][1]+n&&(pte&64));
  assert(!!(pte&128)==(k<2)&&!!(pte&A630_MMU_XN)==(k!=0));
  assert(a630_mmu_lookup(&a630_tables,spans[k][0]+n,&physical,&pte)==A630_MMU_UNMAPPED);
 }
 assert(a630_mmu_lookup(&a630_core_tables,0x60000000,&physical,&pte)==A630_MMU_UNMAPPED);
 assert(a630_mmu_lookup(&a630_core_tables,0x11004000,&physical,&pte)==A630_MMU_UNMAPPED);
 assert(a630_mmu_lookup(&a630_tables,0x60008000,&physical,&pte)==A630_MMU_UNMAPPED);
 free((void*)a630_dma);a630_dma=0;alloc_fail=1;assert(!a630_prepare_dma()&&!a630_dma);
 alloc_fail=0;bad_phys=1;assert(!a630_prepare_dma());free((void*)a630_dma);return 0;}
''')
 def test_post_native_handshake_and_faults(self):
  run(r'''
#include "polaris-a630-probe.h"
#include "polaris-a630-power.h"
#include "polaris-a630-post.h"
#include <assert.h>
#include <string.h>
static struct {uint32_t regs[0x30000/4];unsigned op,fail,writes;bool held,stuck,bad;} m;
static bool op(void){return ++m.op!=m.fail;}
static bool own(void*x){assert(x==&m);return m.held;}
static bool rd(void*x,unsigned b,uint32_t o,uint32_t*v){assert(x==&m&&b==2&&m.held);if(!op())return false;*v=m.regs[o/4];return true;}
static bool wr(void*x,unsigned b,uint32_t o,uint32_t v){assert(x==&m&&b==2&&m.held);bool ok=op();m.writes++;m.regs[o/4]=v;
 if(o==A630_CH_INTR_CLEAR)m.regs[A630_CH_INTR_INFO/4]&=~v;
 if(o==A630_CH_INTR_SET&&v==(1u<<23)){
  assert(m.regs[A630_POST_ACK/4]==0&&m.regs[A630_POST_PERF/4]==0x30000001&&m.regs[A630_POST_BW/4]==4);
  if(!m.stuck)m.regs[A630_CH_INTR_INFO/4]|=1u<<31;m.regs[A630_POST_RETURN/4]=m.bad?7:0;
 }
 if(o==A630_CH_INTR_SET&&v==(1u<<16)&&!m.stuck)m.regs[A630_CH_INTR_INFO/4]|=1u<<24;
 return ok;}
static bool sync_io(void*x){assert(x==&m);return op();}
static void wait_io(void*x,uint32_t n){assert(x==&m&&n==10);}
static const struct a630_channel_io io={own,rd,wr,sync_io,wait_io,&m};
static void reset(void){memset(&m,0,sizeof(m));m.held=true;m.regs[A630_CH_SPTP_STATUS/4]=0x28;}
int main(void){struct a630_post_snapshot s;struct a630_channel_snapshot h={.error=A630_CH_READY,.acks=5,.tables_done=7};
 reset();assert(!a630_post_begin(false,&io,&h,&s)&&!m.op);
 reset();h.acks=4;assert(!a630_post_begin(true,&io,&h,&s)&&s.error==A630_CH_ARGUMENT&&!m.op);h.acks=5;
 reset();assert(a630_post_begin(true,&io,&h,&s)&&s.dcvs_done&&s.gpu_ready&&s.stage==3);unsigned count=m.op;
 assert(a630_post_end(&io,&s)&&s.gpu_released);
 for(unsigned f=1;f<=count;f++){reset();m.fail=f;assert(!a630_post_begin(true,&io,&h,&s)&&s.error==A630_CH_IO);}
 reset();m.held=false;assert(!a630_post_begin(true,&io,&h,&s)&&s.error==A630_CH_LEASE&&!m.writes);
 reset();m.stuck=true;assert(!a630_post_begin(true,&io,&h,&s)&&s.error==A630_CH_TIMEOUT&&!s.gpu_ready);
 reset();m.bad=true;assert(!a630_post_begin(true,&io,&h,&s)&&s.error==A630_CH_FW_ERROR&&s.dcvs_return==7&&!s.gpu_ready);
 reset();m.regs[A630_CH_SPTP_STATUS/4]=0xc4;assert(!a630_post_begin(true,&io,&h,&s)&&s.error==A630_CH_RUNNING);
 return 0;}
''')
 def test_zap_rejected_never_treated_as_loaded(self):
  from tools.tests.test_polaris_a630_firmware import fixture
  images=fixture();names=['a630_gmu.bin','a630_sqe.fw','a630_zap.mdt','a630_zap.b00','a630_zap.b01','a630_zap.b02']
  # Sparse synthetic blobs contain format data, never vendor firmware.
  arrays='\n'.join('static const unsigned char f%d[%d]={%s};'%(i,len(images[n]),','.join(str(v) for v in images[n].rstrip(b'\0'))) for i,n in enumerate(names))
  run(r'''
#include "polaris-a630-zap.h"
#include <assert.h>
#include <string.h>
'''+arrays+r'''
static const struct a630_image images[6]={{f0,sizeof(f0)},{f1,sizeof(f1)},{f2,sizeof(f2)},{f3,sizeof(f3)},{f4,sizeof(f4)},{f5,sizeof(f5)}};
static struct {unsigned calls,bad,secure,published,segments;bool held,publish_fail,segment_fail;} m;
static bool owned(void*x){assert(x==&m);return m.held;}
static int32_t call(void*x,uint32_t fn,uint32_t info,uint64_t a,uint64_t b,uint64_t c,uint64_t*ret){
 assert(x==&m&&m.held);m.calls++;
 const uint32_t ids[]={0xc2000601,0xc2000601,0xc2000601,0xc2000601,0xc2000601,0x42000206,0x42000201,0x42000202,0x42000205,0x42000206};
 assert(m.calls<=10&&fn==ids[m.calls-1]);*ret=m.calls<=5?1:0;
 if(m.calls<=5)assert(info==1&&b==0&&c==0);
 else if(m.calls==7){assert(info==0x82&&a==13&&b==0x187640000&&c==0&&m.published==1);}
 else if(m.calls==8)assert(info==3&&a==13&&b==0x8c415000&&c==4096);
 else {assert(info==1&&a==13&&b==0&&c==0);if(m.calls==9)assert(m.segments==1);}
 if(m.calls==m.secure)*ret^=1;
 return m.calls==m.bad?-12:0;
}
static bool publish(void*x){assert(x==&m&&m.calls==6);m.published++;return !m.publish_fail;}
static bool segment(void*x,const uint8_t*d,uint32_t n){assert(x==&m&&m.calls==8&&d==f5&&n==sizeof(f5));m.segments++;return !m.segment_fail;}
static const struct a630_zap_io io={owned,call,publish,segment,&m};
static void reset(void){memset(&m,0,sizeof(m));m.held=true;}
int main(void){struct a630_zap_snapshot s;
 reset();assert(!a630_zap_start(false,&io,images,0x187640000,&s)&&!m.calls);
 reset();assert(!a630_zap_start(true,&io,images,0x187640001,&s)&&s.error==A630_ZAP_ARGUMENT&&!m.calls);
 reset();m.held=false;assert(!a630_zap_start(true,&io,images,0x187640000,&s)&&s.error==A630_ZAP_LEASE&&!m.calls);
 reset();assert(a630_zap_start(true,&io,images,0x187640000,&s)&&s.authenticated&&s.signature&&s.region&&m.calls==9);
 assert(a630_zap_stop(&io,&s)&&s.shutdown&&m.calls==10&&s.authenticated);
 reset();assert(a630_zap_start(true,&io,images,0x187640000,&s));m.bad=10;
 assert(!a630_zap_stop(&io,&s)&&!s.shutdown&&s.restore_error==A630_ZAP_TRANSPORT&&s.authenticated&&s.error==A630_ZAP_READY);
 reset();assert(a630_zap_start(true,&io,images,0x187640000,&s));m.secure=10;
 assert(!a630_zap_stop(&io,&s)&&!s.shutdown&&s.restore_error==A630_ZAP_SECURE&&s.authenticated);
 for(unsigned i=1;i<=9;i++){
  reset();m.bad=i;assert(!a630_zap_start(true,&io,images,0x187640000,&s)&&!s.authenticated&&s.error==A630_ZAP_TRANSPORT&&m.calls==i);
  reset();m.secure=i;assert(!a630_zap_start(true,&io,images,0x187640000,&s)&&!s.authenticated&&s.error==A630_ZAP_SECURE&&m.calls==i);
 }
 reset();m.publish_fail=true;assert(!a630_zap_start(true,&io,images,0x187640000,&s)&&m.calls==6&&!s.authenticated&&!m.segments);
 reset();m.segment_fail=true;assert(!a630_zap_start(true,&io,images,0x187640000,&s)&&m.calls==8&&!s.authenticated);
 return 0;}
''')
 def test_cp_packets_every_io_and_full_image_proof(self):
  run(r'''
#include "polaris-a630-core.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
static uint32_t regs[65536];static uint32_t *ring,*scratch,*target;
static struct {unsigned op,fail,writes,sent,commands,blits;bool held,stuck,bad_fence,bad_event,bad_pixel,halt_stuck;} m;
static bool op(void){return ++m.op!=m.fail;}
static bool own(void*x){assert(x==&m);return m.held;}
static bool rd(void*x,uint32_t w,uint32_t*v){assert(x==&m&&m.held&&w<65536);if(!op())return false;*v=regs[w];return true;}
static void packets(unsigned end){
 while(m.sent<end){unsigned h=ring[m.sent++],n,op;
  if((h>>28)==4){n=h&127;op=(h>>8)&0x3ffff;assert(n==1&&m.sent+n<=end&&op<65536);regs[op]=ring[m.sent++];continue;}
  assert((h>>28)==7);n=h&0x3fff;op=(h>>16)&127;assert(m.sent+n<=end);unsigned at=m.sent;m.sent+=n;m.commands++;
  if(op==0x48){const uint32_t init[8]={0x2f,3,0x20000000,0,0,0,0,0};assert(n==8&&!memcmp(&ring[at],init,sizeof(init)));}
  else if(op==0x66){assert(n==1&&ring[at]==0);}
  else if(op==0x3d){assert(n==3&&ring[at]==A630_CORE_SCRATCH&&ring[at+1]==0&&ring[at+2]==0x600dc0de);if(!m.bad_fence)scratch[0]=ring[at+2];}
  else if(op==0x26){assert(n==0);}
  else if(op==0x65){assert(n==1&&ring[at]==12);}
  else if(op==0x2c){assert(n==1&&ring[at]==3&&regs[0x8e04]==0x05100000&&regs[0x8e07]==0x10000004);
   assert(regs[0x8c17]==0x430&&regs[0x8c18]==A630_CORE_TARGET&&!regs[0x8c19]&&regs[0x8c1a]==4);
   assert(regs[0x8c00]==0x10f03080&&regs[0x8400]==0x10f03080&&regs[0xacc0]==0xf181);
   unsigned y0=regs[0x8405]>>16,y1=regs[0x8406]>>16;assert(y1<64&&y0<=y1&&(regs[0x8406]&65535)==63);
   uint32_t color=(regs[0x8c2f]<<24)|(regs[0x8c2c]<<16)|(regs[0x8c2d]<<8)|regs[0x8c2e];
   for(unsigned y=y0;y<=y1;y++)for(unsigned x=0;x<64;x++)target[y*64+x]=color;
   if(m.bad_pixel)target[4095]=0;m.blits++;
  }else if(op==0x46){assert(n==4&&ring[at+2]==0);unsigned a=ring[at+1];assert(a==A630_CORE_SCRATCH+32||a==A630_CORE_SCRATCH+16);if(!m.bad_event)scratch[(a-A630_CORE_SCRATCH)/4]=ring[at+3];}
  else assert(0);
 }
}
static bool wr(void*x,uint32_t w,uint32_t v){assert(x==&m&&m.held&&w<65536);m.writes++;bool ok=op();
 if(w==0x808&&v==3&&m.halt_stuck)return ok;regs[w]=v;
 if(w==0x807&&v&&!m.stuck){packets(v);regs[0x806]=v;}
 return ok;}
static bool sync_io(void*x){assert(x==&m);return op();}
static void wait_io(void*x,uint32_t n){assert(x==&m&&n==10);}
static const struct a630_core_io io={own,rd,wr,sync_io,wait_io,&m};
static void reset(void){memset(&m,0,sizeof(m));memset(regs,0,sizeof(regs));m.held=true;}
int main(void){ring=aligned_alloc(16384,32768);scratch=aligned_alloc(16384,16384);target=aligned_alloc(16384,16384);assert(ring&&scratch&&target);struct a630_core_snapshot s;
 reset();assert(!a630_core_run(false,true,true,&io,ring,scratch,target,&s)&&!m.op);
 reset();assert(!a630_core_run(true,false,true,&io,ring,scratch,target,&s)&&s.error==A630_CORE_ARGUMENT&&!m.op);
 reset();assert(!a630_core_run(true,true,false,&io,ring,scratch,target,&s)&&s.error==A630_CORE_ARGUMENT&&!m.op);
 reset();m.held=false;assert(!a630_core_run(true,true,true,&io,ring,scratch,target,&s)&&s.error==A630_CORE_LEASE&&!m.writes);
 reset();assert(a630_core_run(true,true,true,&io,ring,scratch,target,&s));unsigned count=m.op;
 assert(s.init_done&&s.secure_done&&s.fence==0x600dc0de&&s.image&&s.pixels==4096&&s.halted&&!s.keep_live&&m.blits==3);
 for(unsigned f=1;f<=count;f++){reset();m.fail=f;assert(!a630_core_run(true,true,true,&io,ring,scratch,target,&s));if(s.error!=A630_CORE_IO&&s.halt_error!=A630_CORE_IO)fprintf(stderr,"fail=%u err=%u halt=%u stage=%u\n",f,s.error,s.halt_error,s.stage);assert(s.error==A630_CORE_IO||s.halt_error==A630_CORE_IO);}
 reset();m.stuck=true;assert(!a630_core_run(true,true,true,&io,ring,scratch,target,&s)&&s.error==A630_CORE_TIMEOUT&&s.keep_live&&!s.image);
 reset();m.bad_fence=true;assert(!a630_core_run(true,true,true,&io,ring,scratch,target,&s)&&s.error==A630_CORE_DATA&&s.halted&&!s.image&&!m.blits);
 reset();m.bad_event=true;assert(!a630_core_run(true,true,true,&io,ring,scratch,target,&s)&&s.error==A630_CORE_DATA&&s.halted&&!s.image);
 reset();m.bad_pixel=true;assert(!a630_core_run(true,true,true,&io,ring,scratch,target,&s)&&s.error==A630_CORE_DATA&&s.halted&&!s.image&&s.offset==4095);
 reset();regs[0x210]=2;assert(!a630_core_run(true,true,true,&io,ring,scratch,target,&s)&&s.error==A630_CORE_RUNNING&&!m.writes&&s.keep_live);
 reset();regs[0x201]=1u<<23;assert(!a630_core_run(true,true,true,&io,ring,scratch,target,&s)&&s.error==A630_CORE_FAULT&&s.keep_live&&!s.image);
 free(ring);free(scratch);free(target);return 0;}
''')
