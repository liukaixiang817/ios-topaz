"""Resident submission failure/order/wrap tests; never physical GPU evidence."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


def run(source):
    with tempfile.TemporaryDirectory() as directory:
        p = Path(directory)
        (p / 'test.c').write_text(source)
        subprocess.run(['/usr/bin/clang', '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-I', str(ROOT / 'tools'),
                        str(p / 'test.c'), '-o', str(p / 'test')], check=True)
        subprocess.run([str(p / 'test')], check=True)


class A630SubmitTests(unittest.TestCase):
    def test_first_runtime_fault_is_fixed_read_only_and_formatting_never_reads_hardware(self):
        text = (ROOT / 'tools/polaris-a630-runtime.h').read_text()
        def body(name):
            start = text.index(name)
            left = text.index('{', start)
            at, depth = left + 1, 1
            while depth:
                depth += (text[at] == '{') - (text[at] == '}')
                at += 1
            return text[start:at] + '\n'
        decl = text[text.index('struct a630_client_fault {'):text.index('static struct a630_client_fault a630_client_first_fault;')]
        run(r'''
#include "polaris-a630-core.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
''' + decl + r'''
static unsigned a630_client_io,reads,expired;
static uint32_t a630_client_dead,a630_client_fault_published;
static struct a630_client_fault a630_client_first_fault;
static struct {struct a630_core_snapshot live;}a630_client_submit;
static bool a630_core_read(void*p,uint32_t reg,uint32_t*v){
 assert(p==&a630_client_io);if(expired)return false;
 const uint32_t regs[]={0x823,0x821,0x824};assert(reads<3&&reg==regs[reads]);
 *v=0x8000+reads++;return true;}
static bool a630_smmu_read(void*p,uint32_t reg,uint32_t*v){
 assert(p==&a630_client_io);if(expired)return false;
 const uint32_t regs[]={0x8058,0x8060,0x8064,0x8068};assert(reads>=3&&reads<7&&reg==regs[reads-3]);
 *v=0x9000+reads++;return true;}
/* No write/reset/free/deadline-renew callback exists in this compilation. */
''' + body('uint32_t polaris_gpu_fault_line(') + body('void polaris_gpu_quarantine(void)') + r'''
int main(void){char b[68];
 a630_client_submit.live=(struct a630_core_snapshot){.error=6,.offset=0x823,.expected=0,.actual=0x80};
 assert(!polaris_gpu_fault_line(0,b,sizeof(b)));
 polaris_gpu_quarantine();assert(reads==7&&a630_client_dead&&a630_client_fault_published);
 assert(a630_client_first_fault.valid==127&&a630_client_first_fault.cp==0x8000&&a630_client_first_fault.fsr==0x9003);
 unsigned before=reads;polaris_gpu_quarantine();assert(reads==before);
 memset(&a630_client_first_fault,0xff,sizeof(a630_client_first_fault));
 for(unsigned n=0;n<3;n++){unsigned length=polaris_gpu_fault_line(n,b,sizeof(b));assert(length==strlen(b)&&length<=67);}
 assert(reads==before);assert(!polaris_gpu_fault_line(3,b,sizeof(b)));
 a630_client_dead=0;a630_client_fault_published=0;reads=0;expired=1;
 polaris_gpu_quarantine();assert(!reads&&!a630_client_first_fault.valid);
 assert(a630_client_fault_published&&a630_client_first_fault.error==6);
 return 0;}
''')

    def test_real_gpu_counter_rollover_and_read_failure(self):
        text = (ROOT / 'tools/polaris-a630-runtime.h').read_text()
        start = text.index('bool polaris_gpu_timestamp(uint64_t *value)')
        end = text.index('\n}\n', start) + 3
        run(r'''
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
static unsigned a630_client_io,at,mode,available=1;
static bool a630_client_begin(void){return available;}
static bool a630_core_read(void *p,uint32_t reg,uint32_t *v){
 assert(p==&a630_client_io);assert(reg==(at%3==1?0x980:0x981));
 if(mode==1){if(at++==1)return false;*v=0;return true;}
 if(mode==2){*v=at++;return true;}
 const uint32_t words[]={1,0xfffffffe,2,2,4,2};assert(at<6);*v=words[at++];return true;}
''' + text[start:end] + r'''
int main(void){uint64_t v=0;
 assert(polaris_gpu_timestamp(&v)&&v==0x200000004ull&&at==6);
 at=0;mode=1;v=123;assert(!polaris_gpu_timestamp(&v)&&v==123);
 at=0;mode=2;assert(!polaris_gpu_timestamp(&v)&&at==12&&v==123);
 available=0;at=0;assert(!polaris_gpu_timestamp(&v)&&at==0);
 assert(!polaris_gpu_timestamp(0));return 0;}
''')

    def test_completion_wrap_and_ambiguous_dma_quarantine(self):
        run(r'''
#include "polaris-a630-submit.h"
#include <assert.h>
#include <string.h>
struct model {uint32_t control,rptr,wptr,cp,irq,writes,syncs;unsigned mode;bool owned;
 uint32_t ring[8192],scratch[16];};
static bool owned(void*x){return ((struct model*)x)->owned;}
static bool rd(void*x,uint32_t reg,uint32_t*v){struct model*m=x;
 switch(reg){case 0x806:*v=m->rptr;break;case 0x210:*v=0;break;case 0x201:*v=m->irq;break;
 case 0x823:*v=m->cp;break;case 0x808:*v=m->control;break;default:*v=0;}return true;}
static uint32_t take(struct model*m){uint32_t v=m->ring[m->rptr];m->rptr=(m->rptr+1)%8192;return v;}
static bool wr(void*x,uint32_t reg,uint32_t v){struct model*m=x;m->writes++;
 if(reg==0x808){assert(v==1||v==3);m->control=v;return true;}
 assert(reg==0x807&&m->control==1&&m->syncs);m->wptr=v;
 if(m->mode==1){m->cp=0x80;return true;}
 if(m->mode==2)return true;
 while(m->rptr!=m->wptr){uint32_t header=take(m),n=header&0x3fff,op=(header>>16)&127;
  assert((header>>28)==7&&__builtin_parity(header&0xffff)==1&&__builtin_parity((header>>16)&255)==1);
  if(op==0x3f){assert(n==3&&take(m)==0x20010000&&take(m)==0&&take(m)==64);}
  else if(op==0x46&&n==1){uint32_t event=take(m);assert(event==24||event==25||event==49);}
  else if(op==0x46&&n==4){assert(take(m)==4&&take(m)==0x10020030&&take(m)==0);
   uint32_t f=take(m);if(m->mode!=3)m->scratch[12]=f;}
  else assert(op==0x26&&n==0);
 }return true;}
static bool sync(void*x){((struct model*)x)->syncs++;return true;}
static void wait_(void*x,uint32_t u){(void)x;(void)u;}
int main(void){
 struct a630_core_snapshot p={.error=A630_CORE_READY,.stage=7,.init_done=1,.secure_done=1,
  .image=1,.pixels=4096,.fence=0x600dc0de,.idle=1,.halted=1,.wptr=8188,.rptr=8188};
 struct a630_submit r;struct model m={.control=3,.owned=true,.rptr=8188,.wptr=8188};
 const struct a630_core_io io={owned,rd,wr,sync,wait_,&m};
 const struct a630_ib ib={0x20010000,64};
 assert(!a630_submit_adopt(NULL,&p));p.pixels=4095;assert(!a630_submit_adopt(&r,&p));p.pixels++;
 assert(a630_submit_adopt(&r,&p));
 /* Independently check 13 fixed words + four/IB; crossing the actual ring end. */
 assert(a630_submit_run(&r,&io,m.ring,m.scratch,&ib,1));
 assert(r.wptr==8188+13+4-8192&&m.rptr==r.wptr&&r.completed==1&&m.control==3&&!r.poisoned);
 for(unsigned n=0;n<500;n++)assert(a630_submit_run(&r,&io,m.ring,m.scratch,&ib,1));
 assert(r.completed==501&&r.count==501);
 uint32_t writes=m.writes;
 struct a630_ib bad={0x10010000,1};assert(!a630_submit_run(&r,&io,m.ring,m.scratch,&bad,1));
 assert(m.writes==writes&&!r.poisoned);
 for(unsigned mode=1;mode<=3;mode++){
  memset(&m,0,sizeof(m));m.mode=mode;m.control=3;m.owned=true;m.rptr=m.wptr=p.wptr;
  assert(a630_submit_adopt(&r,&p));
  assert(!a630_submit_run(&r,&io,m.ring,m.scratch,&ib,1)&&r.poisoned&&r.live.keep_live);
  writes=m.writes;assert(!a630_submit_run(&r,&io,m.ring,m.scratch,&ib,1)&&m.writes==writes);
 }
 return 0;
}
''')

    def test_desktop_table_pool_high_dirty_bits_unmap_and_no_table_dma(self):
        run(r'''
#include "polaris-a630-mmu.h"
#include <assert.h>
#include <stdlib.h>
int main(void){
 void*pool=aligned_alloc(4096,512*4096);assert(pool);struct a630_mmu s;
 assert(a630_mmu_init(&s,pool,0x280000000ull,512));
 /* Reach table indices beyond both31 and255 with independent page walks. */
 for(unsigned n=0;n<300;n++)assert(a630_mmu_map(&s,0x20000000ull+n*0x200000ull,
   0x180000000ull+n*4096,A630_MMU_USER|A630_MMU_CACHED|A630_MMU_EXEC)==A630_MMU_OK);
 assert(s.used==303&&s.dirty_high[0]&&s.dirty_high[8]);
 uint64_t pa,pte;
 for(unsigned n=0;n<300;n++){
  uint64_t va=0x20000000ull+n*0x200000ull;
  assert(!a630_mmu_lookup(&s,va,&pa,&pte)&&pa==0x180000000ull+n*4096);
  assert((pte&((1ull<<6)|(1ull<<2)))==0x44&&!(pte&A630_MMU_XN));
  assert(!a630_mmu_unmap(&s,va));assert(a630_mmu_lookup(&s,va,&pa,&pte)==A630_MMU_UNMAPPED);
 }
 assert(s.used==303);a630_mmu_cleaned(&s);assert(!s.dirty);
 for(unsigned n=0;n<15;n++)assert(!s.dirty_high[n]);
 assert(a630_mmu_map(&s,0x20000000,0x280100000ull,0)==A630_MMU_ARGUMENT);
 free(pool);return 0;
}
''')

    def test_msm_wire_sizes_and_offsets(self):
        run(r'''
#include "polaris-gpu-abi.h"
#include <stddef.h>
_Static_assert(sizeof(struct msm_param)==24,"GET_PARAM");
_Static_assert(sizeof(struct msm_gem_new)==16,"GEM_NEW");
_Static_assert(sizeof(struct msm_gem_info)==24,"GEM_INFO");
_Static_assert(sizeof(struct msm_gem_submit)==72,"SUBMIT");
_Static_assert(offsetof(struct msm_gem_submit,bos)==16,"BO user ptr");
_Static_assert(offsetof(struct msm_gem_submit,queueid)==36,"queue");
_Static_assert(sizeof(struct msm_gem_submit_cmd)==32,"CMD");
_Static_assert(sizeof(struct msm_gem_submit_bo)==16,"BO");
_Static_assert(sizeof(struct msm_wait_fence)==32,"WAIT");
_Static_assert(sizeof(struct redwood_surface)==40,"surface bridge");
int main(void){return 0;}
''')


if __name__ == '__main__':
    unittest.main()
