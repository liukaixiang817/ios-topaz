"""Polaris SMMUv2 ownership, exact register programming and fault unwind."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class A630SMMUTests(unittest.TestCase):
    def test_handoff_and_every_io_failure(self):
        source = r'''
#include "polaris-a630-mmu.h"
#include "polaris-a630-smmu.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
struct model {
 uint32_t r[16384], original[16384];
 unsigned operations, fail, calls, writes, clean, sync, waits, wide, implwrites;
 bool held, stuck, badack, halt_stuck, implbad, forbidimpl, badactlr, drift, s2quirk, ignored_fault, sticky_fault;
};
static struct model m;
static bool op(struct model *x) {x->operations++;return x->operations!=x->fail;}
static void allowed(uint32_t off, bool wide) {
 assert(off<65536 && !(off&3));
 /* HYP's protected CB5..7, and every context's forbidden ATOS window. */
 assert(off<0xd000);
 assert(off<0x8000 || (off&0xfff)<0x800);
 assert(wide ? ((off&0xfff)==0x20 || (off&0xfff)==0x28) : true);
}
static bool stopped(void *ctx) {struct model *x=ctx;x->calls++;return x->held;}
static bool rd(void *ctx,uint32_t off,uint32_t *v) {
 struct model *x=ctx;allowed(off,false);if(!op(x))return false;
 *v=x->r[off/4];if((off&0xfff)==0x7f4 && x->stuck)*v=1;
 if(off==0x6000){*v&=~8u;if((*v&4)&&!x->halt_stuck)*v|=8;}
 return true;
}
static bool wr(void *ctx,uint32_t off,uint32_t v) {
 struct model *x=ctx;allowed(off,false);assert(x->held);x->writes++;
 /* A failed callback may still have posted the write. */
 bool ok=op(x);
 if(off>=0xc00&&off<0xe00){
  unsigned slot=(off-0xc00)/4,type=(v>>16)&3;
  if(type==2&&(x->s2quirk||x->ignored_fault))return ok;
  if(type==1){assert(!(x->r[(0x800+4*slot)/4]&(1u<<31)));
   if(x->s2quirk)v=(v&~0x30000u)|0x20000u;
  }
 }
 if(off==0x8058){
  assert(!x->r[0x8000/4]&&!(x->r[0x804/4]&(1u<<31))&&v==2);
  if(!x->sticky_fault)x->r[off/4]&=~v;return ok;
 }
 bool impl=false;for(unsigned n=1;n<12;n++)if(off==a630_smmu_impl_offsets[n])impl=true;
 if(x->forbidimpl)assert(!impl && off!=0x6000);
 if(impl)x->implwrites++;
 if(off==0x9004&&x->badactlr)return ok;
 if(off==0x9000&&(v&1)&&x->drift)x->r[0x6b68/4]^=1;
 /* The real0034 last implementation register did not accept the value.
  * Model hardware accepting these writes only after micro-MMU IDLE ACK. */
 if(impl && (!(x->r[0x6000/4]&4)||x->halt_stuck))return ok;
 if(off==0x6b68&&x->implbad)return ok;
 if (!x->badack) x->r[off/4]=off==0x6000?v&~8u:v;
 return ok;
}
static bool rd64(void *ctx,uint32_t off,uint64_t *v) {
 struct model *x=ctx;allowed(off,true);if(!op(x))return false;
 *v=x->r[off/4]|((uint64_t)x->r[off/4+1]<<32);return true;
}
static bool wr64(void *ctx,uint32_t off,uint64_t v) {
 struct model *x=ctx;allowed(off,true);x->writes++;x->wide++;
 x->r[off/4]=(uint32_t)v;x->r[off/4+1]=(uint32_t)(v>>32);return op(x);
}
static bool clean(void *ctx,const void *p,size_t n) {
 struct model *x=ctx;assert(p&&n==12288);x->clean++;return op(x);
}
static bool sync_io(void *ctx) {struct model *x=ctx;x->sync++;return op(x);}
static void wait_io(void *ctx,uint32_t n) {struct model *x=ctx;assert(n==1);x->waits++;}
static const struct a630_smmu_io io={stopped,rd,wr,rd64,wr64,clean,sync_io,wait_io};
static void reset(void) {
 memset(&m,0,sizeof(m));m.held=true;
 /* 16 exact-match slots,8 CBs,4KiB register pages,8 pages per half. */
 m.r[0x20/4]=0x48000610;m.r[0x24/4]=0x20000008;m.r[0x28/4]=0x1210;
 m.r[0]=1;m.r[0x3c/4]=0x12345678;
 /* Nonzero saved registers expose an incomplete rollback. */
 m.r[0x1004/4]=0x21234;m.r[0x1804/4]=0x101;
 m.r[0x9010/4]=0x38010;m.r[0x9030/4]=0x35a9;
 m.r[0x9020/4]=0x92000000;m.r[0x9024/4]=0x80000;
 m.r[0x9028/4]=0x94000000;m.r[0x902c/4]=0x90000;
 m.r[0x9038/4]=0xaabbccdd;m.r[0x903c/4]=0xeeff0011;
 for(unsigned n=0;n<16;n++)m.r[(0xc00+4*n)/4]=0x20402;
 for(unsigned n=0;n<12;n++)m.r[a630_smmu_impl_offsets[n]/4]=0x5a000000+n;
 m.r[0x6b68/4]=0xa8000082;
 memcpy(m.original,m.r,sizeof(m.r));
}
static void restored(void) {
 /* TLB commands are write-only architectural operations, not saved state. */
 m.r[0x9610/4]=m.original[0x9610/4];m.r[0x97f0/4]=m.original[0x97f0/4];
 assert(!memcmp(m.r,m.original,sizeof(m.r)));
}
int main(void) {
 void *pool=aligned_alloc(4096,32768);assert(pool);struct a630_mmu pt;
 assert(a630_mmu_init(&pt,pool,0x180000000,8));
 for(unsigned n=0;n<4;n++)assert(!a630_mmu_map(&pt,0x60000000+4096*n,0x190000000ull+4096*n,0));
 struct a630_smmu_snapshot s;
 reset();assert(a630_smmu_begin(false,true,&pt,&io,&m,&s)==A630_SMMU_DISABLED);
 assert(!m.operations&&!m.calls);
 assert(a630_smmu_begin(true,false,&pt,&io,&m,&s)==A630_SMMU_ARGUMENT&&!m.operations);
 m.held=false;assert(a630_smmu_begin(true,true,&pt,&io,&m,&s)==A630_SMMU_LEASE&&!m.operations);
 reset();assert(a630_smmu_begin(true,true,&pt,&io,&m,&s)==A630_SMMU_READY);
 unsigned count=m.operations;assert(s.slot==0&&s.bank==1&&s.context==0x9000);
 assert(m.r[0x800/4]==0x80000005 && m.r[0xc00/4]==0x701);
 assert(m.r[0x1004/4]==0x1f300 && m.r[0x1804/4]==1);
 assert(m.r[0x9020/4]==0x80000000 && m.r[0x9024/4]==0x10001);
 assert(m.r[0x9010/4]==0x38001 && m.r[0x9030/4]==0x803519);
 assert(m.r[0x9000/4]==0xc01127 && m.r[0x9038/4]==0xf404ff44);
 assert(m.r[0]==0x400 && m.wide==2 && m.clean==1 && !pt.dirty);
 assert(s.halt_changed&&s.halt_polls==1&&s.impl_changed==0xfff);
 assert(!(m.r[0x6000/4]&4)&&m.r[0x6b68/4]==0x9a82a382);
 assert(a630_smmu_end(&io,&m,&s)&&s.restored&&!s.restore_error);restored();
 /* Every start callback failure, including posted writes and final sync. */
 for(unsigned fail=1;fail<=count;fail++) {
  reset();m.fail=fail;assert(a630_smmu_begin(true,true,&pt,&io,&m,&s)==A630_SMMU_IO);
  unsigned first=s.error,offset=s.failed_offset;m.fail=0;
  assert(a630_smmu_end(&io,&m,&s));assert(s.error==first&&s.failed_offset==offset);restored();
 }
 reset();assert(a630_smmu_begin(true,true,&pt,&io,&m,&s)==A630_SMMU_READY);
 m.operations=0;assert(a630_smmu_end(&io,&m,&s));unsigned cleanup=m.operations;
 for(unsigned fail=1;fail<=cleanup;fail++) {
  reset();assert(a630_smmu_begin(true,true,&pt,&io,&m,&s)==A630_SMMU_READY);
  m.operations=0;m.fail=fail;assert(!a630_smmu_end(&io,&m,&s)&&s.restore_error&&!s.restored);
  assert(s.error==A630_SMMU_READY);m.fail=0;assert(a630_smmu_end(&io,&m,&s));restored();
 }
 reset();m.stuck=true;assert(a630_smmu_begin(true,true,&pt,&io,&m,&s)==A630_SMMU_TLB);
 assert(s.polls==500000 && m.waits==500000);m.stuck=false;
 assert(a630_smmu_end(&io,&m,&s));restored();
 reset();m.badack=true;assert(a630_smmu_begin(true,true,&pt,&io,&m,&s)==A630_SMMU_ACK);
 m.badack=false;assert(a630_smmu_end(&io,&m,&s));restored();
 reset();m.halt_stuck=true;
 assert(a630_smmu_begin(true,true,&pt,&io,&m,&s)==A630_SMMU_HALT);
 assert(s.halt_polls==30000&&s.impl_changed==0&&s.failed_offset==0x6000);
 assert(m.r[0x6b68/4]==0xa8000082);m.halt_stuck=false;
 assert(a630_smmu_end(&io,&m,&s)&&!(m.r[0x6000/4]&4));restored();
 reset();m.implbad=true; /* Halt is not permission to waive readback. */
 assert(a630_smmu_begin(true,true,&pt,&io,&m,&s)==A630_SMMU_ACK);
 assert(s.failed_offset==0x6b68&&s.expected==0x9a82a382&&s.actual==0xa8000082);
 assert(a630_smmu_end(&io,&m,&s)&&!(m.r[0x6000/4]&4));restored();
 reset();m.r[0x6000/4]|=4; /* Another halt request cannot be stolen. */
 assert(a630_smmu_begin(true,true,&pt,&io,&m,&s)==A630_SMMU_OWNERSHIP&&!m.writes);
 reset();assert(a630_smmu_begin(true,true,&pt,&io,&m,&s)==A630_SMMU_READY);
 m.held=false;unsigned writes=m.writes;assert(!a630_smmu_end(&io,&m,&s));
 assert(m.writes==writes&&!s.restored&&s.restore_error==A630_SMMU_LEASE);
 /* Exact SID, not reference machine's 0x400 wildcard. */
 reset();m.r[0x800/4]=0x84000005;
 assert(a630_smmu_begin(true,true,&pt,&io,&m,&s)==A630_SMMU_OWNERSHIP&&!m.writes);
 reset();m.r[0x800/4]=0x80000005;m.r[0x804/4]=0x80000005;
 assert(a630_smmu_begin(true,true,&pt,&io,&m,&s)==A630_SMMU_OWNERSHIP&&!m.writes);
 /* Foreign streams, including protected contexts, cannot be displaced. */
 reset();m.r[0x800/4]=0x80000002;m.r[0xc00/4]=7;
 assert(a630_smmu_begin(true,true,&pt,&io,&m,&s)==A630_SMMU_OWNERSHIP&&!m.writes);
 reset();m.r[0x800/4]=0x80000002;m.r[0xc00/4]=7;m.r[0]=0x400;
 for(unsigned n=0;n<12;n++)m.r[a630_smmu_impl_offsets[n]/4]=a630_smmu_impl_values[n];
 memcpy(m.original,m.r,sizeof(m.r));
 assert(a630_smmu_begin(true,true,&pt,&io,&m,&s)==A630_SMMU_READY);
 assert(s.foreign&&s.slot==1&&s.bank==1&&!s.halt_changed&&!m.implwrites);
 assert(a630_smmu_end(&io,&m,&s)&&!m.implwrites);restored();
 reset();for(unsigned n=0;n<16;n++)m.r[(0x800+4*n)/4]=0x80000020+n;
 assert(a630_smmu_begin(true,true,&pt,&io,&m,&s)==A630_SMMU_OWNERSHIP&&!m.writes);
 reset();for(unsigned n=1;n<5;n++)m.r[(0x8000+4096*n)/4]=1;
 assert(a630_smmu_begin(true,true,&pt,&io,&m,&s)==A630_SMMU_OWNERSHIP&&!m.writes);
 reset();m.r[0x24/4]|=0x80000000;
 assert(a630_smmu_begin(true,true,&pt,&io,&m,&s)==A630_SMMU_LAYOUT&&!m.writes);

 /* Owned-context handoff: opaque implementation6b68 deliberately remains
  * the real0035 readback. Not a masked/waived profile-write ACK. */
 reset();m.r[0x6000/4]=0x2378;m.forbidimpl=true;
 memcpy(m.original,m.r,sizeof(m.r));
 assert(a630_smmu_begin_handoff(true,true,&pt,&io,&m,&s)==A630_SMMU_READY);
 unsigned handoff_ops=m.operations;
 assert(s.preserved_impl&&s.impl_checks==3&&!s.impl_changed&&!s.halt_changed&&!m.implwrites);
 assert(s.actlr_changed&&m.r[0x9004/4]==0x70000000);
 assert(m.r[0x6b68/4]==0xa8000082&&m.r[0x800/4]==0x80000005);
 assert(a630_smmu_end(&io,&m,&s)&&s.impl_checks==4);restored();
 for(unsigned fail=1;fail<=handoff_ops;fail++) {
  reset();m.r[0x6000/4]=0x2378;m.forbidimpl=true;
  memcpy(m.original,m.r,sizeof(m.r));m.fail=fail;
  assert(a630_smmu_begin_handoff(true,true,&pt,&io,&m,&s)==A630_SMMU_IO);
  m.fail=0;assert(a630_smmu_end(&io,&m,&s));restored();
 }
 reset();m.r[0x6000/4]=0x2378;m.forbidimpl=true;
 memcpy(m.original,m.r,sizeof(m.r));
 assert(a630_smmu_begin_handoff(true,true,&pt,&io,&m,&s)==A630_SMMU_READY);
 m.operations=0;assert(a630_smmu_end(&io,&m,&s));unsigned handoff_cleanup=m.operations;
 for(unsigned fail=1;fail<=handoff_cleanup;fail++) {
  reset();m.r[0x6000/4]=0x2378;m.forbidimpl=true;
  memcpy(m.original,m.r,sizeof(m.r));
  assert(a630_smmu_begin_handoff(true,true,&pt,&io,&m,&s)==A630_SMMU_READY);
  m.operations=0;m.fail=fail;assert(!a630_smmu_end(&io,&m,&s));m.fail=0;
  assert(a630_smmu_end(&io,&m,&s));restored();
 }
 reset();m.forbidimpl=true; /* Unknown control cannot be silently borrowed. */
 assert(a630_smmu_begin_handoff(true,true,&pt,&io,&m,&s)==A630_SMMU_OWNERSHIP&&!m.writes);
 reset();m.r[0x6000/4]=0x237c;m.forbidimpl=true;
 assert(a630_smmu_begin_handoff(true,true,&pt,&io,&m,&s)==A630_SMMU_OWNERSHIP&&!m.writes);
 reset();m.r[0x6000/4]=0x2378;m.forbidimpl=true;m.badactlr=true;
 memcpy(m.original,m.r,sizeof(m.r));
 assert(a630_smmu_begin_handoff(true,true,&pt,&io,&m,&s)==A630_SMMU_ACK&&s.failed_offset==0x9004);
 m.badactlr=false;assert(a630_smmu_end(&io,&m,&s));restored();
 reset();m.r[0x6000/4]=0x2378;m.forbidimpl=true;m.drift=true;
 assert(a630_smmu_begin_handoff(true,true,&pt,&io,&m,&s)==A630_SMMU_ACK&&s.failed_offset==0x6b68);
 m.drift=false;assert(!a630_smmu_end(&io,&m,&s)&&s.restore_error==A630_SMMU_ACK);
 assert(!m.implwrites); /* Never fix another owner's opaque state. */
 /* Foreign stream survives the handoff path including its opaque tuning. */
 reset();m.r[0x6000/4]=0x2378;m.forbidimpl=true;m.r[0]=0x400;
 m.r[0x800/4]=0x80000002;m.r[0xc00/4]=7;
 memcpy(m.original,m.r,sizeof(m.r));
 assert(a630_smmu_begin_handoff(true,true,&pt,&io,&m,&s)==A630_SMMU_READY);
 assert(s.slot==1&&s.foreign&&!s.impl_changed&&!s.halt_changed);
 assert(a630_smmu_end(&io,&m,&s));restored();

 /* Actual0036 setup succeeded, then HYP ignored the teardown FAULT write.
  * The alternative encoding must be isolated and read back as FAULT. */
 reset();m.s2quirk=true;m.r[0x6000/4]=0x2378;m.forbidimpl=true;
 memcpy(m.original,m.r,sizeof(m.r));
 assert(a630_smmu_begin_handoff(true,true,&pt,&io,&m,&s)==A630_SMMU_READY);
 assert(a630_smmu_end(&io,&m,&s)&&s.fault_quirk&&s.fault_canonical);
 assert((m.r[0xc00/4]&0x300ff)==0x200ff && !m.r[0x800/4]);
 m.original[0xc00/4]=(m.original[0xc00/4]&~255u)|255u;restored();
 reset();m.s2quirk=true;m.r[0x6000/4]=0x2378;m.forbidimpl=true;
 assert(a630_smmu_begin_handoff(true,true,&pt,&io,&m,&s)==A630_SMMU_READY);
 m.operations=0;assert(a630_smmu_end(&io,&m,&s));unsigned quirk_cleanup=m.operations;
 for(unsigned fail=1;fail<=quirk_cleanup;fail++) {
  reset();m.s2quirk=true;m.r[0x6000/4]=0x2378;m.forbidimpl=true;
  memcpy(m.original,m.r,sizeof(m.r));
  assert(a630_smmu_begin_handoff(true,true,&pt,&io,&m,&s)==A630_SMMU_READY);
  m.operations=0;m.fail=fail;assert(!a630_smmu_end(&io,&m,&s));m.fail=0;
  assert(a630_smmu_end(&io,&m,&s));
  m.original[0xc00/4]=(m.original[0xc00/4]&~255u)|255u;restored();
 }
 reset();m.ignored_fault=true;m.r[0x6000/4]=0x2378;m.forbidimpl=true;
 assert(a630_smmu_begin_handoff(true,true,&pt,&io,&m,&s)==A630_SMMU_READY);
 assert(!a630_smmu_end(&io,&m,&s)&&s.restore_error==A630_SMMU_ACK);
 assert(!(m.r[0x800/4]&(1u<<31))); /* Unsupported BYPASS never becomes routable. */
 reset();m.r[0x800/4]=0x80000005;s=(struct a630_smmu_snapshot){.slot=0};
 unsigned before=m.writes;
 assert(!a630_smmu_fault(&io,&m,&s,0x20000)&&s.error==A630_SMMU_OWNERSHIP&&m.writes==before);

 /* Independent GPUstream0 context while the already configured GMUstream5
  * remains inCB1. No shared implementation write or live CB1 modification. */
 reset();m.r[0]=0x400;m.r[0x6000/4]=0x2378;m.forbidimpl=true;
 m.r[0x800/4]=0x80000005;m.r[0xc00/4]=0x301;m.r[0x9000/4]=0xc01127;
 uint32_t gmu_control=m.r[0x9000/4];
 assert(a630_smmu_begin_core(true,true,&pt,&io,&m,&s)==A630_SMMU_READY);
 unsigned core_ops=m.operations;
 assert(s.stream==0&&s.core&&s.bank==0&&s.slot==1&&s.context==0x8000);
 assert(m.r[0x800/4]==0x80000005&&m.r[0xc00/4]==0x301&&m.r[0x9000/4]==gmu_control&&!m.implwrites);
 assert(a630_smmu_end(&io,&m,&s)&&s.restored&&m.r[0x9000/4]==gmu_control);
 for(unsigned f=1;f<=core_ops;f++){
  reset();m.r[0]=0x400;m.r[0x6000/4]=0x2378;m.forbidimpl=true;
  m.r[0x800/4]=0x80000005;m.r[0xc00/4]=0x301;m.r[0x9000/4]=0xc01127;m.fail=f;
  assert(a630_smmu_begin_core(true,true,&pt,&io,&m,&s)!=A630_SMMU_READY);
  assert(m.r[0x9000/4]==0xc01127&&!m.implwrites);
 }
 /* Own disabledCB0 old translation fault is snapshotted, W1C-cleared
  * before enable, with format bits400 preserved; liveGMU/global remain untouched. */
 reset();m.r[0]=0x400;m.r[0x6000/4]=0x2378;m.forbidimpl=true;
 m.r[0x800/4]=0x80000005;m.r[0xc00/4]=0x301;m.r[0x9000/4]=0xc01127;
 m.r[0x48/4]=0x123;m.r[0x8058/4]=0x402;m.r[0x8060/4]=0x10000000;m.r[0x8068/4]=1;
 assert(a630_smmu_begin_core(true,true,&pt,&io,&m,&s)==A630_SMMU_READY);
 assert(s.stale_fsr==0x402&&s.clean_fsr==0x400&&s.stale_cleared&&s.stale_far[0]==0x10000000&&s.stale_fsynr==1);
 assert(m.r[0x8058/4]==0x400&&m.r[0x48/4]==0x123&&m.r[0x9000/4]==0xc01127&&!m.implwrites);
 assert(a630_smmu_end(&io,&m,&s)&&m.r[0x8058/4]==0x400); /* never recreate the old fault */
 reset();m.r[0]=0x400;m.r[0x6000/4]=0x2378;m.forbidimpl=true;
 m.r[0x800/4]=0x80000005;m.r[0xc00/4]=0x301;m.r[0x9000/4]=0xc01127;
 m.r[0x8058/4]=0x402;m.sticky_fault=true;
 assert(a630_smmu_begin_core(true,true,&pt,&io,&m,&s)==A630_SMMU_ACK&&s.failed_offset==0x8058&&!s.stale_cleared);
 assert(!(m.r[0x804/4]&(1u<<31))&&!m.r[0x8000/4]&&m.r[0x9000/4]==0xc01127);
 reset();m.r[0]=0x400;m.r[0x6000/4]=0x2378;m.forbidimpl=true;
 m.r[0x800/4]=0x80000005;m.r[0xc00/4]=0x301;m.r[0x9000/4]=0xc01127;
 m.r[0x8058/4]=0x40000402;
 assert(a630_smmu_begin_core(true,true,&pt,&io,&m,&s)==A630_SMMU_OWNERSHIP&&!s.stale_cleared&&m.r[0x8058/4]==0x40000402);
 reset();m.r[0x6000/4]=0x2378;m.r[0x8000/4]=1;
 assert(a630_smmu_begin_core(true,true,&pt,&io,&m,&s)==A630_SMMU_OWNERSHIP&&!m.writes);
 reset();m.r[0x6000/4]=0x2378;m.r[0x24/4]|=1u<<16;
 assert(a630_smmu_begin_core(true,true,&pt,&io,&m,&s)==A630_SMMU_OWNERSHIP&&!m.writes);
 free(pool);return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory)
            (p / 'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang', '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', '-I', str(ROOT / 'tools'),
                            str(p / 'test.c'), '-o', str(p / 'test')], check=True)
            subprocess.run([str(p / 'test')], check=True)


if __name__ == '__main__':
    unittest.main()
