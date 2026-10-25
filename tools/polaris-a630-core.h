/* Original A630 command processor + bounded owned64x64 offscreen proof.
 * Native c7cb50c1 register profile; Linuxv6.12 A630 non-preempting8word
 * ME_INIT; Mesa25.0.7 PM4/a6xx.xml/fd6_blitter/A630 device properties.
 * No user client/desktop rendering is registered by this diagnostic.
 * Caller owns stream0, authenticated native ZAP, NC buffers and GPU OOB.
 */
#ifndef POLARIS_A630_CORE_H
#define POLARIS_A630_CORE_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "polaris-a630-core-profile.h"
#define A630_CORE_SQE 0x10000000u
#define A630_CORE_RING 0x10010000u
#define A630_CORE_SCRATCH 0x10020000u
#define A630_CORE_TARGET 0x11000000u
#define A630_CORE_WORDS 8192u
enum a630_core_error {A630_CORE_DISABLED,A630_CORE_ARGUMENT,A630_CORE_LEASE,
    A630_CORE_IO,A630_CORE_RUNNING,A630_CORE_TIMEOUT,A630_CORE_FAULT,
    A630_CORE_DATA,A630_CORE_READY};
struct a630_core_io {
    bool (*owned)(void *);
    bool (*read)(void *,uint32_t,uint32_t *); /* register WORD indices */
    bool (*write)(void *,uint32_t,uint32_t);
    bool (*sync)(void *);
    void (*wait)(void *,uint32_t);
    void *ctx;
};
struct a630_core_snapshot {
    uint32_t error,stage,offset,expected,actual,started,halted,idle,keep_live;
    uint32_t wptr,rptr,status,irq,hw_fault,protect,cp_irq,polls;
    uint32_t init_done,secure_done,fence,image,pixels,halt_error;
    uint32_t prepared,cp_before,cp_auth,config[7],live[7],fault_valid;
    uint32_t sqe_state[8],sqe_valid,sqe_index_restored;
};
static inline uint32_t a630_core_parity(uint32_t v)
{v^=v>>16;v^=v>>8;v^=v>>4;return (0x9669u>>(v&15))&1;}
static inline uint32_t a630_core_pkt7(uint32_t op,uint32_t n)
{return 0x70000000u|n|(a630_core_parity(n)<<15)|(op<<16)|(a630_core_parity(op)<<23);}
static inline uint32_t a630_core_pkt4(uint32_t reg,uint32_t n)
{return 0x40000000u|n|(a630_core_parity(n)<<7)|(reg<<8)|(a630_core_parity(reg)<<27);}
static inline bool a630_core_rd(const struct a630_core_io *io,struct a630_core_snapshot *s,uint32_t w,uint32_t *v)
{
    if(!io->owned(io->ctx)){s->error=A630_CORE_LEASE;return false;}
    if(io->read(io->ctx,w,v))return true;s->error=A630_CORE_IO;s->offset=w;return false;
}
static inline bool a630_core_wr(const struct a630_core_io *io,struct a630_core_snapshot *s,uint32_t w,uint32_t v)
{
    if(!io->owned(io->ctx)){s->error=A630_CORE_LEASE;return false;}
    if(io->write(io->ctx,w,v)&&io->sync(io->ctx))return true;
    s->error=A630_CORE_IO;s->offset=w;return false;
}
static inline bool a630_core_idle(const struct a630_core_io *io,struct a630_core_snapshot *s)
{
    for(unsigned n=0;n<20000;n++){
        s->polls++;
        if(!a630_core_rd(io,s,0x806,&s->rptr)||!a630_core_rd(io,s,0x210,&s->status)||
           !a630_core_rd(io,s,0x201,&s->irq)||!a630_core_rd(io,s,0x823,&s->cp_irq))return false;
        /* Native RBBM interrupt fault bits; completion interrupts are benign. */
        if((s->irq&0x03c002c2u)||(s->cp_irq&0xf7u)){
            s->error=A630_CORE_FAULT;s->offset=0x823;s->expected=0;s->actual=s->cp_irq;goto fault;
        }
        if(s->rptr==s->wptr&&!(s->status&0xfffffffeu)){s->idle=1;return true;}
        io->wait(io->ctx,10);
    }
    s->error=A630_CORE_TIMEOUT;s->offset=0x806;s->expected=s->wptr;s->actual=s->rptr;
fault:
    /* Best-effort read-only first-fault detail. Never acknowledges a foreign IRQ. */
    io->read(io->ctx,0x821,&s->hw_fault);io->read(io->ctx,0x824,&s->protect);
    io->read(io->ctx,0x823,&s->cp_irq);return false;
}
static inline bool a630_core_sync(const struct a630_core_io *io,struct a630_core_snapshot *s)
{
    if(!io->owned(io->ctx)){s->error=A630_CORE_LEASE;return false;}
    if(io->sync(io->ctx))return true;s->error=A630_CORE_IO;return false;
}
static inline bool a630_core_emit(uint32_t *ring,struct a630_core_snapshot *s,uint32_t v)
{if(s->wptr>=A630_CORE_WORDS){s->error=A630_CORE_ARGUMENT;return false;}ring[s->wptr++]=v;return true;}
static inline bool a630_core_reg(uint32_t *ring,struct a630_core_snapshot *s,uint32_t reg,uint32_t value)
{return a630_core_emit(ring,s,a630_core_pkt4(reg,1))&&a630_core_emit(ring,s,value);}
static inline bool a630_core_submit(const struct a630_core_io *io,struct a630_core_snapshot *s)
{
    s->idle=0;
    if(!io->sync(io->ctx)){s->error=A630_CORE_IO;return false;}
    return a630_core_wr(io,s,0x807,s->wptr)&&a630_core_idle(io,s);
}
static inline void a630_core_fault_snapshot(const struct a630_core_io *io,struct a630_core_snapshot *s)
{
    /* Own first failure only. No interrupt acknowledgement, reset, TLB
     * operation or ring submission. Native a6xx_snapshot uses these indexed
     * SQE status registers; bound this capture to8words and restore its index. */
    const uint32_t words[]={0x830,0x831,0x800,0x801,0x802,0x808,0x825};
    for(unsigned n=0;n<7;n++)
        if(io->owned(io->ctx)&&io->read(io->ctx,words[n],&s->live[n]))s->fault_valid|=1u<<n;
    uint32_t index;
    if(!io->owned(io->ctx)||!io->read(io->ctx,0x908,&index))return;
    for(unsigned n=0;n<8;n++){
        if(!io->owned(io->ctx)||!io->write(io->ctx,0x908,n)||!io->sync(io->ctx)||
           !io->read(io->ctx,0x909,&s->sqe_state[n]))break;
        s->sqe_valid|=1u<<n;
    }
    if(io->owned(io->ctx)&&io->write(io->ctx,0x908,index)&&io->sync(io->ctx))s->sqe_index_restored=1;
}
static inline bool a630_core_halt(const struct a630_core_io *io,struct a630_core_snapshot *s)
{
    struct a630_core_snapshot r=*s;r.error=0;
    /* Halting SQE alone does not drain a rendering engine. Idle first. */
    if(s->started&&!a630_core_idle(io,&r))goto failed;
    if(!a630_core_wr(io,&r,0x808,3))goto failed;
    uint32_t value=0;
    if(!a630_core_rd(io,&r,0x808,&value)||!(value&2))goto failed;
    s->halted=1;s->idle=1;s->keep_live=0;return true;
failed:
    s->halt_error=r.error?r.error:A630_CORE_RUNNING;s->keep_live=1;return false;
}
/* Native a6xx_rb_start loads SQE/RB addresses BEFORE subsystem_get(zap).
 * Preparation cannot release SQE or submit any command. Authentication
 * remains mandatory at the separate execution boundary below. */
static inline bool a630_core_prepare(bool exact_board,bool mappings_ready,
    const struct a630_core_io *io,uint32_t *ring,volatile uint32_t *scratch,
    volatile uint32_t *target,struct a630_core_snapshot *s)
{
    if(!s)return false;*s=(struct a630_core_snapshot){0};if(!exact_board)return false;
    if(!mappings_ready||!io||!io->owned||!io->read||!io->write||
       !io->sync||!io->wait||!ring||!scratch||!target||
       ((uintptr_t)ring&0x3fff)||((uintptr_t)scratch&0x3fff)||((uintptr_t)target&0x3fff)){
        s->error=A630_CORE_ARGUMENT;return false;}
    s->stage=1;s->keep_live=1;
    if(!a630_core_rd(io,s,0x210,&s->status))return false;
    if(s->status&0xfffffffeu){s->error=A630_CORE_RUNNING;return false;}
    if(!a630_core_wr(io,s,0x808,3)||!a630_core_rd(io,s,0x808,&s->actual))return false;
    if(!(s->actual&2)){s->error=A630_CORE_RUNNING;return false;}
    s->halted=1;s->keep_live=0;
    if(!a630_core_rd(io,s,0x806,&s->rptr))return false;
    if(s->rptr){s->error=A630_CORE_RUNNING;return false;}
    if(!a630_core_rd(io,s,0x823,&s->cp_before))return false;
    for(unsigned n=0;n<A630_CORE_WORDS;n++)ring[n]=0;
    for(unsigned n=0;n<16;n++)scratch[n]=0;
    for(unsigned n=0;n<4096;n++)target[n]=0xa5a5a5a5;
    s->stage=2;
    for(unsigned n=0;n<sizeof(a630_core_profile)/sizeof(a630_core_profile[0]);n++)
        if(!a630_core_wr(io,s,a630_core_profile[n].word,a630_core_profile[n].value))return false;
    if(!a630_core_wr(io,s,0x830,A630_CORE_SQE)||!a630_core_wr(io,s,0x831,0)||
       !a630_core_wr(io,s,0x800,A630_CORE_RING)||!a630_core_wr(io,s,0x801,0)||
       !a630_core_wr(io,s,0x802,0x0800020c)||!a630_core_wr(io,s,0x804,0)||
       !a630_core_wr(io,s,0x805,0)||!a630_core_wr(io,s,0x807,0))return false;
    const uint32_t words[]={0x830,0x831,0x800,0x801,0x802,0x807,0x808};
    const uint32_t values[]={A630_CORE_SQE,0,A630_CORE_RING,0,0x0800020c,0,3};
    for(unsigned n=0;n<7;n++){
        if(!a630_core_rd(io,s,words[n],&s->config[n]))return false;
        if(s->config[n]!=values[n]){
            s->error=A630_CORE_DATA;s->offset=words[n];s->expected=values[n];s->actual=s->config[n];return false;
        }
    }
    s->prepared=1;return true;
}
/* A failed/absent AUTH never reaches SQE release, even after preparation. */
static inline bool a630_core_execute(bool authenticated,const struct a630_core_io *io,
    uint32_t *ring,volatile uint32_t *scratch,volatile uint32_t *target,struct a630_core_snapshot *s)
{
    if(!s)return false;
    if(!authenticated||!s->prepared||s->stage!=2||!s->halted||s->started||!io||
       !io->owned||!io->read||!io->write||!io->sync||!io->wait||!ring||!scratch||!target||
       ((uintptr_t)ring&0x3fff)||((uintptr_t)scratch&0x3fff)||((uintptr_t)target&0x3fff)){
        s->error=A630_CORE_ARGUMENT;return false;
    }
    if(!a630_core_rd(io,s,0x823,&s->cp_auth))return false;
    s->stage=3;s->started=1;s->halted=0;s->idle=0;s->keep_live=1;
    if(!a630_core_wr(io,s,0x808,1))goto done;
    /* Linuxv6.12 A630 CP initialization: no preemption/IFPC restore list. */
    const uint32_t init[]={0x2f,3,0x20000000,0,0,0,0,0};
    if(!a630_core_emit(ring,s,a630_core_pkt7(0x48,8)))goto done;
    for(unsigned n=0;n<8;n++)if(!a630_core_emit(ring,s,init[n]))goto done;
    if(!a630_core_submit(io,s))goto done;
    s->init_done=1;s->stage=4;
    if(!a630_core_emit(ring,s,a630_core_pkt7(0x66,1))||!a630_core_emit(ring,s,0)||
       !a630_core_submit(io,s))goto done;
    s->secure_done=1;s->stage=5;
    const uint32_t fence[]={A630_CORE_SCRATCH,0,0x600dc0de};
    if(!a630_core_emit(ring,s,a630_core_pkt7(0x3d,3)))goto done;
    for(unsigned n=0;n<3;n++)if(!a630_core_emit(ring,s,fence[n]))goto done;
    if(!a630_core_emit(ring,s,a630_core_pkt7(0x26,0))||!a630_core_submit(io,s)||!a630_core_sync(io,s))goto done;
    s->fence=scratch[0];if(s->fence!=0x600dc0de){s->error=A630_CORE_DATA;s->expected=0x600dc0de;s->actual=s->fence;goto done;}
    s->stage=6;
    /* A630 has2CCUs, each64KiB depthcache: coloroffset0x20000 ->10000004.
     * Its blit ECO is05100000 (different from the reference642L's04100000). */
    if(!a630_core_emit(ring,s,a630_core_pkt7(0x65,1))||!a630_core_emit(ring,s,12)||
       !a630_core_reg(ring,s,0x8e07,0x10000004))goto done;
    const uint32_t tops[]={0,20,44},bottoms[]={20,44,64};
    const uint32_t colors[3][3]={{255,128,0},{255,255,255},{0,128,255}};
    for(unsigned k=0;k<3;k++){
        if(!a630_core_reg(ring,s,0x8405,tops[k]<<16)||
           !a630_core_reg(ring,s,0x8406,63|((bottoms[k]-1)<<16)))goto done;
        for(unsigned c=0;c<4;c++)if(!a630_core_reg(ring,s,0x8c2c+c,c==3?255:colors[k][c]))goto done;
        if(!a630_core_reg(ring,s,0x8c00,0x10f03080)||!a630_core_reg(ring,s,0x8400,0x10f03080)||
           !a630_core_reg(ring,s,0xacc0,0xf181)||!a630_core_reg(ring,s,0x8c01,0)||
           !a630_core_reg(ring,s,0x8c17,0x430)||!a630_core_reg(ring,s,0x8c18,A630_CORE_TARGET)||
           !a630_core_reg(ring,s,0x8c19,0)||!a630_core_reg(ring,s,0x8c1a,4)||
           !a630_core_emit(ring,s,a630_core_pkt7(0x26,0))||
           !a630_core_reg(ring,s,0x8e04,0x05100000)||
           !a630_core_emit(ring,s,a630_core_pkt7(0x2c,1))||!a630_core_emit(ring,s,3)||
           !a630_core_emit(ring,s,a630_core_pkt7(0x26,0))||!a630_core_reg(ring,s,0x8e04,0))goto done;
    }
    const uint32_t events[2][4]={{0x1d,A630_CORE_SCRATCH+32,0,0x0c0c0c0c},{4,A630_CORE_SCRATCH+16,0,0x0d0e0d0e}};
    for(unsigned e=0;e<2;e++){
        if(!a630_core_emit(ring,s,a630_core_pkt7(0x46,4)))goto done;
        for(unsigned n=0;n<4;n++)if(!a630_core_emit(ring,s,events[e][n]))goto done;
    }
    if(!a630_core_emit(ring,s,a630_core_pkt7(0x26,0))||!a630_core_submit(io,s)||!a630_core_sync(io,s))goto done;
    if(scratch[8]!=0x0c0c0c0c||scratch[4]!=0x0d0e0d0e){s->error=A630_CORE_DATA;s->actual=scratch[4];goto done;}
    for(unsigned y=0;y<64;y++)for(unsigned x=0;x<64;x++){
        unsigned k=y<20?0:y<44?1:2;
        uint32_t want=0xff000000u|(colors[k][0]<<16)|(colors[k][1]<<8)|colors[k][2];
        uint32_t actual=target[y*64+x];
        if(actual!=want){s->error=A630_CORE_DATA;s->offset=y*64+x;s->expected=want;s->actual=actual;goto done;}
        s->pixels++;
    }
    s->image=1;s->stage=7;s->error=A630_CORE_READY;
done:
    if(s->error!=A630_CORE_READY)a630_core_fault_snapshot(io,s);
    a630_core_halt(io,s);return s->error==A630_CORE_READY&&s->halted;
}
/* Protocol harness wrapper; the hardware coordinator performs preparation,
 * then fresh PAS authentication, then execution using these same helpers. */
static inline bool a630_core_run(bool exact_board,bool mappings_ready,bool authenticated,
    const struct a630_core_io *io,uint32_t *ring,volatile uint32_t *scratch,
    volatile uint32_t *target,struct a630_core_snapshot *s)
{
    if(!s)return false;
    if(!exact_board){*s=(struct a630_core_snapshot){0};return false;}
    if(!authenticated){*s=(struct a630_core_snapshot){.error=A630_CORE_ARGUMENT};return false;}
    return a630_core_prepare(exact_board,mappings_ready,io,ring,scratch,target,s)&&
        a630_core_execute(authenticated,io,ring,scratch,target,s);
}
#endif
