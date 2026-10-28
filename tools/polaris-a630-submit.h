/* A630 synchronous resident submission. No power/reset/SCM operation.
 * PM4: native MiCode a6xx_submit + Mesa25.0.7 adreno_pm4.xml.
 * The coordinator serializes a SINGLE trusted writer, pins every BO and
 * owns SID0/CB0. Success requires flush fence, RPTR, idle and SQE halt.
 * Any uncertain completion quarantines the whole address space.
 */
#ifndef POLARIS_A630_SUBMIT_H
#define POLARIS_A630_SUBMIT_H
#include "polaris-a630-core.h"
#define A630_SUBMIT_MAX 128u
#define A630_CLIENT_IOVA 0x20000000ull
#define A630_CLIENT_END  0x40000000ull
struct a630_ib { uint64_t address; uint32_t words; };
struct a630_submit {
    uint32_t wptr, fence, completed, poisoned, count, error;
    struct a630_core_snapshot live;
    uint64_t timing[5]; /* prior idle, ring publish, execute/idle, fence visibility, halt */
    uint32_t timing_mask, timing_polls;
};
typedef uint64_t (*a630_submit_clock_fn)(void *);
static inline void a630_submit_mark(struct a630_submit *r,a630_submit_clock_fn clock,
    void *context,uint64_t *previous,unsigned stage)
{
    if (!r || !previous || stage>=5 || !clock) return;
    uint64_t now=clock(context);
    if (now>=*previous) {r->timing[stage]=now-*previous;r->timing_mask|=1u<<stage;}
    *previous=now; /* Diagnostics never influence the hardware completion decision. */
}
static inline bool a630_submit_adopt(struct a630_submit *r, const struct a630_core_snapshot *p)
{
    if (!r || !p || p->error != A630_CORE_READY || p->stage != 7 ||
        !p->init_done || !p->secure_done || !p->image || p->pixels != 4096 ||
        p->fence != 0x600dc0de || !p->idle || !p->halted || p->keep_live ||
        p->wptr >= A630_CORE_WORDS || p->rptr != p->wptr) return false;
    *r = (struct a630_submit){.wptr=p->wptr, .live=*p};
    return true;
}
static inline void a630_submit_word(uint32_t *ring, uint32_t *at, uint32_t value)
{
    ring[*at] = value;
    *at = (*at + 1) % A630_CORE_WORDS;
}
static inline bool a630_submit_profiled(struct a630_submit *r, const struct a630_core_io *io,
    uint32_t *ring, volatile uint32_t *scratch, const struct a630_ib *ibs, uint32_t count,
    a630_submit_clock_fn clock,void *clock_context)
{
    if (!r || r->poisoned || !io || !io->owned || !io->read || !io->write ||
        !io->sync || !io->wait || !ring || !scratch || !ibs || !count || count > A630_SUBMIT_MAX ||
        r->wptr >= A630_CORE_WORDS) return false;
    for (unsigned n=0; n<count; n++)
        if ((ibs[n].address & 3) || !ibs[n].words || ibs[n].words > 0xfffff ||
            ibs[n].address < A630_CLIENT_IOVA || ibs[n].address >= A630_CLIENT_END ||
            (uint64_t)ibs[n].words * 4 > A630_CLIENT_END - ibs[n].address) return false;
    /* Nothing is placed in the ring until the previous work is proven idle
     * and stopped. No overwrite of unread commands, including at wrap. */
    struct a630_core_snapshot *s = &r->live;
    s->wptr = r->wptr; s->error = 0;
    uint64_t stamp=clock?clock(clock_context):0;
    uint32_t polls=s->polls;
    for(unsigned n=0;n<5;n++)r->timing[n]=0;
    r->timing_mask=0;r->timing_polls=0;
    uint32_t control;
    if (!a630_core_idle(io,s) || !a630_core_rd(io,s,0x808,&control) || control != 3) goto poison;
    a630_submit_mark(r,clock,clock_context,&stamp,0);
    uint32_t at=r->wptr, fence=r->fence+1;
    if (!fence) fence=1;
    scratch[12]=0;
    /* CCU depth/color plus A6xx UCHE CACHE_INVALIDATE: a newly mapped BO
     * can reuse physical pages after a completed client's close. */
    const uint32_t invalidate[3]={0x18,0x19,0x31};
    for (unsigned n=0; n<3; n++) {
        a630_submit_word(ring,&at,a630_core_pkt7(0x46,1));
        a630_submit_word(ring,&at,invalidate[n]);
    }
    for (unsigned n=0; n<count; n++) {
        a630_submit_word(ring,&at,a630_core_pkt7(0x3f,3));
        a630_submit_word(ring,&at,(uint32_t)ibs[n].address);
        a630_submit_word(ring,&at,(uint32_t)(ibs[n].address>>32));
        a630_submit_word(ring,&at,ibs[n].words);
    }
    a630_submit_word(ring,&at,a630_core_pkt7(0x26,0));
    a630_submit_word(ring,&at,a630_core_pkt7(0x46,4));
    a630_submit_word(ring,&at,4); /* CACHE_FLUSH_TS, all render data visible */
    a630_submit_word(ring,&at,A630_CORE_SCRATCH+48);
    a630_submit_word(ring,&at,0);
    a630_submit_word(ring,&at,fence);
    a630_submit_word(ring,&at,a630_core_pkt7(0x26,0));
    if (!a630_core_sync(io,s)) goto poison;
    a630_submit_mark(r,clock,clock_context,&stamp,1);
    s->wptr=at; s->halted=0; s->idle=0; s->keep_live=1;
    /* Ring and tables visible before either CP release or the new WPTR. */
    if (!a630_core_wr(io,s,0x808,1) || !a630_core_wr(io,s,0x807,at) ||
        !a630_core_idle(io,s)) goto poison;
    a630_submit_mark(r,clock,clock_context,&stamp,2);
    if (!a630_core_sync(io,s)) goto poison;
    if (scratch[12] != fence) {s->error=A630_CORE_DATA;goto poison;}
    a630_submit_mark(r,clock,clock_context,&stamp,3);
    if (!a630_core_halt(io,s)) goto poison;
    a630_submit_mark(r,clock,clock_context,&stamp,4);
    r->timing_polls=s->polls-polls;
    r->wptr=at;r->fence=fence;r->completed=fence;r->count++;
    return true;
poison:
    r->poisoned=1;r->error=s->error?s->error:A630_CORE_RUNNING;s->keep_live=1;
    /* No reset, unmap, memory release, IRQ clear or retry on ambiguity. */
    return false;
}
static inline bool a630_submit_run(struct a630_submit *r,const struct a630_core_io *io,
    uint32_t *ring,volatile uint32_t *scratch,const struct a630_ib *ibs,uint32_t count)
{
    return a630_submit_profiled(r,io,ring,scratch,ibs,count,NULL,NULL);
}
#endif
