/* Default-OFF RAM experiment using the ORIGINAL Polaris HFI_USE_REG table.
 * MiCode c7cb50c1 adreno_a6xx.c:a6xx_gmu_dcvs_nohfi; no PLL/rail/MMIO map.
 * Caller serializes with submissions and proves idle/halted before transitions.
 * An ambiguous transaction is sticky failure: no retry/resume/reset permission.
 * Request/return success is NOT a measurement of GPU frequency or temperature.
 */
#ifndef POLARIS_A630_PERFORMANCE_H
#define POLARIS_A630_PERFORMANCE_H
#include "polaris-a630-post.h"
#define A630_PERF_IDLE_NS UINT64_C(250000000)
#define A630_PERF_HIGH_NS UINT64_C(30000000000)
#define A630_PERF_COOL_NS UINT64_C(10000000000)
struct a630_perf_state {
    uint32_t mode,perf,bus,target_perf,target_bus,fault,stopped,armed;
    uint32_t offset,expected,actual,returned,polls;
    uint64_t high_since,cool_until,last_ns,transitions;
};
static inline bool a630_perf_intent(uint32_t mode,uint32_t gpu,uint32_t cow,
    bool has_rw,uint32_t rw,uint32_t marker,uint32_t quiesce,uint64_t midr,
    uint64_t mpidr,uint64_t timer,bool original_board)
{
    return mode>=1 && mode<=3 && gpu==9 && cow==1 && has_rw && !rw &&
        !marker && quiesce==1 && original_board &&
        ((midr>>24)&255)==0x51 && ((midr>>4)&0xfff)==0x802 &&
        (mpidr&~UINT64_C(0x300))==UINT64_C(0x400) && timer==19200000;
}
static inline bool a630_perf_io_valid(const struct a630_channel_io *io)
{
    return io && io->owned && io->read && io->write && io->sync && io->wait;
}
static inline bool a630_perf_read_state(const struct a630_channel_io *io,
    struct a630_channel_snapshot *r,uint32_t perf,uint32_t bus)
{
    const uint32_t off[]={A630_POST_ACK,A630_POST_PERF,A630_POST_BW,A630_POST_RETURN};
    const uint32_t expected[]={0,0x30000000u|perf,bus,0};
    uint32_t v;
    for(unsigned n=0;n<4;n++) {
        if(!a630_ch_read(io,r,2,off[n],&v))return false;
        if(v!=expected[n]){r->error=A630_CH_PROTOCOL;r->failed_offset=off[n];
            r->expected=expected[n];r->actual=v;return false;}
    }
    if(!a630_ch_read(io,r,2,A630_CH_INTR_INFO,&v))return false;
    if(v&((1u<<31)|A630_CH_FW_FAULTS)) {
        r->error=A630_CH_PROTOCOL;r->failed_offset=A630_CH_INTR_INFO;r->actual=v;return false;
    }
    return true;
}
static inline bool a630_perf_fail(struct a630_perf_state *s,
    const struct a630_channel_snapshot *r)
{
    if(!s->fault){s->fault=r->error?r->error:A630_CH_IO;s->offset=r->failed_offset;
        s->expected=r->expected;s->actual=r->actual;s->polls=r->polls;}
    return false;
}
static inline bool a630_perf_init(struct a630_perf_state *s,unsigned mode,
    bool admitted,const struct a630_channel_io *io)
{
    if(!s)return false;*s=(struct a630_perf_state){0};
    if(!admitted || mode<1 || mode>3 || !a630_perf_io_valid(io))return false;
    struct a630_channel_snapshot r={0};
    if(!a630_perf_read_state(io,&r,1,4))return a630_perf_fail(s,&r);
    s->mode=mode;s->perf=1;s->bus=4;
    s->target_perf=mode==1?1:4;s->target_bus=mode==2?4:8;s->armed=1;return true;
}
static inline bool a630_perf_change(struct a630_perf_state *s,
    const struct a630_channel_io *io,uint32_t perf,uint32_t bus,bool quiescent)
{
    if(!s || !s->armed || s->fault || !a630_perf_io_valid(io))return false;
    if(!quiescent){struct a630_channel_snapshot r={.error=A630_CH_RUNNING};return a630_perf_fail(s,&r);}
    if(!((perf==1 && bus==4) || (perf==s->target_perf && bus==s->target_bus)))return false;
    struct a630_channel_snapshot r={0};
    if(!a630_perf_read_state(io,&r,s->perf,s->bus))return a630_perf_fail(s,&r);
    if(perf==s->perf && bus==s->bus)return true;
    if(!a630_ch_write(io,&r,2,A630_POST_ACK,0) ||
       !a630_ch_write(io,&r,2,A630_POST_PERF,0x30000000u|perf) ||
       !a630_ch_write(io,&r,2,A630_POST_BW,bus) ||
       !a630_post_oob(io,&r,23,31) ||
       !a630_ch_read(io,&r,2,A630_POST_RETURN,&s->returned))return a630_perf_fail(s,&r);
    if(s->returned){r.error=A630_CH_FW_ERROR;r.failed_offset=A630_POST_RETURN;
        r.actual=s->returned;return a630_perf_fail(s,&r);}
    if(!a630_ch_write(io,&r,2,A630_CH_INTR_SET,1u<<31) ||
       !a630_perf_read_state(io,&r,perf,bus))return a630_perf_fail(s,&r);
    s->perf=perf;s->bus=bus;s->polls=r.polls;s->transitions++;return true;
}
static inline bool a630_perf_desired(struct a630_perf_state *s,uint64_t now,
    uint64_t activity,uint32_t *perf,uint32_t *bus)
{
    if(!s || !s->armed || s->stopped || s->fault || !perf || !bus)return false;
    if(!now || now<s->last_ns || activity>now || now>UINT64_MAX-A630_PERF_COOL_NS) {
        struct a630_channel_snapshot r={.error=A630_CH_ARGUMENT};return a630_perf_fail(s,&r);
    }
    s->last_ns=now;
    bool high=activity && now-activity<=A630_PERF_IDLE_NS && now>=s->cool_until;
    if(s->high_since && now-s->high_since>=A630_PERF_HIGH_NS) {
        high=false;s->cool_until=now+A630_PERF_COOL_NS;
    }
    if(high){if(!s->high_since)s->high_since=now;}else s->high_since=0;
    *perf=high?s->target_perf:1;*bus=high?s->target_bus:4;return true;
}
static inline bool a630_perf_stop(struct a630_perf_state *s,
    const struct a630_channel_io *io,bool quiescent)
{
    if(!s)return false;
    if(!s->armed)return !s->fault;
    s->stopped=1;
    return a630_perf_change(s,io,1,4,quiescent);
}
#endif
