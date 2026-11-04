/* Persistent own-MSS active-clock protocol, NOT the old four-VRM roundtrip.
 * Own c7cb50c1 sdm845.dtsi gives the six named clocks and pil-msa.c their order.
 * Parent supplies a live exclusive APPS clock/reset generation, power/proxy
 * votes, source-bound native access and resource lifetime. This integer-only
 * engine cannot create that authority. HELD preserves votes for actual MSS use;
 * release is allowed only after that epoch's completed stop/AXI/reset protocol.
 * No automatic unwind, firmware refcount fabrication, PLL or HWCG changes. */
#ifndef POLARIS_MSS_CLOCKS_H
#define POLARIS_MSS_CLOCKS_H
#include "polaris-mss-shutdown.h"
#define PMCK_CLOCKS 6u
#define PMCK_EVENTS 6100u
#define PMCK_LIMIT UINT64_C(192000) /*10ms per active transition, not a lease*/
#define PMCK_POLL UINT64_C(20) /* ceil1us at19.2MHz */
#define PMCK_POLLS 500u
enum pmck_result {PMCK_FAILED=-1,PMCK_WAIT,PMCK_IO,PMCK_HELD,PMCK_RESTORED};
enum pmck_kind {PMCK_READ=1,PMCK_WRITE,PMCK_ORDER};
enum pmck_step {PMCK_SAMPLE,PMCK_UPDATE,PMCK_BARRIER,PMCK_READBACK,PMCK_STATUS};
enum pmck_error {PMCK_OK,PMCK_ARGUMENT,PMCK_REENTRY,PMCK_TIME,PMCK_ACCESS,
    PMCK_CHANGED,PMCK_READBACK_ERROR,PMCK_STATUS_ERROR,PMCK_STOP};
struct pmck_clock {uint64_t enable,status;uint32_t mask,hwcg,voted,gate_delay;};
static inline struct pmck_clock pmck_clock(unsigned n)
{
    /* iface, bus(Q6 MEMNOC), mem(BOOT ROM), GPLL0 gate, SNOC, mnoc(MFAB).
     * DT numeric IDs differ across kernel versions: no numeric ID is used. */
    const struct pmck_clock clocks[PMCK_CLOCKS]={
        {0x18a000,0x18a000,1,2,0,0},
        {0x18a154,0x18a154,1,0,1,0},
        {0x152004,0x138004,0x400,2,1,0},
        {0x152004,0,0x20000,0,0,9600},
        {0x18a150,0x18a150,1,0,0,0},
        {0x18a004,0x18a004,1,2,1,0}
    };
    return n<PMCK_CLOCKS?clocks[n]:(struct pmck_clock){0};
}
struct pmck_command {uint64_t address;uint32_t sequence,phase,clock,step,kind,value;};
struct pmck_event {
    struct pmck_command command;uint64_t before,after;
    int32_t return_raw;uint32_t issued,returned,value;
};
struct pmck_lifecycle {
    uint64_t epoch,opening,last,transition_opening,not_before,held_at,release_at,reset_at;
    uint32_t phase,unknown,error,pending,clock,step,events,polls;
    uint32_t saved[PMCK_CLOCKS],current,desired,changed,held,restored,write_intent[2],write_returned[2];
    struct pmck_event event[PMCK_EVENTS];
};
static inline int pmck_fail(struct pmck_lifecycle*c,unsigned error)
{if(c){c->unknown=1;if(!c->error)c->error=error;}return PMCK_FAILED;}
static inline int pmck_time(struct pmck_lifecycle*c,uint64_t now)
{
    if(!now||now<c->last||now<c->transition_opening||
       ((c->phase==1||c->phase==3)&&now-c->transition_opening>PMCK_LIMIT))return pmck_fail(c,PMCK_TIME);
    c->last=now;return 1;
}
static inline int pmck_begin(struct pmck_lifecycle*c,uint64_t epoch,uint64_t now,uint64_t hz)
{
    if(!c||!epoch||!now||hz!=19200000||now>UINT64_MAX-PMCK_LIMIT||!pms_zero(c,sizeof(*c)))return PMCK_FAILED;
    c->epoch=epoch;c->opening=c->last=c->transition_opening=c->not_before=now;c->phase=1;return PMCK_WAIT;
}
static inline int pmck_release(struct pmck_lifecycle*c,const struct pmsd_shutdown*s,uint64_t now)
{
    if(!c||!s||c->unknown||c->error)return PMCK_FAILED;
    if(!pmsr_disjoint(c,sizeof(*c),s,sizeof(*s))||c->phase!=2||c->pending||c->held!=0x3f||
       !c->held_at||now<c->last||now>UINT64_MAX-PMCK_LIMIT||
       s->unknown||s->pending||s->complete!=1||s->phase!=3||
       s->stop.unknown||s->stop.pending||s->stop.complete!=1||s->stop.phase!=3||
       s->stop.stop.unknown||s->stop.stop.error||s->stop.stop.pending||s->stop.stop.ack_held!=1||
       s->stop.stop.config.epoch!=c->epoch||s->stop.stop.opening<c->held_at||
       s->stop.halt.unknown||s->stop.halt.error||s->stop.halt.pending||s->stop.halt.ports_held!=7||
       s->reset.unknown||s->reset.error||s->reset.pending||s->reset.complete!=1||
       s->reset.step!=PMSR_EVENTS||s->reset.events!=PMSR_EVENTS||s->reset.write_returned!=0x3f||
       s->reset.opening<s->stop.halt.last||s->reset.last<s->reset.not_before||now<s->reset.last)
        return pmck_fail(c,PMCK_STOP);
    c->phase=3;c->clock=5;c->step=PMCK_SAMPLE;c->polls=0;
    c->release_at=c->transition_opening=c->last=c->not_before=now;c->reset_at=s->reset.last;return PMCK_WAIT;
}
static inline void pmck_advance(struct pmck_lifecycle*c,uint64_t now)
{
    c->step=PMCK_SAMPLE;c->polls=0;c->not_before=now;
    if(c->phase==1){
        c->held|=1u<<c->clock;
        if(++c->clock==PMCK_CLOCKS){c->phase=2;c->held_at=now;}
    }else{
        c->restored|=1u<<c->clock;
        if(!c->clock)c->phase=4;else c->clock--;
    }
}
static inline int pmck_next(struct pmck_lifecycle*c,uint64_t now,struct pmck_command*out)
{
    if(!c||!out||c->unknown||c->error)return PMCK_FAILED;
    if(!pmsr_disjoint(c,sizeof(*c),out,sizeof(*out)))return pmck_fail(c,PMCK_ARGUMENT);
    if(c->pending)return pmck_fail(c,PMCK_REENTRY);
    if(pmck_time(c,now)<0)return PMCK_FAILED;
    if(c->phase==2)return c->held==0x3f?PMCK_HELD:pmck_fail(c,PMCK_ARGUMENT);
    if(c->phase==4)return c->restored==0x3f?PMCK_RESTORED:pmck_fail(c,PMCK_ARGUMENT);
    if((c->phase!=1&&c->phase!=3)||c->clock>=PMCK_CLOCKS||c->step>PMCK_STATUS)return pmck_fail(c,PMCK_ARGUMENT);
    if(now<c->not_before)return PMCK_WAIT;
    if(c->events>=PMCK_EVENTS||(c->step==PMCK_STATUS&&c->polls>=PMCK_POLLS))return pmck_fail(c,PMCK_STATUS_ERROR);
    struct pmck_clock clock=pmck_clock(c->clock);
    struct pmck_command command={.address=clock.enable,.sequence=c->events+1,.phase=c->phase,
        .clock=c->clock,.step=c->step,.kind=PMCK_READ};
    if(c->step==PMCK_UPDATE){command.kind=PMCK_WRITE;command.value=c->desired;c->write_intent[c->phase==3]|=1u<<c->clock;}
    else if(c->step==PMCK_BARRIER){command.address=0;command.kind=PMCK_ORDER;}
    else if(c->step==PMCK_STATUS){
        if(!clock.status)return pmck_fail(c,PMCK_ARGUMENT);command.address=clock.status;c->polls++;
    }
    struct pmck_event*e=&c->event[c->events++];e->command=command;e->before=now;e->issued=1;
    c->pending=command.sequence;*out=command;return PMCK_IO;
}
static inline int pmck_complete(struct pmck_lifecycle*c,const struct pmck_command*command,
    uint64_t now,int returned,uint32_t value)
{
    if(!c||!command||c->unknown||c->error)return PMCK_FAILED;
    if(!pmsr_disjoint(c,sizeof(*c),command,sizeof(*command)))return pmck_fail(c,PMCK_ARGUMENT);
    if(!c->pending||c->pending!=c->events||c->events>PMCK_EVENTS||c->clock>=PMCK_CLOCKS||
       (c->phase!=1&&c->phase!=3))return pmck_fail(c,PMCK_REENTRY);
    struct pmck_event*e=&c->event[c->events-1];
    if(!e->issued||e->returned||!pmsr_equal(command,&e->command,sizeof(*command))||
       command->phase!=c->phase||command->clock!=c->clock||command->step!=c->step)return pmck_fail(c,PMCK_REENTRY);
    e->after=now;e->return_raw=returned;e->returned=returned==1;e->value=value;
    if(returned!=1)return pmck_fail(c,PMCK_ACCESS);
    if(pmck_time(c,now)<0)return PMCK_FAILED;
    struct pmck_clock clock=pmck_clock(c->clock);unsigned reverse=c->phase==3;
    uint32_t stable=clock.enable==clock.status?UINT32_C(0x0fffffff):UINT32_MAX;
    switch(c->step){
    case PMCK_SAMPLE:
        c->current=value;
        if(!reverse){
            c->saved[c->clock]=value;c->desired=value|clock.mask;
            if(!(value&clock.mask)){c->changed|=1u<<c->clock;c->step=PMCK_UPDATE;}
            else if(clock.status)c->step=PMCK_STATUS;
            else c->step=PMCK_BARRIER; /* gate delay also applies to a prior vote */
        }else{
            if(!(value&clock.mask)||((value^c->saved[c->clock])&(stable&~clock.mask)))return pmck_fail(c,PMCK_CHANGED);
            c->desired=(value&~clock.mask)|(c->saved[c->clock]&clock.mask);
            if(c->changed&(1u<<c->clock))c->step=PMCK_UPDATE;
            else pmck_advance(c,now); /* borrowed vote remains asserted */
        }break;
    case PMCK_UPDATE:
        c->write_returned[reverse]|=1u<<c->clock;c->step=PMCK_BARRIER;break;
    case PMCK_BARRIER:{
        uint64_t delay=clock.gate_delay?clock.gate_delay:(reverse&&clock.voted?192:0);
        if(now>UINT64_MAX-delay)return pmck_fail(c,PMCK_TIME);
        c->not_before=now+delay;c->step=PMCK_READBACK;break;
    }
    case PMCK_READBACK:
        if((value^c->desired)&stable)return pmck_fail(c,PMCK_READBACK_ERROR);
        if(!clock.status||(reverse&&clock.voted))pmck_advance(c,now);
        else c->step=PMCK_STATUS;break;
    case PMCK_STATUS:
        if(clock.status==clock.enable&&((value^c->desired)&stable))return pmck_fail(c,PMCK_CHANGED);
        if((value&clock.hwcg)||(!reverse&&(!(value&UINT32_C(0x80000000))||
            (value&UINT32_C(0xf0000000))==UINT32_C(0x20000000)))||
            (reverse&&(value&UINT32_C(0x80000000))))pmck_advance(c,now);
        else{
            if(now>UINT64_MAX-PMCK_POLL)return pmck_fail(c,PMCK_TIME);c->not_before=now+PMCK_POLL;
        }break;
    default:return pmck_fail(c,PMCK_ARGUMENT);
    }
    c->pending=0;return c->phase==2?PMCK_HELD:c->phase==4?PMCK_RESTORED:PMCK_WAIT;
}
#endif
