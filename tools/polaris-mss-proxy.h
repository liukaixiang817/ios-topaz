/* Own SDM845 proxy XO + PRNG lifecycle. XO request3 is an ARC index, from
 * own clk-rpmh.c, not a voltage. Own GCC PRNG uses152004 bit13, status134004.
 * Parent must bind current xo.lvl CmdDb entry30080 and retain its continuous
 * CPU/DRV/clock owner. No AOP, active-clock startup or implicit power grant. */
#ifndef POLARIS_MSS_PROXY_H
#define POLARIS_MSS_PROXY_H
#include "polaris-mss-supplies.h"
#define PMPX_EVENTS 530u
#define PMPX_TOTAL UINT64_C(3840000) /*200ms each proxy transition*/
enum pmpx_result {PMPX_FAILED=-1,PMPX_WAIT,PMPX_IO,PMPX_HELD,PMPX_RESTORED};
enum pmpx_step {PMPX_XO_SAMPLE,PMPX_XO_ON,PMPX_XO_VERIFY,PMPX_PRNG_SAMPLE,
    PMPX_PRNG_ON,PMPX_ON_ORDER,PMPX_ON_READBACK,PMPX_ON_STATUS,PMPX_HOLD,
    PMPX_PRNG_RETURN_SAMPLE,PMPX_PRNG_RETURN,PMPX_RETURN_ORDER,PMPX_RETURN_READBACK,
    PMPX_XO_RETURN_SAMPLE,PMPX_XO_RETURN,PMPX_XO_RETURN_VERIFY,PMPX_DONE};
enum pmpx_kind {PMPX_READ=1,PMPX_WRITE,PMPX_ORDER,PMPX_RAIL};
struct pmpx_command {uint64_t address;uint32_t sequence,step,kind,value,write,reserved;};
struct pmpx_event {
    struct pmpx_command command;uint64_t before,after;
    uint32_t returned,value;uint8_t request_sha256[32];
};
struct pmpx_lifecycle {
    uint64_t epoch,opening,last,transition,held_at,release_at,not_before,status_opening;
    uint32_t phase,step,pending,events,error,unknown,held,restored,polls,xo_saved,prng_saved,changed;
    struct pmpx_event event[PMPX_EVENTS];
};
static inline int pmpx_fail(struct pmpx_lifecycle*p,unsigned e)
{if(p){p->unknown=1;if(!p->error)p->error=e;}return PMPX_FAILED;}
static inline int pmpx_time(struct pmpx_lifecycle*p,uint64_t now)
{
    if(!now||now<p->last||now<p->transition||((p->phase==1||p->phase==3)&&now-p->transition>PMPX_TOTAL))return pmpx_fail(p,1);
    p->last=now;return 1;
}
static inline int pmpx_begin(struct pmpx_lifecycle*p,const struct pmsp_lifecycle*s,uint64_t now)
{
    if(!p||!s||!pmsr_disjoint(p,sizeof(*p),s,sizeof(*s))||!pms_zero(p,sizeof(*p))||!now||now>UINT64_MAX-PMPX_TOTAL)return PMPX_FAILED;
    if(s->phase!=3||s->held!=1||s->unknown||s->error||s->pending||!s->epoch||!s->held_at||now<s->last)return pmpx_fail(p,2);
    p->epoch=s->epoch;p->opening=p->last=p->transition=p->not_before=now;p->phase=1;return PMPX_WAIT;
}
static inline int pmpx_next(struct pmpx_lifecycle*p,uint64_t now,struct pmpx_command*out)
{
    if(!p||!out||p->unknown||p->error)return PMPX_FAILED;
    if(!pmsr_disjoint(p,sizeof(*p),out,sizeof(*out))||p->pending)return pmpx_fail(p,3);
    if(pmpx_time(p,now)<0)return PMPX_FAILED;
    if(p->phase==2)return p->held==1&&p->step==PMPX_HOLD?PMPX_HELD:pmpx_fail(p,2);
    if(p->phase==4)return p->restored==1&&p->step==PMPX_DONE?PMPX_RESTORED:pmpx_fail(p,2);
    if((p->phase!=1&&p->phase!=3)||p->events>=PMPX_EVENTS||p->step>=PMPX_DONE||p->step==PMPX_HOLD)return pmpx_fail(p,2);
    if(now<p->not_before)return PMPX_WAIT;
    struct pmpx_command c={.sequence=p->events+1,.step=p->step,.kind=PMPX_RAIL};
    switch(p->step){
    case PMPX_XO_SAMPLE:case PMPX_XO_VERIFY:case PMPX_XO_RETURN_SAMPLE:case PMPX_XO_RETURN_VERIFY:break;
    case PMPX_XO_ON:c.write=1;c.value=3;break;
    case PMPX_XO_RETURN:c.write=1;c.value=p->xo_saved;break;
    case PMPX_PRNG_SAMPLE:case PMPX_ON_READBACK:case PMPX_PRNG_RETURN_SAMPLE:case PMPX_RETURN_READBACK:
        c.kind=PMPX_READ;c.address=0x152004;break;
    case PMPX_PRNG_ON:c.kind=PMPX_WRITE;c.address=0x152004;c.value=p->prng_saved|0x2000;break;
    case PMPX_PRNG_RETURN:c.kind=PMPX_WRITE;c.address=0x152004;c.value=p->prng_saved;break;
    case PMPX_ON_ORDER:case PMPX_RETURN_ORDER:c.kind=PMPX_ORDER;break;
    case PMPX_ON_STATUS:
        if(p->polls>=500||now<p->status_opening||now-p->status_opening>PMCK_LIMIT)return pmpx_fail(p,4);
        c.kind=PMPX_READ;c.address=0x134004;p->polls++;break;
    default:return pmpx_fail(p,2);
    }
    struct pmpx_event*e=&p->event[p->events++];e->command=c;e->before=now;p->pending=c.sequence;*out=c;return PMPX_IO;
}
static inline int pmpx_complete(struct pmpx_lifecycle*p,const struct pmpx_command*c,
    uint64_t now,int returned,uint32_t value,const struct pmrv_request*q)
{
    if(!p||!c||p->unknown||p->error)return PMPX_FAILED;
    if(!pmsr_disjoint(p,sizeof(*p),c,sizeof(*c))||!p->pending||p->pending!=p->events||p->events>PMPX_EVENTS||
       (q&&!pmsr_disjoint(p,sizeof(*p),q,sizeof(*q))))return pmpx_fail(p,3);
    struct pmpx_event*e=&p->event[p->events-1];
    if(e->returned||!pmsr_equal(c,&e->command,sizeof(*c))||c->step!=p->step||returned!=1)return pmpx_fail(p,3);
    if(pmpx_time(p,now)<0)return PMPX_FAILED;
    if(c->kind==PMPX_RAIL){
        if(!q||!pmrv_retired(q)||q->epoch!=p->epoch||q->resource!=PMRV_XO||q->write!=c->write||q->value!=c->value||
           q->io.started<e->before||q->io.last>now)return pmpx_fail(p,5);
        struct pwfi_sha256 hash;pwfi_init(&hash);const uint8_t*raw=(const void*)q;
        for(unsigned n=0;n<sizeof(*q);n++)pwfi_byte(&hash,raw[n]);pwfi_final(&hash,e->request_sha256);value=q->response;
    }else if(q)return pmpx_fail(p,5);
    e->after=now;e->value=value;e->returned=1;p->not_before=now;
    switch(p->step){
    case PMPX_XO_SAMPLE:if(value>3)return pmpx_fail(p,6);p->xo_saved=value;p->step++;break;
    case PMPX_XO_VERIFY:case PMPX_XO_RETURN_SAMPLE:if(value!=3)return pmpx_fail(p,6);p->step++;break;
    case PMPX_PRNG_SAMPLE:p->prng_saved=value;p->changed=!(value&0x2000);p->step=p->changed?PMPX_PRNG_ON:PMPX_ON_ORDER;break;
    case PMPX_ON_READBACK:
        if(value!=(p->prng_saved|0x2000))return pmpx_fail(p,6);p->status_opening=now;p->step++;break;
    case PMPX_ON_STATUS:
        if((value&2)||!(value&0x80000000)||(value&0xf0000000)==0x20000000){p->step=PMPX_HOLD;p->phase=2;p->held=1;p->held_at=now;}
        else{if(now>UINT64_MAX-20)return pmpx_fail(p,1);p->not_before=now+20;}break;
    case PMPX_PRNG_RETURN_SAMPLE:
        if(value!=(p->prng_saved|0x2000))return pmpx_fail(p,6);
        p->step=p->changed?PMPX_PRNG_RETURN:PMPX_XO_RETURN_SAMPLE;break;
    case PMPX_RETURN_ORDER:
        if(now>UINT64_MAX-192)return pmpx_fail(p,1);p->not_before=now+192;p->step++;break;
    case PMPX_RETURN_READBACK:if(value!=p->prng_saved)return pmpx_fail(p,6);p->step++;break;
    case PMPX_XO_RETURN_VERIFY:
        if(value!=p->xo_saved)return pmpx_fail(p,6);p->step=PMPX_DONE;p->phase=4;p->restored=1;break;
    default:p->step++;break;
    }
    p->pending=0;return p->phase==2?PMPX_HELD:p->phase==4?PMPX_RESTORED:PMPX_WAIT;
}
static inline int pmpx_release(struct pmpx_lifecycle*p,const struct pmsp_lifecycle*s,const struct pmck_lifecycle*c,uint64_t now)
{
    if(!p||!s||!c||p->unknown||p->error)return PMPX_FAILED;
    if(!pmsr_disjoint(p,sizeof(*p),s,sizeof(*s))||!pmsr_disjoint(p,sizeof(*p),c,sizeof(*c))||
       p->phase!=2||p->held!=1||p->step!=PMPX_HOLD||p->pending||!p->held_at||
       s->phase!=3||s->held!=1||s->unknown||s->error||s->pending||s->epoch!=p->epoch||
       c->phase!=4||c->unknown||c->error||c->pending||c->held!=63||c->restored!=63||c->epoch!=p->epoch||
       c->opening<p->held_at||c->reset_at<p->held_at||c->release_at<c->reset_at||c->last<c->release_at||
       now<c->last||now<p->last||now<s->last||now>UINT64_MAX-PMPX_TOTAL)return pmpx_fail(p,7);
    p->phase=3;p->step=PMPX_PRNG_RETURN_SAMPLE;p->transition=p->release_at=p->last=p->not_before=now;return PMPX_WAIT;
}
#endif
