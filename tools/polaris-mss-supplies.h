/* Persistent own MSS ARC + four ICNSS VRM request sequencing.
 * This is not a native owner: the parent must retain one exclusive CPU/DRV2
 * epoch, current source/namespace/CmdDb and all original-provider exclusions
 * throughout HELD and the MSS protocol. No original service may race it.
 * Per-transition limits never renew that separate owner or the old roundtrip.
 * XO/PRNG/AOP remain separate mandatory startup dependencies.
 */
#ifndef POLARIS_MSS_SUPPLIES_H
#define POLARIS_MSS_SUPPLIES_H
#include "polaris-mss-rail-request.h"
#include "polaris-mss-clocks.h"
#include "polaris-wifi-firmware-identity.h"
#define PMSP_RESOURCES 19u
#define PMSP_EVENTS 101u /*19 sample +22 raise +19 verify +22 return +19 final*/
#define PMSP_TRANSITION UINT64_C(38400000) /*2s finite returned-request phase*/
enum pmsp_result {PMSP_FAILED=-1,PMSP_WAIT,PMSP_REQUEST,PMSP_HELD,PMSP_RESTORED};
enum pmsp_error {PMSP_OK,PMSP_ARGUMENT,PMSP_REENTRY,PMSP_TIME,PMSP_REQUEST_ERROR,PMSP_VALUE,PMSP_STOP};
struct pmsp_command {uint32_t sequence,phase,index,resource,write,value;};
struct pmsp_event {
    struct pmsp_command command;uint64_t issued,consumed,request_started,request_last;
    uint32_t response,request_events,returned,reserved;uint8_t request_sha256[32];
};
struct pmsp_lifecycle {
    uint64_t epoch,opening,last,transition,held_at,release_at,reset_at,clocks_returned_at;
    uint32_t phase,index,pending,events,error,unknown,held,restored;
    uint32_t minimum[3],saved[PMSP_RESOURCES],target[PMSP_RESOURCES];
    struct pmsp_event event[PMSP_EVENTS];
};
static inline int pmsp_fail(struct pmsp_lifecycle*s,unsigned error)
{if(s){s->unknown=1;if(!s->error)s->error=error;}return PMSP_FAILED;}
static inline int pmsp_time(struct pmsp_lifecycle*s,uint64_t now)
{
    if(!now||now<s->last||now<s->transition||
       (s->phase!=3&&s->phase!=7&&now-s->transition>PMSP_TRANSITION))return pmsp_fail(s,PMSP_TIME);
    s->last=now;return 1;
}
/* Indices must come from THIS epoch's complete own CmdDb selector at raw
 * level384. They are not microvolts, hardcoded maxima or saved vote values. */
static inline int pmsp_begin(struct pmsp_lifecycle*s,uint64_t epoch,const uint32_t minimum[3],uint64_t now,uint64_t hz)
{
    if(!s||!minimum||!pmsr_disjoint(s,sizeof(*s),minimum,12)||!pms_zero(s,sizeof(*s))||
       !epoch||!now||hz!=19200000||now>UINT64_MAX-PMSP_TRANSITION)return PMSP_FAILED;
    for(unsigned k=0;k<3;k++)if(!minimum[k]||minimum[k]>15)return PMSP_FAILED;
    for(unsigned k=0;k<3;k++)s->minimum[k]=minimum[k];
    s->epoch=epoch;s->opening=s->last=s->transition=now;s->phase=1;return PMSP_WAIT;
}
/* VRM vote readback includes RESP_REQ bit31 separately from payload.
 * Own PMIC4 fields: mV13, enable1, mode3, headroom9 bits. Keep the raw word
 * in request/event evidence; never send this metadata as a regulator value.
 * ARC indices have no such allowance. Unknown/reserved bits still refuse. */
static inline int pmsp_response_value(unsigned resource,uint32_t raw,uint32_t*out)
{
    if(!out||resource>=PMSP_RESOURCES)return 0;
    uint32_t mask=15,metadata=0;
    if(resource>=3){
        static const uint32_t fields[4]={0x1fff,1,7,0x1ff};
        mask=fields[(resource-3)%4];metadata=UINT32_C(0x80000000);
    }
    if(raw&~(mask|metadata))return 0;
    *out=raw&mask;return 1;
}
static inline int pmsp_values(struct pmsp_lifecycle*s)
{
    static const uint32_t low[4]={800,1800,1304,3104},high[4]={800,1800,1304,3312};
    for(unsigned k=0;k<3;k++){
        if(s->saved[k]>15||!s->minimum[k]||s->minimum[k]>15)return 0;
        s->target[k]=s->saved[k]>s->minimum[k]?s->saved[k]:s->minimum[k];
    }
    for(unsigned k=0;k<4;k++){
        unsigned n=3+4*k;uint32_t mode=s->saved[n+2];
        if(s->saved[n]>high[k]||s->saved[n+1]>1||(mode!=0&&mode!=4&&mode!=5&&mode!=7)||s->saved[n+3]>511)return 0;
        s->target[n]=s->saved[n]>low[k]?s->saved[n]:low[k];s->target[n+1]=1;
        s->target[n+2]=mode;s->target[n+3]=s->saved[n+3];
    }
    return 1;
}
static inline unsigned pmsp_write_resource(unsigned n,unsigned release)
{
    /* Own pil_mss_make_proxy_votes: MX, MSS, then q6v5 CX. VRM voltage before
     * enable. Reverse release preserves dependency rails until MSS returns. */
    static const unsigned up[11]={1,2,0,3,4,7,8,11,12,15,16};
    static const unsigned down[11]={16,15,12,11,8,7,4,3,0,2,1};
    return n<11?(release?down[n]:up[n]):PMSP_RESOURCES;
}
static inline int pmsp_next(struct pmsp_lifecycle*s,uint64_t now,struct pmsp_command*out)
{
    if(!s||!out||s->error||s->unknown)return PMSP_FAILED;
    if(!pmsr_disjoint(s,sizeof(*s),out,sizeof(*out))||s->pending)return pmsp_fail(s,PMSP_REENTRY);
    if(pmsp_time(s,now)<0)return PMSP_FAILED;
    if(s->phase==3)return s->held==1?PMSP_HELD:pmsp_fail(s,PMSP_ARGUMENT);
    if(s->phase==7)return s->restored==1?PMSP_RESTORED:pmsp_fail(s,PMSP_ARGUMENT);
    if(!s->phase||s->phase>6||s->events>=PMSP_EVENTS)return pmsp_fail(s,PMSP_ARGUMENT);
    struct pmsp_command c={.sequence=s->events+1,.phase=s->phase,.index=s->index};
    if(s->phase==2||s->phase==5){
        if(s->index>=22)return pmsp_fail(s,PMSP_ARGUMENT);
        c.resource=pmsp_write_resource(s->index/2,s->phase==5);c.write=!(s->index&1);
        if(c.write)c.value=s->phase==2?s->target[c.resource]:s->saved[c.resource];
    }else{if(s->index>=PMSP_RESOURCES)return pmsp_fail(s,PMSP_ARGUMENT);c.resource=s->index;}
    struct pmsp_event*e=&s->event[s->events++];e->command=c;e->issued=now;s->pending=c.sequence;*out=c;return PMSP_REQUEST;
}
static inline int pmsp_complete(struct pmsp_lifecycle*s,const struct pmsp_command*c,
    const struct pmrv_request*q,uint64_t now)
{
    if(!s||!c||!q||s->error||s->unknown)return PMSP_FAILED;
    if(!pmsr_disjoint(s,sizeof(*s),c,sizeof(*c))||!pmsr_disjoint(s,sizeof(*s),q,sizeof(*q))||
       !s->pending||s->pending!=s->events||s->events>PMSP_EVENTS)return pmsp_fail(s,PMSP_REENTRY);
    struct pmsp_event*e=&s->event[s->events-1];
    if(e->returned||!pmsr_equal(c,&e->command,sizeof(*c))||c->phase!=s->phase||c->index!=s->index||
       !pmrv_retired(q)||q->epoch!=s->epoch||q->resource!=c->resource||q->write!=c->write||q->value!=c->value||
       q->io.started<e->issued||q->io.last>now||q->io.started<s->last)return pmsp_fail(s,PMSP_REQUEST_ERROR);
    if(pmsp_time(s,now)<0)return PMSP_FAILED;
    e->request_started=q->io.started;e->request_last=q->io.last;e->response=q->response;e->request_events=q->io.events;
    struct pwfi_sha256 hash;pwfi_init(&hash);const uint8_t*raw=(const void*)q;
    for(unsigned n=0;n<sizeof(*q);n++)pwfi_byte(&hash,raw[n]);pwfi_final(&hash,e->request_sha256);
    e->consumed=now;e->returned=1;
    uint32_t response=q->response;
    if(!c->write&&!pmsp_response_value(c->resource,q->response,&response))return pmsp_fail(s,PMSP_VALUE);
    if(s->phase==1)s->saved[c->resource]=response;
    else if(!c->write){
        uint32_t expected=(s->phase==2||s->phase==4)?s->target[c->resource]:s->saved[c->resource];
        if(response!=expected)return pmsp_fail(s,PMSP_VALUE);
    }
    s->pending=0;s->index++;
    if((s->phase==1||s->phase==4||s->phase==6)&&s->index==PMSP_RESOURCES){
        if(s->phase==1&&!pmsp_values(s))return pmsp_fail(s,PMSP_VALUE);
        if(s->phase==6){s->phase=7;s->restored=1;return PMSP_RESTORED;}
        s->phase++;s->index=0;
    }else if((s->phase==2||s->phase==5)&&s->index==22){
        if(s->phase==2){s->phase=3;s->held=s->held_at?0:1;s->held_at=now;return PMSP_HELD;}
        s->phase=6;s->index=0;
    }
    return PMSP_WAIT;
}
/* Only after the same-epoch stop/AXI/reset has admitted restoring all six
 * active clocks. Proxy clocks/AOP and continuous native owner remain parent
 * responsibilities. A failed start is not a substitute for this sequence. */
static inline int pmsp_release(struct pmsp_lifecycle*s,const struct pmck_lifecycle*c,uint64_t now)
{
    if(!s||!c||s->error||s->unknown)return PMSP_FAILED;
    if(!pmsr_disjoint(s,sizeof(*s),c,sizeof(*c))||s->phase!=3||s->held!=1||s->pending||!s->held_at||
       c->phase!=4||c->unknown||c->error||c->pending||c->held!=63||c->restored!=63||
       c->epoch!=s->epoch||c->opening<s->held_at||!c->reset_at||c->reset_at<c->held_at||
       c->release_at<c->reset_at||c->last<c->release_at||now<c->last||now<s->last||now>UINT64_MAX-PMSP_TRANSITION)
        return pmsp_fail(s,PMSP_STOP);
    s->phase=4;s->index=0;s->release_at=s->transition=s->last=now;s->reset_at=c->reset_at;
    s->clocks_returned_at=c->last;return PMSP_WAIT;
}
#endif
