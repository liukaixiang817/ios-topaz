/* SOFTWARE-ONLY WCN3990 host CE register cleanup model.
 * No native caller is admitted: WLAN OFF plus host drain is NOT sufficient
 * evidence that prefetched RX/RRI transactions have stopped. Any future native
 * integration must establish peripheral quiescence before clearing addresses.
 * Register definitions match primary ath10k ce.c/hw.c at458c6079fc1d41d564c37679c8ace02cd83ee817.
 * Observe every owned field first, then disable RRI updates/host ring sizes,
 * clear host bases/watermarks, finally clear the wrapper RRI address. Opposite
 * firmware rings are untouched. No guessed qcax HALT register (WCN3990 has
 * none in its table), SMMU write, memory free or DMA-retired claim follows.
 * This model does not supply that prerequisite or permit memory release. */
#ifndef POLARIS_WIFI_CE_UNPUBLISH_H
#define POLARIS_WIFI_CE_UNPUBLISH_H
#include "polaris-wifi-ce-init.h"
struct pwcx_state {
    struct pwce_init initial;struct pwce_command command;
    uint64_t opening,last;uint32_t started,unknown,error,stage,pipe,index,verify,events,pending,complete;
};
static inline int pwcx_fail(struct pwcx_state*s,unsigned e)
{s->unknown=1;if(!s->error)s->error=e;return -1;}
static inline int pwcx_begin(struct pwcx_state*s,const struct pwce_init*i,uint64_t now)
{
    if(!s||!i||!pwce_zero(s,sizeof(*s))||!i->started||!i->complete||i->unknown||i->error||i->pending||
       !i->epoch||now<i->last||now>UINT64_MAX-19200000)return 0;
    struct pwdm_layout expected={0};
    if(!pwdm_plan(&expected,i->layout.allocation)||!pwce_equal(&expected,&i->layout,sizeof(expected)))return 0;
    s->initial=*i;s->opening=s->last=now;s->started=1;return 1;
}
static inline void pwcx_store(const struct pwcx_state*s,unsigned*offset,uint32_t*value)
{
    const struct pwdm_pipe*p=&s->initial.layout.pipe[s->pipe];unsigned i=s->index;
    if(i<3){pwce_store(&s->initial,s->pipe,i,offset,value);
        if(i==2){*value&=~0x80000u;if(p->sources)*value&=~0xffffu;}return;}
    i-=3;*value=0;
    /* Clear size before base. This ordering is not evidence of an idle DMA
     * engine; the backing must remain resident. No index write is needed. */
    if(p->sources){const unsigned at[]={8,0,4,0x4c};if(i<4){*offset=at[i];return;}i-=4;}
    const unsigned at[]={0x14,0xc,0x10,0x50};*offset=at[i];
}
static inline int pwcx_next(struct pwcx_state*s,uint64_t now,struct pwce_command*out)
{
    if(!s||!out||!s->started||s->unknown||s->error)return -1;
    if(s->pending||now<s->last||now-s->opening>19200000||s->events>=PWCE_EVENTS)return pwcx_fail(s,1);
    s->last=now;if(s->complete)return 2;
    if(s->stage>3||s->pipe>=12||s->verify>2)return pwcx_fail(s,1);
    unsigned count=s->stage==0||s->stage==3?2:pwce_writes(&s->initial.layout.pipe[s->pipe]);
    if(s->index>=count)return pwcx_fail(s,1);
    struct pwce_command c={.sequence=s->events+1,.stage=s->stage,.pipe=s->pipe,.index=s->index};
    if(s->stage==0||s->stage==3){
        c.address=PWCE_WRAPPER+4+4*s->index;
        if(!s->stage){uint64_t rri=s->initial.layout.allocation+s->initial.layout.rri;c.value=s->index?(uint32_t)(rri>>32):(uint32_t)rri;}
    }else{
        unsigned offset;
        if(s->stage==1)pwce_store(&s->initial,s->pipe,s->index,&offset,&c.value);else pwcx_store(s,&offset,&c.value);
        c.address=PWCE_BASE+4096*s->pipe+offset;
    }
    c.operation=s->stage<2||s->verify==2?PWCE_READ:s->verify==1?PWCE_ORDER:PWCE_WRITE;
    if(c.operation==PWCE_ORDER)c.address=c.value=0;
    if(c.operation!=PWCE_ORDER&&!pwce_register(c.address,c.operation==PWCE_WRITE))return pwcx_fail(s,1);
    s->command=c;s->pending=1;*out=c;return 1;
}
static inline int pwcx_complete(struct pwcx_state*s,const struct pwce_command*c,uint64_t now,int returned,uint32_t value)
{
    if(!s||!c||!s->started||s->unknown||s->error)return -1;
    if(!s->pending||!pwce_equal(c,&s->command,sizeof(*c))||now<s->last||now-s->opening>19200000||returned!=1)return pwcx_fail(s,2);
    s->last=now;s->pending=0;s->events++;
    if(c->operation==PWCE_READ&&value!=c->value)return pwcx_fail(s,3);
    if(s->stage>=2&&s->verify<2){s->verify++;return 1;}s->verify=0;s->index++;
    unsigned count=s->stage==0||s->stage==3?2:pwce_writes(&s->initial.layout.pipe[s->pipe]);
    if(s->index==count){
        s->index=0;
        if(!s->stage)s->stage=1;
        else if(s->stage==3){s->complete=1;return 2;}
        else if(++s->pipe==12){s->pipe=0;s->stage++;}
    }return 1;
}
#endif
