/* Terminal whole-system shutdown policy for a RAM-only native session.
 * Arm DEN0022D 5.10/5.15, own DT arm,psci-1.0 + smc. This is NOT WLAN DMA
 * retirement: every mapping, allocation and VMID grant stays resident through
 * the nonreturning SYSTEM_OFF. No per-device power drop or memory return.
 * Native integration must bind actual host quiescence, copied kernel slot,
 * current CPU owner and retained backing; this pure policy grants none of them.
 */
#ifndef POLARIS_WIFI_SYSTEM_OFF_H
#define POLARIS_WIFI_SYSTEM_OFF_H
#include "../shim/polaris/runtime-quiesce.h"
#include "polaris-wifi-mailbox.h"
#define PWOF_LIMIT UINT64_C(1152000000) /* One60s window at19.2MHz. */
#define PWOF_POLL UINT64_C(19200)
enum pwof_kind {PWOF_PSCI=1,PWOF_STATUS,PWOF_PUBLISH,PWOF_POWER_OFF};
enum pwof_phase {PWOF_VERSION=1,PWOF_FEATURES,PWOF_INITIAL,PWOF_REQUEST,PWOF_DRAIN,PWOF_PEERS,PWOF_TERMINAL};
struct pwof_command {uint64_t function,argument;uint32_t kind,phase,peer,sequence;};
struct pwof_state {
    uint64_t opening,last,next_poll,cookie;
    struct polaris_shutdown_request request;
    struct polaris_shutdown_status initial,drained;
    struct pwof_command command;int64_t version,features,affinity[7],returned_off;
    uint32_t started,unknown,error,phase,pending,events,peer;
};
static inline int pwof_same(const void*a,const void*b,unsigned bytes)
{const uint8_t*x=a,*y=b;for(unsigned n=0;n<bytes;n++)if(x[n]!=y[n])return 0;return 1;}
static inline int pwof_fail(struct pwof_state*s,unsigned error)
{if(s){s->unknown=1;if(!s->error)s->error=error;}return -1;}
static inline int pwof_time(struct pwof_state*s,uint64_t now)
{
    if(!s||!s->started||s->unknown||s->error)return 0;
    if(now<s->last||now<s->opening||now-s->opening>PWOF_LIMIT){pwof_fail(s,1);return 0;}
    s->last=now;return 1;
}
static inline int pwof_begin(struct pwof_state*s,uint64_t now,uint64_t frequency)
{
    if(!s||!pwmb_zero(s,sizeof(*s))||!now||now>UINT64_MAX-PWOF_LIMIT||frequency!=19200000)return 0;
    s->started=1;s->opening=s->last=now;s->phase=PWOF_VERSION;return 1;
}
/*0 wait;1 exactly one typed operation;negative retains all resources. There
 * is deliberately no successful completion return after issuing SYSTEM_OFF. */
static inline int pwof_next(struct pwof_state*s,uint64_t now,struct pwof_command*out)
{
    if(!out||!pwof_time(s,now))return -1;
    if(s->pending||s->events==UINT32_MAX||s->phase<PWOF_VERSION||s->phase>PWOF_TERMINAL)return pwof_fail(s,2);
    if(s->phase==PWOF_DRAIN&&now<s->next_poll)return 0;
    struct pwof_command c={.phase=s->phase,.peer=s->peer,.sequence=s->events+1};
    switch(s->phase){
    case PWOF_VERSION:c.kind=PWOF_PSCI;c.function=UINT64_C(0x84000000);break;
    case PWOF_FEATURES:c.kind=PWOF_PSCI;c.function=UINT64_C(0x8400000a);c.argument=UINT64_C(0x84000008);break;
    case PWOF_INITIAL:case PWOF_DRAIN:c.kind=PWOF_STATUS;break;
    case PWOF_REQUEST:c.kind=PWOF_PUBLISH;break;
    case PWOF_PEERS:
        if(s->peer>=7)return pwof_fail(s,2);
        c.kind=PWOF_PSCI;c.function=UINT64_C(0xc4000004);c.argument=(uint64_t)(s->peer+1)*0x100;break;
    case PWOF_TERMINAL:c.kind=PWOF_POWER_OFF;c.function=UINT64_C(0x84000008);break;
    }
    s->command=c;s->pending=1;*out=c;return 1;
}
static inline int pwof_status_base(const struct polaris_shutdown_status*k)
{return k&&k->cookie&&!k->error&&!k->write_epoch&&!k->flushed_epoch&&pwmb_zero(k->reserved,sizeof(k->reserved));}
static inline int pwof_complete(struct pwof_state*s,const struct pwof_command*c,
    uint64_t now,int delivered,int64_t value,const struct polaris_shutdown_status*k)
{
    if(!s||!c||!pwof_time(s,now))return -1;
    if(!s->pending||!pwof_same(c,&s->command,sizeof(*c))||delivered!=1)return pwof_fail(s,3);
    s->pending=0;s->events++;
    if(s->phase==PWOF_VERSION){
        s->version=value;if(value<0x10000||value>0x1ffff)return pwof_fail(s,4);s->phase++;
    }else if(s->phase==PWOF_FEATURES){
        s->features=value;if(value)return pwof_fail(s,4);s->phase++;
    }else if(s->phase==PWOF_INITIAL){
        if(!pwof_status_base(k)||k->phase!=POLARIS_Q_RUNNING||k->sequence||k->mode||
           k->capabilities!=POLARIS_Q_RAM_CONFIG)return pwof_fail(s,5);
        s->initial=*k;s->cookie=k->cookie;s->request.cookie=k->cookie;
        s->request.sequence=1;s->request.mode=2;s->phase++;
    }else if(s->phase==PWOF_REQUEST){
        if(value)return pwof_fail(s,6);s->phase++;
    }else if(s->phase==PWOF_DRAIN){
        if(!pwof_status_base(k)||k->cookie!=s->cookie)return pwof_fail(s,7);
        if(k->phase==POLARIS_Q_RUNNING){if(!pwof_same(k,&s->initial,sizeof(*k)))return pwof_fail(s,7);}
        else if(k->phase==POLARIS_Q_REQUESTED){
            if(k->sequence!=1||k->mode!=2||k->capabilities!=POLARIS_Q_RAM_CONFIG)return pwof_fail(s,7);
        }else if(polaris_q_ram_drained(k,s->cookie,1,2)){s->drained=*k;s->phase++;return 1;}
        else return pwof_fail(s,7);
        s->next_poll=now+PWOF_POLL;
    }else if(s->phase==PWOF_PEERS){
        /* Existing kernel drain parks boot CPU700 after masking IRQs and
         * stopping all its secondaries. Its drained status is not OFF proof. */
        if(s->peer>=7||!k||!pwof_same(k,&s->drained,sizeof(*k)))return pwof_fail(s,8);
        s->affinity[s->peer]=value;
        if(value!=(s->peer==6?0:1))return pwof_fail(s,8);
        if(++s->peer==7)s->phase++;
    }else if(s->phase==PWOF_TERMINAL){
        s->returned_off=value;return pwof_fail(s,9); /* Even returned0 is failure. */
    }else return pwof_fail(s,2);
    return 1;
}
#endif
