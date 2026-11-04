/* Own msm_qmp.c/PIL load_state transport over a CURRENT connected, idle
 * AOP channel. No link/channel takeover, pending-message cancellation, RX
 * consumption or guessed mailbox offsets. Native parent must continuously
 * exclude original QMP writers and bind DT/GCD/Device/source ownership.
 * Reads both complete descriptors before writing; restores idle TX payload
 * after fresh remote consumption. UNKNOWN never clears length or sends OFF.
 */
#ifndef POLARIS_MSS_AOP_H
#define POLARIS_MSS_AOP_H
#include "polaris-mss-proxy.h"
#define PMAQ_BASE UINT64_C(0xc300000)
#define PMAQ_BYTES 0x100000u
#define PMAQ_IRQ UINT64_C(0x1799000c)
#define PMAQ_EVENTS 2048u
#define PMAQ_TOTAL UINT64_C(38400000)
#define PMAQ_TX_TIMEOUT UINT64_C(19200000)
#define PMAQ_POLL UINT64_C(192000)
enum pmaq_result {PMAQ_FAILED=-1,PMAQ_WAIT,PMAQ_IO,PMAQ_CONSUMED};
enum pmaq_step {PMAQ_DESC,PMAQ_CONFIRM,PMAQ_RX_EMPTY,PMAQ_TX_EMPTY,PMAQ_SAVE,
    PMAQ_WRITE,PMAQ_READBACK,PMAQ_PRE_DESC,PMAQ_PRE_RX,PMAQ_PRE_TX,PMAQ_LENGTH,
    PMAQ_ORDER,PMAQ_DOORBELL,PMAQ_POLL_DESC,PMAQ_POLL_RX,PMAQ_POLL_TX,
    PMAQ_RESTORE,PMAQ_RESTORE_READ,PMAQ_FINAL_DESC,PMAQ_FINAL_RX,PMAQ_FINAL_TX,PMAQ_DONE};
enum pmaq_kind {PMAQ_READ=1,PMAQ_WRITE32,PMAQ_FULL_ORDER};
struct pmaq_command {uint64_t address;uint32_t sequence,step,index,kind,value,reserved;};
struct pmaq_event {struct pmaq_command command;uint64_t before,after;uint32_t returned,value;};
struct pmaq_notify {
    uint64_t epoch,opening,last,not_before,sent_at,consumed_at;
    uint32_t on,attempted,step,index,pending,events,unknown,error,complete,polls,writes,length_issued,doorbell_issued;
    uint32_t require_previous,descriptor[16],previous[16],saved[24];
    struct pmaq_event event[PMAQ_EVENTS];
};
static inline int pmaq_fail(struct pmaq_notify*q,unsigned error)
{if(q){q->unknown=1;if(!q->error)q->error=error;}return PMAQ_FAILED;}
static inline uint32_t pmaq_word(unsigned on,unsigned n)
{
    static const char msg_on[96]="{class: image, res: load_state, name: modem, val: on}";
    static const char msg_off[96]="{class: image, res: load_state, name: modem, val: off}";
    if(on>1||n>=24)return 0;const uint8_t*p=(const void*)(on?msg_on:msg_off);uint32_t v=0;
    for(unsigned j=0;j<4;j++)v|=(uint32_t)p[4*n+j]<<(8*j);return v;
}
static inline int pmaq_geometry(const uint32_t d[16])
{
    if(d[0]!=0x4d41494c||d[1]!=1||d[2])return 0;
    const unsigned state[8]={3,4,5,6,9,10,11,12};
    for(unsigned k=0;k<8;k++)if(d[state[k]]!=0xffff)return 0;
    uint32_t rx=d[8],rxbytes=d[7],tx=d[14],txbytes=d[13];
    if((rx&3)||(tx&3)||(rxbytes&3)||(txbytes&3)||rx<64||tx<64||rxbytes<4||txbytes<100||
       rx>PMAQ_BYTES||rxbytes>PMAQ_BYTES-rx||tx>PMAQ_BYTES||txbytes>PMAQ_BYTES-tx)return 0;
    return rx>=tx+txbytes||tx>=rx+rxbytes;
}
static inline int pmaq_time(struct pmaq_notify*q,uint64_t now)
{
    if(!now||now<q->last||now<q->opening||now-q->opening>PMAQ_TOTAL||
       (q->step>=PMAQ_POLL_DESC&&q->step<=PMAQ_POLL_TX&&
        (!q->sent_at||now<q->sent_at||now-q->sent_at>PMAQ_TX_TIMEOUT)))return pmaq_fail(q,1);
    q->last=now;return 1;
}
static inline int pmaq_on(struct pmaq_notify*q,uint64_t epoch,uint64_t now)
{
    if(!q||!pms_zero(q,sizeof(*q))||!epoch||!now||now>UINT64_MAX-PMAQ_TOTAL)return PMAQ_FAILED;
    q->attempted=q->on=1;q->epoch=epoch;q->opening=q->last=q->not_before=now;return PMAQ_WAIT;
}
static inline int pmaq_off(struct pmaq_notify*q,const struct pmaq_notify*on,
    const struct pmpx_lifecycle*x,const struct pmsp_lifecycle*s,uint64_t now)
{
    if(!q||!on||!x||!s||!pmsr_disjoint(q,sizeof(*q),on,sizeof(*on))||
       !pmsr_disjoint(q,sizeof(*q),x,sizeof(*x))||!pmsr_disjoint(q,sizeof(*q),s,sizeof(*s))||
       !pms_zero(q,sizeof(*q))||!now||now>UINT64_MAX-PMAQ_TOTAL)return PMAQ_FAILED;
    if(on->on!=1||on->attempted!=1||on->complete!=1||on->unknown||on->error||on->pending||on->step!=PMAQ_DONE||
       !on->epoch||!on->consumed_at||x->epoch!=on->epoch||s->epoch!=on->epoch||
       x->phase!=4||x->restored!=1||x->unknown||x->error||x->pending||x->opening<on->consumed_at||
       s->phase!=7||s->restored!=1||s->unknown||s->error||s->pending||s->opening<on->consumed_at||
       s->release_at<x->last||now<s->last||now<x->last||now<on->last)return pmaq_fail(q,2);
    q->epoch=on->epoch;q->attempted=q->require_previous=1;q->opening=q->last=q->not_before=now;
    for(unsigned k=0;k<16;k++)q->previous[k]=on->descriptor[k];return PMAQ_WAIT;
}
static inline int pmaq_next(struct pmaq_notify*q,uint64_t now,struct pmaq_command*out)
{
    if(!q||!out||q->unknown||q->error)return PMAQ_FAILED;
    if(!pmsr_disjoint(q,sizeof(*q),out,sizeof(*out))||q->pending)return pmaq_fail(q,3);
    if(q->complete)return q->complete==1&&q->step==PMAQ_DONE?PMAQ_CONSUMED:pmaq_fail(q,2);
    if(q->attempted!=1||!q->epoch||q->on>1||q->step>=PMAQ_DONE||q->events>=PMAQ_EVENTS||pmaq_time(q,now)<0)return pmaq_fail(q,2);
    if(now<q->not_before)return PMAQ_WAIT;
    struct pmaq_command c={.sequence=q->events+1,.step=q->step,.index=q->index,.kind=PMAQ_READ};
    uint64_t tx=PMAQ_BASE+q->descriptor[14],rx=PMAQ_BASE+q->descriptor[8];
    switch(q->step){
    case PMAQ_DESC:case PMAQ_CONFIRM:case PMAQ_PRE_DESC:case PMAQ_POLL_DESC:case PMAQ_FINAL_DESC:
        if(q->index>=16)return pmaq_fail(q,2);c.address=PMAQ_BASE+4*q->index;
        if(q->step==PMAQ_POLL_DESC&&!q->index&&++q->polls>101)return pmaq_fail(q,4);break;
    case PMAQ_RX_EMPTY:case PMAQ_PRE_RX:case PMAQ_POLL_RX:case PMAQ_FINAL_RX:c.address=rx;break;
    case PMAQ_TX_EMPTY:case PMAQ_PRE_TX:case PMAQ_POLL_TX:case PMAQ_FINAL_TX:c.address=tx;break;
    case PMAQ_SAVE:case PMAQ_WRITE:case PMAQ_READBACK:case PMAQ_RESTORE:case PMAQ_RESTORE_READ:
        if(q->index>=24)return pmaq_fail(q,2);c.address=tx+4+q->index*4;
        if(q->step==PMAQ_WRITE||q->step==PMAQ_RESTORE){c.kind=PMAQ_WRITE32;c.value=q->step==PMAQ_WRITE?pmaq_word(q->on,q->index):q->saved[q->index];}break;
    case PMAQ_LENGTH:c.address=tx;c.kind=PMAQ_WRITE32;c.value=96;q->length_issued=1;break;
    case PMAQ_ORDER:c.kind=PMAQ_FULL_ORDER;break;
    case PMAQ_DOORBELL:c.address=PMAQ_IRQ;c.kind=PMAQ_WRITE32;c.value=1;q->doorbell_issued=1;break;
    default:return pmaq_fail(q,2);
    }
    if(q->step>PMAQ_DESC&&!pmaq_geometry(q->descriptor))return pmaq_fail(q,2);
    struct pmaq_event*e=&q->event[q->events++];e->command=c;e->before=now;q->pending=c.sequence;
    if(c.kind==PMAQ_WRITE32)q->writes++;*out=c;return PMAQ_IO;
}
static inline int pmaq_complete(struct pmaq_notify*q,const struct pmaq_command*c,uint64_t now,int returned,uint32_t value)
{
    if(!q||!c||q->error||q->unknown)return PMAQ_FAILED;
    if(!pmsr_disjoint(q,sizeof(*q),c,sizeof(*c))||!q->pending||q->pending!=q->events||q->events>PMAQ_EVENTS)return pmaq_fail(q,3);
    struct pmaq_event*e=&q->event[q->events-1];
    if(e->returned||!pmsr_equal(c,&e->command,sizeof(*c))||c->step!=q->step||c->index!=q->index||returned!=1)return pmaq_fail(q,3);
    if(pmaq_time(q,now)<0)return PMAQ_FAILED;e->after=now;e->value=value;e->returned=1;
    switch(q->step){
    case PMAQ_DESC:
        q->descriptor[q->index]=value;
        if(q->require_previous&&value!=q->previous[q->index])return pmaq_fail(q,5);
        if(++q->index==16){if(!pmaq_geometry(q->descriptor))return pmaq_fail(q,5);q->index=0;q->step++;}break;
    case PMAQ_CONFIRM:case PMAQ_PRE_DESC:case PMAQ_POLL_DESC:case PMAQ_FINAL_DESC:
        if(value!=q->descriptor[q->index])return pmaq_fail(q,5);
        if(++q->index==16){q->index=0;q->step++;}break;
    case PMAQ_RX_EMPTY:case PMAQ_TX_EMPTY:case PMAQ_PRE_RX:case PMAQ_PRE_TX:case PMAQ_POLL_RX:case PMAQ_FINAL_RX:
        if(value)return pmaq_fail(q,6);q->step++;break;
    case PMAQ_SAVE:q->saved[q->index]=value;if(++q->index==24){q->index=0;q->step++;}break;
    case PMAQ_WRITE:case PMAQ_RESTORE:q->step++;break;
    case PMAQ_READBACK:case PMAQ_RESTORE_READ:{
        uint32_t expected=q->step==PMAQ_READBACK?pmaq_word(q->on,q->index):q->saved[q->index];
        if(value!=expected)return pmaq_fail(q,7);
        if(++q->index==24){q->index=0;q->step++;}else q->step--;break;
    }
    case PMAQ_LENGTH:q->sent_at=now;q->step++;break;
    case PMAQ_ORDER:case PMAQ_DOORBELL:q->step++;break;
    case PMAQ_POLL_TX:
        if(!value){q->consumed_at=now;q->step=PMAQ_RESTORE;}
        else if(value==96){if(now>UINT64_MAX-PMAQ_POLL)return pmaq_fail(q,1);q->step=PMAQ_POLL_DESC;q->not_before=now+PMAQ_POLL;}
        else return pmaq_fail(q,6);break;
    case PMAQ_FINAL_TX:
        if(value||!q->length_issued||!q->doorbell_issued||!q->consumed_at)return pmaq_fail(q,6);
        q->complete=1;q->step=PMAQ_DONE;break;
    default:return pmaq_fail(q,2);
    }
    q->pending=0;return q->complete?PMAQ_CONSUMED:PMAQ_WAIT;
}
#endif
