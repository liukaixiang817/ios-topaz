/* Own msm_qmp.c/PIL load_state transport over an idle AOP channel. An
 * exclusively owned, pristine DOWN AP endpoint can perform the source QMP
 * handshake; mixed/in-flight inherited states refuse. No pending-message
 * cancellation, RX consumption or guessed offsets. Native parent must continuously
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
/* Own QMP_TOUT_MS=5000. One absolute connection deadline, never renewed.
 * Polling replaces interrupts only while the original AP writers are excluded. */
#define PMAQ_CONNECT_TIMEOUT UINT64_C(96000000)
#define PMAQ_CONNECT_POLL UINT64_C(1920000)
#define PMAQ_UP 0x0000ffffu
#define PMAQ_DOWN 0xffff0000u
enum pmaq_result {PMAQ_FAILED=-1,PMAQ_WAIT,PMAQ_IO,PMAQ_CONSUMED};
enum pmaq_step {PMAQ_DESC,PMAQ_CONFIRM,PMAQ_RX_EMPTY,PMAQ_TX_EMPTY,PMAQ_SAVE,
    PMAQ_WRITE,PMAQ_READBACK,PMAQ_PRE_DESC,PMAQ_PRE_RX,PMAQ_PRE_TX,PMAQ_LENGTH,
    PMAQ_ORDER,PMAQ_DOORBELL,PMAQ_POLL_DESC,PMAQ_POLL_RX,PMAQ_POLL_TX,
    PMAQ_RESTORE,PMAQ_RESTORE_READ,PMAQ_FINAL_DESC,PMAQ_FINAL_RX,PMAQ_FINAL_TX,PMAQ_DONE,
    PMAQ_CONNECT_RX,PMAQ_CONNECT_TX,PMAQ_CONNECT_WRITE,PMAQ_CONNECT_READBACK,
    PMAQ_CONNECT_ORDER,PMAQ_CONNECT_IRQ,PMAQ_CONNECT_DESC,
    PMAQ_CONNECT_CHECK_RX,PMAQ_CONNECT_CHECK_TX};
enum pmaq_kind {PMAQ_READ=1,PMAQ_WRITE32,PMAQ_FULL_ORDER};
struct pmaq_command {uint64_t address;uint32_t sequence,step,index,kind,value,reserved;};
struct pmaq_event {struct pmaq_command command;uint64_t before,after;uint32_t returned,value;};
struct pmaq_notify {
    uint64_t epoch,opening,last,not_before,sent_at,consumed_at;
    uint32_t on,attempted,step,index,pending,events,unknown,error,complete,polls,writes,length_issued,doorbell_issued;
    uint32_t require_previous,descriptor[16],previous[16],saved[24];
    uint64_t connected_at;
    uint32_t connecting,connect_phase,connect_polls,sample[16];
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
static inline int pmaq_layout(const uint32_t d[16])
{
    if(d[0]!=0x4d41494c||d[1]!=1||d[2])return 0;
    uint32_t rx=d[8],rxbytes=d[7],tx=d[14],txbytes=d[13];
    if((rx&3)||(tx&3)||(rxbytes&3)||(txbytes&3)||rx<64||tx<64||rxbytes<4||txbytes<100||
       rx>PMAQ_BYTES||rxbytes>PMAQ_BYTES-rx||tx>PMAQ_BYTES||txbytes>PMAQ_BYTES-tx)return 0;
    return rx>=tx+txbytes||tx>=rx+rxbytes;
}
static inline int pmaq_geometry(const uint32_t d[16])
{
    const unsigned state[8]={3,4,5,6,9,10,11,12};
    if(!pmaq_layout(d))return 0;
    for(unsigned k=0;k<8;k++)if(d[state[k]]!=PMAQ_UP)return 0;return 1;
}
static inline int pmaq_pristine(const uint32_t d[16])
{
    const unsigned down[7]={4,5,6,9,10,11,12};
    if(!pmaq_layout(d)||d[3]!=PMAQ_UP)return 0;
    for(unsigned k=0;k<7;k++)if(d[down[k]]!=PMAQ_DOWN)return 0;return 1;
}
/* No writes of remote-owned ACKs, allocation fields or reset/down states.
 * These four UP writes are the source's link ACK, local link, local channel,
 * remote channel ACK, in that order. Device readback precedes publication. */
static inline int pmaq_connect_write(const struct pmaq_notify*q,unsigned index)
{
    if(q->connecting!=1||q->connected_at||q->on!=1||q->require_previous||
       !pmaq_layout(q->descriptor)||index>=16||q->descriptor[index]!=PMAQ_DOWN)return 0;
    const uint32_t*d=q->descriptor;
    if(q->connect_phase==0)return (index==4&&pmaq_pristine(d))||
        (index==9&&d[3]==PMAQ_UP&&d[4]==PMAQ_UP&&d[10]==PMAQ_DOWN&&
         d[5]==PMAQ_DOWN&&d[6]==PMAQ_DOWN&&d[11]==PMAQ_DOWN&&d[12]==PMAQ_DOWN);
    if(d[3]!=PMAQ_UP||d[4]!=PMAQ_UP||d[9]!=PMAQ_UP||d[10]!=PMAQ_UP)return 0;
    if(q->connect_phase==1)return index==11&&d[6]==PMAQ_DOWN&&d[12]==PMAQ_DOWN;
    return q->connect_phase==2&&index==6&&d[5]==PMAQ_UP&&d[11]==PMAQ_UP;
}
static inline int pmaq_connect_sample(struct pmaq_notify*q)
{
    if(!pmaq_layout(q->sample))return 0;
    for(unsigned k=0;k<16;k++){
        uint32_t a=q->descriptor[k],b=q->sample[k];
        /* Remote may open its channel before local startup, as in the
         * source LINK_CONNECTED path. Its ACK needs our channel publication.
         * Remote owns only these transitions; local/state/geometry changes
         * by another AP writer or remote reset are not adopted. */
        if(a!=b&&!(a==PMAQ_DOWN&&b==PMAQ_UP&&
           (k==10||k==5||(k==12&&q->connect_phase>=1))))return 0;
    }
    for(unsigned k=0;k<16;k++)q->descriptor[k]=q->sample[k];return 1;
}
static inline int pmaq_time(struct pmaq_notify*q,uint64_t now)
{
    uint64_t start=q->connected_at?q->connected_at:q->opening;
    uint64_t limit=q->connecting&&!q->connected_at?PMAQ_CONNECT_TIMEOUT:PMAQ_TOTAL;
    if(!now||now<q->last||now<start||now<q->opening||now-start>limit||
       now-q->opening>PMAQ_CONNECT_TIMEOUT+PMAQ_TOTAL||
       (q->step>=PMAQ_POLL_DESC&&q->step<=PMAQ_POLL_TX&&
        (!q->sent_at||now<q->sent_at||now-q->sent_at>PMAQ_TX_TIMEOUT)))return pmaq_fail(q,1);
    q->last=now;return 1;
}
static inline int pmaq_on(struct pmaq_notify*q,uint64_t epoch,uint64_t now)
{
    if(!q||!pms_zero(q,sizeof(*q))||!epoch||!now||now>UINT64_MAX-PMAQ_TOTAL-PMAQ_CONNECT_TIMEOUT)return PMAQ_FAILED;
    q->attempted=q->on=1;q->epoch=epoch;q->opening=q->last=q->not_before=now;return PMAQ_WAIT;
}
static inline int pmaq_off(struct pmaq_notify*q,const struct pmaq_notify*on,
    const struct pmpx_lifecycle*x,const struct pmsp_lifecycle*s,uint64_t now)
{
    if(!q||!on||!x||!s||!pmsr_disjoint(q,sizeof(*q),on,sizeof(*on))||
       !pmsr_disjoint(q,sizeof(*q),x,sizeof(*x))||!pmsr_disjoint(q,sizeof(*q),s,sizeof(*s))||
       !pms_zero(q,sizeof(*q))||!now||now>UINT64_MAX-PMAQ_TOTAL-PMAQ_CONNECT_TIMEOUT)return PMAQ_FAILED;
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
    if(q->attempted!=1||!q->epoch||q->on>1||(q->step==PMAQ_DONE||q->step>PMAQ_CONNECT_CHECK_TX)||q->events>=PMAQ_EVENTS||pmaq_time(q,now)<0)return pmaq_fail(q,2);
    if(now<q->not_before)return PMAQ_WAIT;
    struct pmaq_command c={.sequence=q->events+1,.step=q->step,.index=q->index,.kind=PMAQ_READ};
    uint64_t tx=PMAQ_BASE+q->descriptor[14],rx=PMAQ_BASE+q->descriptor[8];
    switch(q->step){
    case PMAQ_DESC:case PMAQ_CONFIRM:case PMAQ_PRE_DESC:case PMAQ_POLL_DESC:case PMAQ_FINAL_DESC:case PMAQ_CONNECT_DESC:
        if(q->index>=16)return pmaq_fail(q,2);c.address=PMAQ_BASE+4*q->index;
        if(q->step==PMAQ_POLL_DESC&&!q->index&&++q->polls>101)return pmaq_fail(q,4);break;
    case PMAQ_RX_EMPTY:case PMAQ_PRE_RX:case PMAQ_POLL_RX:case PMAQ_FINAL_RX:case PMAQ_CONNECT_RX:case PMAQ_CONNECT_CHECK_RX:c.address=rx;break;
    case PMAQ_TX_EMPTY:case PMAQ_PRE_TX:case PMAQ_POLL_TX:case PMAQ_FINAL_TX:case PMAQ_CONNECT_TX:case PMAQ_CONNECT_CHECK_TX:c.address=tx;break;
    case PMAQ_SAVE:case PMAQ_WRITE:case PMAQ_READBACK:case PMAQ_RESTORE:case PMAQ_RESTORE_READ:
        if(q->index>=24)return pmaq_fail(q,2);c.address=tx+4+q->index*4;
        if(q->step==PMAQ_WRITE||q->step==PMAQ_RESTORE){c.kind=PMAQ_WRITE32;c.value=q->step==PMAQ_WRITE?pmaq_word(q->on,q->index):q->saved[q->index];}break;
    case PMAQ_LENGTH:c.address=tx;c.kind=PMAQ_WRITE32;c.value=96;q->length_issued=1;break;
    case PMAQ_CONNECT_WRITE:case PMAQ_CONNECT_READBACK:
        if(!pmaq_connect_write(q,q->index))return pmaq_fail(q,5);
        c.address=PMAQ_BASE+4*q->index;
        if(q->step==PMAQ_CONNECT_WRITE){c.kind=PMAQ_WRITE32;c.value=PMAQ_UP;}break;
    case PMAQ_CONNECT_ORDER:case PMAQ_ORDER:c.kind=PMAQ_FULL_ORDER;break;
    case PMAQ_CONNECT_IRQ:c.address=PMAQ_IRQ;c.kind=PMAQ_WRITE32;c.value=1;break;
    case PMAQ_DOORBELL:c.address=PMAQ_IRQ;c.kind=PMAQ_WRITE32;c.value=1;q->doorbell_issued=1;break;
    default:return pmaq_fail(q,2);
    }
    if(q->step>PMAQ_DONE){
        if(q->connecting!=1||q->connected_at||q->on!=1||q->require_previous||!pmaq_layout(q->descriptor))return pmaq_fail(q,2);
    }else if(q->step>PMAQ_DESC&&!pmaq_geometry(q->descriptor)&&
       !(q->step==PMAQ_CONFIRM&&q->connecting==1&&pmaq_pristine(q->descriptor)))return pmaq_fail(q,2);
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
        if(++q->index==16){
            if(!pmaq_geometry(q->descriptor)){
                if(q->on!=1||q->require_previous||!pmaq_pristine(q->descriptor))return pmaq_fail(q,5);
                q->connecting=1;
            }q->index=0;q->step++;
        }break;
    case PMAQ_CONFIRM:case PMAQ_PRE_DESC:case PMAQ_POLL_DESC:case PMAQ_FINAL_DESC:
        if(value!=q->descriptor[q->index])return pmaq_fail(q,5);
        if(++q->index==16){q->index=0;
            if(q->step==PMAQ_CONFIRM&&q->connecting&&!q->connected_at)q->step=PMAQ_CONNECT_RX;
            else q->step++;
        }break;
    case PMAQ_RX_EMPTY:case PMAQ_TX_EMPTY:case PMAQ_PRE_RX:case PMAQ_PRE_TX:case PMAQ_POLL_RX:case PMAQ_FINAL_RX:
        if(value)return pmaq_fail(q,6);q->step++;break;
    case PMAQ_CONNECT_RX:case PMAQ_CONNECT_CHECK_RX:
        if(value)return pmaq_fail(q,6);q->step++;break;
    case PMAQ_CONNECT_TX:
        if(value)return pmaq_fail(q,6);q->step=PMAQ_CONNECT_WRITE;q->index=4;break;
    case PMAQ_CONNECT_WRITE:q->step=PMAQ_CONNECT_READBACK;break;
    case PMAQ_CONNECT_READBACK:
        if(value!=PMAQ_UP)return pmaq_fail(q,7);
        q->descriptor[q->index]=value;
        if(q->connect_phase==0&&q->index==4){q->index=9;q->step=PMAQ_CONNECT_WRITE;}
        else{q->index=0;q->step=PMAQ_CONNECT_ORDER;}break;
    case PMAQ_CONNECT_ORDER:q->step=PMAQ_CONNECT_IRQ;break;
    case PMAQ_CONNECT_IRQ:q->step=PMAQ_CONNECT_DESC;break;
    case PMAQ_CONNECT_DESC:
        q->sample[q->index]=value;
        if(++q->index==16){
            if(!pmaq_connect_sample(q))return pmaq_fail(q,5);
            q->index=0;q->step=PMAQ_CONNECT_CHECK_RX;
        }break;
    case PMAQ_CONNECT_CHECK_TX:
        if(value)return pmaq_fail(q,6);
        if(q->connect_phase==0&&q->descriptor[10]==PMAQ_UP){
            q->connect_phase=1;q->index=11;q->step=PMAQ_CONNECT_WRITE;
        }else if(q->connect_phase==1&&q->descriptor[5]==PMAQ_UP){
            q->connect_phase=2;q->index=6;q->step=PMAQ_CONNECT_WRITE;
        }else if(q->connect_phase==2&&pmaq_geometry(q->descriptor)){
            q->connected_at=now;q->step=PMAQ_CONFIRM;
        }else{
            if(++q->connect_polls>51||now>UINT64_MAX-PMAQ_CONNECT_POLL)return pmaq_fail(q,4);
            q->not_before=now+PMAQ_CONNECT_POLL;q->step=PMAQ_CONNECT_DESC;
        }break;
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
