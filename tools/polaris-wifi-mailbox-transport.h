/* Cache/publication protocol over a separately qualified fixed mailbox page.
 * Bus callbacks are privileged leaves supplied by the actual native/kernel
 * adapter; this module supplies no address mapping or runtime authority. */
#ifndef POLARIS_WIFI_MAILBOX_TRANSPORT_H
#define POLARIS_WIFI_MAILBOX_TRANSPORT_H
#include "polaris-wifi-mailbox.h"
struct pwmb_bus {
    void*context;
    int (*live)(void*);
    int (*copy)(void*,unsigned,void*,unsigned,unsigned); /* offset, private, bytes, write */
    int (*cache)(void*,unsigned,unsigned,unsigned); /* offset, bytes, clean(1)/invalidate(0), completed DSB */
    int (*sequence)(void*,unsigned,uint64_t*,unsigned); /* ONE aligned64 load/store, not byte copies */
};
struct pwmb_effect {uint32_t kind,offset,bytes,write,issued,returned;};
struct pwmb_link {
    struct pwmb_state state;
    uint8_t wire[PWMB_RECORD],ack[PWMB_LINE];
    struct pwmb_effect effect[16];
    uint32_t effects,busy,complete,reserved;
};
static inline int pwmb_link_open(struct pwmb_link*s,unsigned lane,unsigned role,uint64_t epoch)
{return s&&pwmb_zero(s,sizeof(*s))&&pwmb_open(&s->state,lane,role,epoch);}
static inline int pwmb_bus_live(struct pwmb_link*s,const struct pwmb_bus*b)
{
    return s&&b&&b->live&&b->copy&&b->cache&&b->sequence&&
        pwmb_live(&s->state,s->state.role)&&b->live(b->context)==1;
}
static inline int pwmb_begin_io(struct pwmb_link*s,const struct pwmb_bus*b)
{
    if(!pwmb_bus_live(s,b)||s->busy)return 0;
    pwmb_clear(s->effect,sizeof(s->effect));s->effects=0;s->complete=0;s->busy=1;return 1;
}
static inline int pwmb_effect(struct pwmb_link*s,const struct pwmb_bus*b,unsigned kind,unsigned offset,void*p,unsigned n,unsigned write)
{
    if(!pwmb_bus_live(s,b)||!s->busy||s->effects>=16)return pwmb_fail(&s->state,6);
    unsigned base=s->state.lane*PWMB_SLOT;
    if(offset<base||offset-base>=PWMB_SLOT||!n||n>PWMB_SLOT-(offset-base)||write>1)return pwmb_fail(&s->state,6);
    unsigned is_ack=offset-base>=PWMB_ACK_OFFSET;
    unsigned bound=is_ack?PWMB_ACK_OFFSET+PWMB_LINE:PWMB_RECORD;
    if(offset-base+n>bound||
       (write&&((s->state.role==PWMB_PRODUCER)==is_ack)))return pwmb_fail(&s->state,6);
    if(kind==2&&((offset%PWMB_LINE)||(n%PWMB_LINE)))return pwmb_fail(&s->state,6);
    if(kind==3&&(n!=8||offset-base!=(is_ack?PWMB_ACK_OFFSET:0)+24))return pwmb_fail(&s->state,6);
    struct pwmb_effect*e=&s->effect[s->effects++];*e=(struct pwmb_effect){kind,offset,n,write,1,0};
    int ok=kind==1?b->copy(b->context,offset,p,n,write):kind==2?b->cache(b->context,offset,n,write):
        kind==3?b->sequence(b->context,offset,p,write):0;
    if(ok!=1||!pwmb_bus_live(s,b))return pwmb_fail(&s->state,7);
    e->returned=1;return 1;
}
static inline int pwmb_end_io(struct pwmb_link*s)
{if(s->state.unknown)return -1;s->busy=0;s->complete=1;return 1;}
/* All mutations precede the final atomic sequence store. Cleaning the first
 * pass publishes only the old sequence, which the peer treats as idle. */
static inline int pwmb_publish(struct pwmb_link*s,const struct pwmb_bus*b,unsigned base,uint8_t*p,unsigned bytes,uint64_t sequence)
{
    if(pwmb_effect(s,b,1,base,p,24,1)!=1||pwmb_effect(s,b,1,base+32,p+32,bytes-32,1)!=1||
       pwmb_effect(s,b,2,base,0,bytes,1)!=1||pwmb_effect(s,b,3,base+24,&sequence,8,1)!=1||
       pwmb_effect(s,b,2,base,0,PWMB_LINE,1)!=1)return -1;
    return 1;
}
static inline int pwmb_send(struct pwmb_link*s,const struct pwmb_bus*b,unsigned op,const uint8_t*p,unsigned n)
{
    if(!s||!pwmb_live(&s->state,PWMB_PRODUCER)||s->state.stage||!pwmb_payload(s->state.lane,op,p,n))return 0;
    if(!pwmb_begin_io(s,b))return pwmb_fail(&s->state,6);
    if(!pwmb_prepare(&s->state,op,p,n,s->wire))return pwmb_fail(&s->state,6);
    int complete=pwmb_publish(s,b,s->state.lane*PWMB_SLOT,s->wire,PWMB_RECORD,s->state.next)==1;
    if(pwmb_tx_published(&s->state,s->state.next,complete)!=1)return -1;
    return pwmb_end_io(s);
}
static inline int pwmb_receive_poll(struct pwmb_link*s,const struct pwmb_bus*b,struct pwmb_message*out)
{
    if(!s||!out||!pwmb_live(&s->state,PWMB_CONSUMER))return -1;if(s->state.stage)return 0;
    if(!pwmb_begin_io(s,b))return pwmb_fail(&s->state,6);
    unsigned base=s->state.lane*PWMB_SLOT;uint64_t before=0,after=0;
    if(pwmb_effect(s,b,2,base,0,PWMB_LINE,0)!=1||pwmb_effect(s,b,3,base+24,&before,8,0)!=1)return -1;
    if(before==s->state.next-1){pwmb_end_io(s);return 0;}
    if(pwmb_effect(s,b,2,base,0,PWMB_RECORD,0)!=1||pwmb_effect(s,b,1,base,s->wire,PWMB_RECORD,0)!=1||
       pwmb_effect(s,b,2,base,0,PWMB_LINE,0)!=1||pwmb_effect(s,b,3,base+24,&after,8,0)!=1)return -1;
    int result=pwmb_receive(&s->state,s->wire,before,after,out);
    if(result<0)return -1;pwmb_end_io(s);return result;
}
/* Complete only after the upper consumer has retained/processed the message. */
static inline int pwmb_receive_complete(struct pwmb_link*s,const struct pwmb_bus*b)
{
    if(!s||!pwmb_live(&s->state,PWMB_CONSUMER)||s->state.stage!=2)return -1;
    if(!pwmb_begin_io(s,b)||!pwmb_ack_prepare(&s->state,s->ack))return pwmb_fail(&s->state,6);
    unsigned base=s->state.lane*PWMB_SLOT+PWMB_ACK_OFFSET;
    int complete=pwmb_publish(s,b,base,s->ack,PWMB_LINE,s->state.next)==1;
    if(pwmb_rx_ack_published(&s->state,s->state.next,complete)!=1)return -1;
    pwmb_clear(s->wire,sizeof(s->wire));return pwmb_end_io(s);
}
static inline int pwmb_send_ack_poll(struct pwmb_link*s,const struct pwmb_bus*b)
{
    if(!s||!pwmb_live(&s->state,PWMB_PRODUCER)||s->state.stage!=2)return -1;
    if(!pwmb_begin_io(s,b))return pwmb_fail(&s->state,6);
    unsigned base=s->state.lane*PWMB_SLOT+PWMB_ACK_OFFSET;uint64_t before=0,after=0;
    if(pwmb_effect(s,b,2,base,0,PWMB_LINE,0)!=1||pwmb_effect(s,b,3,base+24,&before,8,0)!=1)return -1;
    if(before==s->state.next-1){pwmb_end_io(s);return 0;}
    if(pwmb_effect(s,b,1,base,s->ack,PWMB_LINE,0)!=1||pwmb_effect(s,b,2,base,0,PWMB_LINE,0)!=1||
       pwmb_effect(s,b,3,base+24,&after,8,0)!=1)return -1;
    int result=pwmb_ack(&s->state,s->ack,before,after);if(result<0)return -1;
    if(result==1)pwmb_clear(s->wire,sizeof(s->wire));pwmb_end_io(s);return result;
}
#endif
