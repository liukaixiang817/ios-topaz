/* CPU0 adapter for the exact fixed kernel page admitted by pwkr_begin.
 * No arbitrary address, firmware service or radio authority comes from a
 * message. Byte copies never publish sequence words; aligned64 stores do. */
#ifndef POLARIS_UEFI_WIFI_MAILBOX_NATIVE_H
#define POLARIS_UEFI_WIFI_MAILBOX_NATIVE_H
#ifndef EFI_XNU_WIFI_MAILBOX_NATIVE_AVAILABLE
#define EFI_XNU_WIFI_MAILBOX_NATIVE_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_MAILBOX_NATIVE_AVAILABLE
#include "uefi-wifi-runtime-handoff.h"
#include "../../tools/polaris-wifi-mailbox-transport.h"
#if !EFI_XNU_WIFI_RUNTIME_HANDOFF_AVAILABLE
#error Native mailbox requires the qualified complete-parent runtime handoff
#endif
struct pwmn_state {
    uint64_t parent,page,epoch;
    struct pwmb_link lane[PWMB_LANES];struct pwmb_bus bus;
    uint32_t attempted,ready,unknown,error;
};
static inline unsigned pwmn_producer(unsigned lane)
{return lane==PWMB_REPLY||lane==PWMB_RX||lane==PWMB_EVENT;}
static inline int pwmn_fail(struct pwmn_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;return -1;}
static inline int pwmn_live(void*context)
{
    struct pwmn_state*s=context;if(!s||!s->ready||s->unknown||s->error)return 0;
    struct pwns_parent*p=(void*)(uintptr_t)s->parent;struct pmsc_owner*o=&p->owner;
    return p->phase==PWNS_READY&&!p->unknown&&!p->error&&pmsc_persistent(o)&&
        o->runtime.parent==s->parent&&o->runtime.mailbox_owner==(uintptr_t)s&&
        o->runtime.mailbox==s->page&&o->opening==s->epoch&&pmsc_live(o);
}
/* A callback independently enforces the lane's cache-line owner, in addition
 * to transport validation. Bootstrap/spare bytes are never message targets. */
static inline int pwmn_span(unsigned offset,unsigned bytes,unsigned write)
{
    if(!bytes||offset>=PWMB_LANES*PWMB_SLOT||write>1)return 0;
    unsigned lane=offset/PWMB_SLOT,at=offset%PWMB_SLOT;
    unsigned record=(pwmn_producer(lane)==write);
    unsigned first=record?0:PWMB_ACK_OFFSET,last=record?PWMB_RECORD:PWMB_ACK_OFFSET+PWMB_LINE;
    return at>=first&&at<last&&bytes<=last-at;
}
static inline int pwmn_copy(void*context,unsigned offset,void*private,unsigned bytes,unsigned write)
{
    struct pwmn_state*s=context;
    if(!private||!pwmn_span(offset,bytes,write)||!pwmn_live(s))return 0;
    unsigned relative=offset%PWMB_SLOT;if(relative>=PWMB_ACK_OFFSET)relative-=PWMB_ACK_OFFSET;
    if(write&&relative<32&&relative+bytes>24)return 0;
    volatile uint8_t*p=(void*)(uintptr_t)(s->page+offset);uint8_t*q=private;
    for(unsigned n=0;n<bytes;n++){if(write)p[n]=q[n];else q[n]=p[n];}return pwmn_live(s);
}
static inline int pwmn_cache(void*context,unsigned offset,unsigned bytes,unsigned clean)
{
    struct pwmn_state*s=context;
    return !(offset%PWMB_LINE)&&!(bytes%PWMB_LINE)&&pwmn_span(offset,bytes,clean)&&
        pwmn_live(s)&&pwkr_cache(s->page+offset,bytes,clean)&&pwmn_live(s);
}
static inline int pwmn_sequence(void*context,unsigned offset,uint64_t*value,unsigned write)
{
    struct pwmn_state*s=context;
    if(!value||!pwmn_span(offset,8,write)||!pwmn_live(s))return 0;
    unsigned at=offset%PWMB_SLOT;
    if(at!=24&&at!=PWMB_ACK_OFFSET+24)return 0;
    uint64_t*p=(void*)(uintptr_t)(s->page+offset);
    if(write)__atomic_store_n(p,*value,__ATOMIC_RELEASE);else *value=__atomic_load_n(p,__ATOMIC_ACQUIRE);
    return pwmn_live(s);
}
static inline int pwmn_begin(struct pwmn_state*s,struct pwns_parent*p)
{
    if(!s||!p||!pwmc_zero(s,sizeof(*s))||pwkr_poll(p)!=2)return 0;
    struct pmsc_owner*o=&p->owner;const struct pweh_result*h=(const void*)(uintptr_t)o->retained;
    if(o->runtime.mailbox_owner||!pmsi_image_range(h->input.early,&h->map,(uintptr_t)s,sizeof(*s))||
       !pwea_disjoint((uintptr_t)s,sizeof(*s),(uintptr_t)p,sizeof(*p)))return 0;
    const uint64_t at[]={o->runtime.copy,o->runtime.context,o->runtime.stack,
        o->retained,o->memory,o->mba,(uintptr_t)h->input.early};
    const uint64_t size[]={sizeof(struct pwks_image),sizeof(struct polaris_efi_ap),o->runtime.stack_bytes,
        sizeof(*h),sizeof(struct pmmn_native),sizeof(struct pmsb_result),sizeof(struct pwea_native)};
    for(unsigned n=0;n<7;n++)if(!pwea_disjoint((uintptr_t)s,sizeof(*s),at[n],size[n]))return 0;
    s->attempted=1;s->parent=(uintptr_t)p;s->page=o->runtime.mailbox;s->epoch=o->opening;
    for(unsigned n=0;n<PWMB_LANES;n++)if(!pwmb_link_open(&s->lane[n],n,
        pwmn_producer(n)?PWMB_PRODUCER:PWMB_CONSUMER,s->epoch))return pwmn_fail(s,1),0;
    s->bus=(struct pwmb_bus){s,pwmn_live,pwmn_copy,pwmn_cache,pwmn_sequence};
    o->runtime.mailbox_owner=(uintptr_t)s;s->ready=1;return pwmn_live(s);
}
static inline int pwmn_current(struct pwmn_state*s)
{
    return pwmn_live(s)&&pwkr_poll((void*)(uintptr_t)s->parent)==2&&pwmn_live(s);
}
/* 1 sent/received,0 peer backpressure/no message,-1 terminal local fault. */
static inline int pwmn_send(struct pwmn_state*s,unsigned lane,unsigned op,const uint8_t*p,unsigned bytes)
{
    if(!s||lane>=PWMB_LANES||!pwmn_producer(lane)||!pwmb_payload(lane,op,p,bytes))return -1;
    if(!pwmn_current(s))return pwmn_fail(s,2);
    struct pwmb_link*l=&s->lane[lane];
    if(l->state.stage==2){int done=pwmb_send_ack_poll(l,&s->bus);if(done<0)return pwmn_fail(s,3);if(!done)return 0;}
    int result=pwmb_send(l,&s->bus,op,p,bytes);return result<0?pwmn_fail(s,3):result;
}
/* Poll delivery of the last producer record without publishing another one. */
static inline int pwmn_sent(struct pwmn_state*s,unsigned lane)
{
    if(!s||lane>=PWMB_LANES||!pwmn_producer(lane))return -1;
    if(!pwmn_current(s))return pwmn_fail(s,2);
    struct pwmb_link*l=&s->lane[lane];
    if(!l->state.stage)return 1;
    if(l->state.stage!=2)return pwmn_fail(s,3);
    int result=pwmb_send_ack_poll(l,&s->bus);return result<0?pwmn_fail(s,3):result;
}
static inline int pwmn_receive(struct pwmn_state*s,unsigned lane,struct pwmb_message*out)
{
    if(!s||!out||lane>=PWMB_LANES||pwmn_producer(lane))return -1;
    if(!pwmn_current(s))return pwmn_fail(s,2);
    int result=pwmb_receive_poll(&s->lane[lane],&s->bus,out);return result<0?pwmn_fail(s,4):result;
}
static inline int pwmn_complete(struct pwmn_state*s,unsigned lane)
{
    if(!s||lane>=PWMB_LANES||pwmn_producer(lane))return -1;
    if(!pwmn_current(s))return pwmn_fail(s,2);
    int result=pwmb_receive_complete(&s->lane[lane],&s->bus);return result<0?pwmn_fail(s,5):result;
}
#endif
#endif
