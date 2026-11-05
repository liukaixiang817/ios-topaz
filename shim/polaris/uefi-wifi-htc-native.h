/* Native HTC worker on the actual polled CE transport. No original UEFI,
 * alternate CPU owner, guessed endpoint, heap allocation or synthetic READY. */
#ifndef POLARIS_UEFI_WIFI_HTC_NATIVE_H
#define POLARIS_UEFI_WIFI_HTC_NATIVE_H
#include "uefi-wifi-ce-transport.h"
#include "../../tools/polaris-wifi-htc.h"
#ifndef EFI_XNU_WIFI_HTC_NATIVE_AVAILABLE
#define EFI_XNU_WIFI_HTC_NATIVE_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_HTC_NATIVE_AVAILABLE
#if !EFI_XNU_WIFI_CE_TRANSPORT_AVAILABLE
#error Native HTC requires actual native CE transport
#endif
struct pmhc_state {
    uint64_t transport,owner,opening,next_poll;struct phtc_state client;
    uint32_t attempted,ready,unknown,error,initial_pipe,opened,poll_pipe,frame_kind,raw_pipe,raw_bytes;
};
static inline int pmhc_fail(struct pmhc_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;return -1;}
static inline int pmhc_live(struct pmhc_state*s)
{
    if(!s||s->ready!=1||s->unknown||s->error||s->client.unknown||s->client.error)return 0;
    struct pmct_state*t=(void*)(uintptr_t)s->transport;
    return t->protocol==(uintptr_t)s&&t->owner==s->owner&&t->opening==s->opening&&pmct_live(t);
}
static inline int pmhc_begin(struct pmhc_state*s,struct pmct_state*t)
{
    if(!s||!t||!pwmc_zero(s,sizeof(*s))||t->protocol||t->busy||t->operations||t->sends||t->receives||t->posts||!pmct_live(t))return 0;
    struct pmce_state*p=(void*)(uintptr_t)t->parent;struct pmwa_state*w=(void*)(uintptr_t)p->wlan;struct pmsn_state*a=(void*)(uintptr_t)w->auth;
    struct pmrf_state*f=(void*)(uintptr_t)w->service;struct pmsg_state*g=(void*)(uintptr_t)f->glink;struct pmsx_state*x=(void*)(uintptr_t)g->channel;
    const uint64_t at[]={(uintptr_t)t,(uintptr_t)p,p->memory,p->smmu,p->smmu_records,p->wlan,(uintptr_t)f,f->grant,f->nv,f->glink,g->channel,x->negotiation,x->smem,x->allocation,(uintptr_t)a,a->records,a->copy,a->segments};
    const uint64_t bytes[]={sizeof(*t),sizeof(*p),sizeof(struct pcdm_state),sizeof(struct pmws_state),sizeof(struct pmws_delivery)*PWSU_READS,sizeof(*w),sizeof(*f),sizeof(struct pmtf_state),sizeof(struct pnnv_state),sizeof(*g),sizeof(*x),sizeof(struct pmsy_state),sizeof(struct pmsq_state),sizeof(struct pmsa_state),sizeof(*a),sizeof(struct pmsn_delivery)*PMSN_RECORDS,sizeof(struct pmlc_copy),sizeof(struct pmsf_segment)*PMIM_SEGMENTS};
    if(!pmsn_child(a,(uintptr_t)s,sizeof(*s)))return 0;
    for(unsigned n=0;n<18;n++)if(!pwea_disjoint((uintptr_t)s,sizeof(*s),at[n],bytes[n]))return 0;
    s->transport=(uintptr_t)t;s->owner=t->owner;s->opening=t->opening;s->attempted=s->ready=1;t->protocol=(uintptr_t)s;return pmhc_live(s);
}
static inline int pmhc_transmit(struct pmhc_state*s)
{
    struct pmct_state*t=(void*)(uintptr_t)s->transport;struct phtc_state*c=&s->client;
    if(!c->pending)return 0;unsigned pipe=c->endpoint[c->tx_eid].tx_pipe;
    if(pmct_reap(t,pipe)<0)return pmhc_fail(s,2);
    for(unsigned n=0;n<c->tx_bytes;n++)t->send[n]=c->tx[n];
    int result=pmct_send(t,pipe,c->tx_bytes,c->tx_eid);if(result<0)return pmhc_fail(s,2);if(!result)return 0;
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;if(phtc_sent(c,o->last,1)!=1)return pmhc_fail(s,2);return 1;
}
static inline int pmhc_input(struct pmhc_state*s,unsigned pipe)
{
    struct pmct_state*t=(void*)(uintptr_t)s->transport;int result=pmct_receive(t,pipe);
    if(result<0)return pmhc_fail(s,3);if(!result)return 0;
    /* CE5 carries the HTT fast path; CE8 is target/uMC. Keep full bytes for
     * the later typed consumer rather than treating these as WMI/HTC control. */
    if(pipe==5||pipe==8){s->frame_kind=2;s->raw_pipe=pipe;s->raw_bytes=t->rx_bytes;return 2;}
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;
    result=phtc_receive(&s->client,pipe,t->receive,t->rx_bytes,o->last);
    if(result<0||!pmct_ack(t)||pmct_refill(t,pipe)<0)return pmhc_fail(s,3);
    if(result==2){s->frame_kind=1;return 2;}return 1;
}
/*1=progress/wait,2=retained upper-layer payload,3=HTC services connected.
 * The caller continues calling even after3; no owner/lease is restarted. */
static inline int pmhc_step(struct pmhc_state*s)
{
    if(!pmhc_live(s))return -1;struct pmct_state*t=(void*)(uintptr_t)s->transport;
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;
    if(pmct_poll(t)<0)return pmhc_fail(s,1);if(s->frame_kind)return 2;
    if(!s->opened){
        while(s->initial_pipe<12){unsigned pipe=s->initial_pipe++;
            if(t->rings.destination[pipe].entries<8)continue;
            if(pmct_refill(t,pipe)!=1)return pmhc_fail(s,1);return 1;
        }
        if(phtc_open(&s->client,s->opening,o->last)!=1)return pmhc_fail(s,1);s->opened=1;return 1;
    }
    if(o->last<s->next_poll)return s->client.phase==8?3:1;s->next_poll=o->last+19200;
    if(!phtc_time(&s->client,o->last))return pmhc_fail(s,4);
    if(s->client.pending){if(pmhc_transmit(s)<0)return -1;return 1;}
    int result=pmhc_input(s,2);if(result<0||result==2)return result;
    if(phtc_next(&s->client,o->last)<0)return pmhc_fail(s,4);
    if(s->client.pending){if(pmhc_transmit(s)<0)return -1;return 1;}
    static const unsigned other[]={1,5,8,9,10,11};unsigned pipe=other[s->poll_pipe++%6];
    result=pmhc_input(s,pipe);if(result<0||result==2)return result;
    if(pmct_refill(t,pipe)<0)return pmhc_fail(s,3);
    return s->client.phase==8?3:1;
}
static inline int pmhc_ack(struct pmhc_state*s)
{
    if(!pmhc_live(s)||!s->frame_kind)return 0;struct pmct_state*t=(void*)(uintptr_t)s->transport;
    if(s->frame_kind==1){if(!phtc_ack(&s->client))return 0;}
    else if(!pmct_ack(t)||pmct_refill(t,s->raw_pipe)<0)return 0;
    s->frame_kind=s->raw_pipe=s->raw_bytes=0;return 1;
}
static inline int pmhc_send(struct pmhc_state*s,unsigned endpoint,const uint8_t*data,unsigned bytes)
{
    if(!pmhc_live(s)||!s->opened||s->client.pending)return -1;
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;int result=phtc_data(&s->client,endpoint,data,bytes,o->last);
    if(result<=0)return result;result=pmhc_transmit(s);return result<0?-1:1; /* queued if CE temporarily full */
}
#endif
#endif
