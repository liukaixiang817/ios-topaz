/* WMI bootstrap on the actual native HTC worker. The independent CE bank's
 * otherwise unused tail is retained for target-requested host memory. */
#ifndef POLARIS_UEFI_WIFI_WMI_NATIVE_H
#define POLARIS_UEFI_WIFI_WMI_NATIVE_H
#include "uefi-wifi-htc-native.h"
#include "../../tools/polaris-wifi-wmi-init.h"
#ifndef EFI_XNU_WIFI_WMI_NATIVE_AVAILABLE
#define EFI_XNU_WIFI_WMI_NATIVE_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_WMI_NATIVE_AVAILABLE
#if !EFI_XNU_WIFI_HTC_NATIVE_AVAILABLE
#error Native WMI requires actual native HTC
#endif
struct pmwi_state {
    uint64_t htc,owner,opening,zeroed;struct pwmi_state client;
    uint32_t attempted,ready,unknown,error,opened,submitted;
    uint8_t zero[4096];
    uint64_t consumer;
};
static inline int pmwi_fail(struct pmwi_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;return -1;}
static inline int pmwi_live(struct pmwi_state*s)
{
    if(!s||s->ready!=1||s->unknown||s->error||s->client.unknown||s->client.error)return 0;
    struct pmhc_state*h=(void*)(uintptr_t)s->htc;
    return h->consumer==(uintptr_t)s&&h->owner==s->owner&&h->opening==s->opening&&pmhc_live(h);
}
static inline int pmwi_child(struct pmhc_state*h,uint64_t child,uint64_t size)
{
    if(!h||!pmhc_live(h))return 0;
    struct pmct_state*t=(void*)(uintptr_t)h->transport;struct pmce_state*p=(void*)(uintptr_t)t->parent;
    struct pmwa_state*w=(void*)(uintptr_t)p->wlan;struct pmsn_state*a=(void*)(uintptr_t)w->auth;
    struct pmrf_state*f=(void*)(uintptr_t)w->service;struct pmsg_state*g=(void*)(uintptr_t)f->glink;struct pmsx_state*x=(void*)(uintptr_t)g->channel;
    const uint64_t at[]={(uintptr_t)h,(uintptr_t)t,(uintptr_t)p,p->memory,p->smmu,p->smmu_records,p->wlan,(uintptr_t)f,f->grant,f->nv,f->glink,g->channel,x->negotiation,x->smem,x->allocation,(uintptr_t)a,a->records,a->copy,a->segments};
    const uint64_t bytes[]={sizeof(*h),sizeof(*t),sizeof(*p),sizeof(struct pcdm_state),sizeof(struct pmws_state),sizeof(struct pmws_delivery)*PWSU_READS,sizeof(*w),sizeof(*f),sizeof(struct pmtf_state),sizeof(struct pnnv_state),sizeof(*g),sizeof(*x),sizeof(struct pmsy_state),sizeof(struct pmsq_state),sizeof(struct pmsa_state),sizeof(*a),sizeof(struct pmsn_delivery)*PMSN_RECORDS,sizeof(struct pmlc_copy),sizeof(struct pmsf_segment)*PMIM_SEGMENTS};
    if(!pmsn_child(a,child,size))return 0;
    for(unsigned n=0;n<19;n++)if(!pwea_disjoint(child,size,at[n],bytes[n]))return 0;
    return 1;
}
static inline int pmwi_begin(struct pmwi_state*s,struct pmhc_state*h)
{
    if(!s||!h||!pwmc_zero(s,sizeof(*s))||h->consumer||h->frame_kind||!pmwi_child(h,(uintptr_t)s,sizeof(*s)))return 0;
    s->htc=(uintptr_t)h;s->owner=h->owner;s->opening=h->opening;s->attempted=s->ready=1;h->consumer=(uintptr_t)s;return pmwi_live(s);
}
/* 1=progress/wait, 2=unconsumed typed upper payload, 3=unified WMI READY.
 * Keep polling after READY; the same finite CPU/resource owner remains held. */
static inline int pmwi_step(struct pmwi_state*s)
{
    if(!pmwi_live(s))return -1;struct pmhc_state*h=(void*)(uintptr_t)s->htc;
    struct pmct_state*t=(void*)(uintptr_t)h->transport;struct pmsc_owner*o=(void*)(uintptr_t)s->owner;
    int result=pmhc_step(h);if(result<0)return pmwi_fail(s,1);
    if(!s->opened&&h->client.wmi){if(!pwmi_open(&s->client,s->opening,o->last))return pmwi_fail(s,2);s->opened=1;}
    if(!s->opened)return result==2?2:1;
    if(!pwmi_time(&s->client,o->last))return pmwi_fail(s,2);
    /* A queued HTC frame is committed only after native CE publication. */
    if(s->submitted&&!h->client.pending&&s->client.pending){if(pwmi_sent(&s->client,o->last,1)!=1)return pmwi_fail(s,3);}
    if(result==2){
        if(h->frame_kind!=1||h->client.rx_eid!=h->client.wmi)return 2;
        int accepted=pwmi_receive(&s->client,h->client.rx,h->client.rx_bytes,o->last);
        if(accepted<0)return pmwi_fail(s,4);if(!accepted)return 2;
        if(!pmhc_ack(h))return pmwi_fail(s,4);
    }
    if(s->client.phase==1){
        if(!s->client.bank){
            uint64_t offset=(t->rings.layout.used+4095u)&~UINT64_C(4095);
            if(offset>=4096+PWDM_USABLE||pwmi_plan(&s->client,t->base+offset,4096+PWDM_USABLE-offset,o->last)!=1)return pmwi_fail(s,5);
        }
        if(s->zeroed<s->client.used){
            if(t->busy||!pwmc_zero(s->zero,sizeof(s->zero)))return pmwi_fail(s,6);
            uint64_t at=s->client.bank+s->zeroed;
            t->busy=1;
            if(pmct_memory(t,at,s->zero,4096,1)<0||pmct_cache(t,at,4096,PWMK_CLEAN_INVALIDATE)<0)return pmwi_fail(s,6);
            t->busy=0;s->zeroed+=4096;return 1;
        }
        if(h->client.phase==8&&pwmi_init(&s->client,o->last)!=1)return pmwi_fail(s,7);
    }
    if(s->client.pending&&!s->submitted&&!h->client.pending){
        int sent=pmhc_send(h,h->client.wmi,s->client.tx,s->client.tx_bytes);
        if(sent<0)return pmwi_fail(s,8);
        if(sent){s->submitted=1;if(!h->client.pending&&pwmi_sent(&s->client,o->last,1)!=1)return pmwi_fail(s,3);}
    }
    return s->client.phase==4?3:1;
}
#endif
#endif
