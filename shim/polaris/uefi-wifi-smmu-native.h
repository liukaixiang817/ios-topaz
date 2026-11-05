/* Read-only current WLAN SID40/41 routing under the actual native MSS owner.
 * Default OFF. Does not reprogram SMMU, adopt a CB, allocate or enable DMA. */
#ifndef POLARIS_UEFI_WIFI_SMMU_NATIVE_H
#define POLARIS_UEFI_WIFI_SMMU_NATIVE_H
#ifndef EFI_XNU_WIFI_SMMU_NATIVE_AVAILABLE
#define EFI_XNU_WIFI_SMMU_NATIVE_AVAILABLE 0
#endif
#include "uefi-wifi-wlfw-native.h"
#if EFI_XNU_WIFI_SMMU_NATIVE_AVAILABLE
#if !EFI_XNU_WIFI_WLFW_NATIVE_AVAILABLE
#error Current WLAN SMMU observation requires actual native WLFW owner
#endif
#include "../../tools/polaris-wifi-smmu-route.h"
struct pmws_delivery {
    struct pwsu_command command;struct pmrg_target target[2];struct pmni_arch opening;struct pmni_result native;
    uint32_t attempted,complete,unknown,error;uint8_t digest[32];
};
struct pmws_state {
    uint64_t wlan,owner,opening,power,records,finished,next_poll;struct pwsu_route route;struct pwea_core source[2];
    uint32_t attempted,ready,unknown,error,pending,reads,complete,reserved;uint8_t records_digest[32],digest[32];
};
static inline int pmws_fail(struct pmws_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;return 0;}
static inline int pmws_live(struct pmws_state*s)
{
    if(!s||s->ready!=1||s->unknown||s->error||s->reads>PWSU_READS)return 0;
    struct pmwa_state*w=(void*)(uintptr_t)s->wlan;struct pmsn_state*a=(void*)(uintptr_t)w->auth;
    return w->smmu==(uintptr_t)s&&w->owner==s->owner&&w->opening==s->opening&&a->power==s->power&&
        w->client.ready&&!w->client.enable_requested&&pmwa_live(w);
}
static inline int pmws_begin(struct pmws_state*s,struct pmws_delivery*records,struct pmwa_state*w)
{
    if(!s||!records||!w||!pwmc_zero(s,sizeof(*s))||!pwmc_zero(records,sizeof(*records)*PWSU_READS)||
       w->smmu||!pmwa_current(w)||!w->client.ready||w->client.enable_requested||w->pending)return 0;
    struct pmsn_state*a=(void*)(uintptr_t)w->auth;struct pmrf_state*r=(void*)(uintptr_t)w->service;
    struct pmsg_state*g=(void*)(uintptr_t)r->glink;struct pmsx_state*x=(void*)(uintptr_t)g->channel;
    struct pmsc_owner*o=(void*)(uintptr_t)w->owner;const struct pweh_result*h=(const void*)(uintptr_t)o->retained;
    uint64_t bytes=sizeof(*records)*PWSU_READS;
    if(!pmsn_child(a,(uintptr_t)s,sizeof(*s))||!pmsn_child(a,(uintptr_t)records,bytes)||!pwea_disjoint((uintptr_t)s,sizeof(*s),(uintptr_t)records,bytes))return 0;
    const uint64_t at[]={(uintptr_t)w,(uintptr_t)r,r->grant,r->nv,r->glink,g->channel,x->negotiation,x->smem,x->allocation,(uintptr_t)a,a->records,a->copy,a->segments};
    const uint64_t sizes[]={sizeof(*w),sizeof(*r),sizeof(struct pmtf_state),sizeof(struct pnnv_state),sizeof(*g),sizeof(*x),sizeof(struct pmsy_state),sizeof(struct pmsq_state),sizeof(struct pmsa_state),sizeof(*a),sizeof(struct pmsn_delivery)*PMSN_RECORDS,sizeof(struct pmlc_copy),sizeof(struct pmsf_segment)*PMIM_SEGMENTS};
    for(unsigned n=0;n<13;n++)if(!pwea_disjoint((uintptr_t)s,sizeof(*s),at[n],sizes[n])||!pwea_disjoint((uintptr_t)records,bytes,at[n],sizes[n]))return 0;
    s->wlan=(uintptr_t)w;s->owner=w->owner;s->opening=w->opening;s->power=a->power;s->records=(uintptr_t)records;s->attempted=1;
    if(!pwea_core_check(h->input.early,&s->source[0],&h->map)||!pmwa_current(w)||pwsu_begin(&s->route,s->opening,o->last,o->current.cpu.frequency)<0)return pmws_fail(s,1);
    s->ready=1;w->smmu=(uintptr_t)s;return pmws_live(s);
}
static inline int pmws_current(struct pmws_state*s)
{
    if(!pmws_live(s)||s->complete!=1||s->pending||s->route.complete!=1||s->route.unknown||s->route.error||s->reads!=s->route.reads)return 0;
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;uint8_t hash[32];
    if(o->last<s->finished||o->last-s->finished>PGCD_FRESH_TICKS)return 0;
    pweh_digest((const void*)(uintptr_t)s->records,s->reads*sizeof(struct pmws_delivery),hash);if(!pgcd_equal(hash,s->records_digest,32))return 0;
    pweh_digest(s,offsetof(struct pmws_state,digest),hash);return pgcd_equal(hash,s->digest,32)&&pmws_live(s);
}
/* One exact read per turn, keeping the parent's worker in control. */
static inline int pmws_step(struct pmws_state*s)
{
    if(!pmws_live(s)||s->pending)return 0;if(s->complete)return pmws_current(s)?2:0;
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;struct pmpn_state*p=(void*)(uintptr_t)s->power;
    if(o->last>=s->next_poll){
        struct pmwa_state*w=(void*)(uintptr_t)s->wlan;struct pmrf_state*f=(void*)(uintptr_t)w->service;
        if(polaris_rmtfs_poll(f->service))return pmws_fail(s,2);s->next_poll=o->last+192000;
    }
    struct pwsu_command command;int result=pwsu_next(&s->route,o->last,&command);
    if(result==PWSU_OBSERVED){
        const struct pweh_result*h=(const void*)(uintptr_t)o->retained;
        if(!pwea_core_check(h->input.early,&s->source[1],&h->map)||!pmwa_current((void*)(uintptr_t)s->wlan)||!pmws_live(s))return pmws_fail(s,2);
        pweh_digest((const void*)(uintptr_t)s->records,s->reads*sizeof(struct pmws_delivery),s->records_digest);
        s->finished=o->last;s->complete=1;pweh_digest(s,offsetof(struct pmws_state,digest),s->digest);return 2;
    }
    if(result!=PWSU_IO||s->reads==PWSU_READS||!pwsu_readable(command.address))return pmws_fail(s,2);
    struct pmws_delivery*r=(struct pmws_delivery*)(uintptr_t)s->records+s->reads;
    if(!pwmc_zero(r,sizeof(*r)))return pmws_fail(s,2);r->command=command;r->attempted=r->unknown=1;s->pending=++s->reads;
    struct pmni_command c={command.address,PMNI_READ,0};uint64_t page=c.address&~UINT64_C(4095);
    if(!pmpn_target(p,page,&r->target[0])||!pmpn_arch(p,&r->opening)||!pmni_access(&r->opening,&c,&r->native)||
       !pmpn_target(p,page,&r->target[1])||r->target[0].index!=r->target[1].index||!pmws_live(s)||
       !pgcd_equal(&command,&r->command,sizeof(command))||pwsu_complete(&s->route,&command,o->last,1,r->native.value)<0)return pmws_fail(s,3);
    r->unknown=0;r->complete=1;pweh_digest(r,offsetof(struct pmws_delivery,digest),r->digest);s->pending=0;return 1;
}
#endif
#endif
