/* Actual current owner -> independent CE backing -> current SMMU admission ->
 * WLFW CFG/MISSION -> polled empty CE rings. Default OFF. Retains all memory;
 * normal pre-CE shutdown cannot consume this DMA lifetime. */
#ifndef POLARIS_UEFI_WIFI_CE_NATIVE_H
#define POLARIS_UEFI_WIFI_CE_NATIVE_H
#include "uefi-wifi-ce-memory-native.h"
#include "uefi-wifi-smmu-native.h"
#include "../../tools/polaris-wifi-ce-init.h"
#ifndef EFI_XNU_WIFI_CE_NATIVE_AVAILABLE
#define EFI_XNU_WIFI_CE_NATIVE_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_CE_NATIVE_AVAILABLE
#if !EFI_XNU_WIFI_CE_MEMORY_AVAILABLE || !EFI_XNU_WIFI_SMMU_NATIVE_AVAILABLE
#error Native CE requires its actual independent memory and current SMMU producer
#endif
struct pmce_delivery {
    struct pwce_command command;struct pmrg_target target[2];struct pmni_arch opening;struct pmni_result native;
    uint32_t attempted,complete,unknown,error;uint8_t digest[32];
};
struct pmce_state {
    uint64_t wlan,memory,smmu,smmu_records,owner,opening,power,next_poll,next_wire,base;
    struct pmtf_zero zero[PWDM_BYTES/4096];struct pmce_delivery records[PWCE_EVENTS];
    struct pwce_init init;struct pwea_core source[2];
    uint32_t attempted,ready,unknown,error,pending,pages,phase,events,admitted,complete;
    uint8_t memory_digest[32],zero_digest[32],smmu_digest[32],records_digest[32],digest[32];
};
#if defined(POLARIS_WIFI_CE_SOFTWARE_PEER)
static int pmce_zero(uint64_t,struct pmtf_zero*);
static int pmce_cache(uint64_t,unsigned,struct pwmk_record*);
#else
static inline int pmce_zero(uint64_t at,struct pmtf_zero*r)
{for(unsigned n=0;n<512;n++){volatile uint64_t*p=(void*)(uintptr_t)(at+8*n);r->issued++;*p=0;if(*p)return 0;r->returned++;}return 1;}
static inline int pmce_cache(uint64_t at,unsigned op,struct pwmk_record*r)
{return pwma_actual_cache_page((void*)(uintptr_t)at,op,r);}
#endif
static inline int pmce_fail(struct pmce_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;return 0;}
static inline int pmce_live(struct pmce_state*s)
{
    if(!s||s->ready!=1||s->unknown||s->error||s->pages>PWDM_BYTES/4096||s->events>PWCE_EVENTS)return 0;
    struct pmwa_state*w=(void*)(uintptr_t)s->wlan;struct pcdm_state*m=(void*)(uintptr_t)s->memory;
    struct pmsn_state*a=(void*)(uintptr_t)w->auth;
    return w->ce==(uintptr_t)s&&w->owner==s->owner&&w->opening==s->opening&&a->power==s->power&&
        m->consumer==(uintptr_t)s&&m->self==(uintptr_t)m&&m->allocation.address==s->base&&m->complete==1&&!m->unknown&&!m->error&&
        pgcd_equal(m->digest,s->memory_digest,32)&&w->client.ready&&!w->client.error&&!w->client.disable_requested&&pmwa_live(w);
}
static inline int pmce_begin(struct pmce_state*s,struct pcdm_state*m,struct pmwa_state*w,struct pmws_state*u,struct pmws_delivery*d)
{
    if(!s||!m||!w||!u||!d||!pwmc_zero(s,sizeof(*s))||!pwmc_zero(u,sizeof(*u))||!pwmc_zero(d,sizeof(*d)*PWSU_READS)||
       w->ce||w->smmu||w->pending||w->client.enable_requested||!w->client.ready||!pmwa_current(w)||m->consumer||
       m->self!=(uintptr_t)m||m->complete!=1||m->unknown||m->error||m->calls!=3||m->allocated!=1||
       m->translated[0]!=PWDM_BYTES/4096||m->translated[1]!=PWDM_BYTES/4096)return 0;
    struct pmsc_owner*o=(void*)(uintptr_t)w->owner;const struct pweh_result*h=(const void*)(uintptr_t)o->retained;
    struct pmsn_state*a=(void*)(uintptr_t)w->auth;struct pmrf_state*r=(void*)(uintptr_t)w->service;
    struct pmsg_state*g=(void*)(uintptr_t)r->glink;struct pmsx_state*x=(void*)(uintptr_t)g->channel;
    uint8_t hash[32];pweh_digest(m,offsetof(struct pcdm_state,digest),hash);if(!pgcd_equal(hash,m->digest,32))return 0;
    pweh_digest(h->input.early,sizeof(struct pwea_native),hash);if(m->early!=(uintptr_t)h->input.early||!pgcd_equal(hash,m->early_digest,32))return 0;
    uint64_t base=m->allocation.address;
    struct pwdm_layout expected={0};
    if(!pwdm_plan(&expected,base)||!pgcd_equal(&expected,&m->layout,sizeof(expected))||
       !polaris_efi_range_owned(h->map.data,h->map.map.bytes,h->map.map.stride,base,PWDM_BYTES,2))return 0;
    const uint64_t fresh[]={(uintptr_t)s,(uintptr_t)u,(uintptr_t)d};
    const uint64_t sizes[]={sizeof(*s),sizeof(*u),sizeof(*d)*PWSU_READS};
    const uint64_t old[]={(uintptr_t)m,(uintptr_t)w,(uintptr_t)r,r->grant,r->nv,r->glink,g->channel,x->negotiation,x->smem,x->allocation,(uintptr_t)a,a->records,a->copy,a->segments};
    const uint64_t bytes[]={sizeof(*m),sizeof(*w),sizeof(*r),sizeof(struct pmtf_state),sizeof(struct pnnv_state),sizeof(*g),sizeof(*x),sizeof(struct pmsy_state),sizeof(struct pmsq_state),sizeof(struct pmsa_state),sizeof(*a),sizeof(struct pmsn_delivery)*PMSN_RECORDS,sizeof(struct pmlc_copy),sizeof(struct pmsf_segment)*PMIM_SEGMENTS};
    for(unsigned i=0;i<3;i++){
        if(!pmsn_child(a,fresh[i],sizes[i]))return 0;
        for(unsigned j=0;j<14;j++)if(!pwea_disjoint(fresh[i],sizes[i],old[j],bytes[j]))return 0;
        for(unsigned j=0;j<i;j++)if(!pwea_disjoint(fresh[i],sizes[i],fresh[j],sizes[j]))return 0;
    }
    const struct pmmn_native*modem=(const void*)(uintptr_t)o->memory;
    if(!pwea_disjoint(base,PWDM_BYTES,(uintptr_t)h->input.early->image.base,h->input.early->image.bytes)||
       !pwea_disjoint(base,PWDM_BYTES,h->input.early->memory.input.bank,h->input.early->memory.input.bank_bytes))return 0;
    for(unsigned n=0;n<2;n++)if(!pwea_disjoint(base,PWDM_BYTES,h->input.early->memory.claim[n].requested,h->input.early->memory.claim[n].bytes))return 0;
    for(unsigned n=0;n<PMME_CLAIMS;n++)if(!pwea_disjoint(base,PWDM_BYTES,modem->memory.claim[n].requested,modem->memory.claim[n].bytes))return 0;
    struct pnnv_state*nv=(void*)(uintptr_t)r->nv;
    if(!pwea_disjoint(base,PWDM_BYTES,nv->allocation.address,PNV_BYTES))return 0;
    s->wlan=(uintptr_t)w;s->memory=(uintptr_t)m;s->smmu=(uintptr_t)u;s->smmu_records=(uintptr_t)d;
    s->owner=w->owner;s->opening=w->opening;s->power=a->power;s->base=base;s->attempted=1;pgcd_copy(s->memory_digest,m->digest,32);
    if(!pwea_core_check(h->input.early,&s->source[0],&h->map)||!pmwa_current(w))return pmce_fail(s,1);
    s->ready=1;w->ce=m->consumer=(uintptr_t)s;return pmce_live(s);
}
static inline int pmce_at(struct pmce_state*s,struct pwmc_translation*t,uint64_t page)
{t->page=page;return pmce_live(s)&&pwmc_actual_translate(t)&&pwmc_translation_valid(t)&&t->page==page&&pmce_live(s);}
/* One page, one route read, one WLFW poll or one MMIO command each turn. */
static inline int pmce_step(struct pmce_state*s)
{
    if(!pmce_live(s)||s->pending)return 0;if(s->complete)return 2;
    struct pmwa_state*w=(void*)(uintptr_t)s->wlan;struct pcdm_state*m=(void*)(uintptr_t)s->memory;
    struct pmws_state*u=(void*)(uintptr_t)s->smmu;struct pmsc_owner*o=(void*)(uintptr_t)s->owner;
    struct pmrf_state*f=(void*)(uintptr_t)w->service;struct pmsg_state*g=(void*)(uintptr_t)f->glink;
    if(o->last>=s->next_poll){if(polaris_rmtfs_poll(f->service))return pmce_fail(s,2);s->next_poll=o->last+192000;}
    if(!s->phase){
        if(s->pages<PWDM_BYTES/4096){
            struct pmtf_zero*z=&s->zero[s->pages];uint64_t at=s->base+4096*s->pages;s->pending=1;
            if(!pmce_at(s,&z->AT[0],at)||!pmce_zero(at,z)||z->issued!=512||z->returned!=512||!pmce_live(s)||
               !pmce_cache(at,PWMK_CLEAN_INVALIDATE,&z->cache)||!pwmk_record_valid(&z->cache,at,PWMK_CLEAN_INVALIDATE)||!pmce_at(s,&z->AT[1],at))return pmce_fail(s,3);
            z->complete=1;s->pending=0;s->pages++;return 1;
        }
        pweh_digest(s->zero,sizeof(s->zero),s->zero_digest);
        if(!pmws_begin(u,(void*)(uintptr_t)s->smmu_records,w))return pmce_fail(s,4);s->phase=1;return 1;
    }
    if(s->phase==1){
        int done=pmws_step(u);if(!done)return pmce_fail(s,4);if(done!=2)return 1;
        /* Fresh route admitted at first activation. Same uninterrupted CPU/
         * resource owner continues; the pre-enable observer is not renewed. */
        if(!pmws_current(u)||!pmsc_mark_effect(o,PMSC_DMA))return pmce_fail(s,4);
        pgcd_copy(s->smmu_digest,u->digest,32);s->admitted=1;
        if(polaris_wifi_wlfw_enable(&w->client,&polaris_wcn3990_config))return pmce_fail(s,5);
        s->phase=2;return 1;
    }
    if(s->phase==2){
        if(o->last<s->next_wire)return 1;
        int result=polaris_wifi_wlfw_poll(&w->client,pmsg_now(g));if(result&&result!=35)return pmce_fail(s,5);
        s->next_wire=o->last+192000;
        if(!w->client.enabled)return 1;
        if(!pmce_live(s)||!pgcd_equal(u->digest,s->smmu_digest,32)||pwce_begin(&s->init,&m->layout,s->opening,o->last)<0)return pmce_fail(s,6);
        s->phase=3;return 1;
    }
    if(s->phase!=3||!s->admitted||!w->client.enabled||s->events==PWCE_EVENTS)return pmce_fail(s,6);
    struct pwce_command command;int next=pwce_next(&s->init,o->last,&command);
    if(next==2){
        const struct pweh_result*h=(const void*)(uintptr_t)o->retained;
        if(!pwea_core_check(h->input.early,&s->source[1],&h->map)||!pmce_live(s))return pmce_fail(s,6);
        pweh_digest(s->records,s->events*sizeof(s->records[0]),s->records_digest);s->complete=1;
        pweh_digest(s,offsetof(struct pmce_state,digest),s->digest);return 2;
    }
    if(next!=1)return pmce_fail(s,6);
    struct pmce_delivery*r=&s->records[s->events];if(!pwmc_zero(r,sizeof(*r)))return pmce_fail(s,6);
    r->command=command;r->attempted=r->unknown=1;s->pending=++s->events;
    struct pmpn_state*p=(void*)(uintptr_t)s->power;struct pmni_command c={command.address,command.operation==PWCE_READ?PMNI_READ:command.operation==PWCE_ORDER?PMNI_FULL_ORDER:PMNI_WRITE,command.operation==PWCE_WRITE?command.value:0};
    uint64_t page=c.address&~UINT64_C(4095);
    if((command.operation!=PWCE_ORDER&&!pmpn_target(p,page,&r->target[0]))||!pmpn_arch(p,&r->opening)||!pmni_access(&r->opening,&c,&r->native)||
       (command.operation!=PWCE_ORDER&&!pmpn_target(p,page,&r->target[1]))||r->target[0].index!=r->target[1].index||!pmce_live(s)||
       !pgcd_equal(&command,&r->command,sizeof(command))||pwce_complete(&s->init,&command,o->last,1,r->native.value)<0)return pmce_fail(s,7);
    r->complete=1;r->unknown=0;pweh_digest(r,offsetof(struct pmce_delivery,digest),r->digest);s->pending=0;return 1;
}
#endif
#endif
