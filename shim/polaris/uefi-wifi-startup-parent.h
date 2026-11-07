/* One native startup orchestrator. It calls the actual producer chain, never
 * provider substitutes or software completion events. CPU0 remains held on
 * every failure. Reaching READY is still pre-XNU; the persistent handoff and
 * post-CE retirement must be connected before enabling a physical candidate. */
#ifndef POLARIS_UEFI_WIFI_STARTUP_PARENT_H
#define POLARIS_UEFI_WIFI_STARTUP_PARENT_H
#ifndef EFI_XNU_WIFI_STARTUP_PARENT_AVAILABLE
#define EFI_XNU_WIFI_STARTUP_PARENT_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_STARTUP_PARENT_AVAILABLE
#include "uefi-wifi-network-native.h"
#if EFI_XNU_WIFI_NATIVE_WATCHDOG_READONLY
#include "uefi-apps-watchdog-native-readonly.h"
#endif
#if !EFI_XNU_WIFI_NETWORK_NATIVE_AVAILABLE || !EFI_XNU_WIFI_NONCE_NATIVE_AVAILABLE
#error Complete native startup requires network and candidate-bound nonce producers
#endif
enum pwns_phase {
    PWNS_UNUSED,PWNS_IMAGES,PWNS_MAP,PWNS_RPMH,PWNS_CMDDB,PWNS_RSC,PWNS_POWER,
    PWNS_CLOCK_OWNER,PWNS_AOP_BEGIN,PWNS_AOP,PWNS_SUPPLY_BEGIN,PWNS_SUPPLY,
    PWNS_PROXY_BEGIN,PWNS_PROXY,PWNS_CLOCK_BEGIN,PWNS_CLOCK,PWNS_BOOT_BEGIN,
    PWNS_BOOT,PWNS_AUTH_BEGIN,PWNS_AUTH,PWNS_RMTFS_BEGIN,PWNS_RMTFS,
    PWNS_SMEM,PWNS_LOCK,PWNS_ALLOCATE,PWNS_PUBLISH,PWNS_UNLOCK,
    PWNS_CHANNEL,PWNS_SMP_BEGIN,PWNS_SMP,PWNS_GLINK_BEGIN,PWNS_GLINK,PWNS_QRTR,
    PWNS_SERVICE,PWNS_WLAN_BEGIN,PWNS_WLAN,PWNS_CE_BEGIN,PWNS_CE,
    PWNS_TRANSPORT,PWNS_HTC,PWNS_WMI_BEGIN,PWNS_WMI,PWNS_HTT_BEGIN,PWNS_HTT,
    PWNS_DATA,PWNS_NONCE,PWNS_READY
};
struct pwns_parent {
    uint64_t nv_memory,ce_memory,htt_memory,segments,nonce_source,nonce_digest;
    uint32_t attempted,phase,unknown,error;uint64_t turns;
    struct pmsc_owner owner;
    struct pmli_ledger images;struct pmrg_map map;struct pmrd_state rpmh;
    struct pmdc_state cmddb;struct pmrs_state rsc;
    struct pmpn_state power;struct pmpn_request power_records[PMPN_REQUESTS];
    struct pmsp_lifecycle supply;struct pmpx_lifecycle proxy;
    struct pmcn_state clocks;struct pmcn_delivery clock_records[PMCN_RECORDS];
    struct pmck_lifecycle active_clocks;
    struct pman_state aop;struct pman_delivery aop_records[PMAN_RECORDS];
    struct pmbn_state boot;struct pmbn_delivery boot_records[PMBN_RECORDS];
    struct pmsn_state auth;struct pmsn_delivery auth_records[PMSN_RECORDS];struct pmlc_copy copy;
    struct pmtf_state rmtfs;struct pmsq_state smem;struct pmsl_lock lock;
    struct pmsa_state allocation;struct pmsx_state channel;struct pmsy_state smp;
    struct pmsg_state glink;struct pmrf_state service;struct pmwa_state wlan;
    struct pmws_state smmu;struct pmws_delivery smmu_records[PWSU_READS];
    struct pmce_state ce;struct pmct_state transport;struct pmhc_state htc;
    struct pmwi_state wmi;struct pmht_state htt;struct pmhd_state data;
    struct pmnp_state nonce;
#if EFI_XNU_WIFI_NATIVE_WATCHDOG_READONLY
    struct pawn_state watchdog;
#endif
};
static inline int pwns_fail(struct pwns_parent*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;return -1;}
static inline int pwns_begin(struct pwns_parent*s,const struct pweh_result*h,
    const struct pmmn_native*m,const uint8_t memory_digest[32],const struct pmsb_result*b,
    struct pnnv_state*nv,struct pcdm_state*ce,struct pcdm_state*htt,
    const struct pmsf_segment*segments,const uint8_t*nonces,const uint8_t nonce_digest[32])
{
    if(!s||!h||!m||!memory_digest||!b||!nv||!ce||!htt||!segments||!nonces||!nonce_digest||
       !pwmc_zero(s,offsetof(struct pwns_parent,owner)))return 0;
    s->attempted=1;
    const struct pwea_native*e=h->input.early;
    if(!e||!pweh_binding(h)||!pmsi_image_range(e,&h->map,(uintptr_t)s,sizeof(*s)))return pwns_fail(s,1),0;
    const uint64_t at[]={(uintptr_t)h,(uintptr_t)m,(uintptr_t)b,(uintptr_t)e,(uintptr_t)memory_digest,
        (uintptr_t)nv,(uintptr_t)ce,(uintptr_t)htt,(uintptr_t)segments,(uintptr_t)nonces,(uintptr_t)nonce_digest};
    const uint64_t bytes[]={sizeof(*h),sizeof(*m),sizeof(*b),sizeof(*e),32,sizeof(*nv),sizeof(*ce),sizeof(*htt),
        sizeof(*segments)*PMIM_SEGMENTS,PWNP_BYTES,32};
    for(unsigned n=0;n<11;n++){
        if(!pmsi_image_range(e,&h->map,at[n],bytes[n])||!pwea_disjoint((uintptr_t)s,sizeof(*s),at[n],bytes[n]))return pwns_fail(s,1),0;
        for(unsigned j=0;j<n;j++)if(!pwea_disjoint(at[n],bytes[n],at[j],bytes[j]))return pwns_fail(s,1),0;
    }
    if(!nv->complete||nv->unknown||nv->error||nv->consumer||!ce->complete||ce->unknown||ce->error||ce->consumer||
       !htt->complete||htt->unknown||htt->error||htt->consumer||
       !pwea_disjoint(ce->allocation.address,PWDM_BYTES,htt->allocation.address,PHTM_BYTES))return pwns_fail(s,1),0;
    s->nv_memory=(uintptr_t)nv;s->ce_memory=(uintptr_t)ce;s->htt_memory=(uintptr_t)htt;
    s->segments=(uintptr_t)segments;s->nonce_source=(uintptr_t)nonces;s->nonce_digest=(uintptr_t)nonce_digest;
    if(!pmsc_begin(&s->owner,h,m,memory_digest,b))return pwns_fail(s,2),0;
    s->phase=PWNS_IMAGES;return 1;
}
/* One actual producer action per turn. WAIT never advances a phase. No fake
 * elapsed time, remote reply, scan entry or authorization is supplied here. */
static inline int pwns_step(struct pwns_parent*s)
{
    if(!s||!s->attempted||s->unknown||s->error||s->phase<PWNS_IMAGES||s->phase>PWNS_READY)return -1;
    if(s->turns==UINT64_MAX||!pmsc_live(&s->owner))return pwns_fail(s,3);
    s->turns++;int ok=0,result=0;uint64_t now=s->owner.last;
    switch(s->phase){
    case PWNS_IMAGES:ok=pmli_capture(&s->images,&s->owner);break;
    case PWNS_MAP:ok=pmrg_capture(&s->map,&s->images,&s->owner);break;
    case PWNS_RPMH:ok=pmrd_capture(&s->rpmh,&s->map);break;
    case PWNS_CMDDB:ok=pmdc_capture(&s->cmddb,&s->map);break;
    case PWNS_RSC:ok=pmrs_capture(&s->rsc,&s->rpmh,&s->map);break;
    case PWNS_POWER:ok=pmpn_begin(&s->power,s->power_records,&s->rsc,&s->cmddb,&s->rpmh,&s->map);break;
    case PWNS_CLOCK_OWNER:ok=pmcn_begin(&s->clocks,s->clock_records,&s->power);break;
    case PWNS_AOP_BEGIN:ok=pman_begin(&s->aop,s->aop_records,&s->clocks);break;
    case PWNS_AOP:result=pman_step(&s->aop);if(result==PMAQ_WAIT)return 1;ok=result==PMAQ_CONSUMED;break;
    case PWNS_SUPPLY_BEGIN:{
        uint32_t minimum[3];for(unsigned n=0;n<3;n++)minimum[n]=s->cmddb.pass[1].resource[n].minimum;
        ok=pmsp_begin(&s->supply,s->owner.opening,minimum,now,s->owner.current.cpu.frequency)==PMSP_WAIT;break;}
    case PWNS_SUPPLY:{
        struct pmsp_command c;result=pmsp_next(&s->supply,now,&c);
        if(result==PMSP_REQUEST){if(!pmpn_supply(&s->power,&s->supply,&c))return pwns_fail(s,4);return 1;}
        if(result==PMSP_WAIT)return 1;ok=result==PMSP_HELD;break;}
    case PWNS_PROXY_BEGIN:ok=pmpn_proxy_begin(&s->power,&s->proxy);break;
    case PWNS_PROXY:{
        struct pmpx_command c;result=pmpx_next(&s->proxy,now,&c);if(result==PMPX_WAIT)return 1;
        if(result==PMPX_IO){
            ok=c.kind==PMPX_RAIL?pmpn_proxy(&s->power,&s->proxy,&c):pmcn_proxy(&s->clocks,&s->proxy,&c);
            if(!ok)return pwns_fail(s,4);return 1;
        }ok=result==PMPX_HELD;break;}
    case PWNS_CLOCK_BEGIN:ok=pmcn_clock_begin(&s->clocks,&s->active_clocks);break;
    case PWNS_CLOCK:{
        struct pmck_command c;result=pmck_next(&s->active_clocks,now,&c);if(result==PMCK_WAIT)return 1;
        if(result==PMCK_IO){if(!pmcn_clock(&s->clocks,&s->active_clocks,&c))return pwns_fail(s,4);return 1;}
        ok=result==PMCK_HELD;break;}
    case PWNS_BOOT_BEGIN:ok=pmbn_begin(&s->boot,s->boot_records,&s->aop);break;
    case PWNS_BOOT:result=pmbn_step(&s->boot);if(result==PMBA_WAIT)return 1;ok=result==PMBA_READY;break;
    case PWNS_AUTH_BEGIN:ok=pmsn_begin(&s->auth,s->auth_records,&s->copy,&s->boot,(const void*)(uintptr_t)s->segments);break;
    case PWNS_AUTH:result=pmsn_step(&s->auth);if(result==1)return 1;ok=result==2;break;
    case PWNS_RMTFS_BEGIN:ok=pmtf_begin(&s->rmtfs,&s->auth);break;
    case PWNS_RMTFS:result=pmtf_step(&s->rmtfs);if(result==1)return 1;ok=result==2;break;
    case PWNS_SMEM:ok=pmsq_capture(&s->smem,&s->map);break;
    case PWNS_LOCK:ok=pmsl_acquire(&s->lock,&s->smem);break;
    case PWNS_ALLOCATE:ok=pmsa_prepare(&s->allocation,&s->lock);break;
    case PWNS_PUBLISH:ok=pmsa_publish(&s->allocation);break;
    case PWNS_UNLOCK:ok=pmsl_release(&s->lock);break;
    case PWNS_CHANNEL:ok=pmsx_begin(&s->channel,&s->auth,&s->allocation);break;
    case PWNS_SMP_BEGIN:ok=pmsy_begin(&s->smp,&s->channel);break;
    case PWNS_SMP:result=pmsy_step(&s->smp);if(result==1)return 1;ok=result==2;break;
    case PWNS_GLINK_BEGIN:ok=pmsg_begin(&s->glink,&s->channel);break;
    case PWNS_GLINK:result=pmsg_step(&s->glink);if(result==1)return 1;ok=result==2;break;
    case PWNS_QRTR:result=pmsg_peer_step(&s->glink);if(result==1)return 1;ok=result==2;break;
    case PWNS_SERVICE:ok=pmrf_begin(&s->service,&s->glink,&s->rmtfs,(void*)(uintptr_t)s->nv_memory);break;
    case PWNS_WLAN_BEGIN:ok=pmwa_begin(&s->wlan,&s->service);break;
    case PWNS_WLAN:result=pmwa_step(&s->wlan);if(result==1)return 1;ok=result==2;break;
    case PWNS_CE_BEGIN:ok=pmce_begin(&s->ce,(void*)(uintptr_t)s->ce_memory,&s->wlan,&s->smmu,s->smmu_records);break;
    case PWNS_CE:result=pmce_step(&s->ce);if(result==1)return 1;ok=result==2;break;
    case PWNS_TRANSPORT:ok=pmct_begin(&s->transport,&s->ce);break;
    case PWNS_HTC:ok=pmhc_begin(&s->htc,&s->transport);break;
    case PWNS_WMI_BEGIN:ok=pmwi_begin(&s->wmi,&s->htc);break;
    case PWNS_WMI:result=pmwi_step(&s->wmi);if(result==1)return 1;ok=result==3;break;
    case PWNS_HTT_BEGIN:ok=pmht_begin(&s->htt,(void*)(uintptr_t)s->htt_memory,&s->wmi);break;
    case PWNS_HTT:result=pmht_step(&s->htt);if(result==1)return 1;ok=result==3;break;
    case PWNS_DATA:ok=pmhd_begin(&s->data,&s->htt);break;
    case PWNS_NONCE:ok=pmnp_begin(&s->nonce,&s->wmi,(const void*)(uintptr_t)s->nonce_source,(const void*)(uintptr_t)s->nonce_digest);break;
    case PWNS_READY:return pmwi_live(&s->wmi)&&pmhd_live(&s->data)&&pmnp_live(&s->nonce)?2:pwns_fail(s,5);
    default:return pwns_fail(s,3);
    }
    if(!ok)return pwns_fail(s,4);s->phase++;return s->phase==PWNS_READY?2:1;
}
#endif
#endif
