/* Native passive scan: published CE commands plus actual returned scan events
 * and management frames. Never synthesizes APs or infers radio completion. */
#ifndef POLARIS_UEFI_WIFI_SCAN_NATIVE_H
#define POLARIS_UEFI_WIFI_SCAN_NATIVE_H
#include "uefi-wifi-wmi-native.h"
#include "../../tools/polaris-wifi-wmi-scan.h"
#ifndef EFI_XNU_WIFI_SCAN_NATIVE_AVAILABLE
#define EFI_XNU_WIFI_SCAN_NATIVE_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_SCAN_NATIVE_AVAILABLE
#if !EFI_XNU_WIFI_WMI_NATIVE_AVAILABLE
#error Native scan requires actual WMI READY
#endif
struct pmwsn_state {
    uint64_t wmi,owner,opening,consumer;struct pwsc_state client;
    uint32_t attempted,ready,unknown,error,submitted;
};
static inline int pmwsn_fail(struct pmwsn_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;return -1;}
static inline int pmwsn_live(struct pmwsn_state*s)
{
    if(!s||s->ready!=1||s->unknown||s->error||s->client.unknown||s->client.error)return 0;
    struct pmwi_state*w=(void*)(uintptr_t)s->wmi;
    return w->consumer==(uintptr_t)s&&w->owner==s->owner&&w->opening==s->opening&&w->client.phase==4&&pmwi_live(w);
}
static inline int pmwsn_begin(struct pmwsn_state*s,struct pmwi_state*w,unsigned scan_id)
{
    if(!s||!w||!pwmc_zero(s,sizeof(*s))||w->consumer||w->client.phase!=4||!pmwi_live(w))return 0;
    struct pmhc_state*h=(void*)(uintptr_t)w->htc;struct pmsc_owner*o=(void*)(uintptr_t)w->owner;
    if(h->client.pending||h->frame_kind||!pwea_disjoint((uintptr_t)s,sizeof(*s),(uintptr_t)w,sizeof(*w))||
       !pmwi_child(h,(uintptr_t)s,sizeof(*s))||!pwsc_open(&s->client,&w->client,scan_id,o->last))return 0;
    s->wmi=(uintptr_t)w;s->owner=w->owner;s->opening=w->opening;s->attempted=s->ready=1;w->consumer=(uintptr_t)s;return pmwsn_live(s);
}
static inline int pmwsn_restart(struct pmwsn_state*s,unsigned scan_id)
{
    if(!pmwsn_live(s)||s->consumer||s->submitted)return 0;
    struct pmwi_state*w=(void*)(uintptr_t)s->wmi;struct pmhc_state*h=(void*)(uintptr_t)w->htc;
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;
    return !h->client.pending&&!h->frame_kind&&pwsc_restart(&s->client,scan_id,o->last);
}
/* 1=progress/wait,2=retained other payload,3=scan COMPLETED received.
 * count==0 is a completed empty scan, never a successful AP discovery. */
static inline int pmwsn_step(struct pmwsn_state*s)
{
    if(!pmwsn_live(s))return -1;struct pmwi_state*w=(void*)(uintptr_t)s->wmi;
    struct pmhc_state*h=(void*)(uintptr_t)w->htc;struct pmsc_owner*o=(void*)(uintptr_t)s->owner;
    int result=pmwi_step(w);if(result<0)return pmwsn_fail(s,1);
    if(!pwsc_time(&s->client,o->last))return pmwsn_fail(s,2);
    if(s->submitted&&!h->client.pending){
        if(pwsc_sent(&s->client,o->last,1)!=1)return pmwsn_fail(s,3);s->submitted=0;
    }
    if(result==2){
        if(h->frame_kind!=1||h->client.rx_eid!=h->client.wmi)return 2;
        int accepted=pwsc_receive(&s->client,h->client.rx,h->client.rx_bytes,o->last);
        if(accepted<0)return pmwsn_fail(s,4);if(!accepted)return 2;
        if(!pmhc_ack(h))return pmwsn_fail(s,4);
    }
    if(!s->client.pending&&pwsc_next(&s->client,o->last)<0)return pmwsn_fail(s,5);
    if(s->client.pending&&!s->submitted&&!h->client.pending){
        int sent=pmhc_send(h,h->client.wmi,s->client.tx,s->client.tx_bytes);
        if(sent<0)return pmwsn_fail(s,6);
        if(sent){s->submitted=1;if(!h->client.pending){if(pwsc_sent(&s->client,o->last,1)!=1)return pmwsn_fail(s,3);s->submitted=0;}}
    }return s->client.completed?3:1;
}
#endif
#endif
