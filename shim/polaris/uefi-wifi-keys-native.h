/* Native serialized CCMP key installer. EAPOL/entropy is a separate producer;
 * only matching actual HTT security indications complete this installation. */
#ifndef POLARIS_UEFI_WIFI_KEYS_NATIVE_H
#define POLARIS_UEFI_WIFI_KEYS_NATIVE_H
#include "uefi-wifi-station-native.h"
#include "../../tools/polaris-wifi-wmi-keys.h"
#ifndef EFI_XNU_WIFI_KEYS_NATIVE_AVAILABLE
#define EFI_XNU_WIFI_KEYS_NATIVE_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_KEYS_NATIVE_AVAILABLE
#if !EFI_XNU_WIFI_STATION_NATIVE_AVAILABLE
#error Native keys require actual native station
#endif
struct pmky_state {
    uint64_t station,wpa,owner,opening;struct pwki_state client;
    uint32_t attempted,ready,unknown,error,submitted,completed;
};
static inline int pmky_fail(struct pmky_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;pwpa_stop((void*)(uintptr_t)s->wpa);return -1;}
static inline int pmky_live(struct pmky_state*s)
{
    if(!s||s->ready!=1||s->unknown||s->error||s->client.unknown||s->client.error)return 0;
    struct pmst_state*p=(void*)(uintptr_t)s->station;struct pwpa_state*w=(void*)(uintptr_t)s->wpa;
    return p->consumer==(uintptr_t)s&&p->owner==s->owner&&p->opening==s->opening&&w->epoch==s->opening&&!w->unknown&&!w->error&&pmst_live(p);
}
static inline int pmky_begin(struct pmky_state*s,struct pmst_state*p,struct pwpa_state*w)
{
    if(!s||!p||!w||!pwmc_zero(s,sizeof(*s))||p->consumer||!pmst_live(p)||!p->client.up_published||!p->client.peer_valid||
       w->epoch!=p->opening||!psta_equal(w->peer,p->client.station.target.bssid,6)||!psta_equal(w->own,p->client.station.own,6)||
       w->phase!=3||!w->keys_ready||w->pending||w->unknown||w->error||w->install_issued||w->installed)return 0;
    struct pmhd_state*d=(void*)(uintptr_t)p->data;struct pmht_state*t=(void*)(uintptr_t)d->parent;
    struct pmwi_state*a=(void*)(uintptr_t)t->wmi;struct pmhc_state*h=(void*)(uintptr_t)a->htc;struct pmsc_owner*o=(void*)(uintptr_t)p->owner;
    const uint64_t address[]={(uintptr_t)p,p->scan,(uintptr_t)d,(uintptr_t)t,t->memory,t->wmi};
    const uint64_t size[]={sizeof(*p),sizeof(struct pmwsn_state),sizeof(*d),sizeof(*t),sizeof(struct pcdm_state),sizeof(*a)};
    if(h->client.pending||h->frame_kind||p->submitted||p->mgmt_wait||!pmwi_child(h,(uintptr_t)s,sizeof(*s))||
       !pmwi_child(h,(uintptr_t)w,sizeof(*w))||!pwea_disjoint((uintptr_t)s,sizeof(*s),(uintptr_t)w,sizeof(*w)))return 0;
    for(unsigned n=0;n<6;n++)if(!pwea_disjoint((uintptr_t)s,sizeof(*s),address[n],size[n])||!pwea_disjoint((uintptr_t)w,sizeof(*w),address[n],size[n]))return 0;
    if(!pwpa_install(w,o->last)||!pwki_open(&s->client,w,p->client.peer_id,o->last))return 0;
    s->station=(uintptr_t)p;s->wpa=(uintptr_t)w;s->owner=p->owner;s->opening=p->opening;s->attempted=s->ready=1;p->consumer=(uintptr_t)s;return pmky_live(s);
}
/*1=progress/wait,2=other retained event,3=private data,4=disconnected,
 *5=both keys confirmed by target. Data still needs per-frame security checks.*/
static inline int pmky_step(struct pmky_state*s)
{
    if(!pmky_live(s))return -1;struct pmst_state*p=(void*)(uintptr_t)s->station;
    struct pwpa_state*w=(void*)(uintptr_t)s->wpa;struct pmhd_state*d=(void*)(uintptr_t)p->data;
    struct pmht_state*t=(void*)(uintptr_t)d->parent;struct pmwi_state*a=(void*)(uintptr_t)t->wmi;struct pmhc_state*h=(void*)(uintptr_t)a->htc;
    struct pmct_state*c=(void*)(uintptr_t)h->transport;struct pmsc_owner*o=(void*)(uintptr_t)s->owner;
    int result=pmst_step(p);if(result<0)return pmky_fail(s,1);
    if(result==4){pwpa_stop(w);return 4;}
    if(s->submitted&&!h->client.pending){if(pwki_sent(&s->client,o->last,1)!=1)return pmky_fail(s,2);s->submitted=0;}
    if(!pwki_live(&s->client,o->last))return pmky_fail(s,3);
    if(result==2){
        const uint8_t*frame;unsigned bytes;
        if(h->frame_kind==1&&h->client.rx_eid==h->client.htt){frame=h->client.rx;bytes=h->client.rx_bytes;}
        else if(h->frame_kind==2&&h->raw_pipe==5&&c->rx_bytes>=9){frame=c->receive+8;bytes=c->rx_bytes-8;}
        else return 2;
        int used=pwki_htt(&s->client,frame,bytes,o->last);if(used<0)return pmky_fail(s,4);if(!used)return 2;
        if(!pmhc_ack(h))return pmky_fail(s,4);
    }
    if(s->client.phase==4&&!s->completed){if(s->client.confirmed!=3||pwpa_installed(w,o->last,1)!=1)return pmky_fail(s,5);s->completed=1;}
    if(result==3)return 3;
    if(!s->client.pending&&pwki_next(&s->client,o->last)<0)return pmky_fail(s,6);
    if(s->client.pending&&!s->submitted&&!h->client.pending){
        int sent=pmhc_send(h,h->client.wmi,s->client.tx,sizeof(s->client.tx));if(sent<0)return pmky_fail(s,7);
        if(sent){s->submitted=1;if(!h->client.pending){if(pwki_sent(&s->client,o->last,1)!=1)return pmky_fail(s,2);s->submitted=0;}}
    }return s->completed?5:1;
}
#endif
#endif
