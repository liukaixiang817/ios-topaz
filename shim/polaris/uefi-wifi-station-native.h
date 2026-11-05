/* Native WMI + HTT3 station. Requires a completed actual scan and an initialized
 * independent HTT bank. Channel inputs must come from the parent radio's
 * regulatory configuration; this module does not infer TX permission from AP
 * beacons. Default OFF, not registered in the whole-device parent yet. */
#ifndef POLARIS_UEFI_WIFI_STATION_NATIVE_H
#define POLARIS_UEFI_WIFI_STATION_NATIVE_H
#include "uefi-wifi-scan-native.h"
#include "uefi-wifi-htt-data.h"
#include "../../tools/polaris-wifi-wmi-station.h"
#ifndef EFI_XNU_WIFI_STATION_NATIVE_AVAILABLE
#define EFI_XNU_WIFI_STATION_NATIVE_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_STATION_NATIVE_AVAILABLE
#if !EFI_XNU_WIFI_SCAN_NATIVE_AVAILABLE || !EFI_XNU_WIFI_HTT_DATA_AVAILABLE
#error Native station requires native scan and HTT data
#endif
struct pmst_state {
    uint64_t scan,data,owner,opening,consumer;struct pwst_state client;
    uint32_t attempted,ready,unknown,error,submitted,mgmt_wait,mgmt_id,mgmt_status,mgmt_completed;
};
static inline int pmst_fail(struct pmst_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;return -1;}
static inline int pmst_live(struct pmst_state*s)
{
    if(!s||s->ready!=1||s->unknown||s->error||s->client.unknown||s->client.error)return 0;
    struct pmwsn_state*q=(void*)(uintptr_t)s->scan;struct pmhd_state*d=(void*)(uintptr_t)s->data;
    struct pmht_state*t=(void*)(uintptr_t)d->parent;
    return q->consumer==(uintptr_t)s&&d->consumer==(uintptr_t)s&&q->owner==s->owner&&d->owner==s->owner&&
        q->opening==s->opening&&d->opening==s->opening&&t->wmi==q->wmi&&pmwsn_live(q)&&pmhd_live(d);
}
static inline int pmst_begin(struct pmst_state*s,struct pmwsn_state*q,struct pmhd_state*d,
    unsigned index,unsigned security,const struct pwst_channel*channel)
{
    if(!s||!q||!d||!channel||!pwmc_zero(s,sizeof(*s))||q->consumer||d->consumer||!q->client.completed||
       !pmwsn_live(q)||!pmhd_live(d)||q->owner!=d->owner||q->opening!=d->opening||d->frame_ready||d->submitted)return 0;
    struct pmht_state*t=(void*)(uintptr_t)d->parent;struct pmwi_state*w=(void*)(uintptr_t)q->wmi;
    struct pmhc_state*h=(void*)(uintptr_t)w->htc;struct pmsc_owner*o=(void*)(uintptr_t)q->owner;
    /* Primary mac.c selects WMI management when service76 is present. This
     * implementation supports the alternative HTT3 path only, never silently
     * sends management through the wrong advertised transport. */
    if(t->wmi!=q->wmi||d->rings.major<3||pwmi_service(&w->client,76)||h->client.pending||h->frame_kind)return 0;
    const uint64_t address[]={q->wmi,(uintptr_t)q,(uintptr_t)d,(uintptr_t)t,t->memory};
    const uint64_t size[]={sizeof(*w),sizeof(*q),sizeof(*d),sizeof(*t),sizeof(struct pcdm_state)};
    if(!pmwi_child(h,(uintptr_t)s,sizeof(*s)))return 0;
    for(unsigned n=0;n<5;n++){
        if(!pwea_disjoint((uintptr_t)s,sizeof(*s),address[n],size[n]))return 0;
        for(unsigned j=0;j<n;j++)if(!pwea_disjoint(address[n],size[n],address[j],size[j]))return 0;
    }
    unsigned low=pwmi_get(w->client.regulatory+20),high=pwmi_get(w->client.regulatory+24);
    if((low&&channel->frequency<low)||(high&&channel->frequency>high)||
       !pwst_open(&s->client,&q->client,index,security,channel,o->last))return 0;
    s->scan=(uintptr_t)q;s->data=(uintptr_t)d;s->owner=q->owner;s->opening=q->opening;s->attempted=s->ready=1;
    q->consumer=d->consumer=(uintptr_t)s;return pmst_live(s);
}
static inline int pmst_commit(struct pmst_state*s)
{
    struct pmhd_state*d=(void*)(uintptr_t)s->data;struct pmht_state*t=(void*)(uintptr_t)d->parent;
    struct pmwi_state*w=(void*)(uintptr_t)t->wmi;struct pmhc_state*h=(void*)(uintptr_t)w->htc;
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;
    if(s->submitted&&!(s->submitted==1?h->client.pending:d->submitted)){
        if(s->submitted==2&&d->rings.tx_owner[s->mgmt_id]!=2&&d->rings.tx_owner[s->mgmt_id]!=3)return pmst_fail(s,1);
        if(pwst_sent(&s->client,o->last,1)!=1)return pmst_fail(s,1);s->submitted=0;
    }
    if(s->mgmt_wait&&d->rings.tx_owner[s->mgmt_id]==3){
        if(!pmhd_tx_ack(d,s->mgmt_id,&s->mgmt_status))return pmst_fail(s,1);
        s->mgmt_wait=0;s->mgmt_completed++;
    }return 1;
}
/* 1=progress/wait,2=other retained WMI/HTT event,3=private received data for
 * the authentication consumer,4=connection rejected,5=VDEV_UP published.
 * 5 does NOT mean WPA authenticated, IP assigned, or working Internet. */
static inline int pmst_step(struct pmst_state*s)
{
    if(!pmst_live(s))return -1;struct pmhd_state*d=(void*)(uintptr_t)s->data;
    struct pmht_state*t=(void*)(uintptr_t)d->parent;struct pmwi_state*w=(void*)(uintptr_t)t->wmi;
    struct pmhc_state*h=(void*)(uintptr_t)w->htc;struct pmsc_owner*o=(void*)(uintptr_t)s->owner;
    int result=pmhd_poll(d);if(result<0||pmst_commit(s)<0)return pmst_fail(s,2);
    if(!pwst_live(&s->client,o->last))return pmst_fail(s,3);
    if(result==2){
        if(h->frame_kind!=1||h->client.rx_eid!=h->client.wmi)return 2;
        int used=pwst_wmi(&s->client,h->client.rx,h->client.rx_bytes,o->last);
        if(used<0)return pmst_fail(s,4);if(!used)return 2;if(!pmhc_ack(h))return pmst_fail(s,4);
    }
    if(s->client.phase==4){
        for(unsigned n=0;n<66;n++){
            const struct phtr_peer*p=&d->rings.peer[n];
            if(p->valid&&!p->vdev&&psta_equal(p->mac,s->client.station.target.bssid,6)){
                if(pwst_peer(&s->client,p->id,p->vdev,p->mac,1,o->last)!=1)return pmst_fail(s,5);break;
            }
        }
    }else if(s->client.peer_valid){
        unsigned found=0;for(unsigned n=0;n<66;n++){
            const struct phtr_peer*p=&d->rings.peer[n];
            if(p->valid&&p->id==s->client.peer_id&&!p->vdev&&psta_equal(p->mac,s->client.station.target.bssid,6))found=1;
        }
        if(!found&&pwst_peer(&s->client,s->client.peer_id,0,s->client.station.target.bssid,0,o->last)!=1)return pmst_fail(s,5);
    }
    if(s->client.phase==9)return 4;if(result==3)return 3;
    if(!s->client.pending&&pwst_next(&s->client,o->last)<0)return pmst_fail(s,6);
    if(s->client.pending&&!s->submitted&&!h->client.pending){
        if(s->client.kind==2){
            if(!s->mgmt_wait){
                pwmi_copy(d->send,s->client.tx,s->client.tx_bytes);
                int sent=pmhd_send(d,s->client.tx_bytes,3,0,17,1);if(sent<0)return pmst_fail(s,7);
                if(sent){s->mgmt_id=d->rings.tx_id;s->mgmt_wait=1;s->submitted=2;}
            }
        }else{
            int sent=pmhc_send(h,h->client.wmi,s->client.tx,s->client.tx_bytes);if(sent<0)return pmst_fail(s,7);
            if(sent)s->submitted=1;
        }
        if(pmst_commit(s)<0)return pmst_fail(s,1);
    }
    return s->client.phase==9?4:s->client.up_published?5:1;
}
#endif
#endif
