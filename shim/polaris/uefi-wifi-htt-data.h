/* Native HTT data transport. Buffers stay resident; explicit target completion
 * and private RX copying govern reuse. This layer does not claim association,
 * key installation, packet authentication, or an IP interface. */
#ifndef POLARIS_UEFI_WIFI_HTT_DATA_H
#define POLARIS_UEFI_WIFI_HTT_DATA_H
#include "uefi-wifi-htt-native.h"
#include "../../tools/polaris-wifi-htt-ring.h"
#ifndef EFI_XNU_WIFI_HTT_DATA_AVAILABLE
#define EFI_XNU_WIFI_HTT_DATA_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_HTT_DATA_AVAILABLE
#if !EFI_XNU_WIFI_HTT_NATIVE_AVAILABLE
#error Native HTT data requires actual initialized HTT
#endif
struct pmhd_state {
    uint64_t parent,owner,opening,consumer;struct phtr_state rings;
    uint8_t send[2048],receive[2048];
    uint32_t attempted,ready,unknown,error,submitted,frame_ready,rx_slot,rx_bytes,rx_offset,rx_format,rx_attention,rx_bad;
};
static inline int pmhd_fail(struct pmhd_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;return -1;}
static inline int pmhd_live(struct pmhd_state*s)
{
    if(!s||s->ready!=1||s->unknown||s->error||!phtr_live(&s->rings))return 0;
    struct pmht_state*p=(void*)(uintptr_t)s->parent;
    return p->consumer==(uintptr_t)s&&p->owner==s->owner&&p->opening==s->opening&&p->client.phase==5&&pmht_live(p);
}
static inline int pmhd_begin(struct pmhd_state*s,struct pmht_state*p)
{
    if(!s||!p||!pwmc_zero(s,sizeof(*s))||p->consumer||p->busy||p->client.phase!=5||!pmht_live(p))return 0;
    struct pmwi_state*w=(void*)(uintptr_t)p->wmi;struct pmhc_state*h=(void*)(uintptr_t)w->htc;
    if(h->client.pending||h->frame_kind||!pmwi_child(h,(uintptr_t)s,sizeof(*s))||
       !pwea_disjoint((uintptr_t)s,sizeof(*s),(uintptr_t)p,sizeof(*p))||!pwea_disjoint((uintptr_t)s,sizeof(*s),p->memory,sizeof(struct pcdm_state))||
       !pwea_disjoint((uintptr_t)s,sizeof(*s),(uintptr_t)w,sizeof(*w))||!phtr_open(&s->rings,&p->client))return 0;
    s->parent=(uintptr_t)p;s->owner=p->owner;s->opening=p->opening;s->attempted=s->ready=1;p->consumer=(uintptr_t)s;return pmhd_live(s);
}
static inline int pmhd_tx_commit(struct pmhd_state*s)
{
    struct pmht_state*p=(void*)(uintptr_t)s->parent;struct pmwi_state*w=(void*)(uintptr_t)p->wmi;struct pmhc_state*h=(void*)(uintptr_t)w->htc;
    if(s->submitted&&!h->client.pending){if(phtr_tx_published(&s->rings,1)!=1)return pmhd_fail(s,1);s->submitted=0;}return 1;
}
/* Call with the complete frame in send[]. Return1 means queued/published;
 * only a later HTT completion determines ACK/discard and permits reuse. */
static inline int pmhd_send(struct pmhd_state*s,unsigned bytes,unsigned mode,unsigned vdev,unsigned tid,unsigned no_encrypt)
{
    if(!pmhd_live(s)||s->submitted)return -1;struct pmht_state*p=(void*)(uintptr_t)s->parent;
    struct pmwi_state*w=(void*)(uintptr_t)p->wmi;struct pmhc_state*h=(void*)(uintptr_t)w->htc;
    if(p->busy||h->client.pending||s->frame_ready||s->rings.rx_count)return 0;
    int result=phtr_tx(&s->rings,s->send,bytes,mode,vdev,tid,no_encrypt);if(result<=0)return result;
    p->busy=1;uint64_t buffer=p->base+p->layout.transmit+(uint64_t)PHTM_BUFFER*s->rings.tx_id;
    if(pmht_memory(p,buffer,s->send,bytes,1)<0||pmht_cache(p,buffer,(bytes+63)&~63u,PWMK_CLEAN_INVALIDATE)<0)return pmhd_fail(s,2);
    if(mode!=3){
        uint64_t descriptor=p->base+p->layout.fragments+(uint64_t)PHTM_FRAGMENT*s->rings.tx_id;
        uint64_t line=descriptor&~UINT64_C(63);unsigned span=(unsigned)(((descriptor+72+63)&~UINT64_C(63))-line);
        if(pmht_memory(p,descriptor,s->rings.fragment,72,1)<0||pmht_cache(p,line,span,PWMK_CLEAN_INVALIDATE)<0)return pmhd_fail(s,2);
    }p->busy=0;
    if(pmhc_send(h,h->client.htt,s->rings.command,s->rings.tx_bytes)!=1)return pmhd_fail(s,3);
    s->submitted=1;return pmhd_tx_commit(s);
}
static inline int pmhd_rx_copy(struct pmhd_state*s)
{
    struct pmht_state*p=(void*)(uintptr_t)s->parent;struct phtr_state*r=&s->rings;
    if(s->frame_ready||p->busy||r->rx_at>=r->rx_count)return -1;
    const struct phtr_rx*rx=&r->rx[r->rx_at];uint64_t at=p->base+p->layout.receive+(uint64_t)PHTM_BUFFER*rx->slot;p->busy=1;
    if(pmht_cache(p,at,PHTM_BUFFER,PWMK_INVALIDATE)<0||pmht_memory(p,at,s->receive,PHTM_BUFFER,0)<0)return pmhd_fail(s,4);
    s->rx_slot=rx->slot;s->rx_bytes=rx->bytes;s->rx_attention=s->rx_bad=0;
    if(r->rx_info&0x20){
        s->rx_offset=7;s->rx_bytes=phtr_u16(s->receive);s->rx_format=1;
        if(!s->rx_bytes||s->rx_bytes>2041||phtr_u16(s->receive+2)!=r->rx_peer||s->receive[4]!=r->rx_vdev)return pmhd_fail(s,5);
    }else{
        s->rx_attention=pwmi_get(s->receive+4);if(!(s->rx_attention&(1u<<31)))return pmhd_fail(s,5);
        s->rx_offset=360;s->rx_format=(pwmi_get(s->receive+36)>>8)&3;
        s->rx_bad=s->rx_attention&0x7d030000u; /* retain errors for the station consumer */
    }
    if(phtr_rx_copied(r,rx->slot,1)!=1)return pmhd_fail(s,5);p->busy=0;s->frame_ready=1;return 3;
}
/* Acknowledging the retained private packet returns just its physical buffer.
 * Target only reads ring entries/index, so cleaning their containing cache
 * lines cannot overwrite target-produced descriptor data. */
static inline int pmhd_ack(struct pmhd_state*s)
{
    if(!pmhd_live(s)||!s->frame_ready)return 0;struct pmht_state*p=(void*)(uintptr_t)s->parent;struct phtr_state*r=&s->rings;
    if(p->busy||phtr_repost(r,s->rx_slot)!=1)return 0;p->busy=1;
    for(unsigned n=0;n<PHTM_BUFFER;n++)p->page[n]=0;
    uint64_t buffer=p->base+p->layout.receive+(uint64_t)PHTM_BUFFER*s->rx_slot;
    uint64_t entry=p->base+p->layout.ring+8u*r->rx_index,index=p->base+p->layout.index;
    if(pmht_memory(p,buffer,p->page,PHTM_BUFFER,1)<0||pmht_cache(p,buffer,PHTM_BUFFER,PWMK_CLEAN_INVALIDATE)<0||
       pmht_memory(p,entry,r->ring_entry,8,1)<0||pmht_cache(p,entry&~UINT64_C(63),64,PWMK_CLEAN_INVALIDATE)<0)return pmhd_fail(s,6),0;
    pwmi_put(p->page,r->repost_next);
    if(pmht_memory(p,index,p->page,64,1)<0||pmht_cache(p,index,64,PWMK_CLEAN_INVALIDATE)<0||phtr_reposted(r,1)!=1)return pmhd_fail(s,6),0;
    p->busy=0;s->frame_ready=s->rx_bytes=s->rx_offset=0;return 1;
}
/*1=progress/wait,2=retained unrelated upper event,3=private HTT RX packet. */
static inline int pmhd_poll(struct pmhd_state*s)
{
    if(!pmhd_live(s))return -1;struct pmht_state*p=(void*)(uintptr_t)s->parent;
    struct pmwi_state*w=(void*)(uintptr_t)p->wmi;struct pmhc_state*h=(void*)(uintptr_t)w->htc;
    struct pmct_state*t=(void*)(uintptr_t)h->transport;
    if(s->frame_ready){if(pmct_poll(t)<0)return pmhd_fail(s,7);return 3;}
    if(s->rings.rx_count){if(pmct_poll(t)<0)return pmhd_fail(s,7);return pmhd_rx_copy(s);}
    int result=pmht_step(p);if(result<0||pmhd_tx_commit(s)<0)return pmhd_fail(s,7);if(result!=2)return 1;
    const uint8_t*frame;unsigned bytes;
    if(h->frame_kind==1&&h->client.rx_eid==h->client.htt){frame=h->client.rx;bytes=h->client.rx_bytes;}
    else if(h->frame_kind==2&&h->raw_pipe==5){
        /* Primary SNOC fast-path callback strips exactly an8-byte HTC header
         * before HTT dispatch; it does not run normal HTC endpoint handling. */
        if(t->rx_bytes<9)return pmhd_fail(s,8);frame=t->receive+8;bytes=t->rx_bytes-8;
    }else return 2;
    if(pmct_reap(t,4)<0)return pmhd_fail(s,8);int accepted=phtr_event(&s->rings,frame,bytes);
    if(accepted<0)return pmhd_fail(s,8);if(!accepted)return 2;
    if(!pmhc_ack(h))return pmhd_fail(s,8);return s->rings.rx_count?pmhd_rx_copy(s):1;
}
static inline int pmhd_tx_ack(struct pmhd_state*s,unsigned id,unsigned*status)
{return pmhd_live(s)&&phtr_tx_ack(&s->rings,id,status);}
#endif
#endif
