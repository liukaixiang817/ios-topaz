/* Native HTT bootstrap with a separate actual pre-native DMA allocation.
 * CE/WMI target-owned memory is never reused for this bank. */
#ifndef POLARIS_UEFI_WIFI_HTT_NATIVE_H
#define POLARIS_UEFI_WIFI_HTT_NATIVE_H
#include "uefi-wifi-wmi-native.h"
#include "../../tools/polaris-wifi-htt-init.h"
#ifndef EFI_XNU_WIFI_HTT_NATIVE_AVAILABLE
#define EFI_XNU_WIFI_HTT_NATIVE_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_HTT_NATIVE_AVAILABLE
#if !EFI_XNU_WIFI_WMI_NATIVE_AVAILABLE
#error Native HTT requires actual WMI initialization
#endif
struct pmht_state {
    uint64_t wmi,memory,owner,opening,base;uint8_t memory_digest[32];
    struct phtt_state client;struct phtm_layout layout;struct pmct_io io;
    struct pwea_core source[2];uint8_t history[32],page[4096];
    uint32_t attempted,ready,unknown,error,busy,operations,zeroed,ring_pages,prepared,submitted;
};
#if defined(POLARIS_WIFI_HTT_SOFTWARE_PEER)
static int pmht_copy(uint64_t,void*,unsigned,unsigned,struct pmct_memory*);
#else
static inline int pmht_copy(uint64_t at,void*private,unsigned bytes,unsigned write,struct pmct_memory*r)
{
    volatile uint8_t*shared=(void*)(uintptr_t)at;uint8_t*p=private;
    for(unsigned n=0;n<bytes;n++){r->issued++;if(write){shared[n]=p[n];if(shared[n]!=p[n])return 0;}else p[n]=shared[n];r->returned++;}return 1;
}
#endif
static inline int pmht_fail(struct pmht_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;return -1;}
static inline int pmht_live(struct pmht_state*s)
{
    if(!s||s->ready!=1||s->unknown||s->error||s->operations>16384||s->client.unknown||s->client.error)return 0;
    struct pmwi_state*w=(void*)(uintptr_t)s->wmi;struct pmhc_state*h=(void*)(uintptr_t)w->htc;
    struct pcdm_state*m=(void*)(uintptr_t)s->memory;
    return h->data_consumer==(uintptr_t)s&&w->owner==s->owner&&w->opening==s->opening&&w->client.phase==4&&
        m->consumer==(uintptr_t)s&&m->self==(uintptr_t)m&&m->complete==1&&!m->unknown&&!m->error&&
        m->allocation.address==s->base&&pgcd_equal(m->digest,s->memory_digest,32)&&pmwi_live(w);
}
static inline int pmht_begin(struct pmht_state*s,struct pcdm_state*m,struct pmwi_state*w)
{
    if(!s||!m||!w||!pwmc_zero(s,sizeof(*s))||w->client.phase!=4||!pmwi_live(w)||m->consumer||
       m->self!=(uintptr_t)m||m->complete!=1||m->unknown||m->error||m->calls!=3||m->allocated!=1||
       m->translated[0]!=PHTM_BYTES/4096||m->translated[1]!=PHTM_BYTES/4096)return 0;
    struct pmhc_state*h=(void*)(uintptr_t)w->htc;struct pmct_state*t=(void*)(uintptr_t)h->transport;
    struct pmce_state*c=(void*)(uintptr_t)t->parent;struct pmwa_state*a=(void*)(uintptr_t)c->wlan;
    struct pmrf_state*f=(void*)(uintptr_t)a->service;struct pnnv_state*nv=(void*)(uintptr_t)f->nv;
    struct pmsc_owner*o=(void*)(uintptr_t)w->owner;const struct pweh_result*r=(const void*)(uintptr_t)o->retained;
    const struct pmmn_native*modem=(const void*)(uintptr_t)o->memory;
    if(h->data_consumer||h->client.pending||h->frame_kind||!pmwi_child(h,(uintptr_t)s,sizeof(*s))||
       !pmwi_child(h,(uintptr_t)m,sizeof(*m))||!pwea_disjoint((uintptr_t)s,sizeof(*s),(uintptr_t)m,sizeof(*m))||
       !pwea_disjoint((uintptr_t)s,sizeof(*s),(uintptr_t)w,sizeof(*w))||!pwea_disjoint((uintptr_t)m,sizeof(*m),(uintptr_t)w,sizeof(*w)))return 0;
    uint8_t hash[32];pweh_digest(m,offsetof(struct pcdm_state,digest),hash);if(!pgcd_equal(hash,m->digest,32))return 0;
    pweh_digest(r->input.early,sizeof(struct pwea_native),hash);if(m->early!=(uintptr_t)r->input.early||!pgcd_equal(hash,m->early_digest,32))return 0;
    uint64_t base=m->allocation.address;
    if(PHTM_BYTES!=PWDM_BYTES||!phtm_plan(&s->layout,base)||
       !polaris_efi_range_owned(r->map.data,r->map.map.bytes,r->map.map.stride,base,PHTM_BYTES,2)||
       !pwea_disjoint(base,PHTM_BYTES,t->base,PWDM_BYTES)||!pwea_disjoint(base,PHTM_BYTES,nv->allocation.address,PNV_BYTES)||
       !pwea_disjoint(base,PHTM_BYTES,(uintptr_t)r->input.early->image.base,r->input.early->image.bytes)||
       !pwea_disjoint(base,PHTM_BYTES,r->input.early->memory.input.bank,r->input.early->memory.input.bank_bytes))return 0;
    for(unsigned n=0;n<2;n++)if(!pwea_disjoint(base,PHTM_BYTES,r->input.early->memory.claim[n].requested,r->input.early->memory.claim[n].bytes))return 0;
    for(unsigned n=0;n<PMME_CLAIMS;n++)if(!pwea_disjoint(base,PHTM_BYTES,modem->memory.claim[n].requested,modem->memory.claim[n].bytes))return 0;
    s->wmi=(uintptr_t)w;s->memory=(uintptr_t)m;s->owner=w->owner;s->opening=w->opening;s->base=base;s->attempted=1;pgcd_copy(s->memory_digest,m->digest,32);
    if(!pwea_core_check(r->input.early,&s->source[0],&r->map)||!pmwi_live(w))return pmht_fail(s,1),0;
    s->ready=1;h->data_consumer=m->consumer=(uintptr_t)s;return pmht_live(s);
}
static inline int pmht_at(struct pmht_state*s,uint64_t at,unsigned bytes,unsigned pass)
{
    if(pass>1||!bytes||bytes>4096||at<s->base||at-s->base>=PHTM_BYTES||bytes>PHTM_BYTES-(at-s->base))return 0;
    unsigned n=0;for(uint64_t page=at&~UINT64_C(4095);page<at+bytes;page+=4096,n++){
        struct pwmc_translation*t=&s->io.AT[pass][n];t->page=page;
        if(!pmht_live(s)||!pwmc_actual_translate(t)||!pwmc_translation_valid(t)||t->page!=page||!pmht_live(s))return 0;
    }return 1;
}
static inline int pmht_io_begin(struct pmht_state*s,unsigned kind)
{
    if(!pmht_live(s)||!s->busy||s->operations==16384)return 0;
    for(unsigned n=0;n<sizeof(s->io);n++)((uint8_t*)&s->io)[n]=0;s->io.kind=kind;s->io.unknown=1;s->operations++;return 1;
}
static inline int pmht_io_end(struct pmht_state*s)
{
    if(!pmht_live(s))return 0;s->io.unknown=0;s->io.complete=1;struct pwfi_sha256 hash;pwfi_init(&hash);
    for(unsigned n=0;n<32;n++)pwfi_byte(&hash,s->history[n]);for(unsigned n=0;n<sizeof(s->io);n++)pwfi_byte(&hash,((const uint8_t*)&s->io)[n]);
    pwfi_final(&hash,s->history);return 1;
}
static inline int pmht_memory(struct pmht_state*s,uint64_t at,void*data,unsigned bytes,unsigned write)
{
    if(!pmht_io_begin(s,2)||!pmht_at(s,at,bytes,0))return pmht_fail(s,2);
    struct pmct_memory*r=&s->io.memory;*r=(struct pmct_memory){at,bytes,write,0,0};
    if(!pmht_copy(at,data,bytes,write,r)||r->issued!=bytes||r->returned!=bytes||!pmht_at(s,at,bytes,1))return pmht_fail(s,2);
    pweh_digest(data,bytes,s->io.data);if(!pmht_io_end(s))return pmht_fail(s,2);return 1;
}
static inline int pmht_cache(struct pmht_state*s,uint64_t at,unsigned bytes,unsigned operation)
{
    if(!pmht_io_begin(s,1)||!pmht_at(s,at,bytes,0)||!pccl_actual(at,bytes,operation,&s->io.cache)||
       !pccl_valid(&s->io.cache,at,bytes,operation)||!pmht_at(s,at,bytes,1)||!pmht_io_end(s))return pmht_fail(s,3);
    return 1;
}
/* One zero/publication page per call. Index is published last, and HTT ring
 * configuration is not sent until all2047 buffers and ring addresses exist. */
static inline int pmht_prepare(struct pmht_state*s)
{
    if(!pmht_live(s)||s->busy||s->prepared)return -1;s->busy=1;
    uint64_t at;
    if(s->zeroed<PHTM_BYTES/4096){
        if(!pwmc_zero(s->page,sizeof(s->page)))return pmht_fail(s,4);
        at=s->base+4096u*s->zeroed;
        if(pmht_memory(s,at,s->page,4096,1)<0||pmht_cache(s,at,4096,PWMK_CLEAN_INVALIDATE)<0)return pmht_fail(s,4);
        s->zeroed++;s->busy=0;return 1;
    }
    if(s->ring_pages<4){
        for(unsigned n=0;n<512;n++){
            unsigned slot=s->ring_pages*512+n;
            phtt_put64(s->page+8*n,slot<PHTM_RX-1?s->base+s->layout.receive+(uint64_t)PHTM_BUFFER*slot:0);
        }
        at=s->base+s->layout.ring+4096u*s->ring_pages;
        if(pmht_memory(s,at,s->page,4096,1)<0||pmht_cache(s,at,4096,PWMK_CLEAN_INVALIDATE)<0)return pmht_fail(s,5);
        s->ring_pages++;s->busy=0;return 1;
    }
    for(unsigned n=0;n<64;n++)s->page[n]=0;pwmi_put(s->page,PHTM_RX-1);at=s->base+s->layout.index;
    if(pmht_memory(s,at,s->page,64,1)<0||pmht_cache(s,at,64,PWMK_CLEAN_INVALIDATE)<0)return pmht_fail(s,5);
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;const struct pweh_result*r=(const void*)(uintptr_t)o->retained;
    if(!pwea_core_check(r->input.early,&s->source[1],&r->map)||!pmht_live(s)||!phtt_open(&s->client,&s->layout,s->opening,o->last))return pmht_fail(s,6);
    s->prepared=1;s->busy=0;return 1;
}
/* 1=progress/wait,2=retained other packet,3=HTT setup commands published.
 * This is not a TX acknowledgement, received IP packet or working network. */
static inline int pmht_step(struct pmht_state*s)
{
    if(!pmht_live(s)||s->busy)return -1;struct pmwi_state*w=(void*)(uintptr_t)s->wmi;
    struct pmhc_state*h=(void*)(uintptr_t)w->htc;struct pmct_state*t=(void*)(uintptr_t)h->transport;
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;
    /* Memory initialization needs RMTFS service, but must not burn the CE
     * polling budget thousands of times while no HTT command was sent. */
    if(!s->prepared){if(pmct_poll(t)<0)return pmht_fail(s,7);return pmht_prepare(s);}
    int result=pmwi_step(w);if(result<0)return pmht_fail(s,7);
    if(!phtt_time(&s->client,o->last))return pmht_fail(s,8);
    if(s->submitted&&!h->client.pending){if(phtt_sent(&s->client,o->last,1)!=1)return pmht_fail(s,9);s->submitted=0;}
    if(result==2){
        if(h->frame_kind!=1||h->client.rx_eid!=h->client.htt)return 2;
        int accepted=phtt_receive(&s->client,h->client.rx,h->client.rx_bytes,o->last);
        if(accepted<0)return pmht_fail(s,10);if(!accepted)return 2;if(!pmhc_ack(h))return pmht_fail(s,10);
    }
    if(!s->client.pending&&phtt_next(&s->client,o->last)<0)return pmht_fail(s,11);
    if(s->client.pending&&!s->submitted&&!h->client.pending){
        int sent=pmhc_send(h,h->client.htt,s->client.tx,s->client.tx_bytes);
        if(sent<0)return pmht_fail(s,12);
        if(sent){s->submitted=1;if(!h->client.pending){if(phtt_sent(&s->client,o->last,1)!=1)return pmht_fail(s,9);s->submitted=0;}}
    }return s->client.phase==5?3:1;
}
#endif
#endif
