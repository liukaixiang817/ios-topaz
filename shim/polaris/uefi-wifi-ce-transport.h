/* Native polled CE transport under the uninterrupted startup owner. RX lines
 * are recycled only when all four descriptors are CPU-owned. Buffers remain
 * resident; no handback, CPU restart or original provider is admitted here. */
#ifndef POLARIS_UEFI_WIFI_CE_TRANSPORT_H
#define POLARIS_UEFI_WIFI_CE_TRANSPORT_H
#include "uefi-wifi-ce-native.h"
#include "uefi-wifi-ce-cache.h"
#include "../../tools/polaris-wifi-ce-ring.h"
#ifndef EFI_XNU_WIFI_CE_TRANSPORT_AVAILABLE
#define EFI_XNU_WIFI_CE_TRANSPORT_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_CE_TRANSPORT_AVAILABLE
#if !EFI_XNU_WIFI_CE_NATIVE_AVAILABLE
#error CE transport requires actual completed native startup
#endif
#define PMCT_OPERATIONS 65536u
struct pmct_memory {uint64_t address;uint32_t bytes,write,issued,returned;};
struct pmct_io {
    uint32_t kind,complete,unknown,reserved;struct pwmc_translation AT[2][3];
    struct pccl_record cache;struct pmct_memory memory;struct pmce_delivery mmio;uint8_t data[32];
};
struct pmct_state {
    uint64_t parent,owner,opening,power,base,next_poll;uint8_t parent_digest[32];
    struct pwcr_state rings;struct pmct_io io;uint8_t history[32];
    uint8_t send[2048],receive[2048],scratch[64];
    uint32_t attempted,ready,unknown,error,busy,operations,frame_ready,rx_pipe,rx_bytes;
    uint64_t sends,receives,posts;
};
#if defined(POLARIS_WIFI_CE_TRANSPORT_SOFTWARE_PEER)
static int pmct_copy(uint64_t,void*,unsigned,unsigned,struct pmct_memory*);
#else
static inline int pmct_copy(uint64_t address,void*private,unsigned bytes,unsigned write,struct pmct_memory*r)
{
    volatile uint8_t*shared=(void*)(uintptr_t)address;uint8_t*p=private;
    for(unsigned n=0;n<bytes;n++){r->issued++;if(write){shared[n]=p[n];if(shared[n]!=p[n])return 0;}else p[n]=shared[n];r->returned++;}return 1;
}
#endif
static inline int pmct_fail(struct pmct_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;return -1;}
static inline int pmct_live(struct pmct_state*s)
{
    if(!s||s->ready!=1||s->unknown||s->error||s->operations>PMCT_OPERATIONS||s->rings.unknown||s->rings.error)return 0;
    struct pmce_state*p=(void*)(uintptr_t)s->parent;
    return p->transport==(uintptr_t)s&&p->owner==s->owner&&p->opening==s->opening&&p->power==s->power&&p->base==s->base&&
        p->complete==1&&!p->pending&&pgcd_equal(p->digest,s->parent_digest,32)&&pmce_live(p);
}
static inline int pmct_begin(struct pmct_state*s,struct pmce_state*p)
{
    if(!s||!p||!pwmc_zero(s,sizeof(*s))||p->transport||!pmce_current(p))return 0;
    struct pmwa_state*w=(void*)(uintptr_t)p->wlan;struct pmsn_state*a=(void*)(uintptr_t)w->auth;
    struct pmrf_state*f=(void*)(uintptr_t)w->service;struct pmsg_state*g=(void*)(uintptr_t)f->glink;struct pmsx_state*x=(void*)(uintptr_t)g->channel;
    const uint64_t at[]={(uintptr_t)p,p->memory,p->smmu,p->smmu_records,p->wlan,(uintptr_t)f,f->grant,f->nv,f->glink,g->channel,x->negotiation,x->smem,x->allocation,(uintptr_t)a,a->records,a->copy,a->segments};
    const uint64_t bytes[]={sizeof(*p),sizeof(struct pcdm_state),sizeof(struct pmws_state),sizeof(struct pmws_delivery)*PWSU_READS,sizeof(*w),sizeof(*f),sizeof(struct pmtf_state),sizeof(struct pnnv_state),sizeof(*g),sizeof(*x),sizeof(struct pmsy_state),sizeof(struct pmsq_state),sizeof(struct pmsa_state),sizeof(*a),sizeof(struct pmsn_delivery)*PMSN_RECORDS,sizeof(struct pmlc_copy),sizeof(struct pmsf_segment)*PMIM_SEGMENTS};
    if(!pmsn_child(a,(uintptr_t)s,sizeof(*s)))return 0;
    for(unsigned n=0;n<17;n++)if(!pwea_disjoint((uintptr_t)s,sizeof(*s),at[n],bytes[n]))return 0;
    for(unsigned n=0;n<PWDM_BYTES/4096;n++)if(p->zero[n].cache.line_bytes!=64)return 0;
    s->parent=(uintptr_t)p;s->owner=p->owner;s->opening=p->opening;s->power=p->power;s->base=p->base;s->attempted=1;
    pgcd_copy(s->parent_digest,p->digest,32);
    if(pwcr_begin(&s->rings,&p->init,64)!=1)return pmct_fail(s,1),0;
    s->ready=1;p->transport=(uintptr_t)s;return pmct_live(s);
}
static inline int pmct_record(struct pmct_state*s,unsigned kind)
{
    if(!pmct_live(s)||s->operations==PMCT_OPERATIONS)return 0;
    for(unsigned n=0;n<sizeof(s->io);n++)((uint8_t*)&s->io)[n]=0;
    s->io.kind=kind;s->io.unknown=1;s->operations++;return 1;
}
static inline int pmct_finish(struct pmct_state*s)
{
    if(!pmct_live(s))return 0;s->io.complete=1;s->io.unknown=0;
    struct pwfi_sha256 h;pwfi_init(&h);for(unsigned n=0;n<32;n++)pwfi_byte(&h,s->history[n]);
    for(unsigned n=0;n<sizeof(s->io);n++)pwfi_byte(&h,((const uint8_t*)&s->io)[n]);pwfi_final(&h,s->history);return 1;
}
static inline int pmct_span(struct pmct_state*s,uint64_t at,unsigned bytes)
{return bytes&&at>=s->base+4096&&at-s->base<4096+PWDM_USABLE&&bytes<=4096+PWDM_USABLE-(at-s->base);}
static inline int pmct_at(struct pmct_state*s,uint64_t address,unsigned bytes,unsigned pass)
{
    if(pass>1||!pmct_span(s,address,bytes)||bytes>8192)return 0;
    uint64_t page=address&~UINT64_C(4095);unsigned n=0;
    for(;page<address+bytes;page+=4096,n++){
        if(n==3)return 0;struct pwmc_translation*t=&s->io.AT[pass][n];t->page=page;
        if(!pmct_live(s)||!pwmc_actual_translate(t)||!pwmc_translation_valid(t)||t->page!=page||!pmct_live(s))return 0;
    }return 1;
}
static inline int pmct_cache(struct pmct_state*s,uint64_t at,unsigned bytes,unsigned operation)
{
    if(!pmct_record(s,1)||!pmct_at(s,at,bytes,0)||!pccl_actual(at,bytes,operation,&s->io.cache)||
       !pccl_valid(&s->io.cache,at,bytes,operation)||!pmct_at(s,at,bytes,1)||!pmct_finish(s))return pmct_fail(s,2);
    return 1;
}
static inline int pmct_memory(struct pmct_state*s,uint64_t at,void*private,unsigned bytes,unsigned write)
{
    if(!pmct_record(s,2)||!pmct_at(s,at,bytes,0))return pmct_fail(s,3);
    struct pmct_memory*r=&s->io.memory;*r=(struct pmct_memory){at,bytes,write,0,0};
    if(!pmct_copy(at,private,bytes,write,r)||r->issued!=bytes||r->returned!=bytes||!pmct_at(s,at,bytes,1))return pmct_fail(s,3);
    pweh_digest(private,bytes,s->io.data);if(!pmct_finish(s))return pmct_fail(s,3);return 1;
}
static inline int pmct_mmio(struct pmct_state*s,uint64_t address,unsigned kind,uint32_t value,uint32_t*out)
{
    if(!pmct_record(s,3))return pmct_fail(s,4);struct pmce_delivery*r=&s->io.mmio;
    struct pmpn_state*p=(void*)(uintptr_t)s->power;struct pmni_command c={address,kind,value};uint64_t page=address&~UINT64_C(4095);
    r->attempted=r->unknown=1;
    if((kind!=PMNI_FULL_ORDER&&!pmpn_target(p,page,&r->target[0]))||!pmpn_arch(p,&r->opening)||!pmni_access(&r->opening,&c,&r->native)||
       (kind!=PMNI_FULL_ORDER&&!pmpn_target(p,page,&r->target[1]))||r->target[0].index!=r->target[1].index||!pmct_live(s))return pmct_fail(s,4);
    r->unknown=0;r->complete=1;if(out)*out=r->native.value;
    if(!pmct_finish(s))return pmct_fail(s,4);return 1;
}
static inline int pmct_publish(struct pmct_state*s,const struct pwcr_transfer*t)
{
    uint64_t ordinary=PWCE_BASE+4096*t->pipe+(t->receive?0x40:0x3c);
    uint64_t address=t->receive?ordinary:PWCR_SHADOW+4*t->pipe;uint32_t got=0;
    if(pmct_mmio(s,address,PMNI_WRITE,t->next,0)<0||pmct_mmio(s,0,PMNI_FULL_ORDER,0,0)<0||
       pmct_mmio(s,ordinary,PMNI_READ,0,&got)<0||got!=t->next||pwcr_publish(&s->rings,t,1)!=1)return pmct_fail(s,5);
    return 1;
}
/* One complete cache-line RX batch, or0 when there is no free batch. */
static inline int pmct_refill(struct pmct_state*s,unsigned pipe)
{
    if(!pmct_live(s)||s->busy)return -1;struct pwcr_transfer t;int next=pwcr_post_rx(&s->rings,pipe,&t);
    if(next<=0)return next;s->busy=1;
    if(pmct_cache(s,t.buffer,t.bytes,PWMK_INVALIDATE)<0||pmct_memory(s,t.descriptor,t.wire,64,1)<0||
       pmct_cache(s,t.descriptor,64,PWMK_CLEAN_INVALIDATE)<0||pmct_publish(s,&t)<0)return pmct_fail(s,6);
    s->posts+=4;s->busy=0;return 1;
}
static inline int pmct_reap(struct pmct_state*s,unsigned pipe)
{
    if(!pmct_live(s)||s->busy||pipe>=12||!s->rings.source[pipe].entries)return -1;
    s->busy=1;uint64_t rri=s->base+s->rings.layout.rri;
    if(pmct_cache(s,rri,64,PWMK_INVALIDATE)<0||pmct_memory(s,rri+4*pipe,s->scratch,4,0)<0)return pmct_fail(s,7);
    uint32_t index=(uint32_t)pwcr_get(s->scratch,4)&0xffffu;
    int count=pwcr_complete_tx(&s->rings,pipe,index);if(count<0)return pmct_fail(s,7);s->busy=0;return count;
}
static inline int pmct_send(struct pmct_state*s,unsigned pipe,unsigned bytes,unsigned token)
{
    if(!pmct_live(s)||s->busy||bytes>sizeof(s->send))return -1;struct pwcr_transfer t;
    int next=pwcr_send(&s->rings,pipe,bytes,token,&t);if(next<=0)return next;s->busy=1;
    if(pmct_memory(s,t.buffer,s->send,bytes,1)<0||pmct_cache(s,t.buffer,(bytes+63)&~63u,PWMK_CLEAN_INVALIDATE)<0||
       pmct_memory(s,t.descriptor,t.wire,16,1)<0||pmct_cache(s,t.descriptor&~UINT64_C(63),64,PWMK_CLEAN_INVALIDATE)<0||
       pmct_publish(s,&t)<0)return pmct_fail(s,8);
    s->sends++;s->busy=0;return 1;
}
static inline int pmct_receive(struct pmct_state*s,unsigned pipe)
{
    if(!pmct_live(s)||s->busy||s->frame_ready||pipe>=12)return -1;
    struct pwcr_ring*r=&s->rings.destination[pipe];if(!r->posted)return 0;s->busy=1;
    uint64_t at=s->base+s->rings.layout.pipe[pipe].destination+16u*r->read;
    if(pmct_cache(s,at&~UINT64_C(63),64,PWMK_INVALIDATE)<0||pmct_memory(s,at,s->scratch,16,0)<0)return pmct_fail(s,9);
    struct pwcr_transfer t;int next=pwcr_receive(&s->rings,pipe,s->scratch,&t);
    if(next<=0){s->busy=0;return next<0?pmct_fail(s,9):0;}
    if(t.bytes>sizeof(s->receive)||pmct_cache(s,t.buffer,(t.bytes+63)&~63u,PWMK_INVALIDATE)<0||
       pmct_memory(s,t.buffer,s->receive,t.bytes,0)<0||pwcr_consume_rx(&s->rings,&t,1)!=1)return pmct_fail(s,9);
    s->rx_pipe=pipe;s->rx_bytes=t.bytes;s->frame_ready=1;s->receives++;s->busy=0;return 1;
}
static inline int pmct_ack(struct pmct_state*s)
{if(!pmct_live(s)||s->busy||s->frame_ready!=1)return 0;s->frame_ready=0;s->rx_bytes=0;return 1;}
static inline int pmct_poll(struct pmct_state*s)
{
    if(!pmct_live(s)||s->busy)return -1;struct pmsc_owner*o=(void*)(uintptr_t)s->owner;
    if(o->last<s->next_poll)return 0;struct pmce_state*p=(void*)(uintptr_t)s->parent;
    struct pmwa_state*w=(void*)(uintptr_t)p->wlan;struct pmrf_state*f=(void*)(uintptr_t)w->service;
    if(polaris_rmtfs_poll(f->service)||!pmct_live(s))return pmct_fail(s,10);s->next_poll=o->last+192000;return 1;
}
#endif
#endif
