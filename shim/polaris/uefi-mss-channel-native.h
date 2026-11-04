/* One native channel caller for this authenticated modem/allocation epoch.
 * Normal-NC accesses remain in the original continuous CPU0 world. This is
 * neither an XNU runtime handoff nor a negotiated SMP2P/GLINK connection. */
#ifndef POLARIS_UEFI_MSS_CHANNEL_NATIVE_H
#define POLARIS_UEFI_MSS_CHANNEL_NATIVE_H
#ifndef EFI_XNU_MSS_CHANNEL_NATIVE_AVAILABLE
#define EFI_XNU_MSS_CHANNEL_NATIVE_AVAILABLE 0
#endif
#ifndef EFI_XNU_MSS_SMP2P_NATIVE_AVAILABLE
#define EFI_XNU_MSS_SMP2P_NATIVE_AVAILABLE 0
#endif
#if EFI_XNU_MSS_CHANNEL_NATIVE_AVAILABLE
#if !EFI_XNU_MSS_AUTH_NATIVE_AVAILABLE || !EFI_XNU_MSS_SMEM_NATIVE_AVAILABLE || !EFI_XNU_MSS_SFPB_IO_AVAILABLE
#error Native channel requires actual modem authentication and locked allocations
#endif
#include "uefi-mss-auth-native.h"
#include "uefi-mss-smem-allocate.h"
struct pmsx_word {
    uint64_t address;uint32_t value,readback,attempted,issued,returned,complete;
    struct pmli_read node[2];struct pmni_translation AT[2];
};
struct pmsx_state {
    uint64_t auth,allocation,smem,owner,opening,negotiation;
    uint8_t auth_digest[32],allocation_digest[32],smem_digest[32];
    struct pmsa_item item[PMSA_ITEMS];
    uint32_t attempted,ready,unknown,error,pending,writes,rings,negotiated;
    struct pmsx_word word;struct pmsl_delivery ring[4];uint8_t history[32];
};
#if EFI_XNU_MSS_SMP2P_NATIVE_AVAILABLE
struct pmsy_state;
static inline int pmsy_current(struct pmsy_state*,struct pmsx_state*);
#endif
static inline int pmsx_negotiated(struct pmsx_state*s)
{
#if EFI_XNU_MSS_SMP2P_NATIVE_AVAILABLE
    return s->negotiated==1&&s->negotiation&&pmsy_current((void*)(uintptr_t)s->negotiation,s);
#else
    (void)s;return 0;
#endif
}
#if defined(POLARIS_MSS_CHANNEL_SOFTWARE_PEER)
static int pmsx_store(uint64_t,uint32_t,uint32_t*);
#else
static inline int pmsx_store(uint64_t at,uint32_t value,uint32_t*readback)
{return pmsa_store(at,value,readback);}
#endif
static inline int pmsx_fail(struct pmsx_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;return 0;}
static inline int pmsx_live(struct pmsx_state*s)
{
    if(!s||s->ready!=1||s->unknown||s->error)return 0;
    struct pmsn_state*a=(void*)(uintptr_t)s->auth;struct pmsa_state*m=(void*)(uintptr_t)s->allocation;
    struct pmsq_state*q=(void*)(uintptr_t)s->smem;
    return a->owner==s->owner&&a->opening==s->opening&&a->complete==1&&a->phase==PMSN_DONE&&
        a->assignments==PMSN_ASSIGNMENTS&&!a->pending&&pgcd_equal(a->digest,s->auth_digest,32)&&
        m->owner==s->owner&&m->opening==s->opening&&m->smem==s->smem&&m->complete==1&&!m->unknown&&!m->error&&!m->pending&&
        pgcd_equal(m->digest,s->allocation_digest,32)&&pgcd_equal(m->item,s->item,sizeof(s->item))&&
        q->channel==(uintptr_t)s&&q->owner==s->owner&&q->opening==s->opening&&q->complete==1&&
        pgcd_equal(q->binding_digest,s->smem_digest,32)&&pgcd_equal(q->pass[1].cache,
            (const void*)(uintptr_t)(q->image+PWFC_CACHE_RVA),PWFC_CACHE_BYTES)&&pmsq_live(q)&&pmsn_live(a);
}
static inline int pmsx_begin(struct pmsx_state*s,struct pmsn_state*a,struct pmsa_state*m)
{
    if(!s||!a||!m||!pwmc_zero(s,sizeof(*s))||!pmsn_current(a)||!pmsa_current(m)||a->owner!=m->owner||a->opening!=m->opening)return 0;
    struct pmsq_state*q=(void*)(uintptr_t)m->smem;if(q->channel||!pmsn_child(a,(uintptr_t)s,sizeof(*s)))return 0;
    const uint64_t at[]={(uintptr_t)a,a->records,a->copy,a->segments,(uintptr_t)m,(uintptr_t)q,m->lock};
    const uint64_t bytes[]={sizeof(*a),sizeof(struct pmsn_delivery)*PMSN_RECORDS,sizeof(struct pmlc_copy),sizeof(struct pmsf_segment)*PMIM_SEGMENTS,sizeof(*m),sizeof(*q),sizeof(struct pmsl_lock)};
    for(unsigned n=0;n<7;n++)if(!pwea_disjoint((uintptr_t)s,sizeof(*s),at[n],bytes[n]))return 0;
    s->auth=(uintptr_t)a;s->allocation=(uintptr_t)m;s->smem=(uintptr_t)q;s->owner=a->owner;s->opening=a->opening;
    pgcd_copy(s->auth_digest,a->digest,32);pgcd_copy(s->allocation_digest,m->digest,32);pgcd_copy(s->smem_digest,q->binding_digest,32);
    pgcd_copy(s->item,m->item,sizeof(s->item));s->attempted=s->ready=1;q->channel=(uintptr_t)s;
    return pmsx_live(s)?1:pmsx_fail(s,1);
}
static inline int pmsx_at(struct pmsx_state*s,struct pmni_translation*t,uint64_t page)
{
    t->page=page;if(!pmsx_live(s)||!pmni_translate(t)||t->page!=page)return 0;
    return t->read_issued==1&&t->read_returned==1&&t->write_issued==1&&t->write_returned==1&&
        t->restore_issued==1&&t->restore_returned==1&&t->saved==t->restored&&
        t->read_par==(UINT64_C(0x4400000000000b00)|page)&&t->write_par==t->read_par&&pmsx_live(s);
}
static inline void pmsx_history(struct pmsx_state*s,const void*record,size_t bytes)
{
    struct pwfi_sha256 h;pwfi_init(&h);for(unsigned n=0;n<32;n++)pwfi_byte(&h,s->history[n]);
    for(size_t n=0;n<bytes;n++)pwfi_byte(&h,((const uint8_t*)record)[n]);pwfi_final(&h,s->history);
}
/* Only APPS-owned words: outbound SMP2P, GLINK TX producer/RX consumer,
 * and TX FIFO. Remote indices, RX payloads and allocation metadata refuse.
 * GLINK words additionally require the forthcoming actual negotiation result. */
static inline int pmsx_write(struct pmsx_state*s,unsigned item,unsigned offset,uint32_t value)
{
    if(!s||s->pending||s->writes==65536||item>=PMSA_ITEMS||(offset&3))return 0;
    if(!pmsx_live(s))return pmsx_fail(s,3);
    const struct pmsa_item*i=&s->item[item];
    if(offset>i->bytes||4>i->bytes-offset||(item&&!pmsx_negotiated(s))||(item==1&&offset!=4&&offset!=8))return 0;
    struct pmsx_word*r=&s->word;for(unsigned n=0;n<sizeof(*r);n++)((uint8_t*)r)[n]=0;
    r->address=PMSQ_BASE+i->data+offset;r->value=value;r->attempted=1;s->pending=1;
    struct pmsq_state*q=(void*)(uintptr_t)s->smem;struct pmsc_owner*o=(void*)(uintptr_t)s->owner;uint64_t page=r->address&~UINT64_C(4095);
    if(!pmsq_target(q,&r->node[0],page)||!pmsx_at(s,&r->AT[0],page)||!pmsc_mark_effect(o,PMSC_REMOTE))goto fail;
    pmsq_order();r->issued=1;
    if(!pmsx_store(r->address,value,&r->readback)||r->readback!=value)goto fail;
    r->returned=1;pmsq_order();
    if(!pmsx_at(s,&r->AT[1],page)||!pmsq_target(q,&r->node[1],page)||!pmli_read_equal(&r->node[0],&r->node[1])||!pmsx_live(s))goto fail;
    r->complete=1;s->writes++;s->pending=0;pmsx_history(s,r,sizeof(*r));return 1;
fail:return pmsx_fail(s,2);
}
static inline const uint8_t*pmsx_read(struct pmsx_state*s,unsigned offset,unsigned bytes)
{
    if(!s||s->pending)return 0;
    if(!pmsx_live(s)){pmsx_fail(s,3);return 0;}
    const uint8_t*raw=pmsq_read((void*)(uintptr_t)s->smem,offset,bytes);
    if(!raw||!pmsx_live(s)){pmsx_fail(s,3);return 0;}return raw;
}
static inline int pmsx_ring(struct pmsx_state*s,unsigned glink)
{
    if(!s||s->pending||s->rings==65536||glink>1||(glink&&!pmsx_negotiated(s)))return 0;
    if(!pmsx_live(s))return pmsx_fail(s,3);
    struct pmsn_state*a=(void*)(uintptr_t)s->auth;struct pmpn_state*p=(void*)(uintptr_t)a->power;
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;
    for(unsigned n=0;n<sizeof(s->ring);n++)((uint8_t*)s->ring)[n]=0;s->pending=2;
    for(unsigned n=0;n<4;n++){
        struct pmsl_delivery*r=&s->ring[n];unsigned memory=n==1||n==2;
        struct pmni_command c={memory?PMS_DOORBELL:0,memory?PMNI_WRITE:PMNI_FULL_ORDER,n==1?(glink?0x1000:PMS_DOORBELL_MASK):0};
        if(!pmsx_live(s)||(memory&&!pmpn_target(p,PMS_DOORBELL&~UINT64_C(4095),&r->target[0]))||!pmpn_arch(p,&r->opening)||
           (memory&&!pmsc_mark_effect(o,PMSC_REMOTE))||!pmni_access(&r->opening,&c,&r->native)||
           (memory&&(!pmpn_target(p,PMS_DOORBELL&~UINT64_C(4095),&r->target[1])||r->target[0].index!=r->target[1].index))||
           !pmsx_live(s))return pmsx_fail(s,4);
    }
    s->rings++;s->pending=0;pmsx_history(s,s->ring,sizeof(s->ring));return 1;
}
#if EFI_XNU_MSS_SMP2P_NATIVE_AVAILABLE
#include "uefi-mss-smp2p-native.h"
#endif
#endif
#endif
