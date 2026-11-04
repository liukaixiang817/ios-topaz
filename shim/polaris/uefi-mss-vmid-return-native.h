/* Exact inverse permission transfers after this epoch's native shutdown and
 * resource retirement. Buffers remain resident. No target reads, freeing,
 * original-provider resumption, CPU restoration or service destruction. */
#ifndef POLARIS_UEFI_MSS_VMID_RETURN_NATIVE_H
#define POLARIS_UEFI_MSS_VMID_RETURN_NATIVE_H
#ifndef EFI_XNU_MSS_VMID_RETURN_NATIVE_AVAILABLE
#define EFI_XNU_MSS_VMID_RETURN_NATIVE_AVAILABLE 0
#endif
#include "uefi-mss-retirement-native.h"
#if EFI_XNU_MSS_VMID_RETURN_NATIVE_AVAILABLE
#if !EFI_XNU_MSS_RETIREMENT_NATIVE_AVAILABLE
#error Permission return requires actual native resource retirement
#endif
#define PMVB_ASSIGNMENTS 4u
struct pmvb_state {
    struct pmsn_assignment assignment[PMVB_ASSIGNMENTS];
    uint64_t retirement,owner,opening,shutdown,wlan,rmtfs,auth;
    uint32_t attempted,ready,unknown,error,pending,count,returned,complete;
    uint8_t digest[32];
};
#if defined(POLARIS_MSS_VMID_RETURN_SOFTWARE_PEER)
static int pmvb_cache(uint64_t,unsigned,struct pwmk_record*);
static int pmvb_round(struct pwma_registers*);
static int pmvb_affinity(uint64_t,int64_t*);
#else
static inline int pmvb_cache(uint64_t at,unsigned op,struct pwmk_record*r)
{return pwma_actual_cache_page((void*)(uintptr_t)at,op,r);}
static inline int pmvb_round(struct pwma_registers*r){pwma_actual_round(r);return 1;}
static inline int pmvb_affinity(uint64_t target,int64_t*raw){return pwrpc_actual_affinity(0,target,raw);}
#endif
static inline int pmvb_fail(struct pmvb_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;return 0;}
static inline int pmvb_live(struct pmvb_state*s)
{
    if(!s||s->ready!=1||s->unknown||s->error||s->count<3||s->count>PMVB_ASSIGNMENTS||s->returned>s->count)return 0;
    struct pmnr_state*r=(void*)(uintptr_t)s->retirement;struct pmnd_state*d=(void*)(uintptr_t)s->shutdown;
    return r->handback==(uintptr_t)s&&r->shutdown==s->shutdown&&r->owner==s->owner&&r->opening==s->opening&&
        r->complete==1&&r->phase==7&&!r->pending&&d->wlan==s->wlan&&d->auth==s->auth&&pmnr_live(r);
}
/* Descriptors and their16KiB protection-granule tails are never inspected by
 * any control-state hash, including interrupted/failed return transactions. */
static inline void pmvb_seal(struct pmvb_state*s,const void*out,size_t bytes,uint8_t digest[32])
{
    struct pwfi_sha256 h;pwfi_init(&h);uintptr_t first=(uintptr_t)out,last=first+bytes;
    for(size_t n=0;n<sizeof(*s);n++){
        if(n<sizeof(s->assignment)&&n%sizeof(struct pmsn_assignment)>=PMSN_ASSIGNMENT_RAW)continue;
        uintptr_t p=(uintptr_t)s+n;if(p>=first&&p<last)continue;pwfi_byte(&h,*(const uint8_t*)p);
    }pwfi_final(&h,digest);
}
static inline int pmvb_peers(struct pmvb_state*s,struct pmsn_assignment*q,unsigned phase)
{
    if(phase>PWMT_ROUNDS)return 0;struct pmsc_owner*o=(void*)(uintptr_t)s->owner;
    for(unsigned n=0;n<7;n++){
        struct pmsb_peer*p=&q->peer[phase][n];if(!pwmc_zero(p,sizeof(*p))||!pmvb_live(s))return 0;
        p->target=(n+1)*0x100;p->issued=1;uint8_t before[32],after[32],ob[32],oa[32];
        pmvb_seal(s,&p->raw,sizeof(p->raw),before);pmsc_seal(o,0,0,ob);int returned=pmvb_affinity(p->target,&p->raw);
        pmvb_seal(s,&p->raw,sizeof(p->raw),after);pmsc_seal(o,0,0,oa);
        if(returned!=1||p->raw!=1||!pgcd_equal(before,after,32)||!pgcd_equal(ob,oa,32)||!pmvb_live(s))return 0;p->returned=1;
    }return 1;
}
static inline int pmvb_at(struct pmvb_state*s,struct pwmc_translation*t,uint64_t page)
{t->page=page;return pmvb_live(s)&&pwmc_actual_translate(t)&&pwmc_translation_valid(t)&&t->page==page&&pmvb_live(s);}
static inline int pmvb_spec(struct pmvb_state*s,unsigned n,struct pwma_spec*out)
{
    if(!pmvb_live(s)||n>=s->count||!pwmc_zero(out,sizeof(*out)))return 0;
    struct pmwa_state*w=(void*)(uintptr_t)s->wlan;struct pmtf_state*t=(void*)(uintptr_t)s->rmtfs;
    struct pmsn_state*a=(void*)(uintptr_t)s->auth;const struct pmsn_assignment*grant;
    struct pwma_spec spec={.descriptor_pa=(uintptr_t)&s->assignment[n].page,.destinations=1,.destination={{PWMA_HLOS,PWMA_RWX}}};
    if(n<w->assignments){
        const struct pwfw_region*r=&w->client.region[n];grant=&w->assignment[n];
        if(r->secure>1||!r->bytes||(r->address&4095)||(r->bytes&4095)||r->address<w->base||
           r->address-w->base>=0x100000||r->bytes>0x100000-(r->address-w->base))return 0;
        spec.region_pa=r->address;spec.region_bytes=r->bytes;spec.sources=r->secure?2:3;
        spec.source[0]=PWMA_MSS_MSA;spec.source[1]=PWMA_WLAN;if(!r->secure)spec.source[2]=PWMA_WLAN_CE;
    }else if(n==w->assignments){
        grant=&t->assignment;spec.region_pa=t->base;spec.region_bytes=t->bytes;
        if(spec.region_bytes!=0x200000)return 0;spec.sources=2;spec.source[0]=PWMA_HLOS;spec.source[1]=PWMA_MSS_MSA;
    }else{
        grant=&a->assignment[3];const struct pmmn_native*m=(const void*)(uintptr_t)((struct pmsc_owner*)(uintptr_t)s->owner)->memory;
        spec.region_pa=m->memory.claim[0].requested;spec.region_bytes=m->memory.claim[0].bytes;
        if(spec.region_bytes!=0x7800000||(spec.region_pa&0xfffff))return 0;spec.sources=1;spec.source[0]=PWMA_MSS_MSA;
    }
    const struct pwmt_transaction*q=&grant->transaction;const struct pwma_spec*prior=&q->spec;
    if(grant->complete!=1||grant->unknown||grant->error||q->complete!=1||q->unknown||q->error||q->pending||
       prior->region_pa!=spec.region_pa||prior->region_bytes!=spec.region_bytes||prior->destinations!=spec.sources)return 0;
    for(unsigned j=0;j<spec.sources;j++)if(prior->destination[j].vmid!=spec.source[j]||prior->destination[j].permissions!=PWMA_RW)return 0;
    uint8_t hash[32];pweh_digest(grant,offsetof(struct pmsn_assignment,digest),hash);
    if(!pgcd_equal(hash,grant->digest,32))return 0;*out=spec;return 1;
}
static inline int pmvb_begin(struct pmvb_state*s,struct pmnr_state*r)
{
    if(!s||!r||((uintptr_t)s&4095)||!pwmc_zero(s,sizeof(*s))||r->handback||!pmnr_current(r))return 0;
    struct pmnd_state*d=(void*)(uintptr_t)r->shutdown;struct pmwa_state*w=(void*)(uintptr_t)d->wlan;
    struct pmsn_state*a=(void*)(uintptr_t)d->auth;struct pmrf_state*f=(void*)(uintptr_t)d->service;
    struct pmsx_state*x=(void*)(uintptr_t)d->channel;
    if(!w->assigned||w->assignments<1||w->assignments>2||w->assignments!=w->client.regions||!w->client.ready||w->pending||
       !pmsn_child(a,(uintptr_t)s,sizeof(*s)))return 0;
    const uint64_t at[]={(uintptr_t)r,(uintptr_t)d,d->records,d->wlan,d->service,d->glink,d->channel,d->smp,a->rmtfs,
        (uintptr_t)a,a->records,a->copy,a->segments,f->nv,x->smem,x->allocation};
    const uint64_t bytes[]={sizeof(*r),sizeof(*d),sizeof(struct pmnd_delivery)*PMND_RECORDS,sizeof(*w),sizeof(*f),
        sizeof(struct pmsg_state),sizeof(*x),sizeof(struct pmsy_state),sizeof(struct pmtf_state),sizeof(*a),
        sizeof(struct pmsn_delivery)*PMSN_RECORDS,sizeof(struct pmlc_copy),sizeof(struct pmsf_segment)*PMIM_SEGMENTS,
        sizeof(struct pnnv_state),sizeof(struct pmsq_state),sizeof(struct pmsa_state)};
    for(unsigned n=0;n<16;n++)if(!pwea_disjoint((uintptr_t)s,sizeof(*s),at[n],bytes[n]))return 0;
    s->retirement=(uintptr_t)r;s->owner=r->owner;s->opening=r->opening;s->shutdown=r->shutdown;
    s->wlan=d->wlan;s->rmtfs=a->rmtfs;s->auth=d->auth;s->count=w->assignments+2;s->attempted=s->ready=1;
    r->handback=(uintptr_t)s;return pmvb_live(s);
}
static inline int pmvb_current(struct pmvb_state*s)
{
    if(!pmvb_live(s)||s->complete!=1||s->pending||s->returned!=s->count||!pmnr_current((void*)(uintptr_t)s->retirement))return 0;
    uint8_t hash[32];pmvb_seal(s,s->digest,32,hash);return pgcd_equal(hash,s->digest,32)&&pmvb_live(s);
}
/* Each call returns one exact interval; previous returns survive a later
 * failure. The caller may not touch any returned target through this API. */
static inline int pmvb_step(struct pmvb_state*s)
{
    if(!pmvb_live(s)||s->pending)return 0;if(s->complete)return pmvb_current(s)?2:0;
    struct pmnr_state*r=(void*)(uintptr_t)s->retirement;struct pmsc_owner*o=(void*)(uintptr_t)s->owner;
    const struct pweh_result*h=(const void*)(uintptr_t)o->retained;unsigned n=s->returned;
    if(!pmnr_current(r))return pmvb_fail(s,1);
    if(n==s->count){s->complete=1;pmvb_seal(s,s->digest,32,s->digest);return pmvb_current(s)?2:pmvb_fail(s,1);}
    struct pmsn_assignment*q=&s->assignment[n];struct pwma_spec spec={0};
    if(!pwmc_zero(q,sizeof(*q))||!pmvb_spec(s,n,&spec))return pmvb_fail(s,1);
    q->attempted=q->unknown=1;s->pending=n+1;
    if(!pwea_core_check(h->input.early,&q->source[0],&h->map)||!pmnr_current(r)||!pmvb_peers(s,q,0)||
       pwmt_begin_profile(&q->transaction,&q->page,&spec,o->last,o->current.cpu.frequency,n+1==s->count?2:0)<0)return pmvb_fail(s,2);
    for(unsigned k=0;k<PWMT_EVENTS;k++){
        struct pwmt_command c;if(!pmvb_live(s))return pmvb_fail(s,3);
        int next=pwmt_next(&q->transaction,o->last,&c);if(next==PWMT_ZERO)break;if(next!=PWMT_IO)return pmvb_fail(s,3);
        if(!pmvb_at(s,&q->descriptor_AT[k],(uintptr_t)&q->page))return pmvb_fail(s,3);
        uint8_t before[32],after[32],ob[32],oa[32];int returned;
        if(c.operation==PWMT_SMC){
            q->response[k]=c.registers;if(!pmsc_mark_effect(o,PMSC_SECURE))return pmvb_fail(s,3);
            pmvb_seal(s,&q->response[k],sizeof(q->response[k]),before);pmsc_seal(o,0,0,ob);
            returned=pmvb_round(&q->response[k]);pmvb_seal(s,&q->response[k],sizeof(q->response[k]),after);pmsc_seal(o,0,0,oa);
        }else{
            unsigned op=c.operation==PWMT_CLEAN?PWMK_CLEAN_INVALIDATE:PWMK_INVALIDATE;
            pmvb_seal(s,&q->cache[k],sizeof(q->cache[k]),before);pmsc_seal(o,0,0,ob);
            returned=pmvb_cache((uintptr_t)&q->page,op,&q->cache[k]);pmvb_seal(s,&q->cache[k],sizeof(q->cache[k]),after);pmsc_seal(o,0,0,oa);
        }
        if(!pgcd_equal(before,after,32)||!pgcd_equal(ob,oa,32)||!pmnr_current(r)||!pmvb_live(s))return pmvb_fail(s,3);q->after[k]=o->current;
        if(pwmt_complete(&q->transaction,&c,o->last,returned,c.operation==PWMT_SMC?&q->response[k]:0,c.operation==PWMT_SMC?0:&q->cache[k])<0||
           (c.operation==PWMT_SMC&&!pmvb_peers(s,q,q->transaction.rounds)))return pmvb_fail(s,4);
    }
    if(q->transaction.complete!=1||q->transaction.unknown||q->transaction.error||q->transaction.pending||
       !pwea_core_check(h->input.early,&q->source[1],&h->map)||!pmnr_current(r)||!pmvb_live(s))return pmvb_fail(s,4);
    q->unknown=0;q->complete=1;pweh_digest(q,offsetof(struct pmsn_assignment,digest),q->digest);s->pending=0;s->returned++;return 1;
}
#endif
#endif
