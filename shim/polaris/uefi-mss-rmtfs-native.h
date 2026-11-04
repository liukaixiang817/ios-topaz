/* Continuous RMTFS client1 memory grant. Exactly the retained inner2MiB,
 * excluding both guards. No NV input, address publication, service registration,
 * handback or release is implied by a secure return. */
#ifndef POLARIS_UEFI_MSS_RMTFS_NATIVE_H
#define POLARIS_UEFI_MSS_RMTFS_NATIVE_H
#include "uefi-mss-auth-native.h"
#ifndef EFI_XNU_MSS_RMTFS_NATIVE_AVAILABLE
#define EFI_XNU_MSS_RMTFS_NATIVE_AVAILABLE 0
#endif
#if EFI_XNU_MSS_RMTFS_NATIVE_AVAILABLE
#if !EFI_XNU_MSS_AUTH_NATIVE_AVAILABLE
#error Native RMTFS requires the continuous authenticated MSS owner
#endif
struct pmtf_zero {
    struct pwmc_translation AT[2];struct pwmk_record cache;
    uint32_t issued,returned,complete,reserved;
};
struct pmtf_state {
    struct pmsn_assignment assignment;
    uint64_t auth,owner,opening,base,bytes;
    uint8_t auth_digest[32];struct pmtf_zero zero[512];
    uint32_t attempted,ready,unknown,error,pending,pages,complete,reserved;
    uint8_t digest[32];
    uint64_t service; /* Later unique consumer, excluded from grant seal. */
};
#if defined(POLARIS_MSS_RMTFS_SOFTWARE_PEER)
static int pmtf_write_zero(uint64_t,struct pmtf_zero*);
static int pmtf_cache_page(uint64_t,unsigned,struct pwmk_record*);
static int pmtf_round(struct pwma_registers*);
static int pmtf_affinity(uint64_t,int64_t*);
#else
static inline int pmtf_write_zero(uint64_t at,struct pmtf_zero*z)
{
    for(unsigned n=0;n<512;n++){volatile uint64_t*p=(void*)(uintptr_t)(at+n*8);
        z->issued++;*p=0;if(*p)return 0;z->returned++;
    }return 1;
}
static inline int pmtf_cache_page(uint64_t at,unsigned op,struct pwmk_record*r)
{return pwma_actual_cache_page((void*)(uintptr_t)at,op,r);}
static inline int pmtf_round(struct pwma_registers*r){pwma_actual_round(r);return 1;}
static inline int pmtf_affinity(uint64_t target,int64_t*raw){return pwrpc_actual_affinity(0,target,raw);}
#endif
static inline int pmtf_fail(struct pmtf_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;return 0;}
static inline int pmtf_live(struct pmtf_state*s)
{
    if(!s||s->ready!=1||s->unknown||s->error)return 0;
    struct pmsn_state*a=(void*)(uintptr_t)s->auth;struct pmsc_owner*o=(void*)(uintptr_t)s->owner;
    const struct pweh_result*h=(const void*)(uintptr_t)o->retained;const struct pwea_claim*q=&h->input.early->memory.claim[1];
    return a->rmtfs==(uintptr_t)s&&a->owner==s->owner&&a->opening==s->opening&&a->complete==1&&a->phase==PMSN_DONE&&!a->pending&&
        pgcd_equal(a->digest,s->auth_digest,32)&&q->retained==1&&q->bytes==0x202000&&q->pages==514&&
        q->exposed==s->base&&q->exposed_bytes==s->bytes&&s->bytes==0x200000&&s->base==q->requested+4096&&pmsn_live(a);
}
/* Never hash/read an in-flight descriptor or its protection-granule tail. */
static inline void pmtf_seal(struct pmtf_state*s,const void*out,size_t bytes,uint8_t digest[32])
{
    struct pwfi_sha256 h;pwfi_init(&h);uintptr_t from=(uintptr_t)out,end=from+bytes;
    for(size_t n=0;n<sizeof(*s);n++){
        if((n>=PMSN_ASSIGNMENT_RAW&&n<sizeof(struct pmsn_assignment))||
           (n>=offsetof(struct pmtf_state,service)&&n<offsetof(struct pmtf_state,service)+8))continue;
        uintptr_t p=(uintptr_t)s+n;if(p>=from&&p<end)continue;pwfi_byte(&h,*(const uint8_t*)p);
    }pwfi_final(&h,digest);
}
static inline int pmtf_begin(struct pmtf_state*s,struct pmsn_state*a)
{
    if(!s||!a||((uintptr_t)s&4095)||!pwmc_zero(s,sizeof(*s))||a->rmtfs||!pmsn_current(a)||!pmsn_child(a,(uintptr_t)s,sizeof(*s)))return 0;
    const uint64_t at[]={(uintptr_t)a,a->records,a->copy,a->segments};
    const uint64_t bytes[]={sizeof(*a),sizeof(struct pmsn_delivery)*PMSN_RECORDS,sizeof(struct pmlc_copy),sizeof(struct pmsf_segment)*PMIM_SEGMENTS};
    for(unsigned n=0;n<4;n++)if(!pwea_disjoint((uintptr_t)s,sizeof(*s),at[n],bytes[n]))return 0;
    struct pmsc_owner*o=(void*)(uintptr_t)a->owner;const struct pweh_result*h=(const void*)(uintptr_t)o->retained;
    const struct pwea_claim*q=&h->input.early->memory.claim[1];
    if(!polaris_efi_range_owned(h->map.data,h->map.map.bytes,h->map.map.stride,q->requested,q->bytes,2))return 0;
    s->auth=(uintptr_t)a;s->owner=a->owner;s->opening=a->opening;s->base=q->exposed;s->bytes=q->exposed_bytes;
    pgcd_copy(s->auth_digest,a->digest,32);s->attempted=s->ready=1;a->rmtfs=(uintptr_t)s;return pmtf_live(s);
}
static inline int pmtf_at(struct pmtf_state*s,struct pwmc_translation*t,uint64_t page)
{t->page=page;return pmtf_live(s)&&pwmc_actual_translate(t)&&pwmc_translation_valid(t)&&t->page==page&&pmtf_live(s);}
static inline int pmtf_peers(struct pmtf_state*s,unsigned phase)
{
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;struct pmsn_assignment*q=&s->assignment;if(phase>PWMT_ROUNDS)return 0;
    for(unsigned n=0;n<7;n++){
        struct pmsb_peer*p=&q->peer[phase][n];if(!pwmc_zero(p,sizeof(*p))||!pmtf_live(s))return 0;
        p->target=(n+1)*0x100;p->issued=1;uint8_t before[32],after[32],ob[32],oa[32];
        pmtf_seal(s,&p->raw,sizeof(p->raw),before);pmsc_seal(o,0,0,ob);int returned=pmtf_affinity(p->target,&p->raw);
        pmtf_seal(s,&p->raw,sizeof(p->raw),after);pmsc_seal(o,0,0,oa);
        if(returned!=1||!pgcd_equal(before,after,32)||!pgcd_equal(ob,oa,32)||p->raw!=1||!pmtf_live(s))return 0;p->returned=1;
    }return 1;
}
/* One whole page per step so the parent retains scheduling control. Full
 * write/readback then CIVAC precedes sharing; guards are never touched. */
static inline int pmtf_current(struct pmtf_state*s);
static inline int pmtf_step(struct pmtf_state*s)
{
    if(!pmtf_live(s)||s->pending)return 0;if(s->complete)return pmtf_current(s)?2:0;
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;const struct pweh_result*h=(const void*)(uintptr_t)o->retained;
    if(s->pages<512){
        struct pmtf_zero*z=&s->zero[s->pages];uint64_t at=s->base+4096*s->pages;s->pending=1;
        if(!pmtf_at(s,&z->AT[0],at)||!pmtf_write_zero(at,z)||z->issued!=512||z->returned!=512||!pmtf_live(s)||
           !pmtf_cache_page(at,PWMK_CLEAN_INVALIDATE,&z->cache)||!pwmk_record_valid(&z->cache,at,PWMK_CLEAN_INVALIDATE)||
           !pmtf_at(s,&z->AT[1],at))return pmtf_fail(s,1);
        z->complete=1;s->pages++;s->pending=0;return 1;
    }
    struct pmsn_assignment*q=&s->assignment;if(q->attempted)return pmtf_fail(s,2);q->attempted=q->unknown=1;s->pending=2;
    struct pwma_spec spec={.descriptor_pa=(uintptr_t)&q->page,.region_pa=s->base,.region_bytes=s->bytes,
        .sources=1,.source={PWMA_HLOS},.destinations=2,.destination={{PWMA_HLOS,PWMA_RW},{PWMA_MSS_MSA,PWMA_RW}}};
    if(!pmsn_current((void*)(uintptr_t)s->auth)||!pwea_core_check(h->input.early,&q->source[0],&h->map)||!pmtf_live(s)||!pmtf_peers(s,0)||
       pwmt_begin(&q->transaction,&q->page,&spec,o->last,o->current.cpu.frequency)<0)return pmtf_fail(s,2);
    for(unsigned k=0;k<PWMT_EVENTS;k++){
        struct pwmt_command c;if(!pmtf_live(s))return pmtf_fail(s,2);
        int next=pwmt_next(&q->transaction,o->last,&c);if(next==PWMT_ZERO)break;if(next!=PWMT_IO)return pmtf_fail(s,2);
        if(!pmtf_at(s,&q->descriptor_AT[k],(uintptr_t)&q->page))return pmtf_fail(s,3);
        uint8_t before[32],after[32],ob[32],oa[32];int returned;
        if(c.operation==PWMT_SMC){
            q->response[k]=c.registers;if(!pmsc_mark_effect(o,PMSC_SECURE))return pmtf_fail(s,3);
            pmtf_seal(s,&q->response[k],sizeof(q->response[k]),before);pmsc_seal(o,0,0,ob);
            returned=pmtf_round(&q->response[k]);
            pmtf_seal(s,&q->response[k],sizeof(q->response[k]),after);pmsc_seal(o,0,0,oa);
        }else{
            unsigned op=c.operation==PWMT_CLEAN?PWMK_CLEAN_INVALIDATE:PWMK_INVALIDATE;
            pmtf_seal(s,&q->cache[k],sizeof(q->cache[k]),before);pmsc_seal(o,0,0,ob);
            returned=pmtf_cache_page((uintptr_t)&q->page,op,&q->cache[k]);
            pmtf_seal(s,&q->cache[k],sizeof(q->cache[k]),after);pmsc_seal(o,0,0,oa);
        }
        if(!pgcd_equal(before,after,32)||!pgcd_equal(ob,oa,32)||!pmtf_live(s)||!pmsn_current((void*)(uintptr_t)s->auth))return pmtf_fail(s,3);q->after[k]=o->current;
        if(pwmt_complete(&q->transaction,&c,o->last,returned,c.operation==PWMT_SMC?&q->response[k]:0,c.operation==PWMT_SMC?0:&q->cache[k])<0||
           (c.operation==PWMT_SMC&&!pmtf_peers(s,q->transaction.rounds)))return pmtf_fail(s,4);
    }
    if(q->transaction.complete!=1||q->transaction.unknown||q->transaction.error||q->transaction.pending||
       !pwea_core_check(h->input.early,&q->source[1],&h->map)||!pmsn_current((void*)(uintptr_t)s->auth)||!pmtf_live(s))return pmtf_fail(s,5);
    q->unknown=0;q->complete=1;pweh_digest(q,offsetof(struct pmsn_assignment,digest),q->digest);
    s->pending=0;s->complete=1;pmtf_seal(s,s->digest,32,s->digest);return 2;
}
static inline int pmtf_current(struct pmtf_state*s)
{
    if(!pmtf_live(s)||s->complete!=1||s->pages!=512||s->pending||s->assignment.complete!=1||s->assignment.unknown||
       s->assignment.error||s->assignment.transaction.complete!=1||s->assignment.transaction.unknown||s->assignment.transaction.pending)return 0;
    uint8_t hash[32];pmtf_seal(s,s->digest,32,hash);return pgcd_equal(hash,s->digest,32)&&pmsn_current((void*)(uintptr_t)s->auth)&&pmtf_live(s);
}
#endif
#endif
