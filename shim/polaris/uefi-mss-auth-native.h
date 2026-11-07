/* Continuous own MSS metadata/modem authentication after actual native MBA
 * readiness. Five exact MP_ASSIGN transitions, actual staged metadata and
 * actual full-bank copy precede RMB publication. Default OFF/unregistered.
 * No provider, new interrupt interval, automatic cleanup, target read after
 * exclusive assignment, memory free or WLAN/DMA retirement claim. */
#ifndef POLARIS_UEFI_MSS_AUTH_NATIVE_H
#define POLARIS_UEFI_MSS_AUTH_NATIVE_H
#ifndef EFI_XNU_MSS_AUTH_NATIVE_AVAILABLE
#define EFI_XNU_MSS_AUTH_NATIVE_AVAILABLE 0
#endif
#if EFI_XNU_MSS_AUTH_NATIVE_AVAILABLE
#if !EFI_XNU_MSS_BOOT_NATIVE_AVAILABLE || !EFI_XNU_MSS_MODEM_COPY_AVAILABLE || !EFI_XNU_MSS_MODEM_IO_AVAILABLE
#error Native MSS authentication requires native MBA, actual copy and typed modem IO
#endif
#include "uefi-mss-boot-native.h"
#include "uefi-mss-modem-copy.h"
#define PMSN_ASSIGNMENTS 5u
#define PMSN_RECORDS (PMMD_EVENTS+PMIM_EVENTS)
enum pmsn_phase {PMSN_MD_OUT=1,PMSN_MD_IO,PMSN_MD_BACK,PMSN_MODEM_SHARE,
    PMSN_COPY,PMSN_PUBLISH,PMSN_MODEM_EXCLUSIVE,PMSN_AUTH,PMSN_MBA_BACK,PMSN_DONE};
struct pmsn_assignment {
    union {struct {
    struct pwmt_transaction transaction;struct pwea_core source[2];
    struct pwmc_translation descriptor_AT[PWMT_EVENTS];
    struct pwma_registers response[PWMT_EVENTS];struct pwmk_record cache[PWMT_EVENTS];
    struct pgcd_arch after[PWMT_EVENTS];struct pmsb_peer peer[PWMT_ROUNDS+1][7];
    uint32_t attempted,unknown,error,complete;uint8_t digest[32];
    };uint8_t control_granule[16384];};
    /* Separate16KiB granule also permits host protection of the in-flight
     *4KiB descriptor without covering control records. The tail is excluded
     * from ALL seals/export while permission/continuation is uncertain. */
    struct pwma_page page;uint8_t descriptor_tail[12288];
};
#define PMSN_ASSIGNMENT_RAW offsetof(struct pmsn_assignment,page)
_Static_assert(PMSN_ASSIGNMENT_RAW%16384==0,"independent descriptor protection granule");
_Static_assert(sizeof(struct pmsn_assignment)==32768,"separate descriptor slots");
struct pmsn_delivery {
    union {struct pmmd_command metadata;struct pmim_command modem;} command;
    struct pmrg_target target[2];struct pmni_arch opening;struct pmni_result native;
    uint32_t kind,attempted,unknown,error,complete,reserved;uint8_t digest[32];
};
struct pmsn_state {
    uint64_t boot,owner,power,clocks,records,copy,segments,opening;
    uint8_t segments_digest[32];struct pmmd_metadata metadata;struct pmim_auth modem;
    struct pmsn_assignment assignment[PMSN_ASSIGNMENTS];
    uint32_t attempted,ready,unknown,error,phase,pending,deliveries,assignments,complete,reserved;
#if EFI_XNU_WIFI_NATIVE_FAULT_HOLD
    uint32_t observe_stage,observe_kind;
    uint64_t observe_address,observe_value;
#endif
    uint8_t records_digest[32],copy_digest[32],digest[32];
    uint64_t rmtfs; /* One later shared-memory owner, excluded from auth seal. */
};
#if EFI_XNU_WIFI_NATIVE_FAULT_HOLD
/* Diagnostic writes stay in this owned control record. The existing RMB
 * access, validation, completion and absolute deadline remain unchanged. */
static int pmsn_observe(struct pmsn_state*);
#define PMSN_TRACE_IO(s,where,op,at,val) do{(s)->observe_stage=(where);(s)->observe_kind=(op); \
    (s)->observe_address=(at);(s)->observe_value=(val);if(!pmsn_observe(s))return pmsn_fail(s,3);}while(0)
#else
#define PMSN_TRACE_IO(s,where,op,at,val) do{}while(0)
#endif
#if defined(POLARIS_MSS_AUTH_SOFTWARE_PEER)
static int pmsn_cache(struct pwma_page*,unsigned,struct pwmk_record*);
static int pmsn_round(struct pwma_registers*);
static int pmsn_affinity(uint64_t,int64_t*);
#else
static inline int pmsn_cache(struct pwma_page*p,unsigned op,struct pwmk_record*r){return pwma_actual_cache_page(p,op,r);}
static inline int pmsn_round(struct pwma_registers*r){pwma_actual_round(r);return 1;}
static inline int pmsn_affinity(uint64_t target,int64_t*raw){return pwrpc_actual_affinity(0,target,raw);}
#endif
static inline int pmsn_fail(struct pmsn_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;if(s->power)pmpn_fail((void*)(uintptr_t)s->power,12);return 0;}
static inline int pmsn_live(struct pmsn_state*s)
{
    if(!s||s->ready!=1||s->unknown||s->error||s->assignments>PMSN_ASSIGNMENTS||s->deliveries>PMSN_RECORDS)return 0;
    struct pmbn_state*b=(void*)(uintptr_t)s->boot;struct pmsc_owner*o=(void*)(uintptr_t)s->owner;
    return b->owner==s->owner&&b->power==s->power&&b->clocks==s->clocks&&b->opening==s->opening&&
        b->complete==1&&o->opening==s->opening&&(o->effects&(PMSC_POWER|PMSC_REMOTE))==(PMSC_POWER|PMSC_REMOTE)&&pmbn_live(b);
}
static inline void pmsn_hash_transform(struct pwfi_sha256 *s,const uint8_t *p)
{
    static const uint32_t k[64]={
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    uint32_t w[64];
    for(unsigned i=0;i<16;i++)w[i]=(uint32_t)p[4*i]<<24|(uint32_t)p[4*i+1]<<16|(uint32_t)p[4*i+2]<<8|p[4*i+3];
    for(unsigned i=16;i<64;i++){
        uint32_t a=w[i-15],b=w[i-2];
        w[i]=w[i-16]+(pwfi_ror(a,7)^pwfi_ror(a,18)^(a>>3))+w[i-7]+(pwfi_ror(b,17)^pwfi_ror(b,19)^(b>>10));
    }
    uint32_t a=s->h[0],b=s->h[1],c=s->h[2],d=s->h[3],e=s->h[4],f=s->h[5],g=s->h[6],h=s->h[7];
    /* Eight rounds rotate register names instead of moving all eight working
     * words each round. Scalar integer operations only; same SHA256 rounds. */
#define PMSN_SHA_ROUND(A,B,C,D,E,F,G,H,I) do { \
    uint32_t t=(H)+(pwfi_ror((E),6)^pwfi_ror((E),11)^pwfi_ror((E),25))+(((E)&(F))^(~(E)&(G)))+k[(I)]+w[(I)]; \
    uint32_t u=(pwfi_ror((A),2)^pwfi_ror((A),13)^pwfi_ror((A),22))+(((A)&(B))^((A)&(C))^((B)&(C))); \
    (D)+=t;(H)=t+u; \
} while(0)
    for(unsigned i=0;i<64;i+=8){
        PMSN_SHA_ROUND(a,b,c,d,e,f,g,h,i);
        PMSN_SHA_ROUND(h,a,b,c,d,e,f,g,i+1);
        PMSN_SHA_ROUND(g,h,a,b,c,d,e,f,i+2);
        PMSN_SHA_ROUND(f,g,h,a,b,c,d,e,i+3);
        PMSN_SHA_ROUND(e,f,g,h,a,b,c,d,i+4);
        PMSN_SHA_ROUND(d,e,f,g,h,a,b,c,i+5);
        PMSN_SHA_ROUND(c,d,e,f,g,h,a,b,i+6);
        PMSN_SHA_ROUND(b,c,d,e,f,g,h,a,i+7);
    }
#undef PMSN_SHA_ROUND
    s->h[0]+=a;s->h[1]+=b;s->h[2]+=c;s->h[3]+=d;s->h[4]+=e;s->h[5]+=f;s->h[6]+=g;s->h[7]+=h;
}
/* Feed exactly the selected readable range, preserving SHA byte order while
 * processing full blocks directly. No read crosses a range boundary. */
static inline void pmsn_hash_bytes(struct pwfi_sha256*h,const uint8_t*p,size_t bytes)
{
    while(bytes&&h->used){pwfi_byte(h,*p++);bytes--;}
    while(bytes>=64){pmsn_hash_transform(h,p);h->bytes+=64;p+=64;bytes-=64;}
    while(bytes){pwfi_byte(h,*p++);bytes--;}
}
static inline void pmsn_hash_range(struct pwfi_sha256*h,uintptr_t first,uintptr_t last,uintptr_t a,uintptr_t b)
{
    if(a<b&&a<last&&first<b){
        uintptr_t left=a>first?a:first,right=b<last?b:last;
        pmsn_hash_bytes(h,(const void*)first,left-first);
        pmsn_hash_bytes(h,(const void*)right,last-right);
    }else pmsn_hash_bytes(h,(const void*)first,last-first);
}
/* Never touch any descriptor or its protection-granule tail, even after a
 * completed transition. Walk the same control spans directly instead of
 * checking every excluded byte against all five descriptor intervals. */
static inline void pmsn_seal(const struct pmsn_state*s,const void*out,size_t bytes,uint8_t digest[32])
{
    struct pwfi_sha256 hash;pwfi_init(&hash);uintptr_t a=(uintptr_t)out,b=a+bytes,cursor=(uintptr_t)s;
    for(unsigned k=0;k<PMSN_ASSIGNMENTS;k++){
        pmsn_hash_range(&hash,cursor,(uintptr_t)&s->assignment[k].page,a,b);
        cursor=(uintptr_t)(&s->assignment[k]+1);
    }
    pmsn_hash_range(&hash,cursor,(uintptr_t)&s->rmtfs,a,b);
    pmsn_hash_range(&hash,(uintptr_t)&s->rmtfs+sizeof(s->rmtfs),(uintptr_t)s+sizeof(*s),a,b);
    pwfi_final(&hash,digest);
}
/* The auth call sites also seal the whole CPU owner. Preserve its exact
 * output exclusion while avoiding byte-at-a-time input for complete blocks. */
static inline void pmsn_owner_seal(const struct pmsc_owner*o,const void*out,size_t bytes,uint8_t digest[32])
{
    struct pwfi_sha256 h;pwfi_init(&h);uintptr_t a=(uintptr_t)out;
    pmsn_hash_range(&h,(uintptr_t)o,(uintptr_t)o+sizeof(*o),a,a+bytes);pwfi_final(&h,digest);
}
static inline int pmsn_bound(struct pmsn_state*s)
{
    if(!pmsn_live(s)||!pmbn_current((void*)(uintptr_t)s->boot)||!pmsc_bound((void*)(uintptr_t)s->owner))return 0;
    uint8_t hash[32];pweh_digest((const void*)(uintptr_t)s->segments,PMIM_SEGMENTS*sizeof(struct pmsf_segment),hash);
    return pgcd_equal(hash,s->segments_digest,32)&&pmsn_live(s);
}
static inline int pmsn_child(struct pmsn_state*s,uint64_t at,uint64_t bytes)
{
    struct pmbn_state*b=(void*)(uintptr_t)s->boot;
    return pmbn_child(b,at,bytes)&&pwea_disjoint(at,bytes,(uintptr_t)b,sizeof(*b))&&
        pwea_disjoint(at,bytes,b->records,sizeof(struct pmbn_delivery)*PMBN_RECORDS);
}
static inline int pmsn_begin(struct pmsn_state*s,struct pmsn_delivery*r,struct pmlc_copy*copy,
    struct pmbn_state*b,const struct pmsf_segment segments[PMIM_SEGMENTS])
{
    if(!s||!r||!copy||!b||!segments||((uintptr_t)s&4095)||!pwmc_zero(s,sizeof(*s)))return 0;s->attempted=1;
    if(!pmbn_current(b))return 0;s->boot=(uintptr_t)b;s->owner=b->owner;s->power=b->power;s->clocks=b->clocks;s->opening=b->opening;
    const uint64_t at[]={(uintptr_t)s,(uintptr_t)r,(uintptr_t)copy,(uintptr_t)segments};
    const uint64_t bytes[]={sizeof(*s),sizeof(*r)*PMSN_RECORDS,sizeof(*copy),PMIM_SEGMENTS*sizeof(*segments)};
    for(unsigned n=0;n<4;n++){
        if(!pmsn_child(s,at[n],bytes[n]))return 0;
        for(unsigned j=0;j<n;j++)if(!pwea_disjoint(at[n],bytes[n],at[j],bytes[j]))return 0;
    }
    if(!pwmc_zero(r,bytes[1])||!pwmc_zero(copy,sizeof(*copy)))return 0;
    const struct pmsc_owner*o=(const void*)(uintptr_t)s->owner;const struct pmmn_native*m=(const void*)(uintptr_t)o->memory;
    const struct pmsb_result*mba=(const void*)(uintptr_t)o->mba;const struct pmsi_result*stage=(const void*)(uintptr_t)mba->stage;
    if(stage->asset[1].bytes!=8412||m->memory.claim[2].bytes!=12288||m->memory.claim[0].bytes!=0x7800000||
       stage->asset_count<27||stage->asset_count>32)return 0;
    for(unsigned n=256;n<PMSI_PAGES;n++)if(stage->page[n].complete!=1||stage->page[n].words_returned!=512||
       !pwmk_record_valid(&stage->page[n].cache,m->memory.claim[2].requested+4096*(n-256),PWMK_CLEAN_INVALIDATE))return 0;
    s->records=(uintptr_t)r;s->copy=(uintptr_t)copy;s->segments=(uintptr_t)segments;
    pweh_digest(segments,bytes[3],s->segments_digest);s->ready=1;s->phase=PMSN_MD_OUT;return pmsn_bound(s);
}
static inline int pmsn_peers(struct pmsn_state*s,struct pmsn_assignment*q,unsigned phase)
{
    if(phase>PWMT_ROUNDS)return 0;struct pmsc_owner*o=(void*)(uintptr_t)s->owner;
    for(unsigned n=0;n<7;n++){
        struct pmsb_peer*p=&q->peer[phase][n];if(!pwmc_zero(p,sizeof(*p))||!pmsn_live(s))return 0;
        p->target=(n+1)*0x100;p->issued=1;uint8_t before[32],after[32],owner_before[32],owner_after[32];
        pmsn_seal(s,&p->raw,sizeof(p->raw),before);pmsn_owner_seal(o,0,0,owner_before);
        int returned=pmsn_affinity(p->target,&p->raw);
        pmsn_seal(s,&p->raw,sizeof(p->raw),after);pmsn_owner_seal(o,0,0,owner_after);
        if(returned!=1||!pgcd_equal(before,after,32)||!pgcd_equal(owner_before,owner_after,32)||p->raw!=1||!pmsn_live(s))return 0;
        p->returned=1;
    }return 1;
}
/* Private exact-stage selector, never an arbitrary caller-supplied VMID or
 * range. A secure return means only the returned permission transaction;
 * allocations are retained and no target is read/cache-touched here. */
static inline int pmsn_secure(struct pmsn_state*s,unsigned index)
{
    static const unsigned phase[]={PMSN_MD_OUT,PMSN_MD_BACK,PMSN_MODEM_SHARE,PMSN_MODEM_EXCLUSIVE,PMSN_MBA_BACK};
    if(!s||index>=PMSN_ASSIGNMENTS||s->phase!=phase[index]||s->pending||s->assignments!=index||!pmsn_bound(s))return 0;
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;const struct pweh_result*h=(const void*)(uintptr_t)o->retained;
    const struct pmmn_native*m=(const void*)(uintptr_t)o->memory;struct pmsn_assignment*q=&s->assignment[index];
    if(!pwmc_zero(q,sizeof(*q)))return 0;q->attempted=q->unknown=1;
    if(index==1&&(s->metadata.phase!=2||s->metadata.pending||s->metadata.unknown||s->metadata.error||
        !s->metadata.authenticated_at||s->metadata.assignment_page!=(uintptr_t)&s->assignment[0].page))goto fail;
    if(index==2&&(s->metadata.phase!=3||s->metadata.pending||s->metadata.unknown||s->metadata.error||!s->metadata.returned_at))goto fail;
    if(index==3){
        struct pmlc_copy*copy=(void*)(uintptr_t)s->copy;
        if(s->modem.phase!=3||s->modem.pending||s->modem.unknown||s->modem.error||s->modem.segment!=PMIM_SEGMENTS||
           copy->auth!=(uintptr_t)&s->modem||copy->owner!=s->owner||copy->complete!=1||copy->unknown||copy->error||
           copy->segments!=PMIM_SEGMENTS||copy->pages!=PMLC_PAGES||!pmlc_bound(copy))goto fail;
        for(unsigned n=0;n<PMIM_SEGMENTS;n++)if(copy->segment[n].complete!=1||copy->segment[n].published!=1||
           !s->modem.publication[n]||s->modem.publication[n]<copy->segment[n].finished)goto fail;
        pweh_digest(copy,sizeof(*copy),s->copy_digest);
    }
    if(index==4&&(s->modem.phase!=5||s->modem.pending||s->modem.unknown||s->modem.error||!s->modem.authenticated_at||
        s->modem.exclusive_page!=(uintptr_t)&s->assignment[3].page))goto fail;
    unsigned claim=index==4?1:index>=2?0:2;const struct pwea_claim*target=&m->memory.claim[claim];
    struct pwma_spec spec={.descriptor_pa=(uintptr_t)&q->page,.region_pa=target->requested,.region_bytes=target->bytes,
        .sources=1,.source={PWMA_HLOS},.destinations=1,.destination={{PWMA_MSS_MSA,PWMA_RW}}};
    if(index==1||index==4){spec.source[0]=PWMA_MSS_MSA;spec.destination[0]=(struct pwma_destination){PWMA_HLOS,PWMA_RWX};}
    if(index==2){spec.destinations=2;spec.destination[0]=(struct pwma_destination){PWMA_HLOS,PWMA_RW};spec.destination[1]=(struct pwma_destination){PWMA_MSS_MSA,PWMA_RW};}
    if(index==3){spec.sources=2;spec.source[1]=PWMA_MSS_MSA;}
    if((claim==0&&target->bytes!=0x7800000)||(claim==1&&target->bytes!=0x100000)||(claim==2&&target->bytes!=12288)||
       !pwea_core_check(h->input.early,&q->source[0],&h->map)||!pmsn_bound(s))goto fail;
    s->pending=index+1;
    if(!pmsn_peers(s,q,0)||!pmsn_live(s)||pwmt_begin_profile(&q->transaction,&q->page,&spec,o->last,o->current.cpu.frequency,claim==0)<0)goto fail;
    for(unsigned k=0;k<PWMT_EVENTS;k++){
        struct pwmt_command command;if(!pmsn_live(s))goto fail;
        int next=pwmt_auth_next(&q->transaction,o->last,&command);if(next==PWMT_ZERO)break;if(next!=PWMT_IO)goto fail;
        struct pwmc_translation*t=&q->descriptor_AT[k];t->page=(uintptr_t)&q->page;
        if(!pwmc_actual_translate(t)||!pwmc_translation_valid(t)||t->page!=(uintptr_t)&q->page||!pmsn_live(s))goto fail;
        uint8_t before[32],after[32],owner_before[32],owner_after[32];int returned;
        if(command.operation==PWMT_SMC){
            q->response[k]=command.registers;if(!pmsc_mark_effect(o,PMSC_SECURE))goto fail;
            pmsn_seal(s,&q->response[k],sizeof(q->response[k]),before);pmsn_owner_seal(o,0,0,owner_before);
            returned=pmsn_round(&q->response[k]);
            pmsn_seal(s,&q->response[k],sizeof(q->response[k]),after);pmsn_owner_seal(o,0,0,owner_after);
        }else{
            unsigned operation=command.operation==PWMT_CLEAN?PWMK_CLEAN_INVALIDATE:PWMK_INVALIDATE;
            pmsn_seal(s,&q->cache[k],sizeof(q->cache[k]),before);pmsn_owner_seal(o,0,0,owner_before);
            returned=pmsn_cache(&q->page,operation,&q->cache[k]);
            pmsn_seal(s,&q->cache[k],sizeof(q->cache[k]),after);pmsn_owner_seal(o,0,0,owner_after);
        }
        if(!pgcd_equal(before,after,32)||!pgcd_equal(owner_before,owner_after,32)||!pmsn_live(s)||!pmsn_bound(s))goto fail;
        q->after[k]=o->current;
        if(pwmt_auth_complete(&q->transaction,&command,o->last,returned,command.operation==PWMT_SMC?&q->response[k]:0,
            command.operation==PWMT_SMC?0:&q->cache[k])<0)goto fail;
        if(command.operation==PWMT_SMC&&!pmsn_peers(s,q,q->transaction.rounds))goto fail;
    }
    if(q->transaction.complete!=1||q->transaction.unknown||q->transaction.error||q->transaction.pending||
       !pwea_core_check(h->input.early,&q->source[1],&h->map)||!pmsn_bound(s))goto fail;
    q->unknown=0;q->complete=1;pweh_digest(q,offsetof(struct pmsn_assignment,digest),q->digest);
    s->assignments++;s->pending=0;return 1;
fail:q->error=2;pmsn_fail(s,2);return 0;
}
static inline int pmsn_io(struct pmsn_state*s,unsigned kind)
{
    if(!pmsn_live(s)||s->pending||s->deliveries==PMSN_RECORDS||(kind!=1&&kind!=2))return 0;
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;struct pmpn_state*p=(void*)(uintptr_t)s->power;
    struct pmmd_command md={0};struct pmim_command modem={0};
    int next=kind==1?pmmd_next(&s->metadata,o->last,&md):pmim_next(&s->modem,o->last,&modem);
    if(next==0)return 1;if(next!=1)return pmsn_fail(s,3);
    struct pmsn_delivery*r=(struct pmsn_delivery*)(uintptr_t)s->records+s->deliveries;
    if(!pwmc_zero(r,sizeof(*r)))return pmsn_fail(s,3);
    r->kind=kind;r->attempted=r->unknown=1;if(kind==1)r->command.metadata=md;else r->command.modem=modem;
    s->pending=++s->deliveries;
    uint64_t address=kind==1?md.address:modem.address;unsigned operation=kind==1?md.kind:modem.kind;
    PMSN_TRACE_IO(s,1,operation,address,0);
    unsigned memory=operation==PMSR_READ||operation==PMSR_WRITE;
    if((memory&&!pmpn_target(p,address&~UINT64_C(4095),&r->target[0]))||!pmpn_arch(p,&r->opening)||
       !pgcd_equal(&r->opening,&p->architecture,offsetof(struct pmni_arch,ticks)))goto fail;
    if(operation==PMSR_WRITE&&!pmsc_mark_effect(o,PMSC_REMOTE))goto fail;
    PMSN_TRACE_IO(s,2,operation,address,0);
    int returned=kind==1?pmni_metadata(&s->metadata,&r->command.metadata,&r->opening,&r->native):
        pmni_modem(&s->modem,&r->command.modem,&r->opening,&r->native);
    PMSN_TRACE_IO(s,3,operation,address,r->native.value);
    if(!returned||(memory&&(!pmpn_target(p,address&~UINT64_C(4095),&r->target[1])||r->target[0].index!=r->target[1].index))||!pmsn_live(s))goto fail;
    PMSN_TRACE_IO(s,4,operation,address,r->native.value);
    if(kind==1){
        if(!pgcd_equal(&md,&r->command.metadata,sizeof(md))||pmmd_complete(&s->metadata,&r->command.metadata,o->last,1,r->native.value)<0)goto fail;
    }else if(!pgcd_equal(&modem,&r->command.modem,sizeof(modem))||pmim_complete(&s->modem,&r->command.modem,o->last,1,r->native.value)<0)goto fail;
    r->unknown=0;r->complete=1;pweh_digest(r,offsetof(struct pmsn_delivery,digest),r->digest);s->pending=0;
    PMSN_TRACE_IO(s,5,operation,address,r->native.value);return 1;
fail:r->error=3;return pmsn_fail(s,3);
}
static inline int pmsn_finish(struct pmsn_state*s)
{
    if(!pmsn_bound(s)||s->complete||s->pending||s->phase!=PMSN_MBA_BACK||s->assignments!=PMSN_ASSIGNMENTS||
       s->metadata.phase!=3||s->metadata.unknown||s->metadata.error||s->metadata.pending||
       s->modem.phase!=5||s->modem.unknown||s->modem.error||s->modem.pending||!s->modem.authenticated_at||
       s->deliveries!=s->metadata.events+s->modem.events)return 0;
    uint8_t hash[32];
    for(unsigned n=0;n<PMSN_ASSIGNMENTS;n++){
        const struct pmsn_assignment*q=&s->assignment[n];pweh_digest(q,offsetof(struct pmsn_assignment,digest),hash);
        if(q->complete!=1||q->unknown||q->error||q->transaction.complete!=1||q->transaction.pending||
           q->transaction.unknown||q->transaction.error||!pgcd_equal(hash,q->digest,32))return 0;
    }
    pweh_digest((const void*)(uintptr_t)s->copy,sizeof(struct pmlc_copy),hash);if(!pgcd_equal(hash,s->copy_digest,32))return 0;
    const struct pmsn_delivery*r=(const void*)(uintptr_t)s->records;unsigned metadata=0,modem=0;
    for(unsigned n=0;n<s->deliveries;n++){
        const struct pmsn_delivery*q=&r[n];pweh_digest(q,offsetof(struct pmsn_delivery,digest),hash);
        if(q->complete!=1||q->unknown||q->error||!pgcd_equal(hash,q->digest,32))return 0;
        if(q->kind==1)metadata++;else if(q->kind==2)modem++;else return 0;
    }
    if(metadata!=s->metadata.events||modem!=s->modem.events||!pmsn_live(s))return 0;
    pweh_digest(r,s->deliveries*sizeof(*r),s->records_digest);s->phase=PMSN_DONE;s->complete=1;
    pmsn_seal(s,s->digest,sizeof(s->digest),s->digest);return 1;
}
static inline int pmsn_current(struct pmsn_state*s)
{
    if(!pmsn_bound(s)||s->complete!=1||s->phase!=PMSN_DONE||s->pending)return 0;uint8_t hash[32];
    pmsn_seal(s,s->digest,sizeof(s->digest),hash);if(!pgcd_equal(hash,s->digest,32))return 0;
    pweh_digest((const void*)(uintptr_t)s->records,s->deliveries*sizeof(struct pmsn_delivery),hash);
    if(!pgcd_equal(hash,s->records_digest,32))return 0;
    pweh_digest((const void*)(uintptr_t)s->copy,sizeof(struct pmlc_copy),hash);return pgcd_equal(hash,s->copy_digest,32)&&pmsn_live(s);
}
/* 0=sticky failure,1=work/wait,2=authenticated modem with returned MBA.
 * The real caller polls the live counter for child not-before times. No new
 * deadline, target access, original firmware call or release is hidden here. */
static inline int pmsn_step(struct pmsn_state*s)
{
    if(!pmsn_live(s)||s->pending)return 0;if(s->complete)return pmsn_current(s)?2:0;
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;struct pmcn_state*c=(void*)(uintptr_t)s->clocks;
    const struct pmck_lifecycle*clocks=(const void*)(uintptr_t)c->clocks;
    struct pmbn_state*b=(void*)(uintptr_t)s->boot;struct pmlc_copy*copy=(void*)(uintptr_t)s->copy;
    switch(s->phase){
    case PMSN_MD_OUT:
        if(!pmsn_secure(s,0)||pmmd_begin(&s->metadata,&b->mba,clocks,&s->assignment[0].transaction,8412,o->last)<0)return pmsn_fail(s,4);
        s->phase=PMSN_MD_IO;break;
    case PMSN_MD_IO:
        if(!pmsn_io(s,1))return pmsn_fail(s,4);if(s->metadata.phase==2)s->phase=PMSN_MD_BACK;break;
    case PMSN_MD_BACK:
        if(!pmsn_secure(s,1)||pmmd_return(&s->metadata,&s->assignment[1].transaction)!=PMMD_RETURNED_ZERO)return pmsn_fail(s,4);
        s->phase=PMSN_MODEM_SHARE;break;
    case PMSN_MODEM_SHARE:
        if(!pmsn_secure(s,2)||pmim_begin(&s->modem,&s->metadata,clocks,&s->assignment[2].transaction,
           (const void*)(uintptr_t)s->segments,o->last)!=PMIM_NEED_SEGMENT||
           !pmlc_begin(copy,o,&s->modem,&s->assignment[2].transaction))return pmsn_fail(s,5);
        s->phase=PMSN_COPY;break;
    case PMSN_COPY:
        if(!pmlc_next_segment(copy))return pmsn_fail(s,5);s->phase=PMSN_PUBLISH;break;
    case PMSN_PUBLISH:
        if(!pmsn_io(s,2))return pmsn_fail(s,5);
        if(s->modem.phase==1)s->phase=PMSN_COPY;else if(s->modem.phase==3)s->phase=PMSN_MODEM_EXCLUSIVE;break;
    case PMSN_MODEM_EXCLUSIVE:
        if(!pmsn_secure(s,3)||pmim_exclusive(&s->modem,&s->assignment[3].transaction,o->last)<0)return pmsn_fail(s,6);
        s->phase=PMSN_AUTH;break;
    case PMSN_AUTH:
        if(!pmsn_io(s,2))return pmsn_fail(s,6);if(s->modem.phase==5)s->phase=PMSN_MBA_BACK;break;
    case PMSN_MBA_BACK:
        if(!pmsn_secure(s,4)||!pmsn_finish(s))return pmsn_fail(s,7);return 2;
    default:return pmsn_fail(s,8);
    }return pmsn_live(s)?1:pmsn_fail(s,8);
}
#endif
#endif
