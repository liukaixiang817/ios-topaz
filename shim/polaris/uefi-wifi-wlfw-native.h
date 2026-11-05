/* Actual current MSA backing, WLFW-returned regions and native MP_ASSIGN.
 * One continuous owner shared with RMTFS; no original UEFI services, second
 * CPU interval, invented region boundary or automatic handback. Default OFF. */
#ifndef POLARIS_UEFI_WIFI_WLFW_NATIVE_H
#define POLARIS_UEFI_WIFI_WLFW_NATIVE_H
#include "uefi-mss-rmtfs-service.h"
#include "polaris-wifi-wlfw.h"
#ifndef EFI_XNU_WIFI_WLFW_NATIVE_AVAILABLE
#define EFI_XNU_WIFI_WLFW_NATIVE_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_WLFW_NATIVE_AVAILABLE
#if !EFI_XNU_MSS_RMTFS_SERVICE_AVAILABLE
#error Native WLFW requires the actual RMTFS service and its owner
#endif
struct pmwa_state {
    struct pmsn_assignment assignment[2];
    uint64_t service,auth,owner,opening,base,next_poll;
    uint32_t attempted,ready,unknown,error,pending,pages,prepared,assignments,assigned,opened;
    struct pmtf_zero zero[512];uint8_t zero_digest[32],wire_digest[32];
    struct polaris_wifi_wlfw client;
    uint64_t smmu; /* Unique current native SMMU observation before CE. */
    uint64_t ce; /* Retained CE owner; requires its own DMA retirement. */
};
#if defined(POLARIS_WIFI_WLFW_SOFTWARE_PEER)
static int pmwa_zero(uint64_t,struct pmtf_zero*);
static int pmwa_cache(uint64_t,unsigned,struct pwmk_record*);
static int pmwa_round(struct pwma_registers*);
static int pmwa_affinity(uint64_t,int64_t*);
#else
static inline int pmwa_zero(uint64_t at,struct pmtf_zero*r)
{for(unsigned n=0;n<512;n++){volatile uint64_t*p=(void*)(uintptr_t)(at+8*n);r->issued++;*p=0;if(*p)return 0;r->returned++;}return 1;}
static inline int pmwa_cache(uint64_t at,unsigned op,struct pwmk_record*r)
{return pwma_actual_cache_page((void*)(uintptr_t)at,op,r);}
static inline int pmwa_round(struct pwma_registers*r){pwma_actual_round(r);return 1;}
static inline int pmwa_affinity(uint64_t target,int64_t*raw){return pwrpc_actual_affinity(0,target,raw);}
#endif
static inline int pmwa_fail(struct pmwa_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;return 0;}
static inline int pmwa_live(struct pmwa_state*s)
{
    if(!s||s->ready!=1||s->unknown||s->error)return 0;
    struct pmrf_state*r=(void*)(uintptr_t)s->service;struct pmsc_owner*o=(void*)(uintptr_t)s->owner;
    const struct pweh_result*h=(const void*)(uintptr_t)o->retained;const struct pwea_claim*q=&h->input.early->memory.claim[0];
    struct pmtf_state*t=(void*)(uintptr_t)r->grant;
    return r->wlan==(uintptr_t)s&&r->owner==s->owner&&r->opening==s->opening&&t->auth==s->auth&&
        q->retained==1&&q->bytes==0x200000&&q->pages==512&&q->requested==s->base&&q->exposed==s->base&&q->exposed_bytes==0x100000&&pmrf_live(r);
}
static inline void pmwa_seal(struct pmwa_state*s,const void*out,size_t bytes,uint8_t digest[32])
{
    struct pwfi_sha256 h;pwfi_init(&h);uintptr_t first=(uintptr_t)out,last=first+bytes;
    for(size_t n=0;n<sizeof(*s);n++){
        if(n<sizeof(s->assignment)&&n%sizeof(struct pmsn_assignment)>=PMSN_ASSIGNMENT_RAW)continue;
        uintptr_t p=(uintptr_t)s+n;if(p>=first&&p<last)continue;pwfi_byte(&h,*(const uint8_t*)p);
    }pwfi_final(&h,digest);
}
static inline int pmwa_at(struct pmwa_state*s,struct pwmc_translation*t,uint64_t page)
{t->page=page;return pmwa_live(s)&&pwmc_actual_translate(t)&&pwmc_translation_valid(t)&&t->page==page&&pmwa_live(s);}
static inline int pmwa_current(struct pmwa_state*s)
{
    if(!pmwa_live(s)||s->pages!=512||s->prepared!=1)return 0;uint8_t hash[32];
    pweh_digest(s->zero,sizeof(s->zero),hash);
    struct pmrf_state*r=(void*)(uintptr_t)s->service;
    return pgcd_equal(hash,s->zero_digest,32)&&pmsn_current((void*)(uintptr_t)s->auth)&&pmrf_scope(r,s->opening,r->node,r->base,0x200000);
}
static inline bool pmwa_scope(void*ctx){return pmwa_current(ctx);}
static inline int pmwa_peers(struct pmwa_state*s,struct pmsn_assignment*q,unsigned phase)
{
    if(phase>PWMT_ROUNDS)return 0;struct pmsc_owner*o=(void*)(uintptr_t)s->owner;
    for(unsigned n=0;n<7;n++){
        struct pmsb_peer*p=&q->peer[phase][n];if(!pwmc_zero(p,sizeof(*p))||!pmwa_live(s))return 0;
        p->target=(n+1)*0x100;p->issued=1;uint8_t before[32],after[32],ob[32],oa[32];
        pmwa_seal(s,&p->raw,sizeof(p->raw),before);pmsc_seal(o,0,0,ob);int returned=pmwa_affinity(p->target,&p->raw);
        pmwa_seal(s,&p->raw,sizeof(p->raw),after);pmsc_seal(o,0,0,oa);
        if(returned!=1||p->raw!=1||!pgcd_equal(before,after,32)||!pgcd_equal(ob,oa,32)||!pmwa_live(s))return 0;p->returned=1;
    }return 1;
}
static inline int pmwa_region(struct pmwa_state*s,unsigned index)
{
    if(index>1||index!=s->assignments||s->pending||!pmwa_current(s))return pmwa_fail(s,3);
    const struct pwfw_region*r=&s->client.region[index];struct pmsn_assignment*q=&s->assignment[index];
    if(!pwmc_zero(q,sizeof(*q))||r->secure>1||!r->bytes||(r->bytes&4095)||(r->address&4095)||
       r->address<s->base||r->address-s->base>=0x100000||r->bytes>0x100000-(r->address-s->base))return pmwa_fail(s,3);
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;const struct pweh_result*h=(const void*)(uintptr_t)o->retained;
    struct pwma_spec spec={.descriptor_pa=(uintptr_t)&q->page,.region_pa=r->address,.region_bytes=r->bytes,
        .sources=1,.source={PWMA_HLOS},.destinations=r->secure?2u:3u,
        .destination={{PWMA_MSS_MSA,PWMA_RW},{PWMA_WLAN,PWMA_RW}}};
    if(!r->secure)spec.destination[2]=(struct pwma_destination){PWMA_WLAN_CE,PWMA_RW};
    q->attempted=q->unknown=1;s->pending=index+1;
    if(!pwea_core_check(h->input.early,&q->source[0],&h->map)||!pmwa_current(s)||!pmwa_peers(s,q,0)||
       pwmt_begin(&q->transaction,&q->page,&spec,o->last,o->current.cpu.frequency)<0)return pmwa_fail(s,3);
    for(unsigned k=0;k<PWMT_EVENTS;k++){
        struct pwmt_command c;if(!pmwa_live(s))return pmwa_fail(s,4);
        int next=pwmt_next(&q->transaction,o->last,&c);if(next==PWMT_ZERO)break;if(next!=PWMT_IO)return pmwa_fail(s,4);
        if(!pmwa_at(s,&q->descriptor_AT[k],(uintptr_t)&q->page))return pmwa_fail(s,4);
        uint8_t before[32],after[32],ob[32],oa[32];int returned;
        if(c.operation==PWMT_SMC){
            q->response[k]=c.registers;if(!pmsc_mark_effect(o,PMSC_SECURE))return pmwa_fail(s,4);
            pmwa_seal(s,&q->response[k],sizeof(q->response[k]),before);pmsc_seal(o,0,0,ob);
            returned=pmwa_round(&q->response[k]);
            pmwa_seal(s,&q->response[k],sizeof(q->response[k]),after);pmsc_seal(o,0,0,oa);
        }else{
            unsigned op=c.operation==PWMT_CLEAN?PWMK_CLEAN_INVALIDATE:PWMK_INVALIDATE;
            pmwa_seal(s,&q->cache[k],sizeof(q->cache[k]),before);pmsc_seal(o,0,0,ob);
            returned=pmwa_cache((uintptr_t)&q->page,op,&q->cache[k]);
            pmwa_seal(s,&q->cache[k],sizeof(q->cache[k]),after);pmsc_seal(o,0,0,oa);
        }
        if(!pgcd_equal(before,after,32)||!pgcd_equal(ob,oa,32)||!pmwa_current(s))return pmwa_fail(s,4);q->after[k]=o->current;
        if(pwmt_complete(&q->transaction,&c,o->last,returned,c.operation==PWMT_SMC?&q->response[k]:0,c.operation==PWMT_SMC?0:&q->cache[k])<0||
           (c.operation==PWMT_SMC&&!pmwa_peers(s,q,q->transaction.rounds)))return pmwa_fail(s,5);
    }
    if(q->transaction.complete!=1||q->transaction.unknown||q->transaction.error||q->transaction.pending||
       !pwea_core_check(h->input.early,&q->source[1],&h->map)||!pmwa_current(s))return pmwa_fail(s,5);
    q->unknown=0;q->complete=1;pweh_digest(q,offsetof(struct pmsn_assignment,digest),q->digest);
    s->pending=0;s->assignments++;return 1;
}
static inline bool pmwa_assign(void*ctx,const struct pwfw_region*r,unsigned count)
{
    struct pmwa_state*s=ctx;struct polaris_wifi_wlfw*c=&s->client;
    if(!pmwa_current(s)||s->assigned||s->assignments||s->pending||!s->opened||!c->busy||!c->assign_issued||c->assigned||c->error||
       c->phase!=1||r!=c->region||count!=c->regions||!count||count>2||!c->exchange[1].received||!c->exchange[1].accepted)return false;
    if(count==2&&r[0].address<r[1].address+r[1].bytes&&r[1].address<r[0].address+r[0].bytes)return false;
    pweh_digest(&c->exchange[1],sizeof(c->exchange[1]),s->wire_digest);
    for(unsigned n=0;n<count;n++)if(!pmwa_region(s,n))return false;s->assigned=1;return pmwa_current(s);
}
static inline int pmwa_begin(struct pmwa_state*s,struct pmrf_state*r)
{
    if(!s||!r||((uintptr_t)s&4095)||!pwmc_zero(s,sizeof(*s))||r->wlan||!pmrf_live(r))return 0;
    struct pmtf_state*t=(void*)(uintptr_t)r->grant;struct pmsn_state*a=(void*)(uintptr_t)t->auth;
    struct pmsc_owner*o=(void*)(uintptr_t)r->owner;const struct pweh_result*h=(const void*)(uintptr_t)o->retained;
    const struct pwea_claim*q=&h->input.early->memory.claim[0];struct pmsg_state*g=(void*)(uintptr_t)r->glink;
    struct polaris_rmtfs_status status;
    if(!pmtf_current(t)||!pmsn_child(a,(uintptr_t)s,sizeof(*s))||!pmsg_scope(g,g->opening,&g->layout)||
       polaris_rmtfs_status(r->service,&status)||!status.started||status.stopping||status.uncertain||status.first_error||
       !polaris_efi_range_owned(h->map.data,h->map.map.bytes,h->map.map.stride,q->requested,q->bytes,2))return 0;
    struct pmsx_state*x=(void*)(uintptr_t)g->channel;
    const uint64_t address[]={(uintptr_t)r,r->glink,r->grant,r->nv,(uintptr_t)a,a->records,a->copy,a->segments,g->channel,x->smem,x->allocation,x->negotiation};
    const uint64_t bytes[]={sizeof(*r),sizeof(*g),sizeof(*t),sizeof(struct pnnv_state),sizeof(*a),sizeof(struct pmsn_delivery)*PMSN_RECORDS,sizeof(struct pmlc_copy),sizeof(struct pmsf_segment)*PMIM_SEGMENTS,sizeof(*x),sizeof(struct pmsq_state),sizeof(struct pmsa_state),sizeof(struct pmsy_state)};
    for(unsigned n=0;n<12;n++)if(!pwea_disjoint((uintptr_t)s,sizeof(*s),address[n],bytes[n]))return 0;
    s->service=(uintptr_t)r;s->auth=(uintptr_t)a;s->owner=r->owner;s->opening=r->opening;s->base=q->requested;
    s->attempted=s->ready=1;r->wlan=(uintptr_t)s;return pmwa_live(s);
}
/* One zero page / one client step per turn; RMTFS continues on this same
 * worker throughout WLAN startup. No original provider regains execution. */
static inline int pmwa_step(struct pmwa_state*s)
{
    if(!pmwa_live(s)||s->pending)return 0;struct pmrf_state*r=(void*)(uintptr_t)s->service;struct pmsg_state*g=(void*)(uintptr_t)r->glink;
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;
    /* Do not burn transport evidence by polling once per4KiB zero page.
     * Service at most every10ms, still under the original180s owner. */
    if(o->last>=s->next_poll){
        if(polaris_rmtfs_poll(r->service))return pmwa_fail(s,6);s->next_poll=o->last+192000;
    }else if(s->pages==512)return 1;
    if(s->pages<512){
        struct pmtf_zero*z=&s->zero[s->pages];uint64_t at=s->base+4096*s->pages;
        if(!pmwa_at(s,&z->AT[0],at)||!pmwa_zero(at,z)||z->issued!=512||z->returned!=512||!pmwa_live(s)||
           !pmwa_cache(at,PWMK_CLEAN_INVALIDATE,&z->cache)||!pwmk_record_valid(&z->cache,at,PWMK_CLEAN_INVALIDATE)||
           !pmwa_at(s,&z->AT[1],at))return pmwa_fail(s,1);
        z->complete=1;s->pages++;return 1;
    }
    if(!s->prepared){pweh_digest(s->zero,sizeof(s->zero),s->zero_digest);s->prepared=1;}
    if(!s->opened){
        struct polaris_wifi_wlfw_cfg cfg={.transport=g->transport,.msa=s->base,.bytes=0x100000,.scope=pmwa_scope,.assign=pmwa_assign,.ctx=s};
        if(!pmwa_current(s)||polaris_wifi_wlfw_open(&s->client,&cfg,pmsg_now(g)))return pmwa_fail(s,2);s->opened=1;return 1;
    }
    int result=polaris_wifi_wlfw_poll(&s->client,pmsg_now(g));if(result&&result!=35)return pmwa_fail(s,6);
    return s->client.ready&&s->assigned?2:1;
}
#endif
#endif
