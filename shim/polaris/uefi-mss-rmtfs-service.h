/* Native RMTFS service: actual fresh-NV producer + authenticated GLINK +
 * actual guarded shared grant. Private RAM shadows only; no disk writes.
 * Retirement is deliberately not inferred from transport or secure success. */
#ifndef POLARIS_UEFI_MSS_RMTFS_SERVICE_H
#define POLARIS_UEFI_MSS_RMTFS_SERVICE_H
#include "uefi-mss-glink-native.h"
#include "uefi-mss-rmtfs-native.h"
#include "uefi-wifi-nv-native.h"
#include "polaris-wifi-rmtfs.h"
#ifndef EFI_XNU_MSS_RMTFS_SERVICE_AVAILABLE
#define EFI_XNU_MSS_RMTFS_SERVICE_AVAILABLE 0
#endif
#if EFI_XNU_MSS_RMTFS_SERVICE_AVAILABLE
#if !EFI_XNU_MSS_GLINK_NATIVE_AVAILABLE || !EFI_XNU_MSS_RMTFS_NATIVE_AVAILABLE || !EFI_XNU_WIFI_NV_NATIVE_AVAILABLE
#error Native RMTFS service needs actual GLINK, shared grant and current NV
#endif
#define PMRF_UNITS (PNV_SHADOW_BYTES/4096u)
struct pmrf_access {
    uint64_t shared,private;uint32_t bytes,write,issued,returned,complete,reserved;
    struct pwmc_translation shared_AT[2],private_AT[2];struct pwmk_record cache[2];
};
struct pmrf_state {
    uint64_t glink,grant,nv,owner,opening,base,pool,wlan;
    uint8_t nv_digest[32],grant_digest[32];
    uint32_t node,attempted,ready,unknown,error,allocations,frees,accesses;
    uint16_t units[PMRF_UNITS];struct pwmc_translation AT;
    struct pmrf_access access;uint8_t history[32];
    struct polaris_rmtfs_cfg cfg;struct polaris_rmtfs*service;
};
static struct pmrf_state*pmrf_runtime;
#if defined(POLARIS_MSS_RMTFS_SERVICE_SOFTWARE_PEER)
static int pmrf_cache(uint64_t,unsigned,struct pwmk_record*);
static int pmrf_copy(uint64_t,uint64_t,unsigned,unsigned,struct pmrf_access*);
#else
static inline int pmrf_cache(uint64_t at,unsigned op,struct pwmk_record*r)
{return pwma_actual_cache_page((void*)(uintptr_t)at,op,r);}
static inline int pmrf_copy(uint64_t shared,uint64_t private,unsigned bytes,unsigned write,struct pmrf_access*r)
{
    for(unsigned n=0;n<bytes;n++){
        volatile uint8_t*p=(void*)(uintptr_t)(shared+n);uint8_t*q=(void*)(uintptr_t)(private+n);r->issued++;
        if(write)*p=*q;else *q=*p;r->returned++;
    }return 1;
}
#endif
static inline int pmrf_fail(struct pmrf_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;return 0;}
static inline int pmrf_live(struct pmrf_state*s)
{
    if(!s||s!=pmrf_runtime||s->ready!=1||s->unknown||s->error)return 0;
    struct pmsg_state*g=(void*)(uintptr_t)s->glink;struct pmtf_state*t=(void*)(uintptr_t)s->grant;struct pnnv_state*v=(void*)(uintptr_t)s->nv;
    return g->owner==s->owner&&g->opening==s->opening&&t->owner==s->owner&&t->opening==s->opening&&t->service==(uintptr_t)s&&
        t->complete==1&&!t->pending&&t->base==s->base&&pgcd_equal(t->digest,s->grant_digest,32)&&pmtf_live(t)&&
        v->consumer==(uintptr_t)s&&v->complete==1&&!v->unknown&&!v->error&&v->allocation.address+PNV_INPUT_BYTES==s->pool&&
        pgcd_equal(v->digest,s->nv_digest,32)&&pmsg_live(g);
}
static inline int pmrf_at(struct pmrf_state*s,struct pwmc_translation*t,uint64_t page)
{
    for(unsigned n=0;n<sizeof(*t);n++)((uint8_t*)t)[n]=0;t->page=page;
    return pmrf_live(s)&&pwmc_actual_translate(t)&&pwmc_translation_valid(t)&&t->page==page&&pmrf_live(s);
}
static inline void pmrf_history(struct pmrf_state*s,const void*data,size_t bytes)
{
    struct pwfi_sha256 h;pwfi_init(&h);for(unsigned n=0;n<32;n++)pwfi_byte(&h,s->history[n]);
    for(size_t n=0;n<bytes;n++)pwfi_byte(&h,((const uint8_t*)data)[n]);pwfi_final(&h,s->history);
}
static inline int pmrf_private(struct pmrf_state*s,uint64_t at,size_t bytes)
{
    if(!bytes||at<s->pool||at-s->pool>=PNV_SHADOW_BYTES||bytes>PNV_SHADOW_BYTES-(at-s->pool))return 0;
    unsigned unit=(unsigned)((at-s->pool)/4096),first=unit;
    while(first&&s->units[first]==UINT16_MAX)first--;
    unsigned count=s->units[first];if(!count||count==UINT16_MAX||count>PMRF_UNITS-first)return 0;
    uint64_t end=s->pool+(uint64_t)(first+count)*4096;return at<end&&bytes<=end-at;
}
uintptr_t pwfr_thread(void){return pmrf_live(pmrf_runtime)?(uintptr_t)pmrf_runtime:0;}
void*pwfr_alloc(size_t bytes)
{
    struct pmrf_state*s=pmrf_runtime;if(!bytes||bytes>PNV_SHADOW_BYTES||!pmrf_live(s))return 0;
    unsigned count=(unsigned)((bytes+4095)/4096),run=0;
    for(unsigned n=0;n<PMRF_UNITS;n++){
        run=s->units[n]?0:run+1;if(run!=count)continue;unsigned first=n+1-count;
        s->units[first]=(uint16_t)count;for(unsigned k=1;k<count;k++)s->units[first+k]=UINT16_MAX;
        uint64_t at=s->pool+(uint64_t)first*4096;
        for(unsigned k=0;k<count;k++){
            uint64_t page=at+4096*k;if(!pmrf_at(s,&s->AT,page)){pmrf_fail(s,1);return 0;}pmrf_history(s,&s->AT,sizeof(s->AT));
            volatile uint64_t*p=(void*)(uintptr_t)page;for(unsigned j=0;j<512;j++){p[j]=0;if(p[j]){pmrf_fail(s,1);return 0;}}
            if(!pmrf_at(s,&s->AT,page)){pmrf_fail(s,1);return 0;}pmrf_history(s,&s->AT,sizeof(s->AT));
        }
        s->allocations++;return (void*)(uintptr_t)at;
    }return 0;
}
void pwfr_free(void*pointer,size_t bytes)
{
    struct pmrf_state*s=pmrf_runtime;if(!pmrf_live(s))return;uint64_t at=(uintptr_t)pointer;
    if((at&4095)||!pmrf_private(s,at,bytes)){pmrf_fail(s,2);return;}
    unsigned first=(unsigned)((at-s->pool)/4096),count=(unsigned)((bytes+4095)/4096);
    if(s->units[first]!=count){pmrf_fail(s,2);return;}
    for(unsigned n=1;n<count;n++)if(s->units[first+n]!=UINT16_MAX){pmrf_fail(s,2);return;}
    for(unsigned n=0;n<count;n++)s->units[first+n]=0;s->frees++;
}
bool pwfr_hash(const void*data,uint32_t bytes,const uint8_t expected[32])
{
    struct pmrf_state*s=pmrf_runtime;if(!pmrf_live(s)||!pmrf_private(s,(uintptr_t)data,bytes))return false;
    uint8_t hash[32];pweh_digest(data,bytes,hash);return pgcd_equal(hash,expected,32)&&pmrf_live(s);
}
static inline bool pmrf_scope(void*ctx,uint64_t epoch,uint32_t node,uint64_t base,uint32_t bytes)
{
    struct pmrf_state*s=ctx;if(!pmrf_live(s)||epoch!=s->opening||node!=s->node||base!=s->base||bytes!=0x200000)return false;
    struct pmsg_state*g=(void*)(uintptr_t)s->glink;uint32_t current;
    return pmsg_scope(g,g->opening,&g->layout)&&!polaris_wifi_glink_qrtr_peer(g->transport,&current)&&current==node;
}
static inline bool pmrf_inputs(void*ctx,const struct polaris_rmtfs_cfg*cfg)
{
    struct pmrf_state*s=ctx;if(!pmrf_live(s)||!cfg)return false;
    struct pnnv_state*v=(void*)(uintptr_t)s->nv;
    if(cfg->epoch!=s->opening||cfg->transport!=((struct pmsg_state*)(uintptr_t)s->glink)->transport)return false;
    for(unsigned n=0;n<4;n++)if((uintptr_t)cfg->inputs[n].data!=v->allocation.address+pnv_part_offset(n)||
        cfg->inputs[n].bytes!=pnv_part_bytes(n)||!pgcd_equal(cfg->inputs[n].sha256,v->inputs.hash[n],32))return false;
    return pmrf_live(s);
}
static inline bool pmrf_order(void*ctx)
{struct pmrf_state*s=ctx;if(!pmrf_live(s))return false;pmsq_order();return pmrf_live(s);}
/* Cache operations are whole-page, while writes own complete cache lines.
 * Never write back a partially owned line over a neighbouring remote byte. */
static inline bool pmrf_shared(struct pmrf_state*s,uint64_t epoch,uint32_t at,void*data,uint32_t bytes,unsigned write)
{
    if(!pmrf_live(s)||!bytes||at>0x200000||bytes>0x200000-at||!pmrf_private(s,(uintptr_t)data,bytes)||
       !pmrf_scope(s,epoch,s->node,s->base,0x200000))return false;
    for(unsigned done=0;done<bytes;){
        struct pmrf_access*r=&s->access;for(unsigned n=0;n<sizeof(*r);n++)((uint8_t*)r)[n]=0;
        r->shared=s->base+at+done;r->private=(uintptr_t)data+done;r->write=write;
        unsigned chunk=bytes-done,shared_left=4096-(unsigned)(r->shared&4095),private_left=4096-(unsigned)(r->private&4095);
        if(chunk>shared_left)chunk=shared_left;if(chunk>private_left)chunk=private_left;r->bytes=chunk;
        uint64_t sp=r->shared&~UINT64_C(4095),pp=r->private&~UINT64_C(4095);
        if(!pmrf_at(s,&r->shared_AT[0],sp)||!pmrf_at(s,&r->private_AT[0],pp)||
           !pmrf_cache(sp,PWMK_INVALIDATE,&r->cache[0])||!pwmk_record_valid(&r->cache[0],sp,PWMK_INVALIDATE)||
           (write&&((r->shared%r->cache[0].line_bytes)||(chunk%r->cache[0].line_bytes)))||!pmrf_live(s)||
           !pmrf_copy(r->shared,r->private,chunk,write,r)||r->issued!=chunk||r->returned!=chunk||!pmrf_live(s))return pmrf_fail(s,3);
        if(write&&(!pmrf_cache(sp,PWMK_CLEAN_INVALIDATE,&r->cache[1])||!pwmk_record_valid(&r->cache[1],sp,PWMK_CLEAN_INVALIDATE)))return pmrf_fail(s,3);
        if(!pmrf_order(s)||!pmrf_at(s,&r->shared_AT[1],sp)||!pmrf_at(s,&r->private_AT[1],pp))return pmrf_fail(s,3);
        r->complete=1;s->accesses++;pmrf_history(s,r,sizeof(*r));done+=chunk;
    }return pmrf_scope(s,epoch,s->node,s->base,0x200000);
}
static inline bool pmrf_read(void*ctx,uint64_t epoch,uint32_t at,void*out,uint32_t bytes)
{return pmrf_shared(ctx,epoch,at,out,bytes,0);}
static inline bool pmrf_write(void*ctx,uint64_t epoch,uint32_t at,const void*data,uint32_t bytes)
{return pmrf_shared(ctx,epoch,at,(void*)data,bytes,1);}
static inline bool pmrf_retired(void*ctx,uint64_t epoch)
{(void)ctx;(void)epoch;return false;} /* Requires the forthcoming actual retirement producer. */
static inline int pmrf_begin(struct pmrf_state*s,struct pmsg_state*g,struct pmtf_state*t,struct pnnv_state*v)
{
    if(!s||!g||!t||!v||pmrf_runtime||!pwmc_zero(s,sizeof(*s))||t->service||v->consumer||!pmtf_current(t)||
       !pmsg_scope(g,g->opening,&g->layout)||g->owner!=t->owner||g->opening!=t->opening||
       v->self!=(uintptr_t)v||v->complete!=1||v->unknown||v->error||v->pending||v->calls!=PNNV_CALLS||v->allocated!=1||
       v->translated[0]!=PNV_BYTES/4096||v->translated[1]!=PNV_BYTES/4096)return 0;
    struct pmsc_owner*o=(void*)(uintptr_t)t->owner;const struct pweh_result*h=(const void*)(uintptr_t)o->retained;
    struct pmsn_state*a=(void*)(uintptr_t)t->auth;struct pmsx_state*x=(void*)(uintptr_t)g->channel;
    if(a!=(void*)(uintptr_t)x->auth||v->early!=(uintptr_t)h->input.early||v->current.cpu.ticks>o->opening||!pmsn_child(a,(uintptr_t)v,sizeof(*v))||!pmsn_child(a,(uintptr_t)s,sizeof(*s)))return 0;
    const uint64_t address[]={(uintptr_t)g,(uintptr_t)t,(uintptr_t)v,(uintptr_t)a,a->records,a->copy,a->segments,(uintptr_t)x,x->smem,x->allocation,x->negotiation};
    const uint64_t sizes[]={sizeof(*g),sizeof(*t),sizeof(*v),sizeof(*a),sizeof(struct pmsn_delivery)*PMSN_RECORDS,sizeof(struct pmlc_copy),sizeof(struct pmsf_segment)*PMIM_SEGMENTS,sizeof(*x),sizeof(struct pmsq_state),sizeof(struct pmsa_state),sizeof(struct pmsy_state)};
    for(unsigned n=0;n<11;n++)if(!pwea_disjoint((uintptr_t)s,sizeof(*s),address[n],sizes[n]))return 0;
    uint8_t hash[32];pweh_digest(v,offsetof(struct pnnv_state,digest),hash);if(!pgcd_equal(hash,v->digest,32))return 0;
    pweh_digest(h->input.early,sizeof(struct pwea_native),hash);if(!pgcd_equal(hash,v->early_digest,32))return 0;
    pweh_digest(&v->inputs,offsetof(struct pnv_result,digest),hash);
    if(!pgcd_equal(hash,v->inputs.digest,32)||!v->inputs.complete||v->inputs.unknown||v->inputs.error||v->inputs.passes!=2||v->inputs.allocation!=v->allocation.address||
       !polaris_efi_range_owned(h->map.data,h->map.map.bytes,h->map.map.stride,v->allocation.address,PNV_BYTES,2))return 0;
    uint32_t node;if(polaris_wifi_glink_qrtr_peer(g->transport,&node)||!node||node>=0xfffffffe)return 0;
    s->glink=(uintptr_t)g;s->grant=(uintptr_t)t;s->nv=(uintptr_t)v;s->owner=g->owner;s->opening=g->opening;s->base=t->base;
    s->pool=v->allocation.address+PNV_INPUT_BYTES;s->node=node;s->attempted=s->ready=1;
    pgcd_copy(s->nv_digest,v->digest,32);pgcd_copy(s->grant_digest,t->digest,32);pmrf_runtime=s;t->service=v->consumer=(uintptr_t)s;
    for(unsigned n=0;n<PNV_INPUT_BYTES/4096;n++){
        if(!pmrf_at(s,&s->AT,v->allocation.address+4096*n))return pmrf_fail(s,4);pmrf_history(s,&s->AT,sizeof(s->AT));
    }
    s->cfg=(struct polaris_rmtfs_cfg){.transport=g->transport,.epoch=s->opening,.remote_node=node,.shared_phys=t->base,.shared_bytes=0x200000,
        .inputs_current=pmrf_inputs,.scope=pmrf_scope,.shared_read=pmrf_read,.shared_write=pmrf_write,.order=pmrf_order,.retired=pmrf_retired,.ctx=s};
    for(unsigned n=0;n<4;n++){
        s->cfg.inputs[n].data=(void*)(uintptr_t)(v->allocation.address+pnv_part_offset(n));s->cfg.inputs[n].bytes=pnv_part_bytes(n);
        pgcd_copy(s->cfg.inputs[n].sha256,v->inputs.hash[n],32);
    }
    s->service=polaris_rmtfs_create(&s->cfg);
    if(!s->service||polaris_rmtfs_start(s->service))return pmrf_fail(s,5);return pmrf_live(s);
}
#endif
#endif
