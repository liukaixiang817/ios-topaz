/* Witness the EXISTING bootstrap handle-array FreePool. The registered ABI
 * call still belongs to the incoming UEFI contract. Return/status/source raw
 * is not permission to accept its complete callback effects or a later map.
 * Never read the released target again, even after EFI_SUCCESS. */
#ifndef POLARIS_UEFI_WIFI_CACHE_RELEASE_H
#define POLARIS_UEFI_WIFI_CACHE_RELEASE_H
#include "uefi-wifi-cache-allocation.h"
struct pbhr_api {uint64_t status;uint32_t issued,returned;};
struct pbhr_input {
    const struct pbha_result*allocation;const struct pbgi_result*seed;const struct ppli_result*images;
    struct efi_system*system;const struct efi_loaded*image;const volatile uint32_t*native;
    uint64_t opening;struct pgcd_io io;
    int(*page)(struct ppli_at*);
    int(*release)(void*,struct efi_system*,uint64_t,uint64_t,struct pbhr_api*);
};
struct pbhr_source {struct pbgi_roots roots;uint8_t pool[232],policy[720];};
struct pbhr_result {
    struct pbhr_input input;uint8_t allocation_digest[32],seed_seal[32],images_seal[32];
    struct pbha_result allocation;struct pbgi_result seed;struct ppli_result images;
    struct pbha_result before_target;
    struct efi_loaded image[2];uint8_t BS[2][PWMC_BS_BYTES];
    struct pgcd_arch arch[2];struct pgcd_fp_guard fp;
    struct pbhr_source source[2];uint8_t hashes[5][5][32];uint32_t hash_count[5],hash_failed[5];
    uint64_t core,entry;struct pbhr_api api;
    uint32_t native[8],native_issued,native_returned;
    uint32_t attempted,issued,returned,unknown,error,complete,arch_issued,arch_returned;
    uint32_t fp_save_issued,fp_save_returned,fp_restore_issued,fp_restore_returned,order_issued,order_returned;
    uint8_t digest[32];
};
_Static_assert(sizeof(struct pbhr_input)==144&&sizeof(struct pbhr_source)==1096&&sizeof(struct pbhr_result)==596496,"complete release-call and archived-input ABI");
_Static_assert(offsetof(struct pbhr_result,before_target)==577176&&offsetof(struct pbhr_result,api)==596344&&offsetof(struct pbhr_result,digest)==596456,"independent release-call decoder offsets");
struct pbhr_live {
    struct pbhr_result*r;struct pbhr_input in;const struct pbhr_input*caller;
    uint8_t allocation_seal[32],seed_seal[32],images_seal[32],intent[32],inner_control[32];
    uint64_t core,boot,entry,old_ticks;unsigned after,post_bound;
};
static inline int pbhr_fail(struct pbhr_result*r,unsigned error)
{if(!r->error)r->error=error;r->unknown=1;return 0;}
static inline void pbhr_seal(const struct pbhr_result*r,const void*skip,size_t bytes,uint8_t out[32])
{struct pwfi_sha256 h;pwfi_init(&h);pbgi_hash_part(&h,r,sizeof(*r),skip,bytes);pwfi_final(&h,out);}
static inline void pbhr_fp_intent(const struct pgcd_fp_guard*f,uint8_t out[32])
{
    struct pwfi_sha256 h;pwfi_init(&h);const uint8_t*b=(const void*)f;
    for(size_t k=0;k<sizeof(*f);k++)if(!(k>=8&&k<16)&&!(k>=164&&k<168))pwfi_byte(&h,b[k]);pwfi_final(&h,out);
}
static inline void pbhr_control_seal(const struct pbhr_result*r,uint8_t out[32])
{
    struct pwfi_sha256 h;pwfi_init(&h);
    pbgi_hash_part(&h,r,offsetof(struct pbhr_result,allocation),0,0);
    pbgi_hash_part(&h,r->image,sizeof(*r)-offsetof(struct pbhr_result,image),0,0);pwfi_final(&h,out);
}
/* The inner reader never uses the outer historical copies. Its full output
 * and original decision records have their own guards. Check the remaining
 * outer control frame at every inner callback; all archived bytes are also
 * checked by the full outer envelope before any registered service. */
static inline int pbhr_inner_guard(void*context)
{
    const struct pbhr_live*l=context;uint8_t hash[32];pbhr_control_seal(l->r,hash);
    return pgcd_equal(hash,l->inner_control,32)&&pgcd_equal(l->caller,&l->in,sizeof(l->in))&&
        (!l->r->before_target.arch_issued||l->r->before_target.clock[0].raw.cpu.ticks>=l->old_ticks)&&
        (uintptr_t)l->in.system->boot==l->boot&&pgcd_equal(l->in.system->boot,l->r->BS[0],PWMC_BS_BYTES)&&
        pgcd_equal(l->in.image,&l->r->image[0],sizeof(l->r->image[0]));
}
static inline int pbhr_stable(const struct pbhr_live*l)
{
    const struct pbhr_result*r=l->r;
    if(!pgcd_equal(&r->input,&l->in,sizeof(l->in))||!pgcd_equal(l->caller,&l->in,sizeof(l->in)))return 0;
    if(!pgcd_equal(l->in.allocation,&r->allocation,sizeof(r->allocation))||
       !pgcd_equal(l->in.seed,&r->seed,sizeof(r->seed))||!pgcd_equal(l->in.images,&r->images,sizeof(r->images)))return 0;
    if(r->core!=l->core||r->entry!=l->entry||(uintptr_t)l->in.system->boot!=l->boot||
       !pgcd_equal(l->in.system->boot,r->BS[0],PWMC_BS_BYTES)||
       !pgcd_equal(l->in.image,&r->image[0],sizeof(r->image[0])))return 0;
    if(!l->after){
        const struct pbha_result*a=l->in.allocation;
        struct pbgi_live g={.r=(struct pbgi_result*)l->in.seed,.core=l->core};pbgi_root_seal(l->in.seed,g.root_seal);
        if(!pbgi_roots_current(&g)||!pgcd_equal(a->raw,(const void*)(uintptr_t)a->container,a->bytes))return 0;
        for(unsigned list=0;list<2;list++)for(unsigned k=0;k<l->in.seed->count[list];k++){
            const struct pbgi_node*n=&l->in.seed->node[list][k];
            if(!pgcd_equal(n->raw,(const void*)(uintptr_t)n->address,n->bytes))return 0;
        }
    }else if(l->post_bound){
        const struct pbhr_source*s=&r->source[1];const uint32_t locks[3]={0x1b340,0x1bd48,0x1c1f8};
        for(unsigned k=0;k<3;k++)if(!pgcd_equal(s->roots.lock[k],(const void*)(uintptr_t)(l->core+locks[k]),24))return 0;
        if(!pgcd_equal(s->roots.head[0],(const void*)(uintptr_t)(l->core+0x1b358),16)||
           !pgcd_equal(s->roots.head[1],(const void*)(uintptr_t)(l->core+0x1bd60),16)||
           s->roots.key!=pwfi_le((const void*)(uintptr_t)(l->core+0x1cdb0),8)||
           s->roots.depth!=pwfi_le((const void*)(uintptr_t)(l->core+0x1cc08),8)||
           s->roots.busy!=pwfi_le((const void*)(uintptr_t)(l->core+0x1dc10),8)||
           s->roots.smm!=pwfi_le((const void*)(uintptr_t)(l->core+0x1cb78),8)||
           s->roots.TPL!=pwfi_le((const void*)(uintptr_t)(l->core+0x1b098),8)||
           !pgcd_equal(s->pool,(const void*)(uintptr_t)(l->core+0x1d1a0),sizeof(s->pool))||
           !pgcd_equal(s->policy,(const void*)(uintptr_t)(l->core+0x1be68),sizeof(s->policy)))return 0;
    }
    return 1;
}
static inline int pbhr_native(struct pbhr_live*l,unsigned slot)
{
    if(slot>=8)return 0;struct pbhr_result*r=l->r;r->native_issued|=1u<<slot;
    r->native[slot]=*l->in.native;r->native_returned|=1u<<slot;return !r->native[slot];
}
static inline int pbhr_arch(struct pbhr_live*l,unsigned slot,uint64_t minimum_ticks)
{
    struct pbhr_result*r=l->r;if(slot>1||r->arch_issued!=slot||r->arch_returned!=slot||!pbhr_stable(l))return 0;
    r->arch_issued=slot+1;uint8_t before[32],after[32];pbhr_seal(r,&r->arch[slot],sizeof(r->arch[slot]),before);
    int ok=l->in.io.arch(l->in.io.opaque,&r->arch[slot]);if(!ok)return 0;
    pbhr_seal(r,&r->arch[slot],sizeof(r->arch[slot]),after);
    r->arch_returned=slot+1;
    if(!pgcd_equal(before,after,32)||!pbhr_stable(l)||r->arch_issued!=slot+1)return 0;
    const struct pgcd_arch*a=&r->arch[slot];
    uint64_t previous=slot?r->arch[0].cpu.ticks:r->before_target.clock[r->before_target.arch_returned-1].raw.cpu.ticks;
    if(previous<minimum_ticks)previous=minimum_ticks;
    return pwfc_arch_stable(&l->in.seed->call.after.cpu,&a->cpu)&&a->cpacr==l->in.seed->call.after.cpacr&&
        !a->cpu.daif&&a->cpu.group1==1&&a->cpu.ticks>=previous&&a->cpu.ticks>=l->in.opening&&
        a->cpu.ticks-l->in.opening<=PGCD_FRESH_TICKS;
}
/* Fixed Core-owned provider globals only. After the registered service returns,
 * these are raw incoming-contract provider observations, not a fresh typed
 * post-release map. No head/node/target pointer from them is followed. */
static inline int pbhr_source(struct pbhr_live*l,unsigned slot)
{
    struct pbhr_result*r=l->r;struct pbhr_source*s=&r->source[slot];
    const uint32_t locks[3]={0x1b340,0x1bd48,0x1c1f8};
    for(unsigned k=0;k<3;k++){
        pgcd_copy(s->roots.lock[k],(const void*)(uintptr_t)(l->core+locks[k]),24);
        if(pwfi_le(s->roots.lock[k],8)!=16||pwfi_le(s->roots.lock[k]+8,8)!=4||pwfi_le(s->roots.lock[k]+16,4)!=1)return 0;
    }
    pgcd_copy(s->roots.head[0],(const void*)(uintptr_t)(l->core+0x1b358),16);
    pgcd_copy(s->roots.head[1],(const void*)(uintptr_t)(l->core+0x1bd60),16);
    s->roots.key=pwfi_le((const void*)(uintptr_t)(l->core+0x1cdb0),8);
    s->roots.depth=pwfi_le((const void*)(uintptr_t)(l->core+0x1cc08),8);s->roots.busy=pwfi_le((const void*)(uintptr_t)(l->core+0x1dc10),8);
    s->roots.smm=pwfi_le((const void*)(uintptr_t)(l->core+0x1cb78),8);s->roots.TPL=pwfi_le((const void*)(uintptr_t)(l->core+0x1b098),8);
    pgcd_copy(s->pool,(const void*)(uintptr_t)(l->core+0x1d1a0),sizeof(s->pool));
    pgcd_copy(s->policy,(const void*)(uintptr_t)(l->core+0x1be68),sizeof(s->policy));
    return !s->roots.depth&&!s->roots.busy&&!s->roots.smm&&s->roots.TPL==4&&pwfi_le(s->pool+16,4)==4;
}
static inline int pbhr_actual_release(void*opaque,struct efi_system*system,uint64_t entry,uint64_t handles,struct pbhr_api*raw)
{
    (void)opaque;if(!system||!system->boot||(uintptr_t)system->boot->free_pool!=entry||!raw)return 0;
    raw->issued=1;raw->status=system->boot->free_pool((void*)(uintptr_t)handles);raw->returned=1;return 1;
}
/* A deliberately limited ordinary small-free path. The selected bin must be
 * empty, so InsertHeadList writes only that Core head and the target. A known
 * retained GCD container at the backing-page base has allocated signature;
 * the original 3ae4..3aec test therefore skips both granule walks/reclamation.
 * Its full existing typed/source/AT/current-byte checks still apply. This is
 * a source-path restriction, never an allocated-address inventory or lease.
 * Other valid FreePool paths remain unsupported and are refused before call. */
static inline int pbhr_small_path(const struct pbhr_result*r,unsigned*index)
{
    static const uint16_t sizes[7]={128,256,384,640,1024,1664,2688};
    const struct pbha_result*a=&r->before_target;const struct pbgi_result*s=&r->seed;
    unsigned n=0;while(n<7&&a->bytes>sizes[n])n++;
    if(n==7||!a->bytes||a->container&127)return 0;
    uint64_t page=a->container&~UINT64_C(4095),end=a->container+sizes[n];
    if(a->container==page||end>page+4096||end<a->container||pwfi_le(a->raw,4)!=0x30646870||pwfi_le(a->raw+8,4)!=4)return 0;
    unsigned base=0;
    for(unsigned list=0;list<2;list++)for(unsigned k=0;k<s->count[list];k++){
        const struct pbgi_node*b=&s->node[list][k];
        if(pwmc_parent_overlap(a->container,sizes[n],b->address,b->bytes))return 0;
        if(list==1&&b->address==page&&b->bytes==120&&b->returned==1&&
           pwfi_le(b->raw,4)==0x30646870&&pwfi_le(b->raw+8,4)==4&&pwfi_le(b->raw+16,8)==120)base++;
    }
    unsigned off=24+16*n;uint64_t head=r->core+0x1d1a0+off;
    if(base!=1||!pgcd_equal(&r->source[0].roots,&s->roots,sizeof(s->roots))||
       !pgcd_equal(r->source[0].pool,s->pool,sizeof(s->pool))||
       !pgcd_equal(r->source[0].policy,s->type_policy,sizeof(s->type_policy))||
       pwfi_le(r->source[0].pool+8,8)<a->bytes||
       pwfi_le(r->source[0].pool+off,8)!=head||pwfi_le(r->source[0].pool+off+8,8)!=head)return 0;
    *index=n;return 1;
}
/* Check the fixed provider prefix's exact effects for that restricted path.
 * No released target/neighbor is read. Equal roots/key/prefixes do not exclude
 * callback ABA or prove a fresh typed graph, full work, ownership or walltime. */
static inline int pbhr_small_return(const struct pbhr_result*r)
{
    unsigned index;if(!pbhr_small_path(r,&index))return 0;
    const struct pbhr_source*b=&r->source[0],*a=&r->source[1];
    if(!pgcd_equal(&a->roots,&b->roots,sizeof(a->roots))||!pgcd_equal(a->policy,b->policy,sizeof(a->policy)))return 0;
    uint64_t used=pwfi_le(b->pool+8,8)-r->before_target.bytes,link=r->before_target.container+8;
    unsigned off=24+16*index;
    for(unsigned k=0;k<sizeof(a->pool);k++){
        uint8_t expected=k>=8&&k<16?(uint8_t)(used>>(8*(k-8))):
            k>=off&&k<off+16?(uint8_t)(link>>(8*((k-off)&7))):b->pool[k];
        if(a->pool[k]!=expected)return 0;
    }return 1;
}
static __attribute__((noinline)) int pbhr_call_guarded(struct pbhr_result*r,const struct pbhr_input*input,
    int(*guarded_release)(struct pbhr_live*,struct pbhr_result*,const struct pbhr_input*,const uint8_t[32],uint64_t*))
{
    if(!r||!input||!pwmc_zero(r,sizeof(*r)))return 0;
    r->attempted=r->unknown=1;r->input=*input;r->api.status=UINT64_MAX;struct pbhr_input in=*input;uint8_t hash[32];
    if(!in.allocation||!in.seed||!in.images||!in.system||!in.image||!in.native||!in.opening||!in.page||!in.release)return pbhr_fail(r,1);
    const struct pbha_result*a=in.allocation;const struct pbgi_result*s=in.seed;
    ppli_sha(a,offsetof(struct pbha_result,digest),hash);
    if(a->complete!=1||a->unknown||a->error||!pgcd_equal(hash,a->digest,32)||!a->arch_returned||a->arch_returned>PBHA_CLOCKS||a->arch_issued!=a->arch_returned||a->input.seed!=s||a->input.images!=in.images||
       a->input.page!=in.page||s->input.native!=in.native||s->input.opening!=in.opening||
       s->input.io.system!=in.system||s->call.input.image!=in.image||!pgcd_equal(&in.io,&s->input.io,sizeof(in.io))||
       !in.io.arch||!in.io.fp_save||!in.io.fp_restore||!in.io.order||
       !pwmc_parent_in_image(&s->call.image_after,(uintptr_t)r,sizeof(*r)))return pbhr_fail(r,1);
    if(!pwmc_zero((const uint8_t*)a+offsetof(struct pbha_result,digest)+32,sizeof(*a)-offsetof(struct pbha_result,digest)-32))return pbhr_fail(r,1);
    ppli_sha(s,offsetof(struct pbgi_result,digest),hash);
    if(!pgcd_equal(hash,s->digest,32)||!pgcd_equal(hash,a->seed_digest,32)||s->complete!=1||s->unknown||s->error||
       !pwmc_zero((const uint8_t*)s+offsetof(struct pbgi_result,digest)+32,sizeof(*s)-offsetof(struct pbgi_result,digest)-32)||
       s->call.boot_address!=s->core+0x1b800||(uintptr_t)in.system->boot!=s->call.boot_address||a->free_entry!=s->core+0x3be0)return pbhr_fail(r,1);
    ppli_sha(in.images,sizeof(*in.images),hash);
    if(!pgcd_equal(hash,a->images_digest,32)||!ppli_live(in.images)||in.images->count!=a->input.count||in.images->count>PPLI_MAX)return pbhr_fail(r,1);
    struct pbhr_live live={.r=r,.in=in,.caller=input,.core=s->core,.boot=s->call.boot_address,.entry=a->free_entry,
        .old_ticks=a->clock[a->arch_returned-1].raw.cpu.ticks};
    ppli_sha(a,sizeof(*a),live.allocation_seal);ppli_sha(s,sizeof(*s),live.seed_seal);ppli_sha(in.images,sizeof(*in.images),live.images_seal);
    pgcd_copy(r->allocation_digest,a->digest,32);pgcd_copy(r->seed_seal,live.seed_seal,32);pgcd_copy(r->images_seal,live.images_seal,32);
    r->allocation=*a;r->seed=*s;r->images=*in.images;
    r->core=live.core;r->entry=live.entry;r->image[0]=*in.image;pgcd_copy(r->BS[0],(const void*)(uintptr_t)live.boot,PWMC_BS_BYTES);
    if(live.entry!=live.core+0x3be0||!pgcd_equal(&r->image[0],&s->call.image_after,sizeof(r->image[0]))||
       !pgcd_equal(r->BS[0],s->call.BS_after,PWMC_BS_BYTES)||!pbhr_stable(&live))return pbhr_fail(r,1);
    for(unsigned k=0;k<in.images->count;k++)if(pwmc_parent_overlap(a->container,a->bytes,in.images->entry[k].address,sizeof(struct efi_loaded)))return pbhr_fail(r,1);
    uint8_t before[32],after[32];pbhr_seal(r,&r->before_target,sizeof(r->before_target),before);
    pbhr_control_seal(r,live.inner_control);
    const struct pbha_input target={s,in.images,a->input.handles,a->input.count,in.page};
    int ok=pbha_capture_guarded(&r->before_target,&target,pbhr_inner_guard,&live);
    if(!ok)return pbhr_fail(r,2);pbhr_seal(r,&r->before_target,sizeof(r->before_target),after);
    if(!pgcd_equal(before,after,32)||!pbhr_stable(&live)||r->before_target.bytes!=a->bytes||
       !pgcd_equal(r->before_target.raw,a->raw,PBHA_BYTES)||!pbhr_native(&live,0)||!pbhr_arch(&live,0,0)||!pbhr_native(&live,1))return pbhr_fail(r,2);
    if(!pbhr_source(&live,0)||!pgci_verify((const void*)(uintptr_t)live.core,live.core,PGCI_IMAGE_BYTES,r->hashes[0],&r->hash_failed[0],&r->hash_count[0]))return pbhr_fail(r,3);
    unsigned small_index;if(!pbhr_small_path(r,&small_index))return pbhr_fail(r,8);
    r->fp_save_issued=1;pbhr_seal(r,&r->fp,sizeof(r->fp),before);ok=in.io.fp_save(in.io.opaque,&r->fp);
    if(!ok)return pbhr_fail(r,4);pbhr_seal(r,&r->fp,sizeof(r->fp),after);
    r->fp_save_returned=1;
    if(!pgcd_equal(before,after,32)||!pbhr_stable(&live)||r->fp.saved!=1||r->fp.restored||r->fp.cpacr_before!=r->arch[0].cpacr)return pbhr_fail(r,4);
    pbhr_fp_intent(&r->fp,live.intent);if(!pbhr_native(&live,2))return pbhr_fail(r,4);
    r->order_issued=1;pbhr_seal(r,0,0,before);in.io.order(in.io.opaque);pbhr_seal(r,0,0,after);
    r->order_returned=1;
    if(!pgcd_equal(before,after,32)||!pbhr_stable(&live))return pbhr_fail(r,4);
    if(!pbhr_native(&live,3))return pbhr_fail(r,4);
    if(!pgci_verify((const void*)(uintptr_t)live.core,live.core,PGCI_IMAGE_BYTES,r->hashes[1],&r->hash_failed[1],&r->hash_count[1])||!pbhr_stable(&live))return pbhr_fail(r,4);
    /* The real nested guard returns its latest CNTVCT-domain sample through
     * this local scalar. It changes no raw ABI and grants no new interval.
     * A guarded callback must produce it; zero is never a fallback. */
    uint64_t closing_ticks=0;
    r->issued=1;pbhr_seal(r,&r->api,sizeof(r->api),before);
    ok=guarded_release?guarded_release(&live,r,input,before,&closing_ticks):in.release(in.io.opaque,in.system,live.entry,a->input.handles,&r->api);
    if(!ok)return pbhr_fail(r,5);pbhr_seal(r,&r->api,sizeof(r->api),after);
    /* Do not run the pre-call target/root comparison after this point. */
    live.after=1;
    r->returned=1;
    if(!pgcd_equal(before,after,32)||!pbhr_stable(&live)||r->api.issued!=1||r->api.returned!=1||
       (guarded_release&&(!closing_ticks||closing_ticks<r->arch[0].cpu.ticks||closing_ticks<in.opening||
        closing_ticks-in.opening>PGCD_FRESH_TICKS)))return pbhr_fail(r,5);
    if(r->api.status||!pbhr_native(&live,4))return pbhr_fail(r,5);
    r->image[1]=*in.image;pgcd_copy(r->BS[1],(const void*)(uintptr_t)live.boot,PWMC_BS_BYTES);
    if(!pbhr_source(&live,1)||!pbhr_small_return(r)||!pgci_verify((const void*)(uintptr_t)live.core,live.core,PGCI_IMAGE_BYTES,r->hashes[2],&r->hash_failed[2],&r->hash_count[2]))return pbhr_fail(r,6);
    live.post_bound=1;
    if(!pbhr_arch(&live,1,closing_ticks)||!pbhr_native(&live,5))return pbhr_fail(r,6);
    if(!pgci_verify((const void*)(uintptr_t)live.core,live.core,PGCI_IMAGE_BYTES,r->hashes[3],&r->hash_failed[3],&r->hash_count[3])||!pbhr_stable(&live))return pbhr_fail(r,6);
    r->fp_restore_issued=1;pbhr_seal(r,&r->fp,sizeof(r->fp),before);ok=in.io.fp_restore(in.io.opaque,&r->fp);
    if(!ok)return pbhr_fail(r,7);pbhr_seal(r,&r->fp,sizeof(r->fp),after);pbhr_fp_intent(&r->fp,hash);
    r->fp_restore_returned=1;
    if(!pgcd_equal(before,after,32)||!pgcd_equal(hash,live.intent,32)||!pbhr_stable(&live)||
       r->fp.restored!=1||r->fp.cpacr_after!=r->arch[1].cpacr)return pbhr_fail(r,7);
    if(!pbhr_native(&live,6))return pbhr_fail(r,7);
    if(!pgci_verify((const void*)(uintptr_t)live.core,live.core,PGCI_IMAGE_BYTES,r->hashes[4],&r->hash_failed[4],&r->hash_count[4])||!pbhr_stable(&live))return pbhr_fail(r,7);
    r->complete=1;r->unknown=0;ppli_sha(r,offsetof(struct pbhr_result,digest),r->digest);return 1;
}
static inline int pbhr_call(struct pbhr_result*r,const struct pbhr_input*input)
{return pbhr_call_guarded(r,input,0);}
#endif
