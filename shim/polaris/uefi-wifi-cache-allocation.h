/* Actual LocateHandleBuffer target container, at the completed producer's
 * incoming-contract interval before the existing FreePool. This records the
 * allocation's actual Size, not a size invented from returned handle_count.
 * It neither executes release nor qualifies any later map/owner/IRQ lease. */
#ifndef POLARIS_UEFI_WIFI_CACHE_ALLOCATION_H
#define POLARIS_UEFI_WIFI_CACHE_ALLOCATION_H
#include "uefi-wifi-gcd-bootstrap.h"
#define PBHA_BYTES 2088u
#define PBHA_CLOCKS 68u
struct pbha_input {
    const struct pbgi_result*seed;const struct ppli_result*images;
    uint64_t handles,count;int(*page)(struct ppli_at*);
};
struct pbha_result {
    struct pbha_input input;uint8_t seed_digest[32],images_digest[32];
    uint64_t core,container,bytes,capacity,free_entry;
    struct ppli_at key_AT,Core_AT[PBGI_CORE_PAGES],header_AT,target_AT[2];
    uint8_t header[24],raw[PBHA_BYTES],hashes[2][5][32];
    uint32_t hash_count[2],hash_failed[2];struct pbgi_clock clock[PBHA_CLOCKS];
    uint32_t attempted,complete,unknown,error,core_pages,target_pages,raw_bytes,arch_issued,arch_returned;
    uint8_t digest[32];
};
_Static_assert(sizeof(struct pbha_input)==40&&sizeof(struct pbha_result)==14784,"separate actual handle-container raw ABI");
_Static_assert(offsetof(struct pbha_result,raw)==3584&&offsetof(struct pbha_result,clock)==6008&&offsetof(struct pbha_result,digest)==14748,"independent container decoder offsets");
struct pbha_live {
    struct pbha_result*r;struct pbha_input in;const struct pbha_input*caller;
    uint8_t seed_seal[32],image_seal[32],seed_live[32],image_live[32];
    uint64_t map_bytes;unsigned node_count[2],last_clock,image_count,keyed,rooted;
};
static inline int pbha_fail(struct pbha_result*r,unsigned error)
{if(!r->error)r->error=error;r->unknown=1;return 0;}
/* Complete old records are checked at entry and before completion. Only
 * their decision inputs are read between those points: seal all of those
 * on every callback. Old unused map tails/earlier clock history never supply
 * addresses, methods or classification, and cannot be accepted changed. */
static inline int pbha_seed_inputs(const struct pbha_live*l,uint8_t out[32])
{
    const struct pbgi_result*s=l->in.seed;
    if(s->call.map.bytes!=l->map_bytes||s->count[0]!=l->node_count[0]||s->count[1]!=l->node_count[1]||
       s->arch_returned!=l->last_clock+1||s->arch_issued!=s->arch_returned)return 0;
    struct pwfi_sha256 h;pwfi_init(&h);
    pbgi_hash_part(&h,s,offsetof(struct pbgi_result,call)+offsetof(struct pwmc_parent_map,data)+(size_t)l->map_bytes,0,0);
    pbgi_hash_part(&h,s->call.digest,32,0,0);
    pbgi_hash_part(&h,&s->core,offsetof(struct pbgi_result,node)-offsetof(struct pbgi_result,core),0,0);
    for(unsigned k=0;k<2;k++)pbgi_hash_part(&h,s->node[k],l->node_count[k]*sizeof(s->node[k][0]),0,0);
    pbgi_hash_part(&h,s->hashes,offsetof(struct pbgi_result,clock)-offsetof(struct pbgi_result,hashes),0,0);
    pbgi_hash_part(&h,&s->clock[l->last_clock],sizeof(s->clock[0]),0,0);
    pbgi_hash_part(&h,&s->attempted,sizeof(*s)-offsetof(struct pbgi_result,attempted),0,0);pwfi_final(&h,out);return 1;
}
static inline int pbha_image_inputs(const struct pbha_live*l,uint8_t out[32])
{
    const struct ppli_result*i=l->in.images;if(i->count!=l->image_count)return 0;
    struct pwfi_sha256 h;pwfi_init(&h);
    pbgi_hash_part(&h,i,offsetof(struct ppli_result,entry)+l->image_count*sizeof(i->entry[0]),0,0);
    pbgi_hash_part(&h,i->binding_digest,sizeof(*i)-offsetof(struct ppli_result,binding_digest),0,0);
    pwfi_final(&h,out);return 1;
}
static inline int pbha_stable(const struct pbha_live*l)
{
    const struct pbha_result*r=l->r;uint8_t hash[32];
    if(!pgcd_equal(&r->input,&l->in,sizeof(l->in))||!pgcd_equal(l->caller,&l->in,sizeof(l->in)))return 0;
    if(!pbha_seed_inputs(l,hash)||!pgcd_equal(hash,l->seed_live,32)||
       !pbha_image_inputs(l,hash)||!pgcd_equal(hash,l->image_live,32))return 0;
    const struct pbgi_result*s=l->in.seed;const struct pwmc_parent_map*c=&s->call;
    if(r->core!=s->core||!pgcd_equal(r->seed_digest,s->digest,32)||!pgcd_equal(r->images_digest,l->image_seal,32)||
       (uintptr_t)s->input.io.system->boot!=c->boot_address||
       !pgcd_equal(s->input.io.system->boot,c->BS_after,PWMC_BS_BYTES))return 0;
    if(l->keyed&&pwfi_le((const void*)(uintptr_t)(s->core+0x1cdb0),8)!=s->initial_key)return 0;
    if(l->rooted){
        struct pbgi_live graph={.r=(struct pbgi_result*)s,.core=s->core};pbgi_root_seal(s,graph.root_seal);
        if(!pbgi_roots_current(&graph))return 0;
        /* Compare only the producer's already-qualified exact addresses;
         * never follow a newly supplied pointer from a changed live link. */
        for(unsigned list=0;list<2;list++)for(unsigned k=0;k<s->count[list];k++)
            if(!pgcd_equal(s->node[list][k].raw,(const void*)(uintptr_t)s->node[list][k].address,s->node[list][k].bytes))return 0;
    }return 1;
}
static inline void pbha_envelope(const struct pbha_result*r,const void*skip,size_t bytes,uint8_t hash[32])
{struct pwfi_sha256 h;pwfi_init(&h);pbgi_hash_part(&h,r,sizeof(*r),skip,bytes);pwfi_final(&h,hash);}
static inline int pbha_tick(struct pbha_live*l)
{
    struct pbha_result*r=l->r;if(!pbha_stable(l))return 0;
    unsigned k=r->arch_issued;if(k==PBHA_CLOCKS)return 0;struct pbgi_clock*c=&r->clock[k];
    if(!pwmc_zero(c,sizeof(*c)))return 0;
    c->native_issued=1;c->native[0]=*l->in.seed->input.native;c->native_returned=1;if(c->native[0])return 0;
    r->arch_issued=k+1;c->issued=1;uint8_t before[32],after[32];pbha_envelope(r,&c->raw,sizeof(c->raw),before);
    int ok=l->in.seed->input.io.arch(l->in.seed->input.io.opaque,&c->raw);
    if(!ok)return 0;pbha_envelope(r,&c->raw,sizeof(c->raw),after);
    if(!pgcd_equal(before,after,32)||!pbha_stable(l)||r->arch_issued!=k+1||r->arch_returned!=k)return 0;
    c->returned=1;r->arch_returned=k+1;
    const struct pbgi_result*s=l->in.seed;
    uint64_t previous=k?r->clock[k-1].raw.cpu.ticks:s->clock[s->arch_returned-1].raw.cpu.ticks;
    if(!pwfc_arch_stable(&s->call.after.cpu,&c->raw.cpu)||c->raw.cpacr!=s->call.after.cpacr||
       c->raw.cpu.daif||c->raw.cpu.group1!=1||c->raw.cpu.ticks<previous||c->raw.cpu.ticks<s->input.opening||
       c->raw.cpu.ticks-s->input.opening>PGCD_FRESH_TICKS)return 0;
    c->native_issued=3;c->native[1]=*s->input.native;c->native_returned=3;return !c->native[1];
}
static inline int pbha_page(struct pbha_live*l,struct ppli_at*a,uint64_t page)
{
    struct pbha_result*r=l->r;const struct pbgi_result*s=l->in.seed;
    struct pbgi_live graph={.r=(struct pbgi_result*)s};
    if(!pwmc_zero(a,sizeof(*a))||!pbha_stable(l)||!pbgi_RAM(&graph,page,4096))return 0;
    a->page=page;a->native_issued=1;a->native[0]=*s->input.native;a->native_returned=1;if(a->native[0])return 0;
    uint8_t before[32],after[32];pbha_envelope(r,a,sizeof(*a),before);
    int ok=l->in.page(a);if(!ok)return 0;pbha_envelope(r,a,sizeof(*a),after);
    if(!pgcd_equal(before,after,32)||!pbha_stable(l)||a->page!=page||a->issued!=1||a->returned!=1||
       a->saved!=a->restored||a->par!=(UINT64_C(0xff00000000000b80)|page)||
       a->native_issued!=1||a->native_returned!=1||!pwmc_zero(a->native,sizeof(a->native)))return 0;
    a->native_issued=3;a->native[1]=*s->input.native;a->native_returned=3;if(a->native[1])return 0;
    struct ppli_at saved=*a;return pbha_tick(l)&&pgcd_equal(a,&saved,sizeof(saved));
}
static __attribute__((noinline)) int pbha_capture(struct pbha_result*r,const struct pbha_input*input)
{
    if(!r||!input||!pwmc_zero(r,sizeof(*r)))return 0;
    r->attempted=r->unknown=1;r->input=*input;struct pbha_input in=*input;
    if(!in.seed||!in.images||!in.page||!in.handles||!in.count||in.count>PPLI_MAX||in.handles<24)return pbha_fail(r,1);
    const struct pbgi_result*s=in.seed;const struct ppli_result*i=in.images;uint8_t hash[32];
    ppli_sha(s,offsetof(struct pbgi_result,digest),hash);
    if(s->attempted!=1||s->complete!=1||s->unknown||s->error||!pgcd_equal(hash,s->digest,32)||
       s->core_pages!=PBGI_CORE_PAGES||s->hash_count[0]!=5||s->hash_count[1]!=5||
       !s->arch_returned||s->arch_returned>PBGI_CLOCKS||s->arch_issued!=s->arch_returned||
       s->count[0]>PBGI_NODES||s->count[1]>PBGI_NODES||s->call.map.bytes>PGCD_MAP_CAP||
       !pwmc_zero(s->hash_failed,sizeof(s->hash_failed))||s->call.input.phase!=4||
       !ppli_live(i)||i->handles!=in.handles||i->count!=in.count||
       i->next[0]!=in.count||i->next[1]!=in.count||i->native_flag!=(uintptr_t)s->input.native||
       i->own_matches!=1||i->native_issued!=3||i->native_returned!=3||!pwmc_zero(i->native,sizeof(i->native))||
       i->system!=(uintptr_t)s->input.io.system||i->own_handle!=s->call.input.image_handle||
       i->map[1].key!=s->initial_key||i->map[1].bytes!=s->call.map.bytes||i->map[1].stride!=s->call.map.stride||
       !pgcd_equal(i->maps[1],s->call.data,(size_t)s->call.map.bytes)||
       !pwmc_parent_in_image(&s->call.image_after,(uintptr_t)r,sizeof(*r))||
       !pwmc_parent_in_image(&s->call.image_after,(uintptr_t)s,sizeof(*s))||
       !pwmc_parent_in_image(&s->call.image_after,(uintptr_t)i,sizeof(*i)))return pbha_fail(r,1);
    for(unsigned k=0;k<2;k++){
        ppli_prefix(i,k,hash);if(!pgcd_equal(hash,i->prefix_digest[k],32))return pbha_fail(r,1);
        ppli_map_digest(i,k,hash);if(!pgcd_equal(hash,i->map[k].digest,32))return pbha_fail(r,1);
    }
    struct pbha_live live={.r=r,.in=in,.caller=input,.map_bytes=s->call.map.bytes,
        .node_count={s->count[0],s->count[1]},.last_clock=s->arch_returned-1,.image_count=(unsigned)in.count};
    ppli_sha(s,sizeof(*s),live.seed_seal);ppli_sha(i,sizeof(*i),live.image_seal);
    if(!pbha_seed_inputs(&live,live.seed_live)||!pbha_image_inputs(&live,live.image_live))return pbha_fail(r,1);
    pgcd_copy(r->seed_digest,s->digest,32);pgcd_copy(r->images_digest,live.image_seal,32);r->core=s->core;
    r->container=in.handles-24;
    if((r->container&127)||!pbha_tick(&live)||
       !pbha_page(&live,&r->key_AT,(s->core+0x1cdb0)&~UINT64_C(4095)))return pbha_fail(r,2);
    if(pwfi_le((const void*)(uintptr_t)(s->core+0x1cdb0),8)!=s->initial_key)return pbha_fail(r,2);live.keyed=1;
    for(unsigned k=0;k<PBGI_CORE_PAGES;k++){
        if(!pbha_page(&live,&r->Core_AT[k],s->core+4096*k)||r->core_pages!=k)return pbha_fail(r,2);r->core_pages=k+1;
    }
    if(!pgci_verify((const void*)(uintptr_t)s->core,s->core,PGCI_IMAGE_BYTES,r->hashes[0],&r->hash_failed[0],&r->hash_count[0]))return pbha_fail(r,3);
    live.rooted=1;if(!pbha_stable(&live))return pbha_fail(r,3);
    r->free_entry=pwfi_le(s->call.BS_after+72,8);
    if(r->free_entry!=s->core+0x3be0||
       pwmc_parent_overlap(r->container,24,s->core,PGCI_IMAGE_BYTES)||
       pwmc_parent_overlap(r->container,24,(uintptr_t)s->call.image_after.base,s->call.image_after.bytes)||
       !polaris_efi_range_owned(s->call.data,s->call.map.bytes,s->call.map.stride,r->container&~UINT64_C(4095),4096,4)||
       !pbha_page(&live,&r->header_AT,r->container&~UINT64_C(4095)))return pbha_fail(r,3);
    pgcd_copy(r->header,(const void*)(uintptr_t)r->container,sizeof(r->header));
    r->bytes=pwfi_le(r->header+16,8);
    if(pwfi_le(r->header,4)!=UINT64_C(0x30646870)||pwfi_le(r->header+8,4)!=4||r->bytes<48||
       r->bytes>PBHA_BYTES||(r->bytes&7)||r->bytes<40+8*in.count||r->container>UINT64_MAX-r->bytes||
       pwfi_le(s->pool+8,8)<r->bytes||
       pwmc_parent_overlap(r->container,r->bytes,s->core,PGCI_IMAGE_BYTES)||
       pwmc_parent_overlap(r->container,r->bytes,(uintptr_t)s->call.image_after.base,s->call.image_after.bytes))return pbha_fail(r,4);
    r->capacity=r->bytes-40;
    for(unsigned list=0;list<2;list++)for(unsigned k=0;k<s->count[list];k++)
        if(pwmc_parent_overlap(r->container,r->bytes,s->node[list][k].address,s->node[list][k].bytes))return pbha_fail(r,4);
    for(uint64_t page=r->container&~UINT64_C(4095);page<r->container+r->bytes;page+=4096){
        unsigned k=r->target_pages;if(k==2||!polaris_efi_range_owned(s->call.data,s->call.map.bytes,s->call.map.stride,page,4096,4)||
           !pbha_page(&live,&r->target_AT[k],page)||r->target_pages!=k)return pbha_fail(r,4);
        r->target_pages=k+1;
    }
    pgcd_copy(r->raw,(const void*)(uintptr_t)r->container,r->bytes);r->raw_bytes=(uint32_t)r->bytes;
    if(!pgcd_equal(r->header,r->raw,24)||pwfi_le(r->raw+r->bytes-16,4)!=UINT64_C(0x6c617470)||
       pwfi_le(r->raw+r->bytes-8,8)!=r->bytes||
       !pgcd_equal(r->raw+24,i->handle_values[0],8*in.count)||!pgcd_equal(r->raw+24,i->handle_values[1],8*in.count))return pbha_fail(r,4);
    for(unsigned k=0;k<2;k++){
        if(!pbha_tick(&live)||!pgcd_equal(r->raw,(const void*)(uintptr_t)r->container,r->bytes)||
           !pgcd_equal(r->header,r->raw,24)||!pwmc_zero(r->raw+r->bytes,PBHA_BYTES-r->bytes))return pbha_fail(r,5);
    }
    if(!pgci_verify((const void*)(uintptr_t)s->core,s->core,PGCI_IMAGE_BYTES,r->hashes[1],&r->hash_failed[1],&r->hash_count[1])||
       !pbha_stable(&live))return pbha_fail(r,5);
    ppli_sha(s,sizeof(*s),hash);if(!pgcd_equal(hash,live.seed_seal,32))return pbha_fail(r,5);
    ppli_sha(i,sizeof(*i),hash);if(!pgcd_equal(hash,live.image_seal,32))return pbha_fail(r,5);
    r->unknown=0;r->complete=1;ppli_sha(r,offsetof(struct pbha_result,digest),r->digest);return 1;
}
#endif
