/* Capture complete private-map inputs at the existing final cache GetMap,
 * while its real returned map is current and before handle-array FreePool.
 * This is a producer interval, not a later-map, allocation or IRQ lease.
 * Later first-call admission must requalify these objects and callbacks. */
#ifndef POLARIS_UEFI_WIFI_GCD_BOOTSTRAP_H
#define POLARIS_UEFI_WIFI_GCD_BOOTSTRAP_H
#include "uefi-wifi-current-map.h"
#define PBGI_NODES 256u
#define PBGI_CORE_PAGES ((PGCI_IMAGE_BYTES+4095)/4096)
#define PBGI_CLOCKS 832u
struct pbgi_input {
    const struct pwmc_parent_map*call;const volatile uint32_t*native;
    uint64_t opening;struct pgcd_io io;
};
struct pbgi_node {
    uint64_t address;struct ppli_at AT[2];uint8_t raw[120];
    uint32_t bytes,pages,issued,returned;
};
struct pbgi_roots {
    uint8_t lock[3][24];uint64_t head[2][2],key,depth,busy,smm,TPL;
};
struct pbgi_clock {struct pgcd_arch raw;uint32_t native[2],native_issued,native_returned,issued,returned;};
struct pbgi_result {
    struct pbgi_input input;struct pwmc_parent_map call;
    uint64_t core,initial_key;struct ppli_at key_AT,Core_AT[PBGI_CORE_PAGES];
    struct pbgi_roots roots;uint8_t pool[232],type_policy[15*48];
    struct pbgi_node node[2][PBGI_NODES];uint8_t hashes[2][5][32];uint32_t hash_count[2],hash_failed[2];
    struct pbgi_clock clock[PBGI_CLOCKS];
    uint32_t attempted,complete,unknown,error,core_pages,count[2],arch_issued,arch_returned;
    uint8_t digest[32];
};
_Static_assert(sizeof(struct pbgi_node)==256&&sizeof(struct pbgi_roots)==144,"full original map/GCD container and roots");
_Static_assert(sizeof(struct pbgi_input)==96&&sizeof(struct pbgi_clock)==128&&sizeof(struct pbgi_result)==309664,"complete producer raw ABI, separate from private-call frames");
_Static_assert(offsetof(struct pbgi_result,call)==96&&offsetof(struct pbgi_result,node)==71688&&offsetof(struct pbgi_result,clock)==203096&&offsetof(struct pbgi_result,digest)==309628,"independent producer decoder offsets");
struct pbgi_live {
    struct pbgi_result*r;struct pbgi_input in;const struct pbgi_input*caller;
    uint64_t core,bytes;uint8_t call_seal[32],full_call_seal[32],root_seal[32];unsigned keyed,rooted;
};
static inline int pbgi_fail(struct pbgi_result*r,unsigned e)
{if(!r->error)r->error=e;r->unknown=1;return 0;}
static inline void pbgi_call_seal(const struct pwmc_parent_map*r,uint64_t bytes,uint8_t out[32])
{ppli_sha(r,offsetof(struct pwmc_parent_map,data)+(size_t)bytes,out);}
static inline void pbgi_hash_part(struct pwfi_sha256*h,const void*p,size_t bytes,const void*skip,size_t skip_bytes)
{
    const uint8_t*b=p;uintptr_t lo=(uintptr_t)skip;
    for(size_t k=0;k<bytes;k++)if((uintptr_t)(b+k)<lo||(uintptr_t)(b+k)-lo>=skip_bytes)pwfi_byte(h,b[k]);
}
/* Seal every live record field across a callback, excluding only that exact
 * callback output. Unissued array tails must stay zero. The retained map's
 * unreturned tail cannot affect address qualification and is verified against
 * the original full-call SHA before completion, without hashing64KiB of dead
 * output at every AT. No field is erased after an error. */
static inline int pbgi_envelope(const struct pbgi_live*l,const void*skip,size_t skip_bytes,uint8_t out[32])
{
    const struct pbgi_result*r=l->r;
    if(r->core_pages>PBGI_CORE_PAGES||r->count[0]>PBGI_NODES||r->count[1]>PBGI_NODES||r->arch_issued>PBGI_CLOCKS)return 0;
    struct pwfi_sha256 h;pwfi_init(&h);
    pbgi_hash_part(&h,r,offsetof(struct pbgi_result,call)+offsetof(struct pwmc_parent_map,data)+(size_t)l->bytes,skip,skip_bytes);
    const uint8_t*after=r->call.digest;
    pbgi_hash_part(&h,after,(const uint8_t*)r->Core_AT-after,skip,skip_bytes);
    unsigned pages=r->core_pages<PBGI_CORE_PAGES?r->core_pages+1:PBGI_CORE_PAGES;
    pbgi_hash_part(&h,r->Core_AT,pages*sizeof(r->Core_AT[0]),skip,skip_bytes);
    if(!pwmc_zero(r->Core_AT+pages,(PBGI_CORE_PAGES-pages)*sizeof(r->Core_AT[0])))return 0;
    pbgi_hash_part(&h,&r->roots,offsetof(struct pbgi_result,node)-offsetof(struct pbgi_result,roots),skip,skip_bytes);
    for(unsigned list=0;list<2;list++){
        unsigned used=r->count[list]<PBGI_NODES?r->count[list]+1:PBGI_NODES;
        pbgi_hash_part(&h,r->node[list],used*sizeof(r->node[list][0]),skip,skip_bytes);
        if(!pwmc_zero(r->node[list]+used,(PBGI_NODES-used)*sizeof(r->node[list][0])))return 0;
    }
    pbgi_hash_part(&h,r->hashes,offsetof(struct pbgi_result,clock)-offsetof(struct pbgi_result,hashes),skip,skip_bytes);
    pbgi_hash_part(&h,r->clock,r->arch_issued*sizeof(r->clock[0]),skip,skip_bytes);
    if(!pwmc_zero(r->clock+r->arch_issued,(PBGI_CLOCKS-r->arch_issued)*sizeof(r->clock[0])))return 0;
    pbgi_hash_part(&h,&r->attempted,sizeof(*r)-offsetof(struct pbgi_result,attempted),skip,skip_bytes);pwfi_final(&h,out);return 1;
}
static inline void pbgi_root_seal(const struct pbgi_result*r,uint8_t out[32])
{
    struct pwfi_sha256 h;pwfi_init(&h);
    const uint8_t*p=(const void*)&r->roots;
    for(size_t k=0;k<sizeof(r->roots);k++)pwfi_byte(&h,p[k]);
    for(size_t k=0;k<sizeof(r->pool);k++)pwfi_byte(&h,r->pool[k]);
    for(size_t k=0;k<sizeof(r->type_policy);k++)pwfi_byte(&h,r->type_policy[k]);pwfi_final(&h,out);
}
static inline int pbgi_roots_current(const struct pbgi_live*l)
{
    const struct pbgi_result*r=l->r;const struct pbgi_roots*p=&r->roots;uint8_t hash[32];
    pbgi_root_seal(r,hash);if(!pgcd_equal(hash,l->root_seal,32))return 0;
    return pwfi_le((const void*)(uintptr_t)(l->core+0x1cdb0),8)==p->key&&
        pgcd_equal(p->lock[0],(const void*)(uintptr_t)(l->core+0x1b340),24)&&
        pgcd_equal(p->lock[1],(const void*)(uintptr_t)(l->core+0x1bd48),24)&&
        pgcd_equal(p->lock[2],(const void*)(uintptr_t)(l->core+0x1c1f8),24)&&
        pgcd_equal(p->head[0],(const void*)(uintptr_t)(l->core+0x1b358),16)&&
        pgcd_equal(p->head[1],(const void*)(uintptr_t)(l->core+0x1bd60),16)&&
        !pwfi_le((const void*)(uintptr_t)(l->core+0x1cc08),8)&&
        !pwfi_le((const void*)(uintptr_t)(l->core+0x1dc10),8)&&
        !pwfi_le((const void*)(uintptr_t)(l->core+0x1cb78),8)&&
        pwfi_le((const void*)(uintptr_t)(l->core+0x1b098),8)==4&&
        pgcd_equal(r->pool,(const void*)(uintptr_t)(l->core+0x1d1a0),sizeof(r->pool))&&
        pgcd_equal(r->type_policy,(const void*)(uintptr_t)(l->core+0x1be68),sizeof(r->type_policy));
}
static inline int pbgi_stable(const struct pbgi_live*l)
{
    const struct pbgi_result*r=l->r;uint8_t hash[32];
    if(!pgcd_equal(&r->input,&l->in,sizeof(l->in))||!pgcd_equal(l->caller,&l->in,sizeof(l->in))||
       r->core!=l->core||r->call.map.bytes!=l->bytes||l->in.call->map.bytes!=l->bytes)return 0;
    pbgi_call_seal(&r->call,l->bytes,hash);if(!pgcd_equal(hash,l->call_seal,32))return 0;
    pbgi_call_seal(l->in.call,l->bytes,hash);if(!pgcd_equal(hash,l->call_seal,32))return 0;
    if((uintptr_t)l->in.io.system->boot!=r->call.boot_address||
       !pgcd_equal(l->in.io.system->boot,r->call.BS_after,PWMC_BS_BYTES))return 0;
    if(l->keyed&&(r->initial_key!=r->call.map.key||pwfi_le((const void*)(uintptr_t)(l->core+0x1cdb0),8)!=r->initial_key))return 0;
    return !l->rooted||pbgi_roots_current(l);
}
static inline int pbgi_tick(struct pbgi_live*l)
{
    struct pbgi_result*r=l->r;if(!pbgi_stable(l))return 0;
    unsigned k=r->arch_issued;if(k>=PBGI_CLOCKS||r->arch_returned!=k)return 0;
    /* Every retained sample is CNTVCT. Keep the original opening window,
     * and also refuse rollback from the immediately preceding sample. The
     * map's closing sample alone is not the most recent observed counter. */
    uint64_t minimum=k?r->clock[k-1].raw.cpu.ticks:r->call.after.cpu.ticks;
    if(k&&(r->clock[k-1].issued!=1||r->clock[k-1].returned!=1||
       r->clock[k-1].native_issued!=3||r->clock[k-1].native_returned!=3))return 0;
    struct pbgi_clock*c=&r->clock[k];if(!pwmc_zero(c,sizeof(*c)))return 0;
    c->native_issued=1;c->native[0]=*l->in.native;c->native_returned=1;if(c->native[0])return 0;
    uint32_t issued=k+1,returned=r->arch_returned;r->arch_issued=issued;c->issued=1;
    uint8_t before[32],after[32];if(!pbgi_envelope(l,&c->raw,sizeof(c->raw),before))return 0;
    int ok=l->in.io.arch(l->in.io.opaque,&c->raw);
    if(!ok)return 0;
    if(!pbgi_envelope(l,&c->raw,sizeof(c->raw),after)||!pgcd_equal(before,after,32)||
       !pbgi_stable(l)||r->arch_issued!=issued||r->arch_returned!=returned)return 0;
    c->returned=1;r->arch_returned=issued;
    if(!pwfc_arch_stable(&r->call.after.cpu,&c->raw.cpu)||c->raw.cpacr!=r->call.after.cpacr||
       c->raw.cpu.daif||c->raw.cpu.group1!=1||c->raw.cpu.ticks<minimum||c->raw.cpu.ticks<l->in.opening||
       c->raw.cpu.ticks-l->in.opening>PGCD_FRESH_TICKS)return 0;
    c->native_issued=3;c->native[1]=*l->in.native;c->native_returned=3;
    return !c->native[1];
}
static inline int pbgi_RAM(const struct pbgi_live*l,uint64_t address,uint64_t bytes)
{
    const struct pwmc_parent_map*c=&l->r->call;
    if(!address||!bytes||address>UINT64_MAX-bytes||address+bytes>UINT64_MAX-4095)return 0;
    for(unsigned k=0;k<sizeof(pwmc_exclusions)/sizeof(pwmc_exclusions[0]);k++)
        if(pwmc_parent_overlap(address,bytes,pwmc_exclusions[k].base,pwmc_exclusions[k].bytes))return 0;
    for(uint64_t page=address&~UINT64_C(4095);page<address+bytes;page+=4096){
        unsigned found=0;
        for(uint64_t at=0;at<c->map.bytes;at+=c->map.stride){
            const struct efi_memory*d=(const void*)(c->data+at);
            if(d->physical<=page&&page+4096<=d->physical+d->pages*4096){
                if((d->type!=3&&d->type!=4)||d->attributes!=8||d->virtual_address)return 0;found++;
            }
        }if(found!=1)return 0;
    }return 1;
}
static inline int pbgi_page(struct pbgi_live*l,struct ppli_at*a,uint64_t page,int(*read_page)(struct ppli_at*))
{
    if(!pwmc_zero(a,sizeof(*a))||!pbgi_stable(l)||!pbgi_RAM(l,page,4096))return 0;
    a->page=page;a->native_issued=1;a->native[0]=*l->in.native;a->native_returned=1;if(a->native[0])return 0;
    uint8_t before[32],after[32];if(!pbgi_envelope(l,a,sizeof(*a),before))return 0;
    int ok=read_page(a);
    if(!ok||!pbgi_envelope(l,a,sizeof(*a),after)||!pgcd_equal(before,after,32)||!pbgi_stable(l)||
       a->page!=page||a->issued!=1||a->returned!=1||a->saved!=a->restored||
       a->par!=(UINT64_C(0xff00000000000b80)|page)||a->native_issued!=1||a->native_returned!=1||
       !pwmc_zero(a->native,sizeof(a->native)))return 0;
    a->native_issued=3;a->native[1]=*l->in.native;a->native_returned=3;
    if(a->native[1])return 0;struct ppli_at saved=*a;
    if(!pbgi_tick(l)||!pgcd_equal(a,&saved,sizeof(saved)))return 0;return 1;
}
static inline int pbgi_load(struct pbgi_live*l,struct pbgi_node*n,uint64_t address,unsigned bytes,int(*read_page)(struct ppli_at*))
{
    if(!pwmc_zero(n,sizeof(*n))||(bytes!=64&&bytes!=120)||!pbgi_RAM(l,address,bytes))return 0;
    n->address=address;n->bytes=bytes;n->issued=1;
    for(uint64_t page=address&~UINT64_C(4095);page<address+bytes;page+=4096){
        unsigned k=n->pages;if(k==2||!pbgi_page(l,&n->AT[k],page,read_page)||
           n->address!=address||n->bytes!=bytes||n->issued!=1||n->returned||n->pages!=k||
           !pwmc_zero(n->raw,sizeof(n->raw)))return 0;
        n->pages=k+1;
    }
    pgcd_copy(n->raw,(const void*)(uintptr_t)address,bytes);n->returned=1;return 1;
}
static __attribute__((noinline)) int pbgi_capture(struct pbgi_result*r,const struct pbgi_input*input,int(*read_page)(struct ppli_at*))
{
    if(!r||!input||!read_page||!pwmc_zero(r,sizeof(*r)))return 0;r->attempted=r->unknown=1;r->input=*input;
    struct pbgi_input in=*input;
    if(!in.call||!in.native||!in.opening||!in.io.system||!in.io.arch)return pbgi_fail(r,1);
    r->call=*in.call;uint8_t hash[32];ppli_sha(&r->call,offsetof(struct pwmc_parent_map,digest),hash);
    if(r->call.input.phase!=4||r->call.input.capacity!=PWMC_PARENT_MAP_CAP||r->call.input.native_flag!=in.native||
       r->call.input.system!=in.io.system||!pgcd_equal(&in.io,&r->call.io,sizeof(in.io))||r->call.complete!=1||r->call.unknown||r->call.error||
       in.opening>r->call.before.cpu.ticks||r->call.after.cpu.ticks<in.opening||r->call.after.cpu.ticks-in.opening>PGCD_FRESH_TICKS||
       r->call.map.bytes>PGCD_MAP_CAP||!pwmc_parent_map_valid(&r->call)||!pgcd_equal(hash,r->call.digest,32)||
       !pwmc_parent_in_image(&r->call.image_after,(uintptr_t)r,sizeof(*r)))return pbgi_fail(r,1);
    r->core=r->call.boot_address-0x1b800;
    struct pbgi_live live={.r=r,.in=in,.caller=input,.core=r->core,.bytes=r->call.map.bytes};
    pbgi_call_seal(&r->call,live.bytes,live.call_seal);
    pgcd_copy(live.full_call_seal,hash,32);
    if(!pbgi_tick(&live)||!pbgi_RAM(&live,r->core,PGCI_IMAGE_BYTES))return pbgi_fail(r,2);
    if(pwmc_parent_overlap(r->core,PGCI_IMAGE_BYTES,(uintptr_t)r->call.image_after.base,r->call.image_after.bytes)||
       !pbgi_page(&live,&r->key_AT,(r->core+0x1cdb0)&~UINT64_C(4095),read_page))return pbgi_fail(r,2);
    r->initial_key=pwfi_le((const void*)(uintptr_t)(r->core+0x1cdb0),8);
    if(r->initial_key!=r->call.map.key)return pbgi_fail(r,2);live.keyed=1;
    for(unsigned k=0;k<PBGI_CORE_PAGES;k++){
        if(!pbgi_page(&live,&r->Core_AT[k],r->core+4096*k,read_page)||r->core_pages!=k)return pbgi_fail(r,2);r->core_pages=k+1;
    }
    if(!pgci_verify((const void*)(uintptr_t)r->core,r->core,PGCI_IMAGE_BYTES,r->hashes[0],&r->hash_failed[0],&r->hash_count[0]))return pbgi_fail(r,3);
    const uint32_t locks[3]={0x1b340,0x1bd48,0x1c1f8};
    for(unsigned k=0;k<3;k++){pgcd_copy(r->roots.lock[k],(const void*)(uintptr_t)(r->core+locks[k]),24);
        if(pwfi_le(r->roots.lock[k],8)!=16||pwfi_le(r->roots.lock[k]+8,8)!=4||pwfi_le(r->roots.lock[k]+16,4)!=1)return pbgi_fail(r,3);}
    pgcd_copy(r->roots.head[0],(const void*)(uintptr_t)(r->core+0x1b358),16);
    pgcd_copy(r->roots.head[1],(const void*)(uintptr_t)(r->core+0x1bd60),16);
    r->roots.key=pwfi_le((const void*)(uintptr_t)(r->core+0x1cdb0),8);
    r->roots.depth=pwfi_le((const void*)(uintptr_t)(r->core+0x1cc08),8);r->roots.busy=pwfi_le((const void*)(uintptr_t)(r->core+0x1dc10),8);
    r->roots.smm=pwfi_le((const void*)(uintptr_t)(r->core+0x1cb78),8);r->roots.TPL=pwfi_le((const void*)(uintptr_t)(r->core+0x1b098),8);
    pgcd_copy(r->pool,(const void*)(uintptr_t)(r->core+0x1d1a0),sizeof(r->pool));
    pgcd_copy(r->type_policy,(const void*)(uintptr_t)(r->core+0x1be68),sizeof(r->type_policy));
    if(r->roots.key!=r->call.map.key||r->roots.depth||r->roots.busy||r->roots.smm||r->roots.TPL!=4||pwfi_le(r->pool+16,4)!=4)return pbgi_fail(r,3);
    pbgi_root_seal(r,live.root_seal);live.rooted=1;
    for(unsigned list=0;list<2;list++){
        uint64_t head=r->core+(list?0x1bd60:0x1b358),prior=head,next=r->roots.head[list][0];
        while(next!=head){
            unsigned k=r->count[list];if(k==PBGI_NODES||next<(list?32u:8u)||(next&7))return pbgi_fail(r,4);
            uint64_t address=next-(list?32u:8u);unsigned bytes=list?120:64;
            if(address>UINT64_MAX-bytes||address+bytes>UINT64_MAX-4095||(list&&(address&127)))return pbgi_fail(r,4);
            if(list&&!polaris_efi_range_owned(r->call.data,r->call.map.bytes,r->call.map.stride,address&~UINT64_C(4095),4096,4))return pbgi_fail(r,4);
            if(!list&&(address<r->core||address+bytes>r->core+PGCI_IMAGE_BYTES))
                for(uint64_t page=address&~UINT64_C(4095);page<address+bytes;page+=4096)
                    if(!polaris_efi_range_owned(r->call.data,r->call.map.bytes,r->call.map.stride,page,4096,4))return pbgi_fail(r,4);
            if(pwmc_parent_overlap(address,bytes,(uintptr_t)r->call.image_after.base,r->call.image_after.bytes)||
               (list&&pwmc_parent_overlap(address,bytes,r->core,PGCI_IMAGE_BYTES)))return pbgi_fail(r,4);
            for(unsigned a=0;a<=list;a++)for(unsigned j=0;j<(a==list?k:r->count[a]);j++)
                if(pwmc_parent_overlap(address,bytes,r->node[a][j].address,r->node[a][j].bytes))return pbgi_fail(r,4);
            struct pbgi_node*n=&r->node[list][k];
            if(!pbgi_load(&live,n,address,bytes,read_page)||r->count[list]!=k)return pbgi_fail(r,4);
            const uint8_t*b=n->raw+(list?24:0);
            if(pwfi_le(b,8)!=(list?UINT64_C(0x6d646367):UINT64_C(0x70616d6d))||pwfi_le(b+16,8)!=prior)return pbgi_fail(r,4);
            if(list){
                if(pwfi_le(n->raw,4)!=UINT64_C(0x30646870)||pwfi_le(n->raw+8,4)!=4||pwfi_le(n->raw+16,8)!=120||
                   pwfi_le(n->raw+104,4)!=UINT64_C(0x6c617470)||pwfi_le(n->raw+112,8)!=120||
                   pwfi_le(b+24,8)>pwfi_le(b+32,8)||pwfi_le(b+32,8)>=UINT64_C(0x1000000000000)||pwfi_le(b+56,4)>3||pwfi_le(b+60,4))return pbgi_fail(r,4);
            }else if(n->raw[24]>1||pwfi_le(b+28,4)>14||(pwfi_le(b+32,8)&4095)||(pwfi_le(b+40,8)&4095)!=4095||
                pwfi_le(b+32,8)>pwfi_le(b+40,8)||pwfi_le(b+40,8)>=UINT64_C(0x1000000000000))return pbgi_fail(r,4);
            uint64_t lo=pwfi_le(b+(list?24:32),8),hi=pwfi_le(b+(list?32:40),8);
            for(unsigned j=0;j<k;j++){
                const uint8_t*old=r->node[list][j].raw+(list?24:0);
                if(lo<=pwfi_le(old+(list?32:40),8)&&pwfi_le(old+(list?24:32),8)<=hi)return pbgi_fail(r,4);
            }
            prior=next;next=pwfi_le(b+8,8);r->count[list]=k+1;
        }if(!r->count[list]||r->roots.head[list][1]!=prior)return pbgi_fail(r,4);
    }
    /* A lower accounting bound is only consistency, never a list of active
     * allocations or permission to borrow anything from the pool. */
    if(pwfi_le(r->pool+8,8)<UINT64_C(120)*r->count[1])return pbgi_fail(r,4);
    if(!pbgi_tick(&live))return pbgi_fail(r,5);
    for(unsigned list=0;list<2;list++)for(unsigned k=0;k<r->count[list];k++){
        const struct pbgi_node*n=&r->node[list][k];
        if(!pgcd_equal(n->raw,(const void*)(uintptr_t)n->address,n->bytes)||!pwmc_zero(n->raw+n->bytes,120-n->bytes))return pbgi_fail(r,5);
    }
    if(!pbgi_tick(&live))return pbgi_fail(r,5);
    for(unsigned list=0;list<2;list++)for(unsigned k=0;k<r->count[list];k++){
        const struct pbgi_node*n=&r->node[list][k];if(!pgcd_equal(n->raw,(const void*)(uintptr_t)n->address,n->bytes))return pbgi_fail(r,5);
    }
    if(!pgci_verify((const void*)(uintptr_t)r->core,r->core,PGCI_IMAGE_BYTES,r->hashes[1],&r->hash_failed[1],&r->hash_count[1])||
       !pbgi_stable(&live))return pbgi_fail(r,5);
    ppli_sha(&r->call,offsetof(struct pwmc_parent_map,digest),hash);
    if(!pgcd_equal(hash,live.full_call_seal,32)||!pgcd_equal(r->call.digest,live.full_call_seal,32))return pbgi_fail(r,5);
    ppli_sha(in.call,offsetof(struct pwmc_parent_map,digest),hash);
    if(!pgcd_equal(hash,live.full_call_seal,32)||!pgcd_equal(in.call->digest,live.full_call_seal,32))return pbgi_fail(r,5);
    r->unknown=0;r->complete=1;ppli_sha(r,offsetof(struct pbgi_result,digest),r->digest);return 1;
}
#endif
