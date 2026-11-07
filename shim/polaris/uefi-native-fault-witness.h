/* Short, default-OFF remnant observation of ONE spent native diagnostic.
 * A candidate-specific nonce must match before its fixed record is read.
 * No old pointer is followed, no old RAM is written, and no native/radio
 * permission is inferred from remnants. Current map/AT/CPU guards still apply. */
#ifndef POLARIS_UEFI_NATIVE_FAULT_WITNESS_H
#define POLARIS_UEFI_NATIVE_FAULT_WITNESS_H
#include "uefi-apps-watchdog-readonly.h"
#include "uefi-wifi-native-fault.h"
#include "../../tools/polaris-scalar-sha256.h"
struct pnfw_scalar {uint64_t address,maximum;uint32_t bytes,reserved;};
struct pnfw_config {
    struct pfnf_layout layout;
    uint64_t nonce,nonce_bytes;
    uint8_t nonce_sha256[32];
    uint64_t scalar_parent,scalar_parent_bytes;
    uint32_t scalar_count;
    struct pnfw_scalar scalar[64];
};
struct pnfw_ops {
    void *context;
    int (*arch)(void *,struct pawr_arch *);
    int (*translate)(void *,uint64_t,struct pawr_translation *);
    int (*read8)(void *,uint64_t,uint8_t *);
};
struct pnfw_result {
    uint32_t error,issued,returned,nonce_match[4],stable,zero,valid;
    uint32_t scalar_valid,scalar_stable;
    struct pawr_arch opening,closing;
    uint8_t raw[2][sizeof(struct pfnf_record)];
    struct pfnf_record record;
    uint64_t scalar_value[2][64];
};
static inline int pnfw_range(const struct pnfw_config*c,uint64_t address)
{
    if((address>=c->nonce&&address-c->nonce<c->nonce_bytes)||
       (address>=c->layout.record&&address-c->layout.record<sizeof(struct pfnf_record)))return 1;
    if(c->scalar_count>64)return 0;
    for(unsigned n=0;n<c->scalar_count;n++)if(address>=c->scalar[n].address&&
        address-c->scalar[n].address<c->scalar[n].bytes)return 1;
    return 0;
}
static inline int pnfw_mapped(const void*map,uint64_t bytes,uint64_t stride,uint64_t address,uint64_t count)
{
    uint64_t end=address+count,cursor=address;
    while(cursor<end){
        uint64_t next=cursor;
        for(uint64_t at=0;at<bytes;at+=stride){
            const struct efi_memory*m=(const void*)((const uint8_t*)map+at);
            uint64_t stop=m->physical+m->pages*4096;
            if(m->physical<=cursor&&cursor<stop&&(m->type==7||(m->type>=1&&m->type<=4))&&
               !(m->attributes>>63)&&(m->attributes&8))next=stop<end?stop:end;
        }
        if(next==cursor)return 0;cursor=next;
    }
    return 1;
}
static inline int pnfw_live(const struct pnfw_ops*o,const struct pawr_arch*opening)
{struct pawr_arch now={0};return o->arch(o->context,&now)&&pawr_arch_same(opening,&now);}
static inline int pnfw_read(const struct pnfw_config*c,const struct pnfw_ops*o,struct pnfw_result*r,
    uint64_t address,uint64_t bytes,uint8_t*out,struct psha_sha256*hash)
{
    for(uint64_t n=0;n<bytes;n++){
        uint64_t at=address+n;
        if(!pnfw_range(c,at)||(!(n&31)&&!pnfw_live(o,&r->opening))){r->error=3;return 0;}
        if(!n||!(at&4095)){
            struct pawr_translation t={0};uint64_t page=at&~UINT64_C(4095);
            if(!o->translate(o->context,at,&t)||t.saved!=t.restored||
               t.par!=(UINT64_C(0xff00000000000b80)|page)){r->error=4;return 0;}
        }
        uint8_t v=0;r->issued++;
        if(!o->read8(o->context,at,&v)){r->error=5;return 0;}
        r->returned++;if(out)out[n]=v;if(hash)psha_byte(hash,v);
    }
    return 1;
}
static inline int pnfw_nonce(const struct pnfw_config*c,const struct pnfw_ops*o,struct pnfw_result*r,unsigned pass)
{
    struct psha_sha256 hash;uint8_t digest[32];psha_init(&hash);
    if(pass>=4||!pnfw_read(c,o,r,c->nonce,c->nonce_bytes,0,&hash))return 0;
    psha_final(&hash,digest);unsigned different=0;
    for(unsigned n=0;n<32;n++)different|=digest[n]^c->nonce_sha256[n];
    if(different){r->error=6;return 0;}r->nonce_match[pass]=1;return 1;
}
static inline int pnfw_run(const struct pnfw_config*c,const void*map,uint64_t bytes,uint64_t capacity,
    uint64_t stride,uint32_t version,const struct pnfw_ops*o,struct pnfw_result*r)
{
    if(!r)return 0;
    for(size_t n=0;n<sizeof(*r);n++)((uint8_t*)r)[n]=0;
    struct polaris_efi_memory checked={0};
    if(!c||!pfnf_layout_valid(&c->layout)||c->layout.image_bytes>UINT64_C(0x8000000)||
       !c->nonce_bytes||c->nonce_bytes>4096||
       !pfnf_inside(c->layout.image,c->layout.image_bytes,c->nonce,c->nonce_bytes)||
       !pfnf_disjoint(c->nonce,c->nonce_bytes,c->layout.record,sizeof(struct pfnf_record))||
       version!=1||!polaris_efi_memory_check(map,bytes,capacity,stride,&checked)||
       !pnfw_mapped(map,bytes,stride,c->nonce,c->nonce_bytes)||
       !pnfw_mapped(map,bytes,stride,c->layout.record,sizeof(struct pfnf_record))||
       c->scalar_count>64){r->error=1;return 0;}
    if(c->scalar_count){
        unsigned total=0;
        if(!pfnf_inside(c->layout.image,c->layout.image_bytes,c->scalar_parent,c->scalar_parent_bytes)||
           !pfnf_disjoint(c->scalar_parent,c->scalar_parent_bytes,c->nonce,c->nonce_bytes)||
           !pfnf_disjoint(c->scalar_parent,c->scalar_parent_bytes,c->layout.record,sizeof(struct pfnf_record))){r->error=10;return 0;}
        for(unsigned n=0;n<c->scalar_count;n++){
            const struct pnfw_scalar*s=&c->scalar[n];total+=s->bytes;
            if((s->bytes!=4&&s->bytes!=8)||s->reserved||(s->address&(s->bytes-1))||
               !pfnf_inside(c->scalar_parent,c->scalar_parent_bytes,s->address,s->bytes)||
               !pnfw_mapped(map,bytes,stride,s->address,s->bytes)||
               (s->bytes==4&&s->maximum>UINT32_MAX)){r->error=10;return 0;}
            for(unsigned j=0;j<n;j++)if(!pfnf_disjoint(s->address,s->bytes,c->scalar[j].address,c->scalar[j].bytes)){
                r->error=10;return 0;
            }
        }
        if(total>512||c->scalar[0].bytes!=4||c->scalar[0].maximum!=1){r->error=10;return 0;}
    }else if(c->scalar_parent||c->scalar_parent_bytes){r->error=10;return 0;}
    if(!o||!o->arch||!o->translate||!o->read8||!o->arch(o->context,&r->opening)||
       !pawr_arch_valid(&r->opening)){r->error=2;return 0;}
    for(unsigned pass=0;pass<2;pass++){
        if(!pnfw_nonce(c,o,r,pass))return 0;
        if(!pnfw_read(c,o,r,c->layout.record,sizeof(struct pfnf_record),r->raw[pass],0))return 0;
    }
    if(!o->arch(o->context,&r->closing)||!pawr_arch_same(&r->opening,&r->closing)){r->error=3;return 0;}
    unsigned different=0,nonzero=0;
    for(unsigned n=0;n<sizeof(struct pfnf_record);n++){
        different|=r->raw[0][n]^r->raw[1][n];nonzero|=r->raw[0][n];
    }
    if(different){r->error=7;return 0;}r->stable=1;
    if(!nonzero){r->zero=1;return 1;}
    for(unsigned n=0;n<sizeof(struct pfnf_record);n++)((uint8_t*)&r->record)[n]=r->raw[0][n];
    const uint8_t*a=(const void*)&r->record.layout,*b=(const void*)&c->layout;
    for(unsigned n=0;n<sizeof(c->layout);n++)if(a[n]!=b[n]){r->error=8;return 0;}
    struct pfnf_record*f=&r->record;
    if(f->attempted!=1||f->armed>1||f->entered>1||f->reentered>1||f->error>4||f->draw_result>1||
       f->boot_phase>6||f->parent_phase>46||f->parent_unknown>1||f->parent_error>5||
       f->copy_pages>30720||f->copy_segments>28||f->copy_error>12||f->copy_ready>1||
       f->auth_phase>14||f->owner_held>1||f->owner_error>6||
       (f->entered&&(f->vector>15||!f->ticks))){r->error=9;return 0;}
    r->valid=1;
    if(!c->scalar_count)return 1;
    /* Additional fixed scalar fields are read only AFTER the two nonce/record
     * passes validated. No scalar value is ever followed as an old pointer. */
    for(unsigned pass=0;pass<2;pass++){
        if(!pnfw_nonce(c,o,r,pass+2))return 0;
        for(unsigned n=0;n<c->scalar_count;n++){
            uint8_t data[8]={0};const struct pnfw_scalar*s=&c->scalar[n];
            if(!pnfw_read(c,o,r,s->address,s->bytes,data,0))return 0;
            for(unsigned b=0;b<s->bytes;b++)r->scalar_value[pass][n]|=(uint64_t)data[b]<<(8*b);
        }
    }
    if(!o->arch(o->context,&r->closing)||!pawr_arch_same(&r->opening,&r->closing)){r->error=3;return 0;}
    for(unsigned n=0;n<c->scalar_count;n++)if(r->scalar_value[0][n]!=r->scalar_value[1][n]){r->error=11;return 0;}
    r->scalar_stable=1;
    for(unsigned n=0;n<c->scalar_count;n++)if(r->scalar_value[0][n]>c->scalar[n].maximum){r->error=12;return 0;}
    if(r->scalar_value[0][0]!=1){r->error=12;return 0;}
    r->scalar_valid=1;return 1;
}
#endif
