/* Complete LoadedImage metadata from the parent's existing enumeration.
 * No enumeration/map/allocation/provider call is added. These snapshots end
 * before the original handle-array FreePool; they are not an MSS map or an
 * immutable image/source, interrupt-owner or remote-memory permission. */
#ifndef POLARIS_UEFI_WIFI_PARENT_IMAGES_H
#define POLARIS_UEFI_WIFI_PARENT_IMAGES_H
#include "uefi-memory.h"
#include "../../tools/polaris-wifi-firmware-identity.h"
#define PPLI_MAX 256u
#define PPLI_MAP_CAP 65536u
struct ppli_at {
    uint64_t page,saved,par,restored;
    uint32_t issued,returned,native[2],native_issued,native_returned;
};
struct ppli_entry {
    uint64_t handle,address;
    struct efi_loaded image[2];
    struct ppli_at AT[2][2];
    uint32_t pages[2],native[2][2];
};
struct ppli_map {uint64_t key,bytes,stride;uint8_t digest[32];};
struct ppli_result {
    uint64_t native_flag,own_handle,system,handles,count,opening_ticks,closing_ticks;
    struct ppli_map map[2];
    uint32_t bound,attempted,unknown,error,complete,next[2],own_matches;
    uint32_t native[4],native_issued,native_returned;
    uint64_t handle_values[2][PPLI_MAX];struct ppli_at handles_AT[2][2];uint32_t handles_pages[2];
    struct ppli_entry entry[PPLI_MAX];
    uint8_t maps[2][PPLI_MAP_CAP] __attribute__((aligned(8)));
    uint8_t binding_digest[32],prefix_digest[2][32],digest[32];
};
static inline void ppli_copy(void*a,const void*b,size_t n)
{for(size_t k=0;k<n;k++)((uint8_t*)a)[k]=((const volatile uint8_t*)b)[k];}
static inline int ppli_equal(const void*a,const void*b,size_t n)
{unsigned z=0;for(size_t k=0;k<n;k++)z|=((const uint8_t*)a)[k]^((const uint8_t*)b)[k];return !z;}
static inline int ppli_zero(const void*a,size_t n)
{unsigned z=0;for(size_t k=0;k<n;k++)z|=((const uint8_t*)a)[k];return !z;}
static inline void ppli_sha(const void*p,size_t n,uint8_t out[32])
{struct pwfi_sha256 h;pwfi_init(&h);for(size_t k=0;k<n;k++)pwfi_byte(&h,((const uint8_t*)p)[k]);pwfi_final(&h,out);}
static inline int ppli_fail(struct ppli_result*r,unsigned e)
{if(!r->error)r->error=e;r->unknown=1;return 0;}
static inline int ppli_range(uint64_t a,uint64_t n)
{return a&&n&&a<=UINT64_MAX-n&&a+n<=UINT64_MAX-4095;}
static inline int ppli_overlap(uint64_t a,uint64_t n,uint64_t b,uint64_t z)
{return a<b+z&&b<a+n;}
static inline int ppli_owned(const struct ppli_result*r,unsigned pass,uint64_t a,uint64_t n,unsigned code,unsigned data)
{
    if(pass>1||!ppli_range(a,n))return 0;
    const struct ppli_map*m=&r->map[pass];
    struct polaris_efi_memory checked;
    if(!polaris_efi_memory_check(r->maps[pass],m->bytes,PPLI_MAP_CAP,m->stride,&checked))return 0;
    for(uint64_t page=a&~UINT64_C(4095);page<a+n;page+=4096){
        unsigned found=0;
        for(uint64_t off=0;off<m->bytes;off+=m->stride){
            const struct efi_memory*d=(const void*)(r->maps[pass]+off);
            if(page>=d->physical&&page-d->physical<d->pages*4096&&
               (d->type==code||d->type==data)&&(d->attributes>>63)==(d->type==5||d->type==6)&&(d->attributes&15)==8)found++;
        }
        if(found!=1)return 0;
    }
    return 1;
}
static inline int ppli_live(const struct ppli_result*r)
{
    uint8_t digest[32];ppli_sha(r,offsetof(struct ppli_result,closing_ticks),digest);
    return r->bound==1&&r->attempted==1&&r->unknown==1&&!r->error&&!r->complete&&!r->closing_ticks&&
        r->count&&r->count<=PPLI_MAX&&r->next[0]<=r->count&&r->next[1]<=r->count&&
        ppli_equal(digest,r->binding_digest,32);
}
static inline int ppli_bind(struct ppli_result*r,const volatile uint32_t*native,uint64_t handle)
{
    if(!r||!native||!handle||!ppli_zero(r,sizeof(*r)))return 0;
    r->native_flag=(uintptr_t)native;r->own_handle=handle;r->bound=1;return 1;
}
static inline int ppli_native(struct ppli_result*r,unsigned slot)
{
    const volatile uint32_t*flag=(const void*)(uintptr_t)r->native_flag;
    r->native_issued|=1u<<slot;__asm__ volatile("":::"memory");r->native[slot]=*flag;
    __asm__ volatile("":::"memory");r->native_returned|=1u<<slot;return !r->native[slot];
}
static inline void ppli_map_digest(const struct ppli_result*r,unsigned pass,uint8_t out[32])
{
    struct pwfi_sha256 h;pwfi_init(&h);
    for(size_t k=0;k<offsetof(struct ppli_map,digest);k++)pwfi_byte(&h,((const uint8_t*)&r->map[pass])[k]);
    for(size_t k=0;k<PPLI_MAP_CAP;k++)pwfi_byte(&h,r->maps[pass][k]);pwfi_final(&h,out);
}
static inline int ppli_map_capture(struct ppli_result*r,unsigned pass,const void*map,uint64_t bytes,uint64_t stride,uint64_t key)
{
    struct polaris_efi_memory checked;
    if(pass>1||!map||!key||!polaris_efi_memory_check(map,bytes,PPLI_MAP_CAP,stride,&checked)||
       !ppli_zero(&r->map[pass],sizeof(r->map[pass])))return ppli_fail(r,2);
    r->map[pass].key=key;r->map[pass].bytes=bytes;r->map[pass].stride=stride;
    ppli_copy(r->maps[pass],map,PPLI_MAP_CAP);ppli_map_digest(r,pass,r->map[pass].digest);return 1;
}
static inline int ppli_array(struct ppli_result*r,unsigned pass,int(*page_read)(struct ppli_at*))
{
    const uint64_t handles=r->handles,count=r->count,flag=r->native_flag;
    if(!page_read||!ppli_live(r)||!ppli_owned(r,pass,handles,count*8,3,4))return ppli_fail(r,3);
    unsigned pages=0;
    for(uint64_t page=handles&~UINT64_C(4095);page<handles+count*8;page+=4096){
        struct ppli_at at={.page=page};at.native_issued=1;at.native[0]=*(const volatile uint32_t*)(uintptr_t)flag;at.native_returned=1;
        if(at.native[0]){r->handles_AT[pass][pages]=at;return ppli_fail(r,4);}
        int ok=page_read(&at);r->handles_AT[pass][pages]=at;
        if(!ppli_live(r)||r->handles!=handles||r->count!=count||r->native_flag!=flag||!ok||at.page!=page||
           at.issued!=1||at.returned!=1||at.saved!=at.restored||at.par!=(UINT64_C(0xff00000000000b80)|page)||
           at.native_issued!=1||at.native_returned!=1||at.native[0]||at.native[1])return ppli_fail(r,4);
        at.native_issued=3;at.native[1]=*(const volatile uint32_t*)(uintptr_t)flag;at.native_returned=3;
        r->handles_AT[pass][pages++]=at;if(at.native[1])return ppli_fail(r,4);
    }
    r->handles_pages[pass]=pages;ppli_copy(r->handle_values[pass],(const void*)(uintptr_t)handles,count*8);
    if(*(const volatile uint32_t*)(uintptr_t)flag||
       (pass&&!ppli_equal(r->handle_values[0],r->handle_values[1],sizeof(r->handle_values[0]))))return ppli_fail(r,4);
    return 1;
}
static inline int ppli_start(struct ppli_result*r,uint64_t system,uint64_t handles,uint64_t count,
    const void*map,uint64_t bytes,uint64_t stride,uint64_t key,uint64_t ticks,int(*page_read)(struct ppli_at*))
{
    if(!r||r->bound!=1||r->attempted||r->error||r->unknown||r->complete)return 0;
    r->attempted=r->unknown=1;
    if(!system||!count||count>PPLI_MAX||!ppli_range(handles,count*8)||!ticks||(handles&7)||(r->native_flag&3)||
       ppli_overlap(handles,count*8,(uintptr_t)r,sizeof(*r))||ppli_overlap(r->native_flag,4,(uintptr_t)r,sizeof(*r))||
       ppli_overlap(handles,count*8,r->native_flag,4))return ppli_fail(r,1);
    r->system=system;r->handles=handles;r->count=count;r->opening_ticks=ticks;
    ppli_sha(r,offsetof(struct ppli_result,closing_ticks),r->binding_digest);
    if(!ppli_map_capture(r,0,map,bytes,stride,key)||!ppli_owned(r,0,handles,count*8,3,4)||
       !ppli_owned(r,0,r->native_flag,4,3,4)||!ppli_owned(r,0,(uintptr_t)r,sizeof(*r),3,4)||!ppli_native(r,0)||!ppli_array(r,0,page_read))return ppli_fail(r,2);
    return 1;
}
static inline void ppli_prefix(const struct ppli_result*r,unsigned pass,uint8_t out[32])
{
    struct pwfi_sha256 h;pwfi_init(&h);
    const void*array_part[]={r->handle_values[pass],r->handles_AT[pass],&r->handles_pages[pass]};
    const size_t array_size[]={sizeof(r->handle_values[pass]),sizeof(r->handles_AT[pass]),4};
    for(unsigned p=0;p<3;p++)for(size_t k=0;k<array_size[p];k++)pwfi_byte(&h,((const uint8_t*)array_part[p])[k]);
    for(unsigned n=0;n<r->count;n++){
        const struct ppli_entry*e=&r->entry[n];
        const void*part[]={&e->handle,&e->address,&e->image[pass],e->AT[pass],&e->pages[pass],e->native[pass]};
        const size_t size[]={8,8,sizeof(e->image[pass]),sizeof(e->AT[pass]),4,8};
        for(unsigned p=0;p<6;p++)for(size_t k=0;k<size[p];k++)pwfi_byte(&h,((const uint8_t*)part[p])[k]);
    }
    pwfi_final(&h,out);
}
/* The supplied leaf only reads AT/PAR and exactly restores the saved PAR.
 * Its result is local until the fixed pointer/index inputs have been checked. */
static inline int ppli_capture(struct ppli_result*r,unsigned pass,unsigned index,uint64_t handle,uint64_t address,
    int(*page_read)(struct ppli_at*))
{
    if(!r||!ppli_live(r)||pass>1||index!=r->next[pass]||index>=r->count)return r?ppli_fail(r,4):0;
    const uint64_t count=r->count,flag=r->native_flag,system=r->system,own=r->own_handle;
    if(!page_read||!handle||handle!=r->handle_values[pass][index]||!ppli_range(address,sizeof(struct efi_loaded))||
       ppli_overlap(address,sizeof(struct efi_loaded),(uintptr_t)r,sizeof(*r))||
       ppli_overlap(address,sizeof(struct efi_loaded),flag,4)||
       !ppli_owned(r,pass,address,sizeof(struct efi_loaded),3,4))return ppli_fail(r,3);
    struct ppli_entry*e=&r->entry[index];
    if(!pass){
        for(unsigned n=0;n<index;n++)if(r->entry[n].handle==handle||r->entry[n].address==address)return ppli_fail(r,3);
        e->handle=handle;e->address=address;
    }else if(e->handle!=handle||e->address!=address)return ppli_fail(r,3);
    unsigned pages=0;
    for(uint64_t page=address&~UINT64_C(4095);page<address+sizeof(struct efi_loaded);page+=4096){
        struct ppli_at at={.page=page};at.native_issued=1;at.native[0]=*(const volatile uint32_t*)(uintptr_t)flag;at.native_returned=1;
        if(at.native[0])return ppli_fail(r,4);
        int ok=page_read(&at);
        e->AT[pass][pages]=at; /* Retain a partial/error leaf before refusal. */
        if(!ppli_live(r)||r->native_flag!=flag||r->system!=system||r->count!=count||r->own_handle!=own||r->next[pass]!=index||
           e->address!=address||e->handle!=handle||r->error||r->complete||r->unknown!=1||r->attempted!=1)return ppli_fail(r,4);
        if(!ok||at.page!=page||at.issued!=1||at.returned!=1||at.saved!=at.restored||
           at.par!=(UINT64_C(0xff00000000000b80)|page)||at.native_issued!=1||at.native_returned!=1||at.native[0]||at.native[1])return ppli_fail(r,4);
        at.native_issued=3;at.native[1]=*(const volatile uint32_t*)(uintptr_t)flag;at.native_returned=3;
        if(at.native[1])return ppli_fail(r,4);e->AT[pass][pages++]=at;
    }
    e->pages[pass]=pages;e->native[pass][0]=*(const volatile uint32_t*)(uintptr_t)flag;
    if(e->native[pass][0]||!ppli_owned(r,pass,address,sizeof(struct efi_loaded),3,4))return ppli_fail(r,4);
    ppli_copy(&e->image[pass],(const void*)(uintptr_t)address,sizeof(struct efi_loaded));
    e->native[pass][1]=*(const volatile uint32_t*)(uintptr_t)flag;
    const struct efi_loaded*i=&e->image[pass];uint64_t base=(uintptr_t)i->base;
    if(e->native[pass][1]||i->revision!=0x1000||(uintptr_t)i->system!=system||!ppli_range(base,i->bytes)||i->bytes>UINT64_C(67108864)||(base&4095)||
       (i->code_type!=1&&i->code_type!=3&&i->code_type!=5)||(i->data_type!=2&&i->data_type!=4&&i->data_type!=6)||
       !ppli_owned(r,pass,base,i->bytes,i->code_type,i->data_type))return ppli_fail(r,5);
    if(pass&&!ppli_equal(&e->image[0],i,sizeof(*i)))return ppli_fail(r,5);
    if(!pass&&handle==own){
        if(i->code_type!=3||i->data_type!=4||base>(uintptr_t)r||sizeof(*r)>i->bytes||
           (uintptr_t)r-base>i->bytes-sizeof(*r)||flag<base||flag-base>i->bytes-4)return ppli_fail(r,5);
        r->own_matches++;
    }
    r->next[pass]++;if(r->next[pass]==count)ppli_prefix(r,pass,r->prefix_digest[pass]);return 1;
}
static inline int ppli_second(struct ppli_result*r,const void*map,uint64_t bytes,uint64_t stride,uint64_t key,int(*page_read)(struct ppli_at*))
{
    if(!r||!ppli_live(r)||r->next[0]!=r->count||r->next[1]||r->own_matches!=1)return r?ppli_fail(r,4):0;
    if(!ppli_native(r,1))return ppli_fail(r,4);
    uint8_t actual[32];ppli_prefix(r,0,actual);if(!ppli_equal(actual,r->prefix_digest[0],32))return ppli_fail(r,6);
    return ppli_map_capture(r,1,map,bytes,stride,key)&&ppli_array(r,1,page_read)?1:ppli_fail(r,2);
}
static inline int ppli_finish(struct ppli_result*r,uint64_t closing_ticks)
{
    if(!r||!ppli_live(r)||r->next[0]!=r->count||r->next[1]!=r->count||r->own_matches!=1)return r?ppli_fail(r,4):0;
    if(r->map[0].bytes>PPLI_MAP_CAP||r->map[1].bytes>PPLI_MAP_CAP||r->native_issued!=3||r->native_returned!=3||
       !ppli_zero(r->native,sizeof(r->native)))return ppli_fail(r,6);
    uint8_t actual[32];ppli_prefix(r,0,actual);
    if(!ppli_equal(actual,r->prefix_digest[0],32)||!ppli_native(r,2)||r->map[0].key!=r->map[1].key||
       r->map[0].bytes!=r->map[1].bytes||r->map[0].stride!=r->map[1].stride||
       !ppli_equal(r->maps[0],r->maps[1],r->map[0].bytes)||closing_ticks<r->opening_ticks||
       closing_ticks-r->opening_ticks>UINT64_C(3840000))return ppli_fail(r,6);
    ppli_prefix(r,1,actual);if(!ppli_equal(actual,r->prefix_digest[1],32))return ppli_fail(r,6);
    if(r->map[0].bytes>PPLI_MAP_CAP)return ppli_fail(r,6);
    for(unsigned p=0;p<2;p++){ppli_map_digest(r,p,actual);if(!ppli_equal(actual,r->map[p].digest,32))return ppli_fail(r,6);}
    for(unsigned pass=0;pass<2;pass++){
        if(!ppli_zero(r->handle_values[pass]+r->count,(PPLI_MAX-r->count)*8))return ppli_fail(r,6);
        for(unsigned n=0;n<=r->count;n++){
            uint64_t address=n==r->count?r->handles:r->entry[n].address;
            uint64_t bytes=n==r->count?r->count*8:sizeof(struct efi_loaded);
            unsigned pages=(unsigned)(((address+bytes-1)>>12)-(address>>12)+1);
            unsigned recorded=n==r->count?r->handles_pages[pass]:r->entry[n].pages[pass];
            const struct ppli_at*AT=n==r->count?r->handles_AT[pass]:r->entry[n].AT[pass];
            if(pages>2||recorded!=pages)return ppli_fail(r,6);
            for(unsigned k=0;k<pages;k++)if(AT[k].page!=(address&~UINT64_C(4095))+4096*k||AT[k].issued!=1||AT[k].returned!=1||
                AT[k].saved!=AT[k].restored||AT[k].par!=(UINT64_C(0xff00000000000b80)|AT[k].page)||
                AT[k].native_issued!=3||AT[k].native_returned!=3||!ppli_zero(AT[k].native,sizeof(AT[k].native)))return ppli_fail(r,6);
            if(!ppli_zero(AT+pages,(2-pages)*sizeof(*AT)))return ppli_fail(r,6);
        }
    }
    if(!ppli_zero(r->entry+r->count,(PPLI_MAX-r->count)*sizeof(r->entry[0]))||!ppli_native(r,3))return ppli_fail(r,6);
    r->closing_ticks=closing_ticks;r->unknown=0;r->complete=1;
    ppli_sha(r,offsetof(struct ppli_result,digest),r->digest);return 1;
}
static inline int ppli_actual_page(struct ppli_at*a)
{
#if defined(__aarch64__) || defined(__arm64__)
    __asm__ volatile("mrs %0,par_el1":"=r"(a->saved));a->issued=1;
    __asm__ volatile("at s1e1r,%1\n\tisb\n\tmrs %0,par_el1":"=r"(a->par):"r"(a->page):"memory");a->returned=1;
    __asm__ volatile("msr par_el1,%1\n\tisb\n\tmrs %0,par_el1":"=r"(a->restored):"r"(a->saved):"memory");return 1;
#else
    (void)a;return 0;
#endif
}
#endif
