/* Independent early-UEFI allocation producer, before payload/native/radio.
 * This uses the real incoming boot-services contract, not a late PGCD open,
 * a closed context, a synthesized ticket or an old map as a lifetime lease.
 * The engine below is DATA-only. A separate resident caller must qualify and
 * execute each original service and preserve its FP/source/callback envelope.
 * No remote exposure/free is provided. A returned error may have effects, so
 * every failure keeps attempted claims UNKNOWN and never issues cleanup.
 */
#ifndef POLARIS_UEFI_WIFI_EARLY_MEMORY_H
#define POLARIS_UEFI_WIFI_EARLY_MEMORY_H
#include "uefi-wifi-remote-memory.h"
#define PWEA_CALLS 5u
#define PWEA_MAPS 3u
enum pwea_result {PWEA_FAILED=-1,PWEA_WAIT,PWEA_IO,PWEA_RETAINED};
enum pwea_operation {PWEA_MAP=1,PWEA_ALLOCATE};
enum pwea_error {PWEA_OK,PWEA_ARGUMENT,PWEA_REENTRY,PWEA_MAP_ERROR,PWEA_RANGE,
    PWEA_RETURN,PWEA_ALLOC_ERROR,PWEA_DELTA,PWEA_EFFECT};
struct pwea_input {uint64_t image,image_bytes,bank,bank_bytes;};
struct pwea_map {struct pgcd_map map;uint8_t data[PGCD_MAP_CAP] __attribute__((aligned(8)));};
struct pwea_claim {
    uint64_t requested,bytes,pages,status,returned_address,exposed,exposed_bytes;
    uint32_t issued,returned,retained,reserved;
};
struct pwea_command {uint64_t address,pages;uint32_t sequence,operation,index,reserved;};
struct pwea_memory {
    struct pwea_input input;struct pwea_command command;
    uint32_t started,unknown,error,pending,calls,complete;
    struct pwea_claim claim[2];struct pwea_map map[PWEA_MAPS];
};
static inline int pwea_fail(struct pwea_memory*r,unsigned error)
{if(r){if(!r->error)r->error=error;r->unknown=1;}return PWEA_FAILED;}
static inline int pwea_disjoint(uint64_t a,uint64_t n,uint64_t b,uint64_t m)
{return a&&b&&n&&m&&a<=UINT64_MAX-n&&b<=UINT64_MAX-m&&!(a<b+m&&b<a+n);}
static inline int pwea_begin(struct pwea_memory*r,const struct pwea_input*input)
{
    if(!r||!input||!pwea_disjoint((uintptr_t)r,sizeof(*r),(uintptr_t)input,sizeof(*input))||
       !pwea_disjoint(input->image,input->image_bytes,input->bank,input->bank_bytes)||
       (input->image&4095)||(input->bank&4095)||(input->bank_bytes&4095)||
       (uintptr_t)r<input->image||sizeof(*r)>input->image_bytes||
       (uintptr_t)r-input->image>input->image_bytes-sizeof(*r)||!pwmc_zero(r,sizeof(*r)))return PWEA_FAILED;
    r->input=*input;r->started=1;return PWEA_WAIT;
}
static inline int pwea_next(struct pwea_memory*r,struct pwea_command*out)
{
    if(!r||!out||!r->started||r->unknown||r->error)return PWEA_FAILED;
    if(!pwea_disjoint((uintptr_t)r,sizeof(*r),(uintptr_t)out,sizeof(*out))||r->pending)return pwea_fail(r,PWEA_REENTRY);
    if(r->complete)return r->complete==1&&r->calls==PWEA_CALLS?PWEA_RETAINED:pwea_fail(r,PWEA_REENTRY);
    if(r->calls>=PWEA_CALLS)return pwea_fail(r,PWEA_REENTRY);
    struct pwea_command c={.sequence=r->calls+1,.operation=(r->calls&1)?PWEA_ALLOCATE:PWEA_MAP,.index=r->calls/2};
    if(c.operation==PWEA_MAP){
        struct pwea_map*m=&r->map[c.index];
        if(!pwmc_zero(m,sizeof(*m)))return pwea_fail(r,PWEA_REENTRY);
        m->map.bytes=PGCD_MAP_CAP;m->map.issued=1;
    }else{
        struct pwea_claim*q=&r->claim[c.index];const struct pwea_map*m=&r->map[c.index];
        if(!pwmc_zero(q,sizeof(*q))||!pwmc_select_map(&m->map,m->data,c.index,&c.address))return pwea_fail(r,PWEA_RANGE);
        uint64_t bytes=pwmc_bytes(c.index);
        if(!pwea_disjoint(c.address,bytes,r->input.image,r->input.image_bytes)||
           !pwea_disjoint(c.address,bytes,r->input.bank,r->input.bank_bytes)||
           (c.index&&!pwea_disjoint(c.address,bytes,r->claim[0].requested,r->claim[0].bytes)))return pwea_fail(r,PWEA_RANGE);
        c.pages=bytes/4096;q->requested=q->returned_address=c.address;q->bytes=bytes;q->pages=c.pages;q->issued=1;
    }
    r->command=c;r->pending=1;r->calls++;*out=c;return PWEA_IO;
}
/* Hash the whole control/history frame, excluding ONLY the exact current
 * service outputs. An original service cannot rewrite a previous map/claim,
 * its command, the lifetime inputs or any earlier output tail unnoticed.
 * The entire map capacity is a service output; all8192 bytes remain recorded. */
static inline void pwea_call_seal(const struct pwea_memory*r,uint8_t digest[32])
{
    const struct pwea_command*c=&r->command;uintptr_t lo=0,hi=0,lo2=0,hi2=0;
    if(c->operation==PWEA_MAP&&c->index<PWEA_MAPS){
        lo=(uintptr_t)&r->map[c->index].map;hi=lo+offsetof(struct pgcd_map,issued);
        lo2=(uintptr_t)r->map[c->index].data;hi2=lo2+PGCD_MAP_CAP;
    }else if(c->operation==PWEA_ALLOCATE&&c->index<2){
        lo=(uintptr_t)&r->claim[c->index].status;hi=lo+16;
    }
    struct pwfi_sha256 h;pwfi_init(&h);
    for(size_t k=0;k<sizeof(*r);k++){
        uintptr_t p=(uintptr_t)r+k;if((p>=lo&&p<hi)||(p>=lo2&&p<hi2))continue;
        pwfi_byte(&h,((const uint8_t*)r)[k]);
    }
    pwfi_final(&h,digest);
}
static inline int pwea_complete(struct pwea_memory*r,const struct pwea_command*c,int returned,const uint8_t before[32])
{
    if(!r||!c||!before||!r->started||r->unknown||r->error)return PWEA_FAILED;
    if(r->pending!=1||!r->calls||r->calls>PWEA_CALLS||c->sequence!=r->calls||
       !pgcd_equal(c,&r->command,sizeof(*c)))return pwea_fail(r,PWEA_REENTRY);
    uint8_t after[32];pwea_call_seal(r,after);
    if(!pgcd_equal(before,after,32))return pwea_fail(r,PWEA_EFFECT);
    if(returned!=1)return pwea_fail(r,PWEA_RETURN);
    if(c->operation==PWEA_MAP){
        if(c->index>=PWEA_MAPS)return pwea_fail(r,PWEA_REENTRY);
        struct pwea_map*m=&r->map[c->index];struct polaris_efi_memory check;m->map.returned=1;
        if(m->map.status||!m->map.key||m->map.version!=1||
           !polaris_efi_memory_check(m->data,m->map.bytes,PGCD_MAP_CAP,m->map.stride,&check))return pwea_fail(r,PWEA_MAP_ERROR);
        m->map.valid=1;
        if(!polaris_efi_range_owned(m->data,m->map.bytes,m->map.stride,r->input.bank,r->input.bank_bytes,2))return pwea_fail(r,PWEA_MAP_ERROR);
        if(c->index){
            struct pwea_claim*q=&r->claim[c->index-1];const struct pwea_map*prev=&r->map[c->index-1];
            if(!q->returned||q->status||q->returned_address!=q->requested||
               !pwmc_maps_delta(&prev->map,prev->data,&m->map,m->data,q->requested,q->bytes,0))return pwea_fail(r,PWEA_DELTA);
            q->exposed=q->requested+(c->index==2?4096:0);q->exposed_bytes=c->index==2?0x200000:0x100000;q->retained=1;
        }
        if(c->index==2){
            for(unsigned k=0;k<2;k++)if(r->claim[k].retained!=1||
               !polaris_efi_range_owned(m->data,m->map.bytes,m->map.stride,r->claim[k].requested,r->claim[k].bytes,2))return pwea_fail(r,PWEA_DELTA);
            r->complete=1;
        }
    }else{
        if(c->operation!=PWEA_ALLOCATE||c->index>=2)return pwea_fail(r,PWEA_REENTRY);
        struct pwea_claim*q=&r->claim[c->index];q->returned=1;
        if(q->status||q->returned_address!=q->requested)return pwea_fail(r,PWEA_ALLOC_ERROR);
    }
    r->pending=0;return r->complete?PWEA_RETAINED:PWEA_WAIT;
}
#endif
