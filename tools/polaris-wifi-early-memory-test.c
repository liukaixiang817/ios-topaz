/* Original APIs are software peers; firmware addresses are never called. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void text(const char*s){(void)s;}
void report(const char*s,uint64_t n){(void)s;(void)n;}
#define EFI_XNU_WIFI_REMOTE_MEMORY_AVAILABLE 1
#include "uefi-wifi-early-memory.h"
static uint8_t*arena;
static struct pwea_memory*r;
static struct pgcd_result old_view;
static unsigned checks;
#define CHECK(x) do{assert(x);checks++;}while(0)
static void begin(void)
{
    memset(arena,0,0x20000);r=(void*)arena;
    struct pwea_input input={(uintptr_t)arena,0x20000,UINT64_C(0x180000000),0x10000000};
    CHECK(pwea_begin(r,&input)==PWEA_WAIT);
}
static void descriptor(uint8_t*out,unsigned stride,unsigned type,uint64_t base,uint64_t bytes)
{
    struct efi_memory d={.type=type,.physical=base,.pages=bytes/4096,.attributes=8};
    memcpy(out,&d,sizeof(d));for(unsigned k=sizeof(d);k<stride;k++)out[k]=(uint8_t)(k*3);
}
static void map_reply(unsigned slot,unsigned stride)
{
    struct pwea_map*m=&r->map[slot];uint64_t split=slot?r->claim[slot-1].requested:UINT64_C(0x100000000);
    descriptor(m->data,stride,3,(uintptr_t)arena,0x20000);
    descriptor(m->data+stride,stride,2,UINT64_C(0x180000000),0x10000000);
    descriptor(m->data+2*stride,stride,7,0xc0000000,split-0xc0000000);
    if(slot)descriptor(m->data+3*stride,stride,2,split,UINT64_C(0x100000000)-split);
    m->map.status=0;m->map.bytes=(slot?4:3)*stride;m->map.key=10+slot;m->map.stride=stride;m->map.version=1;
}
static struct pwea_command next(unsigned n)
{
    struct pwea_command c;CHECK(pwea_next(r,&c)==PWEA_IO);
    CHECK(c.sequence==n+1&&c.operation==((n&1)?PWEA_ALLOCATE:PWEA_MAP)&&c.index==n/2);return c;
}
static void reply(const struct pwea_command*c,unsigned stride)
{if(c->operation==PWEA_MAP)map_reply(c->index,stride);else r->claim[c->index].status=0;}
static void run_prefix(unsigned calls,unsigned stride)
{
    for(unsigned n=0;n<calls;n++){
        struct pwea_command c=next(n);uint8_t seal[32];pwea_call_seal(r,seal);reply(&c,stride);
        CHECK(pwea_complete(r,&c,1,seal)==(n==4?PWEA_RETAINED:PWEA_WAIT));
    }
}
static void success(void)
{
    for(unsigned stride=40;stride<=64;stride+=8){
        begin();run_prefix(5,stride);
        CHECK(r->complete&&!r->unknown&&r->claim[0].retained&&r->claim[1].retained);
        CHECK(r->claim[0].requested==0xffe00000&&r->claim[0].bytes==0x200000&&r->claim[0].pages==512);
        CHECK(r->claim[0].exposed==0xffe00000&&r->claim[0].exposed_bytes==0x100000);
        CHECK(r->claim[1].requested==0xffbfe000&&r->claim[1].bytes==0x202000&&r->claim[1].pages==514);
        CHECK(r->claim[1].exposed==0xffbff000&&r->claim[1].exposed_bytes==0x200000);
        CHECK(r->map[2].map.bytes==4*stride); /* semantic merged type2 descriptor */
        struct pwea_command c;CHECK(pwea_next(r,&c)==PWEA_RETAINED);
        /* Existing late selector remains the same arithmetic wrapper. */
        memset(&old_view,0,sizeof(old_view));old_view.map[0]=r->map[0].map;
        memcpy(old_view.maps[0],r->map[0].data,PGCD_MAP_CAP);
        for(unsigned kind=0;kind<2;kind++){
            uint64_t a=0,b=0;CHECK(pwmc_select(&old_view,kind,&a));
            CHECK(pwmc_select_map(&old_view.map[0],old_view.maps[0],kind,&b)&&a==b);
        }
    }
}
static void map_failures(void)
{
    for(unsigned slot=0;slot<3;slot++)for(unsigned kind=0;kind<9;kind++){
        begin();run_prefix(slot*2,48);struct pwea_command c=next(slot*2);uint8_t seal[32];pwea_call_seal(r,seal);reply(&c,48);
        struct pwea_map*m=&r->map[slot];
        switch(kind){
        case 0:m->map.status=EFI_TOO_SMALL;break;case 1:m->map.bytes=PGCD_MAP_CAP+1;break;
        case 2:m->map.key=0;break;case 3:m->map.stride=39;break;case 4:m->map.version=2;break;
        case 5:((struct efi_memory*)(m->data+48))->type=7;break;
        case 6:((struct efi_memory*)m->data)->pages=UINT64_MAX;break;
        case 7:((struct efi_memory*)(m->data+48))->physical=(uintptr_t)arena;break;
        case 8:m->map.bytes--;break;
        }
        CHECK(pwea_complete(r,&c,1,seal)==PWEA_FAILED&&r->unknown&&!r->complete);
        CHECK(pwea_next(r,&c)==PWEA_FAILED);
    }
}
static void allocation_failures(void)
{
    for(unsigned slot=0;slot<2;slot++)for(unsigned kind=0;kind<4;kind++){
        begin();run_prefix(slot*2+1,48);struct pwea_command c=next(slot*2+1);uint8_t seal[32];pwea_call_seal(r,seal);reply(&c,48);
        if(kind==0)r->claim[slot].status=EFI_ERROR|9;
        if(kind==1)r->claim[slot].returned_address+=4096;
        if(kind==2)r->claim[slot].returned_address=0;
        CHECK(pwea_complete(r,&c,kind==3?0:1,seal)==PWEA_FAILED&&r->unknown&&!r->complete);
        CHECK(r->claim[slot].issued&&!r->claim[slot].retained);
        CHECK(pwea_next(r,&c)==PWEA_FAILED);
    }
}
static void delta_failures(void)
{
    for(unsigned slot=1;slot<3;slot++)for(unsigned kind=0;kind<7;kind++){
        begin();run_prefix(slot*2,48);struct pwea_command c=next(slot*2);uint8_t seal[32];pwea_call_seal(r,seal);reply(&c,48);
        struct pwea_map*m=&r->map[slot];struct efi_memory*d=(void*)(m->data+3*48);
        switch(kind){
        case 0:m->map.key=r->map[slot-1].map.key;break;
        case 1:d->type=7;break;case 2:d->attributes=0;break;case 3:d->virtual_address=d->physical;break;
        case 4:((struct efi_memory*)m->data)->attributes=0;break; /* unrelated source change */
        case 5:m->data[3*48+40]^=1;break; /* unknown descriptor extension must survive */
        case 6:d->physical+=4096;d->pages--;break; /* claimed first page missing */
        }
        CHECK(pwea_complete(r,&c,1,seal)==PWEA_FAILED&&r->unknown&&!r->complete);
        CHECK(!r->claim[slot-1].retained);
    }
}
static void control_failures(void)
{
    for(unsigned n=0;n<5;n++)for(unsigned kind=0;kind<8;kind++){
        begin();run_prefix(n,48);struct pwea_command c=next(n);uint8_t seal[32];pwea_call_seal(r,seal);reply(&c,48);
        switch(kind){
        case 0:r->input.bank+=4096;break;case 1:r->input.image_bytes--;break;
        case 2:r->command.address++;break;case 3:r->complete=1;break;
        case 4:r->claim[1].reserved=1;break;
        case 5:r->map[n==0?1:0].data[8191]^=1;break;
        case 6:r->map[c.index].map.issued=2;break;
        case 7:r->pending=2;break;
        }
        CHECK(pwea_complete(r,&c,1,seal)==PWEA_FAILED&&r->unknown);
    }
    begin();struct pwea_command c=next(0),other;
    CHECK(pwea_next(r,&other)==PWEA_FAILED);
    begin();CHECK(pwea_next(r,(void*)r)==PWEA_FAILED);
    begin();uint8_t seal[32]={0};CHECK(pwea_complete(r,&c,1,seal)==PWEA_FAILED);
    begin();struct pwea_input input={(uintptr_t)arena,0x20000,UINT64_C(0x180000000),0x10000000};
    CHECK(pwea_begin(r,&input)==PWEA_FAILED);
    memset(r,0,sizeof(*r));input.bank=(uintptr_t)arena;CHECK(pwea_begin(r,&input)==PWEA_FAILED);
    input.bank=UINT64_C(0x180000000);input.image_bytes=sizeof(*r)-1;CHECK(pwea_begin(r,&input)==PWEA_FAILED);
}
int main(void)
{
    CHECK(!posix_memalign((void**)&arena,4096,0x20000));
    success();map_failures();allocation_failures();delta_failures();control_failures();
    free(arena);printf("PASS %u early allocation checks (software only)\n",checks);return 0;
}
