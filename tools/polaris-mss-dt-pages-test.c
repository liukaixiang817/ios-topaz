/* Own DT-only QDSP/RMB namespace admission composed with the real native MBA
 * caller. CPU/SMC/register leaves remain SOFTWARE; no device is accessed. */
struct pmni_translation;
static void dt_pages_at(struct pmni_translation*);
static unsigned dt_pages_fault;
#define PMBN_TEST_AT_HOOK dt_pages_at
#define PMBN_TEST_ENTRY unused_boot_suite
#define PMRG_TEST_UNREGISTERED_MSS 1
#define PMRG_TEST_UNREGISTERED_PDC 1
#define PMRG_TEST_UNREGISTERED_RESTART 1
#include "polaris-mss-boot-native-test.c"
static void dt_pages_at(struct pmni_translation*t)
{
    if(t->page!=0x4080000)return;
    if(dt_pages_fault==1)t->read_par=t->write_par=t->page|0x201;
    if(dt_pages_fault==2)t->read_par=t->write_par=UINT64_C(0xff00000000000b80)|t->page;
    if(dt_pages_fault==3)t->write_par^=4096;
    if(dt_pages_fault==4)t->restored++;
    if(dt_pages_fault==5)t->read_par=t->write_par=(t->page+4096)|0x200;
}
int main(int argc,char**argv)
{
    aop_test_open(argc,argv);boot_setup();CHECK(pmbn_begin(boot_owner,boot_records,aop_owner));
    CHECK(boot_drive()&&pmbn_current(boot_owner)&&target_protected);unsigned native_gap=0,cases=1;
    for(unsigned n=0;n<boot_owner->deliveries;n++){
        const struct pmbn_delivery*d=&boot_records[n];uint64_t page=d->native.command.address&~UINT64_C(4095);
        if(page!=0x4080000&&page!=0x4180000)continue;
        for(unsigned side=0;side<2;side++)CHECK(d->target[side].complete&&!d->target[side].descriptor.type&&
            !d->target[side].descriptor.capabilities&&!d->target[side].descriptor.attributes);
        CHECK(d->native.complete&&d->native.AT.read_par==(page|0x200)&&d->native.issued&&d->native.returned);native_gap++;
    }CHECK(native_gap>10);
    CHECK(resource_page(0x4080000)&&resource_target->complete&&!resource_target->descriptor.type);
    CHECK(resource_page(0x4180000)&&resource_target->complete&&!resource_target->descriptor.type);
    CHECK(resource_page(0xb2e0000)&&resource_target->complete&&!resource_target->descriptor.type);
    CHECK(resource_page(0xc2b0000)&&resource_target->complete&&!resource_target->descriptor.type);
    CHECK(!resource_page(0xc2b1000)&&!resource_page(0xc2afff));
    CHECK(!resource_page(0x4084000)&&!resource_page(0x4081000)&&!resource_page(0xb2e1000));
    uint8_t raw[80];memcpy(raw,image_heap+0x70000,80);
    struct pweh_result*h=malloc(sizeof(*h));CHECK(h);memcpy(h,held,sizeof(*h));
    for(unsigned k=0;k<4;k++){
        uint64_t page=k==3?0xc2b0000:k==2?0xb2e0000:k?0x4180000:0x4080000;
        memcpy(raw,image_heap+(k==3?0x77000:k==2?0x75000:0x70000),80);
        CHECK(pmrg_device_descriptor(h,page,raw));
        for(unsigned fault=0;fault<16;fault++){
            uint8_t q[80];memcpy(q,raw,80);memcpy(h,held,sizeof(*h));
            if(fault<4)put(q+56,fault+1,4);
            if(fault==4)put(q+40,1,8);if(fault==5)put(q+40,8,8);
            if(fault==6)put(q+48,1,8);if(fault==7)put(q+48,8,8);
            if(fault==8)put(q+60,1,4);if(fault==9)put(q+64,1,8);if(fault==10)put(q+72,1,8);
            if(fault==11)put(q+24,page+1,8);if(fault==12)put(q+32,page+4094,8);
            if(fault==13)h->map.map.stride=0;if(fault==14)h->map.map.bytes=0;if(fault==15)h->map.map.bytes=sizeof(h->map.data)+1;
            CHECK(!pmrg_device_descriptor(h,page,q));cases++;
        }
        for(unsigned type=0;type<16;type++){
            memcpy(h,held,sizeof(*h));struct efi_memory*d=(void*)(h->map.data+h->map.map.bytes);
            CHECK(h->map.map.bytes+h->map.map.stride<=sizeof(h->map.data));memset(d,0,h->map.map.stride);
            d->type=type;d->physical=page;d->pages=1;h->map.map.bytes+=h->map.map.stride;
            CHECK(!pmrg_device_descriptor(h,page,raw));cases++;
        }
    }free(h);
    for(dt_pages_fault=1;dt_pages_fault<=5;dt_pages_fault++){
        boot_setup();CHECK(pmbn_begin(boot_owner,boot_records,aop_owner));CHECK(!boot_drive()&&boot_owner->error==3&&boot_calls==0);
        CHECK(boot_records[0].target[0].complete&&!boot_records[0].native.issued&&!boot_records[0].native.returned);
        unsigned calls=boot_calls;CHECK(pmbn_step(boot_owner)==PMBA_FAILED&&boot_calls==calls);cases++;
    }
    dt_pages_fault=0;boot_setup();CHECK(pmbn_begin(boot_owner,boot_records,aop_owner));
    put(image_heap+0x70000+48,1,8);CHECK(pmbn_step(boot_owner)==PMBA_FAILED&&resource_map->error==5&&!boot_calls);cases++;
    aop_test_close();printf("PASS %u DT-page namespace/native-negative scenarios / %u checks; SOFTWARE only\n",cases,checks);return 0;
}
