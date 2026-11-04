/* Actual native authentication + source + locked allocation + channel.
 * Own firmware DATA only; all privileged leaves remain independent software. */
struct pwea_map;struct pmrd_at;struct pmni_translation;struct pmni_command;
static void channel_map(struct pwea_map*);
static void channel_prepare(void);
static int channel_read_at(struct pmrd_at*);
static void channel_write_at(struct pmni_translation*);
static int channel_raw(const struct pmni_command*,unsigned*);
#define PMDC_TEST_EXTRA_MAP channel_map
#define PMDC_TEST_PREPARE channel_prepare
#define PMRD_TEST_TRANSLATE channel_read_at
#define PMSN_TEST_AT_HOOK channel_write_at
#define PMSN_TEST_RAW_HOOK channel_raw
#define PMSN_TEST_ENTRY unused_auth_suite
#define EFI_XNU_MSS_SMEM_NATIVE_AVAILABLE 1
#define EFI_XNU_MSS_SFPB_IO_AVAILABLE 1
#define EFI_XNU_MSS_CHANNEL_NATIVE_AVAILABLE 1
#define POLARIS_MSS_SMEM_SOFTWARE_PEER 1
#define POLARIS_MSS_SMEM_ALLOCATE_SOFTWARE_PEER 1
#define POLARIS_MSS_CHANNEL_SOFTWARE_PEER 1
#include "polaris-mss-auth-native-test.c"
#include "uefi-mss-channel-native.h"
static uint8_t*sm_original,*sm_image,*sm_shadow;
static struct pmsq_state*sm;
static struct pmsl_lock*channel_lock;
static struct pmsa_state*channel_allocation;
static struct pmsx_state*channel;
static unsigned token,channel_fault,channel_stores,channel_rings,channel_read_ats,channel_raw_calls,channel_scenarios;
static void channel_map(struct pwea_map*m)
{
    struct efi_memory*d=(void*)(m->data+m->map.bytes);emit_descriptor((void*)d,0,PMSQ_BASE,PMSQ_BYTES);d->attributes=1;m->map.bytes+=40;
}
static void channel_prepare(void)
{
    sm_image=image_heap+0xa0000;memcpy(sm_image,sm_original,PWFI_IMAGE_BYTES);
    for(unsigned n=0;n<PWFI_RELOC_COUNT;n++)put(sm_image+pwfi_relocations[n],pwfi_le(sm_image+pwfi_relocations[n],8)+(uintptr_t)sm_image,8);
    put(sm_image+PWFI_IMAGEBASE_RVA,(uintptr_t)sm_image,8);
    uint8_t*c=sm_image+PWFC_CACHE_RVA;memset(c,0,PWFC_CACHE_BYTES);
    put(c,PMSQ_BASE,8);put(c+8,PMSQ_BASE,8);put(c+16,PMSQ_BYTES,4);put(c+20,0xc0000,4);
    put(c+24,615,2);put(c+32,(uintptr_t)sm_image+0x5cb0,8);put(c+40,3,4);
    put(c+96,PMSQ_BASE+0xb9000,8);put(c+104,0x7c000,4);put(c+108,32,4);
    put(c+112,32,4);put(c+116,0x7c000,4);put(c+528,0x49494953,4);put(c+532,PMSQ_BYTES,4);
    put(c+536,PMSQ_BASE,8);put(c+544,615,2);
    for(unsigned n=0;n<8;n++)put(c+552+8*n,0x1f40000+4096*n,8);
    put(c+616,0x1fd4000,8);put(c+624,0x1fd4004,8);

    uint8_t*entry=image_heap+0x23000,*i=image_heap+0x23200,*h=image_heap+0x23300;
    static const efi_guid guid={0xf4e5c7d0,0xd239,0x47cb,{0xaa,0xcd,0x7f,0x66,0xef,0x76,0x32,0x38}};
    put(entry,0x65747270,8);put(entry+8,(uintptr_t)core+PMLI_HEAD,8);put(entry+16,(uintptr_t)image_heap+0x7008,8);memcpy(entry+24,&guid,16);
    put(image_heap+0x7008,(uintptr_t)entry+8,8);put(core+PMLI_HEAD+8,(uintptr_t)entry+8,8);
    put(entry+40,(uintptr_t)i+32,8);put(entry+48,(uintptr_t)i+32,8);
    put(i,0x63666970,8);put(i+24,(uintptr_t)h,8);put(i+32,(uintptr_t)entry+40,8);put(i+40,(uintptr_t)entry+40,8);
    put(i+48,(uintptr_t)entry,8);put(i+56,(uintptr_t)sm_image+0x7090,8);put(h,0x6c646e68,8);
    uint8_t*li=image_heap+0x24000,*lh=image_heap+0x24100,*meta=image_heap+0x24180;
    put(image_heap+0x7420,(uintptr_t)li+32,8);put(image_heap+0x230,(uintptr_t)li+32,8);
    put(li,0x63666970,8);put(li+8,(uintptr_t)lh+24,8);put(li+16,(uintptr_t)lh+24,8);put(li+24,(uintptr_t)lh,8);
    put(li+32,(uintptr_t)image_heap+0x228,8);put(li+40,(uintptr_t)image_heap+0x7420,8);
    put(li+48,(uintptr_t)image_heap+0x200,8);put(li+56,(uintptr_t)meta,8);
    put(lh,0x6c646e68,8);put(lh+24,(uintptr_t)li+8,8);put(lh+32,(uintptr_t)li+8,8);
    struct efi_loaded loaded={.revision=0x1000,.system=s,.base=sm_image,.bytes=PWFI_IMAGE_BYTES,.code_type=3,.data_type=4};memcpy(meta,&loaded,sizeof(loaded));
    put(image_heap+0x9008,(uintptr_t)image_heap+0x21008,8);put(image_heap+0x9020,PMSQ_BASE+PMSQ_BYTES-1,8);put(image_heap+0x9038,1,4);
    uint8_t*q=image_heap+0x21000;put(q,0x6d646367,8);put(q+8,(uintptr_t)core+PMRG_HEAD,8);put(q+16,(uintptr_t)image_heap+0x9008,8);
    put(q+24,PMSQ_BASE+PMSQ_BYTES,8);put(q+32,UINT64_MAX,8);put(q+40,1,8);put(q+48,1,8);put(q+56,3,4);put(core+PMRG_HEAD+8,(uintptr_t)q+8,8);
}
static int channel_read_at(struct pmrd_at*t)
{
    if(t->page<PMSQ_BASE||t->page>=PMSQ_BASE+PMSQ_BYTES)return -1;
    t->saved=t->restored=0x123;t->par=UINT64_C(0x4400000000000b00)|t->page;t->issued=t->returned=1;channel_read_ats++;return 1;
}
static void channel_write_at(struct pmni_translation*t)
{
    if(t->page<PMSQ_BASE||t->page>=PMSQ_BASE+PMSQ_BYTES)return;
    t->read_par=t->write_par=UINT64_C(0x4400000000000b00)|t->page;
    if(channel&&channel->pending&&channel_fault==2)t->write_par|=1;
}
static int channel_raw(const struct pmni_command*c,unsigned*out)
{
    if(!channel_lock)return -1;
    if(c->address==PMSL_ADDRESS){
        if(c->kind==PMNI_READ)*out=token;
        else{CHECK(c->kind==PMNI_WRITE&&c->value<=1);if(c->value)CHECK(!token);else CHECK(token==1);token=c->value;}return 1;
    }
    if(c->kind==PMNI_FULL_ORDER)return 1;
    if(channel&&channel->pending==2&&c->address==PMS_DOORBELL){
        CHECK(c->kind==PMNI_WRITE&&(c->value==0x4000||c->value==0x1000||!c->value));channel_raw_calls++;
        if(channel_fault==5)return 0;if(c->value)channel_rings++;
#ifdef PMSX_TEST_RING_HOOK
        PMSX_TEST_RING_HOOK(c);
#endif
        return 1;
    }
    return -1;
}
static void pmsq_order(void){}
static int pmsq_word(uint64_t at,uint32_t*out)
{
    CHECK(at>=PMSQ_BASE&&at<PMSQ_BASE+PMSQ_BYTES&&!(at&3));
#ifdef PMSX_TEST_WORD_HOOK
    PMSX_TEST_WORD_HOOK(at);
#endif
    memcpy(out,sm_shadow+at-PMSQ_BASE,4);return 1;
}
static int pmsa_store(uint64_t at,uint32_t value,uint32_t*out)
{CHECK(token==1&&at>=PMSQ_BASE&&at<PMSQ_BASE+PMSQ_BYTES);put(sm_shadow+at-PMSQ_BASE,value,4);*out=value;return 1;}
static int pmsx_store(uint64_t at,uint32_t value,uint32_t*out)
{
    CHECK(channel&&channel->pending==1&&!token&&auth_owner->complete&&modem_owner==2);channel_stores++;
    put(sm_shadow+at-PMSQ_BASE,value,4);*out=value;
    if(channel_fault==1)return 0;
    if(channel_fault==3)sm_image[PWFC_CACHE_RVA+112]^=8;
    if(channel_fault==4)owner_delay=PMSC_TOTAL+1;
    return 1;
}
static void channel_partition(unsigned index,unsigned offset,unsigned bytes,unsigned hosts)
{
    uint8_t*t=sm_shadow+PMSQ_BYTES-4096+32+48*index,*h=sm_shadow+offset;
    put(t,offset,4);put(t+4,bytes,4);put(t+12,hosts,4);put(t+16,32,4);
    put(h,0x54525024,4);put(h+4,hosts,4);put(h+8,bytes,4);put(h+12,32,4);put(h+16,bytes,4);
}
static void channel_setup(void)
{
    channel=0;channel_lock=0;sm=0;channel_fault=channel_stores=channel_rings=channel_raw_calls=token=0;channel_scenarios++;
    auth_setup(0);auth_success();
    CHECK(0x4300000+sizeof(*auth_copy)<0x7700000);
    sm=(void*)(arena+0x7700000);channel_lock=(void*)(arena+0x7710000);channel_allocation=(void*)(arena+0x7740000);
    CHECK(sizeof(*sm)<0x10000&&sizeof(*channel_lock)<0x30000&&sizeof(*channel_allocation)<0x40000);
    memset(sm,0,sizeof(*sm));memset(channel_lock,0,sizeof(*channel_lock));memset(channel_allocation,0,sizeof(*channel_allocation));
    CHECK(pmsq_capture(sm,resource_map)&&pmsl_acquire(channel_lock,sm));
    memset(sm_shadow,0,PMSQ_BYTES);put(sm_shadow+92,0xc0000,4);put(sm_shadow+192,1,4);
    uint8_t*t=sm_shadow+PMSQ_BYTES-4096;put(t,0x434f5424,4);put(t+4,1,4);put(t+8,2,4);
    channel_partition(0,0x1000,0x88000,0xfffefffe);channel_partition(1,0xb9000,0x7c000,0x10000);
    CHECK(pmsa_prepare(channel_allocation,channel_lock)&&pmsa_publish(channel_allocation)&&pmsl_release(channel_lock)&&pmsa_current(channel_allocation));
    channel=(void*)(arena+0x7780000);memset(channel,0,sizeof(*channel));CHECK(pmsx_begin(channel,auth_owner,channel_allocation));
}
#ifndef PMSX_TEST_ENTRY
#define PMSX_TEST_ENTRY main
#endif
int PMSX_TEST_ENTRY(int argc,char**argv)
{
    CHECK(argc==7);sm_original=malloc(PWFI_IMAGE_BYTES);sm_shadow=malloc(PMSQ_BYTES);CHECK(sm_original&&sm_shadow);
    FILE*f=fopen(argv[6],"rb");CHECK(f&&fread(sm_original,1,PWFI_IMAGE_BYTES,f)==PWFI_IMAGE_BYTES&&!fclose(f));auth_test_open(6,argv);
    channel_setup();CHECK(pmsx_write(channel,0,0,0x504d5324)&&pmsx_read(channel,channel->item[0].data,4));
    CHECK(pmsx_ring(channel,0)&&channel_rings==1&&channel_raw_calls==2);
    CHECK(!pmsx_write(channel,1,4,8)&&!pmsx_write(channel,2,0,1)&&!pmsx_ring(channel,1));
    CHECK(!pmsx_write(channel,0,340,0)&&!pmsx_write(channel,0,1,0)&&!pmsx_write(channel,3,0,0));
    struct pmsx_state*second=(void*)(arena+0x7790000);memset(second,0,sizeof(*second));CHECK(!pmsx_begin(second,auth_owner,channel_allocation));
    fprintf(stderr,"actual native auth/source/allocation/SMP2P word+doorbell PASS; checking failures\n");
    for(unsigned fault=1;fault<=5;fault++){
        channel_setup();channel_fault=fault;
        CHECK(!(fault==5?pmsx_ring(channel,0):pmsx_write(channel,0,0,0x504d5324))&&channel->unknown);
        unsigned calls=channel_stores+channel_raw_calls;CHECK(!pmsx_write(channel,0,4,1)&&!pmsx_ring(channel,0)&&calls==channel_stores+channel_raw_calls);
    }
    auth_test_close();free(sm_original);free(sm_shadow);
    printf("PASS %u native channel checks, %u scenarios; software privileged leaves only\n",checks,channel_scenarios);return 0;
}
