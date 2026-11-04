/* Original firmware is inert data. Actual current-owner/image/GCD producers
 * feed the RAM reader; no firmware API, MMIO, vote or secure call executes. */
static void rpmh_prepare(void);
#define PMMN_TEST_ARENA_BYTES 0x800000
#define PMMN_TEST_IMAGE_BYTES 0x7c0000
#define PMRG_TEST_PREPARE rpmh_prepare
#define PMRG_TEST_ENTRY unused_resource_suite
#include "polaris-mss-resource-map-test.c"
#define EFI_XNU_MSS_RPMH_STATE_AVAILABLE 1
#define POLARIS_MSS_RPMH_SOFTWARE_PEER 1
#include "uefi-mss-rpmh-state.h"
static uint8_t*rp_original,*rp_image;
static struct pmrd_state*state;
static unsigned rp_ats,rp_fault,rp_trigger,scenarios;
static void rp_list(uint8_t*q,unsigned size,unsigned count,uint8_t*node)
{put(q,size,4);put(q+4,count,4);put(q+8,(uintptr_t)node,8);put(q+16,(uintptr_t)node,8);}
static void rpmh_prepare(void)
{
    rp_image=image_heap+0x80000;memcpy(rp_image,rp_original,PWRPI_IMAGE_BYTES);
    for(unsigned n=0;n<PWRPI_RELOC_COUNT;n++)put(rp_image+pwrpi_relocs[n],pwfi_le(rp_image+pwrpi_relocs[n],8)+(uintptr_t)rp_image,8);
    put(rp_image+PWRPI_IMAGEBASE_RVA,(uintptr_t)rp_image,8);
    put(image_heap+0x1580+72,PWRPI_IMAGE_BYTES,8);
    static const efi_guid guid={0xe1d0b573,0xf29f,0x495d,{0x93,0x52,0xca,0x0d,0xd4,0x2a,0x0a,0x74}};
    memcpy(image_heap+0x118,&guid,16);
    uint8_t*i=image_heap+0x6000,*h=image_heap+0x6100;
    put(image_heap+0x128,(uintptr_t)i+32,8);put(image_heap+0x130,(uintptr_t)i+32,8);
    put(i,0x63666970,8);put(i+24,(uintptr_t)h,8);put(i+32,(uintptr_t)image_heap+0x128,8);
    put(i+40,(uintptr_t)image_heap+0x128,8);put(i+48,(uintptr_t)image_heap+0x100,8);
    put(i+56,(uintptr_t)rp_image+0xd0d8,8);put(h,0x6c646e68,8);
    put(rp_image+0xd2e8,1,4);
    put(rp_image+0xd2f8,(uintptr_t)image_heap+0x10004,8);
    put(image_heap+0x10004,(uintptr_t)image_heap+0x10104,8);put(image_heap+0x10104,16,4);
    for(unsigned n=0;n<5;n++){
        uint8_t*q=image_heap+0x10204+64*n;
        put(image_heap+0x10104+8+8*n,(uintptr_t)q,8);rp_list(q,40,n==2,n==2?image_heap+0x16004:0);
    }
    put(image_heap+0x16004,(uintptr_t)image_heap+0x16104,8);
    put(rp_image+0xd3e0,(uintptr_t)image_heap+0x10404,8);
    put(image_heap+0x10404,(uintptr_t)image_heap+0x10804,8);
    put(rp_image+0xd3e8,(uintptr_t)image_heap+0x10c04,8);
    for(unsigned n=0;n<8;n++){uint8_t*q=image_heap+0x10804+24*n;put(q,n,4);put(q+4,n<4?0:3,4);put(q+8,1234,8);}
    uint8_t*pool=image_heap+0x11004,*active=image_heap+0x11104,*free=image_heap+0x11144,*client=image_heap+0x12004;
    put(rp_image+0xd300,(uintptr_t)pool,8);put(pool,(uintptr_t)active,8);put(pool+8,(uintptr_t)free,8);
    rp_list(active,80,1,client);rp_list(free,80,0,0);put(client,2,4);put(client+0x34,UINT32_MAX,4);
    for(unsigned n=0;n<4;n++){uint8_t*q=image_heap+0x13004+32*n;put(client+0x10+8*n,(uintptr_t)q,8);rp_list(q,n<2?16:24,0,0);}
    memset(rp_image+0xd538,0,8+16*24);rp_image[0xd538]=1;put(rp_image+0xd53c,1,4);
    uint8_t*hal=rp_image+0xd538+48;put(hal+12,0x179c0000,4);put(hal+16,2,4);put(hal+20,1,1);put(hal+24,8,4);put(hal+28,16,4);
    put(rp_image+0xd2ec,3,4);put(rp_image+0xd2f0,(uintptr_t)image_heap+0x14004,8);
    static const unsigned addresses[]={0x30000,0x30010,0x30060},values[]={8,2,1};
    for(unsigned n=0;n<3;n++){
        uint8_t*q=image_heap+0x14004+24*n,*s=image_heap+0x15004+128*n;
        put(q,addresses[n],4);put(q+8,(uintptr_t)s,8);put(s,2,4);put(s+8,4,4);put(s+12,values[n],4);
        put(s+16,1,1);put(s+24,values[n],4);put(s+28,1,1);
    }
}
static int pmrd_translate(struct pmrd_at*t)
{
    rp_ats++;t->saved=0x123;t->restored=t->saved;t->par=UINT64_C(0xff00000000000b80)|t->page;t->issued=t->returned=1;
    if(rp_ats==rp_trigger){
        if(rp_fault==1)return 0;
        if(rp_fault==2)t->par|=1;
        if(rp_fault==3)t->restored++;
        if(rp_fault==4)t->page+=4096;
        if(rp_fault==5)put(core+0x1cdb0,101,8);
        if(rp_fault==6)owner_delay=PMSC_TOTAL+1;
        if(rp_fault==7)image_heap[0x15004+0x3f]^=1;
        if(rp_fault==8)rp_image[0x1000]^=1;
    }
    return 1;
}
static void rpmh_setup(void)
{
    scenarios++;rp_ats=rp_fault=rp_trigger=0;resource_setup();CHECK(resource_run());
    state=(void*)(arena+0x400000);CHECK(0x400000+sizeof(*state)<PMMN_TEST_IMAGE_BYTES);memset(state,0,sizeof(*state));
}
static int rpmh_run(void){return pmrd_capture(state,resource_map);}
#ifndef PMRD_TEST_ENTRY
#define PMRD_TEST_ENTRY main
#endif
int PMRD_TEST_ENTRY(int argc,char**argv)
{
    CHECK(argc==3);CHECK(!posix_memalign((void**)&arena,0x4000,PMMN_TEST_ARENA_BYTES));
    original=malloc(PGCI_IMAGE_BYTES);rp_original=malloc(PWRPI_IMAGE_BYTES);CHECK(original&&rp_original);
    FILE*f=fopen(argv[1],"rb");CHECK(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));
    f=fopen(argv[2],"rb");CHECK(f&&fread(rp_original,1,PWRPI_IMAGE_BYTES,f)==PWRPI_IMAGE_BYTES&&!fclose(f));
    host_page=(size_t)sysconf(_SC_PAGESIZE);CHECK(host_page&&host_page<=0x4000&&!(host_page&(host_page-1)));
    shadow_mapping=mmap(0,0x104000+2*host_page,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(shadow_mapping!=MAP_FAILED);
    shadow=shadow_mapping+host_page;CHECK(!mprotect(shadow,0x104000,PROT_READ|PROT_WRITE));
    heap_mapping=mmap(0,0x100000+2*host_page,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(heap_mapping!=MAP_FAILED);
    image_heap=heap_mapping+host_page;CHECK(!mprotect(image_heap,0x100000,PROT_READ|PROT_WRITE));
    rpmh_setup();int ok=rpmh_run();
    if(!ok)fprintf(stderr,"RPMh error%u reads%u/%u AT%u source%u/%u CPU%u\n",state->error,state->pass[0].reads,state->pass[1].reads,rp_ats,state->pass[0].source[0].hash_count,state->pass[0].source[0].hash_failed,owner->error);
    CHECK(ok&&pmrd_current(state,resource_map));unsigned total=rp_ats,reads=state->pass[1].reads;
    CHECK(state->pass[1].active_mask==15&&state->pass[1].clients[0]==1&&!state->pass[1].clients[1]&&state->pass[1].free_requests==1&&state->pass[1].cache_rows==3);
    for(unsigned p=0;p<2;p++)for(unsigned q=0;q<2;q++)CHECK(state->pass[p].source[q].complete&&state->pass[p].source[q].hash_count==5);
    CHECK(!rpmh_run());CHECK(pmsc_close_unused(owner)&&!pmrd_current(state,resource_map));
    for(unsigned fault=1;fault<=6;fault++)for(unsigned at=1;at<=total;at++){
        rpmh_setup();rp_fault=fault;rp_trigger=at;CHECK(!rpmh_run()&&state->unknown&&!state->complete&&rp_ats==at);
    }
    rpmh_setup();rp_fault=7;rp_trigger=total/2+1;CHECK(!rpmh_run()&&state->error==10&&!state->complete);
    rpmh_setup();rp_fault=8;rp_trigger=total/2-14;CHECK(!rpmh_run()&&state->error==5&&!state->complete);
    for(unsigned fault=0;fault<26;fault++){
        rpmh_setup();
        switch(fault){
        case 0:put(image_heap+0x6000+48,0,8);break;
        case 1:put(image_heap+0x6000+56,(uintptr_t)rp_image+0xd0dc,8);break;
        case 2:rp_image[0x1000]^=1;break;
        case 3:put(rp_image+0xd2e8,0,4);break;
        case 4:put(image_heap+0x10204+4,1,4);break;
        case 5:put(image_heap+0x10284+4,129,4);break;
        case 6:put(image_heap+0x16004+40,(uintptr_t)image_heap+0x16004,8);break;
        case 7:put(image_heap+0x16004,(uintptr_t)rp_image+0x1000,8);break;
        case 8:put(image_heap+0x10808,1,4);break;
        case 9:put(image_heap+0x10814,(uintptr_t)image_heap+0x16004,8);break;
        case 10:put(image_heap+0x12004+0x38,1,4);break;
        case 11:put(image_heap+0x12004+0x34,0,4);break;
        case 12:put(image_heap+0x13004+64+4,1,4);break;
        case 13:put(image_heap+0x12004+80,(uintptr_t)image_heap+0x12004,8);break;
        case 14:put(rp_image+0xd2ec,129,4);break;
        case 15:put(image_heap+0x14004+24,0x30000,4);break;
        case 16:put(image_heap+0x15004+4,1,4);break;
        case 17:put(image_heap+0x15004+64,(uintptr_t)image_heap+0x15004,8);break;
        case 18:put(image_heap+0x14004+8,(uintptr_t)image_heap+0x14004,8);break;
        case 19:put(rp_image+0xd538+4,2,4);break;
        case 20:put(rp_image+0xd538+48+24,7,4);break;
        case 21:put(rp_image+0xd538+72+12,0x179c0000,4);put(rp_image+0xd538+72+16,2,4);rp_image[0xd538+72+20]=1;break;
        case 22:put(rp_image+0xd2f8,(uintptr_t)image_heap+0x10006,8);break;
        case 23:put(image_heap+0x11144+4,1,4);put(image_heap+0x11144+8,(uintptr_t)image_heap+0x12004,8);put(image_heap+0x11144+16,(uintptr_t)image_heap+0x12004,8);break;
        case 24:owner->effects=1;break;
        case 25:resource_map->pass[1].node[0].raw[0]^=1;break;
        }
        ok=rpmh_run();if(ok)fprintf(stderr,"accepted fault%u\n",fault);CHECK(!ok&&state->unknown&&!state->complete);
    }
    rpmh_setup();CHECK(rpmh_run());state->pass[1].read[0].raw[0]^=1;CHECK(!pmrd_current(state,resource_map));
    rpmh_setup();CHECK(rpmh_run());held->map.data[0]^=1;CHECK(!pmrd_current(state,resource_map));
    CHECK(!munmap(heap_mapping,0x100000+2*host_page));CHECK(!munmap(shadow_mapping,0x104000+2*host_page));free(original);free(rp_original);free(arena);
    printf("PASS %u current RPMh RAM checks, %u scenarios, %u reads/pass, %u AT/capture; no votes/MMIO/provider calls\n",checks,scenarios,reads,total);return 0;
}
