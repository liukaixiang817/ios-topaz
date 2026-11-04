/* Current software image graph feeds the actual GCD RAM reader. No MMIO. */
static void resource_fault_hook(void);
struct pwea_map;
static void resource_extra_map(struct pwea_map*);
#define PMLI_TEST_AT_HOOK resource_fault_hook
#define PMLI_TEST_MAP_HOOK resource_extra_map
#define PMLI_TEST_ENTRY unused_image_suite
#include "polaris-mss-image-ledger-test.c"
#define EFI_XNU_MSS_RESOURCE_MAP_AVAILABLE 1
#include "uefi-mss-resource-map.h"
static struct pmrg_map*resource_map;
static struct pmrg_target*resource_target;
static unsigned resource_fault,resource_trigger;
static unsigned resource_map_type,resource_map_attribute,resource_map_virtual;
static void resource_extra_map(struct pwea_map*m)
{
    if(!resource_map_type)return;
    struct efi_memory*d=(void*)(m->data+m->map.bytes);
    emit_descriptor((void*)d,resource_map_type,0x179e0000,4096);
    d->attributes=resource_map_attribute;d->virtual_address=resource_map_virtual?0x179e0000:0;m->map.bytes+=40;
}
static void resource_fault_hook(void)
{
    if(image_ats!=resource_trigger)return;
    if(resource_fault==1)put(core+PMRG_HEAD,0,8);
    if(resource_fault==2)core[PMRG_TEMPLATE+16]^=1;
    if(resource_fault==3)put(core+PMRG_LOCK+8,8,8);
    if(resource_fault==4)put(image_heap+0x3000+48,0,8);
}
static void resource_setup(void)
{
    resource_fault=resource_trigger=0;image_setup();
    resource_map=(void*)(arena+0x310000);resource_target=(void*)(arena+0x3e0000);
    CHECK(0x200000+sizeof(*ledger)<0x310000&&0x310000+sizeof(*resource_map)<0x3e0000);
    memset(resource_map,0,sizeof(*resource_map));memset(resource_target,0,sizeof(*resource_target));
    uint64_t head=(uintptr_t)core+PMRG_HEAD;
    put(core+PMRG_HEAD,(uintptr_t)image_heap+0x3008,8);put(core+PMRG_HEAD+8,(uintptr_t)image_heap+0x5008,8);
    const uint64_t start[]={0,0x179e0000,0x179e3000},end[]={0x179dffff,0x179e2fff,UINT64_MAX};
    for(unsigned n=0;n<3;n++){
        uint8_t*p=image_heap+0x3000+4096*n;put(p,0x6d646367,8);
        put(p+8,n==2?head:(uintptr_t)p+4104,8);put(p+16,n?(uintptr_t)p-4088:head,8);
        put(p+24,start[n],8);put(p+32,end[n],8);put(p+40,1,8);put(p+48,1,8);put(p+56,3,4);
    }
    CHECK(image_run()&&pmli_current(ledger,owner));
}
static int resource_run(void){return pmrg_capture(resource_map,ledger,owner);}
static int resource_page(uint64_t page)
{memset(resource_target,0,sizeof(*resource_target));return pmrg_target_now(resource_map,page,resource_target);}
int main(int argc,char**argv)
{
    CHECK(argc==2);CHECK(!posix_memalign((void**)&arena,0x4000,PMMN_TEST_ARENA_BYTES));original=malloc(PGCI_IMAGE_BYTES);CHECK(original);
    FILE*f=fopen(argv[1],"rb");CHECK(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));
    host_page=(size_t)sysconf(_SC_PAGESIZE);CHECK(host_page&&host_page<=0x4000&&!(host_page&(host_page-1)));
    shadow_mapping=mmap(0,0x104000+2*host_page,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(shadow_mapping!=MAP_FAILED);
    shadow=shadow_mapping+host_page;CHECK(!mprotect(shadow,0x104000,PROT_READ|PROT_WRITE));
    heap_mapping=mmap(0,0x100000+2*host_page,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(heap_mapping!=MAP_FAILED);
    image_heap=heap_mapping+host_page;CHECK(!mprotect(image_heap,0x100000,PROT_READ|PROT_WRITE));
    resource_setup();unsigned start=image_ats;CHECK(resource_run()&&pmrg_current(resource_map));
    unsigned count=image_ats-start;CHECK(count==18&&resource_map->pass[1].nodes==3);
    const uint64_t allowed[]={0x134000,0x138000,0x152000,0x18a000,0x1f63000,0x1f64000,0x1f65000,
        0x4080000,0x4084000,0x4180000,0xb2e0000,0xc2b0000,0x17990000,0x179e0000,0x179e1000,0x179e2000};
    for(unsigned n=0;n<sizeof(allowed)/sizeof(allowed[0]);n++)CHECK(resource_page(allowed[n])&&resource_target->complete);
    for(uint64_t page=0xc300000;page<0xc400000;page+=4096)CHECK(resource_page(page)&&resource_target->complete);
    CHECK(!resource_page(0x179e3000)&&!resource_page(0xc400000)&&!resource_page(0xc2ff000)&&!resource_page(0x4180004));
    CHECK(!resource_run()&&pmsc_close_unused(owner)&&!pmrg_current(resource_map));
    for(unsigned fault=1;fault<=7;fault++)for(unsigned at=1;at<=count;at++){
        resource_setup();image_fault=fault;image_trigger=image_ats+at;
        CHECK(!resource_run()&&resource_map->unknown&&!resource_map->complete&&image_ats==image_trigger);
    }
    for(unsigned fault=1;fault<=3;fault++)for(unsigned at=1;at<=count;at++){
        resource_setup();resource_fault=fault;resource_trigger=image_ats+at;
        CHECK(!resource_run()&&resource_map->unknown&&!resource_map->complete&&image_ats==resource_trigger);
    }
    resource_setup();resource_fault=4;resource_trigger=image_ats+count/2+1;
    CHECK(!resource_run()&&resource_map->unknown&&!resource_map->complete);
    for(unsigned fault=0;fault<9;fault++){
        resource_setup();
        switch(fault){
        case 0:put(image_heap+0x3000,0,8);break;
        case 1:put(image_heap+0x3010,0,8);break;
        case 2:put(image_heap+0x3008,(uintptr_t)image_heap+0x3008,8);break;
        case 3:put(image_heap+0x3018,4096,8);break;
        case 4:put(image_heap+0x4018,0x179e1000,8);break;
        case 5:put(image_heap+0x4038,5,4);break;
        case 6:put(image_heap+0x403c,1,4);break;
        case 7:ledger->pass[1].image[0].loaded.raw[0]^=1;break;
        case 8:owner->effects=1;break;
        }
        CHECK(!resource_run()&&resource_map->unknown&&!resource_map->complete);
    }
    resource_setup();CHECK(resource_run());put(image_heap+0x4030,0,8);
    CHECK(!resource_page(0x179e0000)&&resource_map->unknown&&!resource_target->complete);
    resource_setup();CHECK(resource_run());resource_map->pass[1].node[1].raw[48]^=1;
    CHECK(!resource_page(0x179e0000)&&!resource_target->complete);
    resource_setup();put(image_heap+0x4038,2,4);CHECK(resource_run());
    CHECK(!resource_page(0x179e0000)&&!resource_target->complete);
    resource_setup();CHECK(resource_run());held->map.data[0]^=1;
    CHECK(!resource_page(0x179e0000)&&!pmli_current(ledger,owner));
    resource_setup();memcpy(image_heap+0x80000,image_heap+0x3000,80);
    put(core+PMRG_HEAD,(uintptr_t)image_heap+0x80008,8);put(image_heap+0x4010,(uintptr_t)image_heap+0x80008,8);
    CHECK(!resource_run()&&resource_map->unknown&&!resource_map->pass[0].nodes);
    for(unsigned kind=0;kind<4;kind++){
        resource_map_type=kind==1?7:11;resource_map_attribute=kind==1||kind==2?8:1;resource_map_virtual=kind==3;
        resource_setup();CHECK(resource_run());
        if(!kind)CHECK(resource_page(0x179e0000));
        else CHECK(!resource_page(0x179e0000)&&!resource_target->complete);
    }
    CHECK(!munmap(heap_mapping,0x100000+2*host_page));CHECK(!munmap(shadow_mapping,0x104000+2*host_page));free(original);free(arena);
    printf("PASS %u current MSS resource namespace checks; no Device loads/stores\n",checks);return 0;
}
