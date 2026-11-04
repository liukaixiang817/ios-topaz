/* Own Core identity is inert data; current graph, CPU and AT are software.
 * Real allocation/stage/MBA/CPU producers supply this native RAM reader. */
struct pwea_map;
static void image_extra_map(struct pwea_map*);
#define PMMN_TEST_RETAINED_MAP_EXTRA image_extra_map
#ifndef PMMN_TEST_ARENA_BYTES
#define PMMN_TEST_ARENA_BYTES 0x400000
#endif
#ifndef PMMN_TEST_IMAGE_BYTES
#define PMMN_TEST_IMAGE_BYTES 0x3c0000
#endif
#define PMSC_TEST_ENTRY unused_cpu_suite
#include "polaris-mss-cpu-owner-test.c"
static int image_at(struct pwmc_translation*);
#undef pwmc_actual_translate
#define pwmc_actual_translate image_at
#define EFI_XNU_MSS_IMAGE_LEDGER_AVAILABLE 1
#include "uefi-mss-image-ledger.h"
static uint8_t*image_heap,*heap_mapping;
static struct pmli_ledger*ledger;
static unsigned image_fault,image_trigger,image_ats;
static unsigned runtime_image;
static void image_extra_map(struct pwea_map*m)
{
    if(!runtime_image){emit_descriptor(m->data+360,4,(uintptr_t)image_heap,0x100000);m->map.bytes=400;}
    else{
        emit_descriptor(m->data+360,4,(uintptr_t)image_heap,0x80000);
        emit_descriptor(m->data+400,5,(uintptr_t)image_heap+0x80000,4096);
        ((struct efi_memory*)(m->data+400))->attributes=UINT64_C(0x8000000000000008);
        emit_descriptor(m->data+440,4,(uintptr_t)image_heap+0x81000,0x7f000);m->map.bytes=480;
    }
#if defined(PMLI_TEST_MAP_HOOK)
    PMLI_TEST_MAP_HOOK(m);
#endif
}
static int image_at(struct pwmc_translation*t)
{
    int ok=early_translate(t);image_ats++;
    if(image_ats==image_trigger){
        if(image_fault==1)return 0;
        if(image_fault==2)t->write_par|=1;
        if(image_fault==3)t->restored++;
        if(image_fault==4)t->page+=4096;
        if(image_fault==5)put(core+PMLI_HANDLE_KEY,2,8);
        if(image_fault==6)put(core+PMLI_LOCK+16,2,8);
        if(image_fault==7)put(core+PMLI_HEAD,(uintptr_t)image_heap+0x208,8);
        if(image_fault==8)put(image_heap+0x100+24,0xdead,8);
    }
#if defined(PMLI_TEST_AT_HOOK)
    PMLI_TEST_AT_HOOK();
#endif
    return ok;
}
static void image_setup(void)
{
    owner_setup(0,0);memset(image_heap,0,0x100000);
    ledger=(void*)(arena+0x200000);CHECK(0x200000+sizeof(*ledger)<0x400000);memset(ledger,0,sizeof(*ledger));
    uint64_t head=(uintptr_t)core+PMLI_HEAD,p0=(uintptr_t)image_heap+0x100,p1=(uintptr_t)image_heap+0x200;
    put(core+PMLI_HEAD,p0+8,8);put(core+PMLI_HEAD+8,p1+8,8);put(core+PMLI_HANDLE_KEY,1,8);put(core+PMLI_LOCATE_KEY,1,8);
    for(unsigned n=0;n<2;n++){
        uint8_t*p=image_heap+0x100+n*0x100;put(p,0x65747270,8);put(p+8,n?head:p1+8,8);put(p+16,n?p0+8:head,8);
        put(p+40,(uintptr_t)p+40,8);put(p+48,(uintptr_t)p+40,8);
    }
    static const efi_guid loaded={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
    memcpy(image_heap+0x218,&loaded,16);
    put(image_heap+0x228,(uintptr_t)image_heap+0x1020,8);put(image_heap+0x230,(uintptr_t)image_heap+0x1420,8);
    for(unsigned n=0;n<3;n++){
        uint8_t*p=image_heap+0x1000+n*0x200,*handle=p+0x100,*loaded_at=p+0x180;
        if(n==1)loaded_at=(void*)self;
        put(p,0x63666970,8);put(p+8,(uintptr_t)handle+24,8);put(p+16,(uintptr_t)handle+24,8);
        put(p+24,(uintptr_t)handle,8);put(p+32,n==2?p1+40:(uintptr_t)p+0x220,8);
        put(p+40,n?(uintptr_t)p-0x1e0:p1+40,8);put(p+48,p1,8);put(p+56,(uintptr_t)loaded_at,8);
        put(handle,0x6c646e68,8);put(handle+24,(uintptr_t)p+8,8);put(handle+32,(uintptr_t)p+8,8);
        if(n!=1){struct efi_loaded image={.revision=0x1000,.system=s,.base=n?image_heap+0x80000:core,
            .bytes=n?4096:PGCI_IMAGE_BYTES,.code_type=n&&runtime_image?5:3,.data_type=n&&runtime_image?6:4};
            memcpy(loaded_at,&image,sizeof(image));}
    }
    image_fault=image_trigger=image_ats=0;CHECK(owner_begin());
}
static int image_run(void){return pmli_capture(ledger,owner);}
#ifndef PMLI_TEST_ENTRY
#define PMLI_TEST_ENTRY main
#endif
int PMLI_TEST_ENTRY(int argc,char**argv)
{
    CHECK(argc==2);CHECK(!posix_memalign((void**)&arena,0x4000,PMMN_TEST_ARENA_BYTES));original=malloc(PGCI_IMAGE_BYTES);CHECK(original);
    FILE*f=fopen(argv[1],"rb");CHECK(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));
    host_page=(size_t)sysconf(_SC_PAGESIZE);CHECK(host_page&&host_page<=0x4000&&!(host_page&(host_page-1)));
    shadow_mapping=mmap(0,0x104000+2*host_page,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(shadow_mapping!=MAP_FAILED);
    shadow=shadow_mapping+host_page;CHECK(!mprotect(shadow,0x104000,PROT_READ|PROT_WRITE));
    heap_mapping=mmap(0,0x100000+2*host_page,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(heap_mapping!=MAP_FAILED);
    image_heap=heap_mapping+host_page;CHECK(!mprotect(image_heap,0x100000,PROT_READ|PROT_WRITE));
    runtime_image=1;image_setup();CHECK(image_run()&&ledger->complete&&!ledger->unknown&&ledger->pass[0].protocols==2&&ledger->pass[0].images==3);
    CHECK(pmli_current(ledger,owner));ledger->pass[1].image[0].loaded.raw[0]^=1;CHECK(!pmli_current(ledger,owner));
    unsigned native_count=image_ats;CHECK(native_count==26);CHECK(!image_run());CHECK(pmsc_close_unused(owner));
    runtime_image=0;image_setup();CHECK(image_run()&&pmli_current(ledger,owner));
    CHECK(pmsc_close_unused(owner)&&!pmli_current(ledger,owner));
    for(unsigned fault=1;fault<=7;fault++)for(unsigned at=1;at<=native_count;at++){
        image_setup();image_fault=fault;image_trigger=at;
        CHECK(!image_run()&&ledger->unknown&&!ledger->complete&&image_ats==at);
    }
    image_setup();image_fault=8;image_trigger=native_count/2+1;
    CHECK(!image_run()&&ledger->unknown&&!ledger->complete);
    for(unsigned fault=0;fault<16;fault++){
        image_setup();
        switch(fault){
        case 0:put(image_heap+0x100,0,8);break;
        case 1:put(image_heap+0x110,0,8);break;
        case 2:put(image_heap+0x108,(uintptr_t)image_heap+0x108,8);break;
        case 3:memcpy(image_heap+0x118,image_heap+0x218,16);break;
        case 4:put(image_heap+0x1000,0,8);break;
        case 5:put(image_heap+0x1030,0,8);break;
        case 6:put(image_heap+0x1028,0,8);break;
        case 7:put(image_heap+0x1020,(uintptr_t)image_heap+0x1020,8);break;
        case 8:put(image_heap+0x1100,0,8);break;
        case 9:put(image_heap+0x1180,0,4);break;
        case 10:put(image_heap+0x11c8,1,8);break;
        case 11:put(image_heap+0x1580+64,(uintptr_t)image_heap,8);break;
        case 12:put(image_heap+0x1238,(uintptr_t)image_heap+0x1180,8);break;
        case 13:put(image_heap+0x1018,(uintptr_t)image_heap+0x1300,8);break;
        case 14:put(image_heap+0x1038,mss->memory.claim[1].requested,8);break;
        case 15:owner->effects=1;break;
        }
        CHECK(!image_run()&&ledger->unknown&&!ledger->complete);
    }
    CHECK(!munmap(heap_mapping,0x100000+2*host_page));CHECK(!munmap(shadow_mapping,0x104000+2*host_page));free(original);free(arena);
    printf("PASS %u current image ledger checks; software Core graph only\n",checks);return 0;
}
