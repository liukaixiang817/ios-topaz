/* Own Core/SmemDxe are inert identity data. Actual current CPU/image/GCD
 * producers are composed; Normal-NC/privileged leaves are software only. */
struct pwea_map;
static void smem_map(struct pwea_map*);
static void smem_prepare(void);
#define PMMN_TEST_ARENA_BYTES 0x800000
#define PMMN_TEST_IMAGE_BYTES 0x7c0000
#define PMRG_TEST_MAP_EXTRA smem_map
#define PMRG_TEST_PREPARE smem_prepare
#define PMRG_TEST_ENTRY unused_resource_suite
#include "polaris-mss-resource-map-test.c"
#define EFI_XNU_MSS_RPMH_STATE_AVAILABLE 1
#define EFI_XNU_MSS_SMEM_NATIVE_AVAILABLE 1
#define POLARIS_MSS_RPMH_SOFTWARE_PEER 1
#define POLARIS_MSS_SMEM_SOFTWARE_PEER 1
#include "uefi-mss-smem-native.h"
static uint8_t*sm_original,*sm_image,*sm_shadow;
static struct pmsq_state*sm;
static unsigned sm_words,sm_fault,sm_ats,sm_scenarios,sm_map_kind,sm_gcd_kind;
static void smem_map(struct pwea_map*m)
{
    struct efi_memory*d=(void*)(m->data+m->map.bytes);emit_descriptor((void*)d,sm_map_kind?4:0,PMSQ_BASE,PMSQ_BYTES);
    d->attributes=1;m->map.bytes+=40;
}
static void smem_prepare(void)
{
    sm_image=image_heap+0x80000;memcpy(sm_image,sm_original,PWFI_IMAGE_BYTES);
    for(unsigned n=0;n<PWFI_RELOC_COUNT;n++)put(sm_image+pwfi_relocations[n],pwfi_le(sm_image+pwfi_relocations[n],8)+(uintptr_t)sm_image,8);
    put(sm_image+PWFI_IMAGEBASE_RVA,(uintptr_t)sm_image,8);put(image_heap+0x1580+72,PWFI_IMAGE_BYTES,8);
    static const efi_guid guid={0xf4e5c7d0,0xd239,0x47cb,{0xaa,0xcd,0x7f,0x66,0xef,0x76,0x32,0x38}};
    memcpy(image_heap+0x118,&guid,16);uint8_t*i=image_heap+0x9000,*h=image_heap+0x9100;
    put(image_heap+0x128,(uintptr_t)i+32,8);put(image_heap+0x130,(uintptr_t)i+32,8);
    put(i,0x63666970,8);put(i+24,(uintptr_t)h,8);put(i+32,(uintptr_t)image_heap+0x128,8);
    put(i+40,(uintptr_t)image_heap+0x128,8);put(i+48,(uintptr_t)image_heap+0x100,8);
    put(i+56,(uintptr_t)sm_image+0x7090,8);put(h,0x6c646e68,8);
    uint8_t*c=sm_image+PWFC_CACHE_RVA;memset(c,0,PWFC_CACHE_BYTES);
    put(c,PMSQ_BASE,8);put(c+8,PMSQ_BASE,8);put(c+16,PMSQ_BYTES,4);put(c+20,0xc0000,4);
    put(c+24,615,2);put(c+32,(uintptr_t)sm_image+0x5cb0,8);put(c+40,3,4);
    put(c+96,PMSQ_BASE+0xb9000,8);put(c+104,0x7c000,4);put(c+108,32,4);
    put(c+112,32,4);put(c+116,0x7c000,4);put(c+528,0x49494953,4);put(c+532,PMSQ_BYTES,4);
    put(c+536,PMSQ_BASE,8);put(c+544,615,2);
    for(unsigned n=0;n<8;n++)put(c+552+8*n,0x1f40000+4096*n,8);
    put(c+616,0x1fd4000,8);put(c+624,0x1fd4004,8);
    put(image_heap+0x5008,(uintptr_t)image_heap+0x6008,8);put(image_heap+0x5020,PMSQ_BASE-1,8);
    put(core+PMRG_HEAD+8,(uintptr_t)image_heap+0x7008,8);
    for(unsigned n=0;n<2;n++){
        uint8_t*q=image_heap+0x6000+4096*n;put(q,0x6d646367,8);
        put(q+8,n?(uintptr_t)core+PMRG_HEAD:(uintptr_t)image_heap+0x7008,8);
        put(q+16,(uintptr_t)image_heap+(n?0x6008:0x5008),8);
        put(q+24,n?PMSQ_BASE+PMSQ_BYTES:PMSQ_BASE,8);put(q+32,n?UINT64_MAX:PMSQ_BASE+PMSQ_BYTES-1,8);
        put(q+40,1,8);put(q+48,1,8);put(q+56,n?3:sm_gcd_kind?sm_gcd_kind:1,4);
    }
}
static int pmrd_translate(struct pmrd_at*t)
{
    t->saved=t->restored=0x123;t->issued=t->returned=1;
    unsigned target=t->page>=PMSQ_BASE&&t->page<PMSQ_BASE+PMSQ_BYTES;
    t->par=(target?UINT64_C(0x4400000000000b00):UINT64_C(0xff00000000000b80))|t->page;
    if(target){sm_ats++;if(sm_fault==1)t->par=UINT64_C(0xff00000000000b80)|t->page;
        if(sm_fault==2)t->restored++;if(sm_fault==3&&sm_ats==2)t->par|=1;}
    return 1;
}
static void pmsq_order(void){}
static int pmsq_word(uint64_t at,uint32_t*out)
{
    CHECK(at>=PMSQ_BASE&&at<PMSQ_BASE+PMSQ_BYTES&&!(at&3)&&sm->pending);sm_words++;
    if(sm_words==2){
        if(sm_fault==4)return 0;
        if(sm_fault==5)put(image_heap+0x6030,8,8);
        if(sm_fault==6)sm_image[PWFC_CACHE_RVA+112]^=8;
        if(sm_fault==7)owner_delay=PMSC_TOTAL+1;
    }
    memcpy(out,sm_shadow+at-PMSQ_BASE,4);return 1;
}
static void smem_setup(void)
{
    sm_words=sm_fault=sm_ats=0;sm_scenarios++;resource_setup();CHECK(resource_run());
    sm=(void*)(arena+0x400000);memset(sm,0,sizeof(*sm));CHECK(0x400000+sizeof(*sm)<PMMN_TEST_IMAGE_BYTES);
    CHECK(pmsq_capture(sm,resource_map)&&pmsq_current(sm));
}
static void smem_test_open(int argc,char**argv)
{
    CHECK(argc==3);CHECK(!posix_memalign((void**)&arena,0x4000,PMMN_TEST_ARENA_BYTES));
    original=malloc(PGCI_IMAGE_BYTES);sm_original=malloc(PWFI_IMAGE_BYTES);sm_shadow=malloc(PMSQ_BYTES);CHECK(original&&sm_original&&sm_shadow);
    uint8_t*dst[]={original,sm_original};size_t bytes[]={PGCI_IMAGE_BYTES,PWFI_IMAGE_BYTES};
    for(unsigned n=0;n<2;n++){FILE*f=fopen(argv[n+1],"rb");CHECK(f&&fread(dst[n],1,bytes[n],f)==bytes[n]&&!fclose(f));}
    host_page=(size_t)sysconf(_SC_PAGESIZE);CHECK(host_page&&host_page<=0x4000&&!(host_page&(host_page-1)));
    shadow_mapping=mmap(0,0x104000+2*host_page,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(shadow_mapping!=MAP_FAILED);
    shadow=shadow_mapping+host_page;CHECK(!mprotect(shadow,0x104000,PROT_READ|PROT_WRITE));
    heap_mapping=mmap(0,0x100000+2*host_page,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(heap_mapping!=MAP_FAILED);
    image_heap=heap_mapping+host_page;CHECK(!mprotect(image_heap,0x100000,PROT_READ|PROT_WRITE));
    for(unsigned n=0;n<PMSQ_BYTES;n++)sm_shadow[n]=(uint8_t)(n^(n>>8));
}
static void smem_test_close(void)
{
    CHECK(!munmap(heap_mapping,0x100000+2*host_page)&&!munmap(shadow_mapping,0x104000+2*host_page));
    free(original);free(sm_original);free(sm_shadow);free(arena);
}
#ifndef PMSQ_TEST_ENTRY
#define PMSQ_TEST_ENTRY main
#endif
int PMSQ_TEST_ENTRY(int argc,char**argv)
{
    smem_test_open(argc,argv);
    for(unsigned kind=1;kind<=2;kind++){
        sm_gcd_kind=kind;smem_setup();const uint8_t*raw=pmsq_read(sm,4092,208);
        CHECK(raw&&!memcmp(raw,sm_shadow+4092,208)&&sm_words==52&&sm->access.pages==2&&sm_ats==4);
        CHECK(pmsq_read(sm,PMSQ_BYTES-4,4)&&sm->reads==2);
        unsigned words=sm_words;CHECK(!pmsq_read(sm,PMSQ_BYTES,4)&&!pmsq_read(sm,0,212)&&!pmsq_read(sm,1,4)&&words==sm_words);
        sm->pass[1].cache[0]^=1;CHECK(!pmsq_read(sm,0,4)&&words==sm_words);
    }
    for(unsigned fault=1;fault<=7;fault++){
        smem_setup();sm_fault=fault;CHECK(!pmsq_read(sm,0,208)&&sm->unknown&&sm->pending&&!sm->reads);
        unsigned words=sm_words;CHECK(!pmsq_read(sm,0,4)&&words==sm_words);
        if(fault<3)CHECK(!sm_words);if(fault==4)CHECK(sm_words==2);
    }
    sm_map_kind=1;smem_setup();CHECK(!pmsq_read(sm,0,4)&&!sm_words);sm_map_kind=0;
    sm_gcd_kind=3;smem_setup();CHECK(!pmsq_read(sm,0,4)&&!sm_words);sm_gcd_kind=1;
    smem_setup();sm_image[0x1000]^=1;memset(sm,0,sizeof(*sm));CHECK(!pmsq_capture(sm,resource_map)&&sm->unknown);
    smem_test_close();
    printf("PASS %u native SMEM checks, %u scenarios; software privileged leaves only\n",checks,sm_scenarios);return 0;
}
