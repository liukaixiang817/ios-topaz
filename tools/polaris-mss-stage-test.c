/* Actual allocation -> retained -> stage control flow, software architecture
 * and cache leaves, real volatile writes/readback to guarded host RAM shadows. */
#define PMMN_TEST_ENTRY unused_mss_memory_suite
#ifndef PMMN_TEST_ARENA_BYTES
#define PMMN_TEST_ARENA_BYTES 0x200000
#endif
#ifndef PMMN_TEST_IMAGE_BYTES
#define PMMN_TEST_IMAGE_BYTES 0x180000
#endif
#ifndef PMSI_TEST_BLOB_BYTES
#define PMSI_TEST_BLOB_BYTES 0x3e000
#endif
#ifndef PMSI_TEST_ASSETS
#define PMSI_TEST_ASSETS 2
#endif
#include "polaris-mss-memory-test.c"
#include <sys/mman.h>
#include <unistd.h>
static int stage_arch(void*,struct pgcd_arch*);
static int stage_at(struct pwmc_translation*);
#undef pgcd_actual_arch
#undef pwmc_actual_translate
#define pgcd_actual_arch stage_arch
#define pwmc_actual_translate stage_at
#define EFI_XNU_MSS_STAGING_AVAILABLE 1
#define POLARIS_MSS_STAGE_SOFTWARE_PEER 1
#include "uefi-mss-stage.h"
#if defined(PMSI_TEST_OWN_BINDING)
#include "uefi-mss-firmware-binding.h"
#endif
static struct pmsi_result*stage;
static struct pmsf_asset*assets;
static uint8_t*blob,*shadow,*shadow_mapping;
static uint8_t allocation_digest[32];
static unsigned stage_fault,stage_at_trigger,stage_ats,stage_writes,stage_caches,stage_arches;
static size_t host_page;
_Static_assert(sizeof(struct pmsi_result)<0x30000,"stage resident fixture");
static int stage_arch(void*p,struct pgcd_arch*a)
{
    int ok=early_arch(p,a);stage_arches++;
    if(stage_arches==stage_at_trigger){
        if(stage_fault==1)a->cpu.ttbr0^=4096;
        if(stage_fault==2)a->cpu.ticks+=PGCD_FRESH_TICKS+1;
        if(stage_fault==3)a->cpacr=0;
    }return ok;
}
static int stage_at(struct pwmc_translation*t)
{
    stage_ats++;int ok=early_translate(t);
    if(stage_ats==stage_at_trigger){
        if(stage_fault==4)t->write_par|=1;
        if(stage_fault==5)t->restored++;
        if(stage_fault==6)t->page+=4096;
        if(stage_fault==7)return 0;
    }return ok;
}
static int pmsi_write_page(uint64_t to,uint64_t from,unsigned bytes,struct pwfi_sha256*h,struct pmsi_page*p)
{
    unsigned n=stage_writes++;CHECK(n<259);
    uint64_t expected=n<256?mss->memory.claim[1].requested+4096*n:mss->memory.claim[2].requested+4096*(n-256);
    CHECK(to==expected&&p->target.page==expected&&pwmc_translation_valid(&p->target));
    CHECK(!bytes||(p->source.page==from&&pwmc_translation_valid(&p->source)));
    if(stage_fault==8&&stage_writes==stage_at_trigger){p->words_issued=1;return 0;}
    if(stage_fault==9&&stage_writes==stage_at_trigger&&bytes)*(uint8_t*)(uintptr_t)from^=1;
    return pmsi_words((uintptr_t)shadow+4096*n,from,bytes,h,p);
}
static int pmsi_cache_page(uint64_t to,struct pwmk_record*r)
{
    stage_caches++;CHECK(stage_caches==stage_writes);
    *r=(struct pwmk_record){.address=to,.ctr_before=4u<<16,.ctr_after=4u<<16,.el=4,.sctlr=5,
        .operation=PWMK_CLEAN_INVALIDATE,.line_bytes=64,.lines_issued=64,.lines_returned=64,.attempted=1,
        .barrier_issued=1,.barrier_returned=1,.complete=1};
    if(stage_caches==stage_at_trigger){
        if(stage_fault==10)r->barrier_returned=0;
        if(stage_fault==11)r->lines_returned--;
        if(stage_fault==12)return 0;
    }return 1;
}
static void stage_setup(unsigned f,unsigned trigger_at)
{
    early_sctlr_extra=4;retained_setup();pweh_digest(mss,sizeof(*mss),allocation_digest);
    memset(arena+0x100000,0,0x100000);
    stage=(void*)(arena+0xc0000);memset(stage,0,sizeof(*stage));
    assets=(void*)(arena+0x100000);blob=arena+0x110000;
#if EFI_XNU_MSS_PAYLOAD_FIRMWARE_AVAILABLE
    blob=(void*)(uintptr_t)(held->payload+EFI_XNU_MSS_FIRMWARE_OFFSET);
#endif
    assets[0]=(struct pmsf_asset){.offset=0,.bytes=238304};
    assets[1]=(struct pmsf_asset){.offset=0x3b000,.bytes=8412};
    for(unsigned k=0;k<2;k++){
        for(unsigned n=0;n<assets[k].bytes;n++)blob[assets[k].offset+n]=(uint8_t)(n*17+k*31);
        pweh_digest(blob+assets[k].offset,assets[k].bytes,assets[k].sha256);
    }
    memset(shadow,0xa5,0x104000);
    stage_fault=f;stage_at_trigger=trigger_at;stage_ats=stage_writes=stage_caches=stage_arches=0;
#if defined(PMSI_TEST_PREPARE)
    PMSI_TEST_PREPARE();
#endif
}
static int stage_run(void)
{return pmsi_stage(stage,mss,allocation_digest,held,blob,PMSI_TEST_BLOB_BYTES,assets,PMSI_TEST_ASSETS);}
#ifndef PMSI_TEST_ENTRY
#define PMSI_TEST_ENTRY main
#endif
int PMSI_TEST_ENTRY(int argc,char**argv)
{
    assert(argc==2||argc==3||argc==4);CHECK(!posix_memalign((void**)&arena,4096,0x200000));original=malloc(PGCI_IMAGE_BYTES);assert(original);
    FILE*f=fopen(argv[1],"rb");CHECK(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));
    host_page=(size_t)sysconf(_SC_PAGESIZE);CHECK(host_page&&host_page<=0x4000&&!(host_page&(host_page-1)));
    shadow_mapping=mmap(0,0x104000+2*host_page,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(shadow_mapping!=MAP_FAILED);
    shadow=shadow_mapping+host_page;CHECK(!mprotect(shadow,0x104000,PROT_READ|PROT_WRITE));
    stage_setup(0,0);CHECK(stage_run());
    CHECK(stage->complete&&!stage->unknown&&stage->pages==259&&stage_writes==259&&stage_caches==259&&stage_ats==383);
    CHECK(stage->source_pages[0]==59&&stage->source_pages[1]==3&&stage->assets_complete==2);
    for(unsigned k=0;k<2;k++){
        uint8_t*to=shadow+(k?0x100000:0);unsigned full=k?12288:0x100000;
        CHECK(!memcmp(to,blob+assets[k].offset,assets[k].bytes));
        for(unsigned n=assets[k].bytes;n<full;n++)CHECK(to[n]==0);
    }
    for(unsigned n=0x103000;n<0x104000;n++)CHECK(shadow[n]==0xa5);
    CHECK(!stage_run()&&stage_writes==259);
#if defined(PMSI_TEST_OWN_BINDING)
    if(argc==4){
        stage_setup(0,0);FILE*input=fopen(argv[3],"rb");
        CHECK(input&&fread(blob,1,0x3e000,input)==0x3e000&&!fclose(input));
        memcpy(assets,pmsf_assets,2*sizeof(*assets));CHECK(stage_run());
        CHECK(!memcmp(shadow,blob,assets[0].bytes)&&!memcmp(shadow+0x100000,blob+assets[1].offset,assets[1].bytes));
    }
#else
    CHECK(argc!=4);
#endif
    if(argc>=3){
        const char*suffix[]={"",".memory",".early",".retained"};
        const void*data[]={stage,mss,early,held};const size_t sizes[]={sizeof(*stage),sizeof(*mss),sizeof(*early),sizeof(*held)};
        for(unsigned n=0;n<4;n++){
            char name[4096];CHECK(snprintf(name,sizeof(name),"%s%s",argv[2],suffix[n])<(int)sizeof(name));
            FILE*out=fopen(name,"wb");CHECK(out&&fwrite(data[n],1,sizes[n],out)==sizes[n]&&!fclose(out));
        }
    }
    for(unsigned kind=4;kind<=7;kind++)for(unsigned n=0;n<10;n++){
        stage_setup(kind,(unsigned[]){1,59,60,62,63,64,180,181,382,383}[n]);
        CHECK(!stage_run()&&stage->unknown&&!stage->complete&&stage_ats==stage_at_trigger);
        unsigned writes=stage_writes;CHECK(!stage_run()&&stage_writes==writes);
    }
    for(unsigned kind=8;kind<=12;kind++)for(unsigned n=0;n<5;n++){
        unsigned at=(unsigned[]){1,59,256,257,259}[n];if(kind==9&&at==256)continue;
        stage_setup(kind,at);CHECK(!stage_run()&&stage->unknown&&!stage->complete);
        CHECK(stage_writes==(kind==9?(at<256?256:259):at));
    }
    for(unsigned kind=1;kind<=3;kind++)for(unsigned n=0;n<4;n++){
        stage_setup(kind,(unsigned[]){1,64,300,582}[n]);CHECK(!stage_run()&&stage->unknown&&!stage->complete);
    }
    for(unsigned kind=0;kind<10;kind++){
        stage_setup(0,0);
        if(kind==0)assets[0].sha256[0]^=1;
        else if(kind==1)blob[assets[1].offset+8411]^=1;
        else if(kind==2)assets[0].bytes++;
        else if(kind==3)assets[1].offset=0;
        else if(kind==4)assets[1].offset=0x3d000;
        else if(kind==5)allocation_digest[0]^=1;
        else if(kind==6)mss->memory.claim[1].requested+=4096;
        else if(kind==7)held->unknown=1;
        else if(kind==8)*native_flag=1;
        else assets[0].offset++;
        CHECK(!stage_run()&&stage->unknown&&!stage_writes);
    }
#if EFI_XNU_MSS_PAYLOAD_FIRMWARE_AVAILABLE
    for(unsigned kind=0;kind<5;kind++){
        stage_setup(0,0);
        if(kind==0)blob+=4096;
        if(kind==1)held->input.logical_bytes--;
        if(kind==2)held->map.data[280]=3;
        if(kind==3)*(uint8_t**)(uintptr_t)held_input.payload_slot+=4096;
        if(kind==4)held->payload=UINT64_MAX-4095;
        CHECK(!stage_run()&&stage->unknown&&!stage_writes);
    }
#endif
    CHECK(!munmap(shadow_mapping,0x104000+2*host_page));free(original);free(arena);
    printf("PASS %u staging checks; software architecture/cache, real guarded RAM writes only\n",checks);return 0;
}
