/* Actual RAM allocation/stage/MBA-share/CPU/copy producers, software leaves.
 * Metadata/clock readiness inputs below are explicit fixtures, not hardware
 * receipts. Shared-bank transactions use the real protocol with software SMC.
 * Own private firmware is DATA. MBA and in-flight descriptor are inaccessible. */
#include <stdint.h>
#if defined(PMLC_TEST_PAGE_BEFORE)
#include <setjmp.h>
#define EFI_XNU_WIFI_AUTH_METADATA_CHECKPOINT 9
#define EFI_XNU_WIFI_FIRMWARE_DIAGNOSTIC_ONLY 1
#define EFI_XNU_WIFI_COPY_PAGE_BEFORE PMLC_TEST_PAGE_BEFORE
static jmp_buf page_checkpoint_jump;
static unsigned page_checkpoint_hits,page_checkpoint_target_AT;
#endif
static uint8_t*copy_payload,*firmware;
static void copy_prepare_assets(void);
#define PMMN_TEST_ARENA_BYTES 0x1000000
#define PMMN_TEST_IMAGE_BYTES 0xfc0000
#define PMMN_TEST_PAYLOAD_BASE ((uintptr_t)copy_payload)
#define PMMN_TEST_PAYLOAD_BYTES (64061440+4096)
#define EFI_XNU_MSS_PAYLOAD_FIRMWARE_AVAILABLE 1
#define EFI_XNU_MSS_FIRMWARE_OFFSET 4096
#define EFI_XNU_MSS_PAYLOAD_FW_BYTES 64061440
#define PMSI_TEST_BLOB_BYTES 64061440
#define PMSI_TEST_ASSETS 28
#define PMSI_TEST_PREPARE copy_prepare_assets
#define PMSC_TEST_ENTRY unused_cpu_suite
#include "polaris-mss-cpu-owner-test.c"
#include "uefi-mss-firmware-binding.h"
static int copy_translate(struct pwmc_translation*);
#undef pwmc_actual_translate
#define pwmc_actual_translate copy_translate
#define EFI_XNU_MSS_MODEM_COPY_AVAILABLE 1
#define POLARIS_MSS_MODEM_COPY_SOFTWARE_PEER 1
#include "uefi-mss-modem-copy.h"
static struct pmlc_copy*copy_record;
static struct pmim_auth*copy_auth;
static struct pwmt_transaction*copy_tx;
static struct pwma_page*copy_descriptor;
static uint8_t*modem_shadow,*modem_mapping;
static unsigned copy_fault,copy_at,copy_ats,copy_writes,copy_caches,copy_source_changed;
static unsigned fresh_retained;
#if defined(PMLC_TEST_PAGE_BEFORE)
__attribute__((noreturn)) static void pmlc_page_checkpoint(struct pmlc_copy*r)
{
    CHECK(r==copy_record&&r->pages==PMLC_TEST_PAGE_BEFORE);
    CHECK(copy_writes==PMLC_TEST_PAGE_BEFORE&&copy_caches==copy_writes);
    CHECK(!page_checkpoint_target_AT&&r->unknown==1&&!r->error&&!r->complete);
    page_checkpoint_hits++;longjmp(page_checkpoint_jump,1);
}
#endif
static void copy_prepare_assets(void)
{
    memcpy(blob,firmware,PMSF_BLOB_BYTES);memcpy(assets,pmsf_assets,sizeof(pmsf_assets));
}
static int copy_translate(struct pwmc_translation*t)
{
#if defined(PMLC_TEST_PAGE_BEFORE)
    if(copy_record&&copy_record->ready&&t->page==copy_auth->base+4096*(uint64_t)PMLC_TEST_PAGE_BEFORE)
        page_checkpoint_target_AT++;
#endif
    copy_ats++;int ok=early_translate(t);
    if(copy_ats==copy_at){
        if(copy_fault==1)return 0;if(copy_fault==2)t->write_par|=1;
        if(copy_fault==3)t->page+=4096;if(copy_fault==4)t->restored++;
    }return ok;
}
static int pmlc_write(uint64_t to,uint64_t from,unsigned bytes,struct pwfi_sha256*h,struct pmsi_page*p)
{
    CHECK(local_mask&&target_protected&&copy_tx->complete&&!copy_tx->unknown);
    CHECK(to==copy_auth->base+4096*copy_writes&&p->target.page==to&&pwmc_translation_valid(&p->target));
    CHECK(!bytes||(p->source.page==from&&pwmc_translation_valid(&p->source)));
    copy_writes++;
    if(copy_writes==copy_at){
        if(copy_fault==5){p->words_issued=1;return 0;}
        if(copy_fault==6&&bytes){*(uint8_t*)(uintptr_t)from^=1;copy_source_changed=1;}
        if(copy_fault==7)put(core+0x1cdb0,held->map.map.key+1,8);
    }
    return pmsi_words((uintptr_t)modem_shadow+to-copy_auth->base,from,bytes,h,p);
}
static int pmlc_cache(uint64_t to,struct pwmk_record*c)
{
    copy_caches++;CHECK(copy_caches==copy_writes);
    *c=(struct pwmk_record){.address=to,.ctr_before=4u<<16,.ctr_after=4u<<16,.el=4,.sctlr=5,
        .operation=PWMK_CLEAN_INVALIDATE,.line_bytes=64,.lines_issued=64,.lines_returned=64,
        .attempted=1,.barrier_issued=1,.barrier_returned=1,.complete=1};
    if(copy_caches==copy_at){
        if(copy_fault==8)return 0;if(copy_fault==9)c->barrier_returned=0;
        if(copy_fault==10)c->lines_returned--;if(copy_fault==11)owner_delay=PMSC_TOTAL+1;
    }return 1;
}
static void copy_setup(void)
{
    CHECK(!mprotect(modem_shadow,0x7800000,PROT_NONE));owner_setup(0,0);
    if(fresh_retained){
        held=(void*)(arena+0xf00000);memset(held,0,sizeof(*held));CHECK(pweh_run(held,&held_input));
        CHECK((uintptr_t)held!=stage->retained);
    }
    CHECK(owner_begin());
    CHECK(pmsc_mark_effect(owner,7));
    copy_auth=(void*)(arena+0x1c0000);copy_tx=(void*)(arena+0x1d0000);copy_descriptor=(void*)(arena+0x1e0000);
    copy_record=(void*)(arena+0x200000);CHECK(0x200000+sizeof(*copy_record)<0xf00000);
    memset(copy_auth,0,sizeof(*copy_auth));memset(copy_tx,0,sizeof(*copy_tx));memset(copy_descriptor,0,sizeof(*copy_descriptor));
    memset(copy_record,0,sizeof(*copy_record));
    uint64_t now=owner->last+1;
    struct pmmd_metadata d={.epoch=1,.phase=3,.authenticated_at=now+1,.returned_at=now+2};
    struct pmck_lifecycle c={.epoch=1,.phase=2,.held=63,.held_at=now,.last=now+2};now+=3;
    struct pwma_spec spec={.descriptor_pa=(uintptr_t)copy_descriptor,.region_pa=mss->memory.claim[0].requested,
        .region_bytes=0x7800000,.sources=1,.source={PWMA_HLOS},.destinations=2,
        .destination={{PWMA_HLOS,PWMA_RW},{PWMA_MSS_MSA,PWMA_RW}}};
    CHECK(pwmt_begin_modem(copy_tx,copy_descriptor,&spec,++now,19200000)==PWMT_WAIT);
    for(unsigned step=PWMT_CLEAN;step<=PWMT_INVALIDATE;step++){
        struct pwmt_command command;CHECK(pwmt_next(copy_tx,++now,&command)==PWMT_IO);
        struct pwmk_record cache={.address=(uintptr_t)copy_descriptor,.ctr_before=4u<<16,.ctr_after=4u<<16,.el=4,.sctlr=5,
            .operation=step==PWMT_CLEAN?PWMK_CLEAN_INVALIDATE:PWMK_INVALIDATE,.line_bytes=64,.lines_issued=64,.lines_returned=64,
            .attempted=1,.barrier_issued=1,.barrier_returned=1,.complete=1};
        if(step==PWMT_SMC)CHECK(!mprotect(copy_descriptor,host_page,PROT_NONE));
        if(step==PWMT_INVALIDATE)CHECK(!mprotect(copy_descriptor,host_page,PROT_READ|PROT_WRITE));
        struct pwma_registers zero={0};CHECK(pwmt_complete(copy_tx,&command,++now,1,step==PWMT_SMC?&zero:0,
            step==PWMT_SMC?0:&cache)==(step==PWMT_INVALIDATE?PWMT_ZERO:PWMT_WAIT));
    }
    CHECK(!mprotect(modem_shadow,0x7800000,PROT_READ|PROT_WRITE));memset(modem_shadow,0xa5,0x7800000);
    CHECK(pmim_begin(copy_auth,&d,&c,copy_tx,pmsf_segments,++now)==PMIM_NEED_SEGMENT);
    owner_delay=1000;copy_fault=copy_at=copy_ats=copy_writes=copy_caches=copy_source_changed=0;
}
static int copy_begin(void){return pmlc_begin(copy_record,owner,copy_auth,copy_tx);}
static void copy_publish_io(void)
{
    CHECK(copy_auth->phase==2);unsigned segment=copy_auth->segment;
    while(copy_auth->phase==2){
        CHECK(pmsc_live(owner));struct pmim_command c;
        CHECK(pmim_next(copy_auth,owner->last,&c)==PMIM_IO);CHECK(pmsc_live(owner));
        CHECK(pmim_complete(copy_auth,&c,owner->last,1,c.step==PMIM_LENGTH_READ?copy_auth->length:3)==PMIM_WAIT);
    }
    CHECK(copy_auth->segment==segment+1);
}
int main(int argc,char**argv)
{
    CHECK(argc==3);CHECK(!posix_memalign((void**)&arena,0x4000,PMMN_TEST_ARENA_BYTES));
    CHECK(!posix_memalign((void**)&copy_payload,0x4000,PMMN_TEST_PAYLOAD_BYTES));
    original=malloc(PGCI_IMAGE_BYTES);firmware=malloc(PMSF_BLOB_BYTES);CHECK(original&&firmware);
    FILE*f=fopen(argv[1],"rb");CHECK(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));
    f=fopen(argv[2],"rb");CHECK(f&&fread(firmware,1,PMSF_BLOB_BYTES,f)==PMSF_BLOB_BYTES&&!fclose(f));
    host_page=(size_t)sysconf(_SC_PAGESIZE);CHECK(host_page&&host_page<=0x4000&&!(host_page&(host_page-1)));
    shadow_mapping=mmap(0,0x104000+2*host_page,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(shadow_mapping!=MAP_FAILED);
    shadow=shadow_mapping+host_page;CHECK(!mprotect(shadow,0x104000,PROT_READ|PROT_WRITE));
    modem_mapping=mmap(0,0x7800000+2*host_page,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(modem_mapping!=MAP_FAILED);
    modem_shadow=modem_mapping+host_page;
    fresh_retained=1;copy_setup();CHECK(copy_begin());CHECK(copy_record->ready&&!copy_writes&&!copy_auth->submitted);
    unsigned first_ats=copy_ats;
#if defined(PMLC_TEST_PAGE_BEFORE)
    if(!setjmp(page_checkpoint_jump)){
        for(unsigned k=0;k<28;k++){CHECK(pmlc_next_segment(copy_record));copy_publish_io();}
        CHECK(0);
    }
    CHECK(page_checkpoint_hits==1&&!page_checkpoint_target_AT);
    CHECK(copy_writes==PMLC_TEST_PAGE_BEFORE&&copy_record->pages==copy_writes);
    CHECK(!copy_record->segment[copy_record->segments].complete&&!copy_record->segment[copy_record->segments].published);
    CHECK(modem_shadow[4096*(uint64_t)PMLC_TEST_PAGE_BEFORE]==0xa5);
    printf("PASS page%u held before target AT/write/cache; %u authenticated source translations\n",PMLC_TEST_PAGE_BEFORE,first_ats);
    goto cleanup;
#endif
    for(unsigned k=0;k<28;k++){
        CHECK(pmlc_next_segment(copy_record));CHECK(copy_record->segment[k].complete&&copy_record->segment[k].published);
        CHECK(copy_auth->submitted==k+1);
        copy_publish_io();
    }
    CHECK(copy_record->complete&&copy_record->pages==30720&&copy_writes==30720&&copy_caches==30720);
    CHECK(copy_auth->phase==3&&copy_auth->length==124977057);
    unsigned cursor=0;
    for(unsigned k=0;k<28;k++){
        const struct pmsf_segment*g=&pmsf_segments[k];
        for(;cursor<g->target_offset;cursor++)CHECK(modem_shadow[cursor]==0);
        if(g->filesz){CHECK(!memcmp(modem_shadow+cursor,firmware+pmsf_assets[g->asset].offset,g->filesz));cursor+=g->filesz;}
        for(;cursor<g->target_offset+g->memsz;cursor++)CHECK(modem_shadow[cursor]==0);
    }
    CHECK(cursor==0x7800000);CHECK(!mprotect(modem_shadow,0x7800000,PROT_NONE));
    CHECK(!pmlc_next_segment(copy_record)&&!pmsc_close_unused(owner));
    printf("PASS whole modem copy: %u source pages, %u target pages; %u checks so far\n",first_ats,copy_writes,checks);fflush(stdout);
    for(unsigned fault=1;fault<=11;fault++){
        copy_setup();CHECK(copy_begin());copy_fault=fault;copy_at=fault<=4?copy_ats+1:1;
        CHECK(!pmlc_next_segment(copy_record)&&copy_record->unknown&&!copy_auth->submitted);
        CHECK(!pmsc_close_unused(owner));
    }
    for(unsigned fault=0;fault<8;fault++){
        copy_setup();
        if(fault==0)assets[2].sha256[0]^=1;
        if(fault==1)assets[2].offset=0;
        if(fault==2)copy_auth->segments[1].target_offset=0;
        if(fault==3)copy_tx->unknown=1;
        if(fault==4)copy_tx->opening=owner->opening-1;
        if(fault==5)owner->effects=0;
        if(fault==6)copy_auth->exclusive_at=copy_auth->last;
        if(fault==7){copy_fault=1;copy_at=1;}
        CHECK(!copy_begin()&&!copy_writes&&!copy_auth->submitted);
    }
    copy_setup();CHECK(copy_begin());CHECK(pmlc_next_segment(copy_record));
    CHECK(!pmlc_next_segment(copy_record)&&copy_record->unknown&&copy_auth->submitted==1);
    copy_setup();CHECK(copy_begin());copy_auth->exclusive_at=copy_auth->last;
    CHECK(!mprotect(modem_shadow,0x7800000,PROT_NONE));
    CHECK(!pmlc_next_segment(copy_record)&&copy_record->unknown&&!copy_writes);
    fresh_retained=0;copy_setup();CHECK(copy_begin());CHECK(pmlc_next_segment(copy_record));
    for(unsigned fault=0;fault<6;fault++){
        copy_setup();CHECK(copy_begin());
        if(fault==0)assets[3].bytes++;
        if(fault==1)copy_tx->spec.destination[0].permissions=PWMA_RWX;
        if(fault==2)copy_auth->segments[0].memsz+=4096;
        if(fault==3)copy_auth->phase=3;
        if(fault==4)copy_auth->segment=1;
        if(fault==5)owner_delay=PMIM_TOTAL+1;
        CHECK(!pmlc_next_segment(copy_record)&&copy_record->unknown&&!copy_writes&&!copy_auth->submitted);
    }
#if defined(PMLC_TEST_PAGE_BEFORE)
cleanup:
#endif
    CHECK(!munmap(modem_mapping,0x7800000+2*host_page));
    CHECK(!munmap(shadow_mapping,0x104000+2*host_page));free(original);free(firmware);free(copy_payload);free(arena);
    printf("PASS %u modem copy checks; software only, no physical execution\n",checks);return 0;
}
