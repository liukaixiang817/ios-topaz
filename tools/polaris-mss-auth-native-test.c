/* Complete native metadata/modem flow with own private firmware as inert
 * DATA. Every privileged operation is a software leaf. Descriptor, metadata,
 * MBA and modem host shadows are protected across the corresponding phases. */
#include <stdint.h>
static uint8_t*auth_payload,*auth_firmware;
static void auth_assets(void);
struct pmni_arch;struct pmni_translation;struct pmni_command;
static void auth_arch_hook(struct pmni_arch*);
static void auth_at_hook(struct pmni_translation*);
static int auth_raw_hook(const struct pmni_command*,unsigned*);
#define PMMN_TEST_ARENA_BYTES 0x8000000
#define PMMN_TEST_IMAGE_BYTES 0x7fc0000
#define PMMN_TEST_PAYLOAD_BASE ((uintptr_t)auth_payload)
#define PMMN_TEST_PAYLOAD_BYTES (64061440+4096)
#define EFI_XNU_MSS_PAYLOAD_FIRMWARE_AVAILABLE 1
#define EFI_XNU_MSS_FIRMWARE_OFFSET 4096
#define EFI_XNU_MSS_PAYLOAD_FW_BYTES 64061440
#define PMSI_TEST_BLOB_BYTES 64061440
#define PMSI_TEST_ASSETS 28
#define PMSI_TEST_PREPARE auth_assets
#define PMBN_TEST_ARCH_HOOK auth_arch_hook
#define PMBN_TEST_AT_HOOK auth_at_hook
#define PMBN_TEST_RAW_HOOK auth_raw_hook
#define PMBN_TEST_ENTRY unused_boot_native_suite
#define EFI_XNU_MSS_MODEM_COPY_AVAILABLE 1
#define EFI_XNU_MSS_MODEM_IO_AVAILABLE 1
#define EFI_XNU_MSS_AUTH_NATIVE_AVAILABLE 1
#define POLARIS_MSS_MODEM_COPY_SOFTWARE_PEER 1
#define POLARIS_MSS_AUTH_SOFTWARE_PEER 1
#include "polaris-mss-boot-native-test.c"
static int auth_translate(struct pwmc_translation*);
#undef pwmc_actual_translate
#define pwmc_actual_translate auth_translate
#include "uefi-mss-auth-native.h"
#include "uefi-mss-firmware-binding.h"
static struct pmsn_state*auth_owner;
static struct pmsn_delivery*auth_records;
static struct pmlc_copy*auth_copy;
static struct pmsf_segment*auth_segments;
static uint8_t*auth_modem,*auth_modem_mapping;
static unsigned auth_rounds[5],auth_caches[5],auth_protected[5],auth_continuations,auth_peers,auth_scenarios;
static unsigned auth_fault,auth_fault_assignment,auth_io_fault,auth_io_trigger,auth_io_calls,auth_copy_fault,auth_copies,auth_cache_pages;
static unsigned metadata_owner,modem_owner,peer_segments,metadata_polls,final_polls,full_bank_verified;
static uint32_t rmb_length,rmb_metadata,rmb_start,rmb_command;
static unsigned auth_bad_status;
static int auth_io_selected(void){return auth_owner&&auth_owner->pending&&auth_owner->deliveries==auth_io_trigger&&
    (auth_owner->phase==PMSN_MD_IO||auth_owner->phase==PMSN_PUBLISH||auth_owner->phase==PMSN_AUTH);}
static void auth_arch_hook(struct pmni_arch*a){if(auth_io_selected()&&auth_io_fault==3)a->ttbr0^=4096;}
static void auth_at_hook(struct pmni_translation*t){
#ifdef PMSN_TEST_AT_HOOK
    PMSN_TEST_AT_HOOK(t);
#endif
    if(auth_io_selected()&&auth_io_fault==2)t->restored++;
}
static void auth_assets(void){memcpy(blob,auth_firmware,PMSF_BLOB_BYTES);memcpy(assets,pmsf_assets,sizeof(pmsf_assets));}
static int auth_translate(struct pwmc_translation*t){return early_translate(t);}
static int pmlc_write(uint64_t to,uint64_t from,unsigned bytes,struct pwfi_sha256*h,struct pmsi_page*p)
{
    CHECK(auth_owner&&auth_owner->phase==PMSN_COPY&&modem_owner==1&&metadata_owner==3&&target_protected);
    CHECK(auth_owner->assignment[2].transaction.complete&&to==auth_copy->base+4096*auth_copies);
    CHECK(p->target.page==to&&pwmc_translation_valid(&p->target));auth_copies++;
    if(auth_copy_fault==1&&auth_copies==1){p->words_issued=1;return 0;}
    if(auth_copy_fault==2&&auth_copies==1&&bytes)*(uint8_t*)(uintptr_t)from^=1;
    return pmsi_words((uintptr_t)auth_modem+to-auth_copy->base,from,bytes,h,p);
}
static int pmlc_cache(uint64_t to,struct pwmk_record*c)
{
    CHECK(modem_owner==1&&auth_copies==++auth_cache_pages);
    *c=(struct pwmk_record){.address=to,.ctr_before=4u<<16,.ctr_after=4u<<16,.el=4,.sctlr=5,
        .operation=PWMK_CLEAN_INVALIDATE,.line_bytes=64,.lines_issued=64,.lines_returned=64,
        .attempted=1,.barrier_issued=1,.barrier_returned=1,.complete=1};return 1;
}
static void verify_modem_bank(void)
{
    unsigned cursor=0;
    for(unsigned n=0;n<28;n++){
        const struct pmsf_segment*g=&pmsf_segments[n];
        CHECK(pwmc_zero(auth_modem+cursor,g->target_offset-cursor));cursor=g->target_offset;
        if(g->filesz){CHECK(!memcmp(auth_modem+cursor,auth_firmware+pmsf_assets[g->asset].offset,g->filesz));cursor+=g->filesz;}
        CHECK(pwmc_zero(auth_modem+cursor,g->target_offset+g->memsz-cursor));cursor=g->target_offset+g->memsz;
    }
    CHECK(cursor==0x7800000&&auth_copies==30720&&auth_cache_pages==30720);full_bank_verified=1;
}
static int pmsn_affinity(uint64_t target,int64_t*raw)
{
    CHECK(local_mask&&owner->held&&target==0x100*(auth_peers%7+1));auth_peers++;*raw=1;
    if(auth_fault==4&&auth_owner->pending==auth_fault_assignment+1)*raw=0;return 1;
}
static int pmsn_cache(struct pwma_page*p,unsigned operation,struct pwmk_record*r)
{
    CHECK(auth_owner->pending>=1&&auth_owner->pending<=5);unsigned n=auth_owner->pending-1;
    struct pmsn_assignment*q=&auth_owner->assignment[n];CHECK(p==&q->page&&local_mask);auth_caches[n]++;
    CHECK((operation==PWMK_CLEAN_INVALIDATE&&auth_caches[n]==1)||(operation==PWMK_INVALIDATE&&auth_caches[n]==2));
    *r=(struct pwmk_record){.address=(uintptr_t)p,.ctr_before=4u<<16,.ctr_after=4u<<16,.el=4,.sctlr=5,
        .operation=operation,.line_bytes=64,.lines_issued=64,.lines_returned=64,.attempted=1,
        .barrier_issued=1,.barrier_returned=1,.complete=1};
    if(operation==PWMK_INVALIDATE){
        CHECK(auth_protected[n]&&!mprotect(p,host_page,PROT_READ|PROT_WRITE));auth_protected[n]=0;
        if(auth_fault_assignment==n&&auth_fault==3)p->data[4095]^=1;
    }
    if(auth_fault_assignment==n&&auth_fault==5)return 0;return 1;
}
static int pmsn_round(struct pwma_registers*r)
{
    CHECK(auth_owner->pending>=1&&auth_owner->pending<=5&&local_mask&&(owner->effects&PMSC_SECURE));
    unsigned n=auth_owner->pending-1;struct pmsn_assignment*q=&auth_owner->assignment[n];unsigned round=++auth_rounds[n];
    if(round==1){
        CHECK(r->x[0]==PWMA_FN&&r->x[1]==PWMA_ARGS&&r->x[2]==(uintptr_t)&q->page+64&&r->x[3]==16);
        unsigned claim=n==4?1:n>=2?0:2;CHECK(pwfi_le(q->page.data+64,8)==mss->memory.claim[claim].requested);
        CHECK(pwfi_le(q->page.data+72,8)==mss->memory.claim[claim].bytes);
        CHECK(pwfi_le(q->page.data+PWMA_SOURCE_OFFSET,4)==(n==1||n==4?15:3));
        CHECK(pwfi_le(q->page.data+PWMA_DEST_OFFSET,4)==(n==1||n==2||n==4?3:15));
        CHECK(pwfi_le(q->page.data+PWMA_DEST_OFFSET+4,4)==(n==1||n==4?7:6));
        if(n==2)CHECK(pwfi_le(q->page.data+PWMA_DEST_OFFSET+24,4)==15&&pwfi_le(q->page.data+PWMA_DEST_OFFSET+28,4)==6);
        if(n==3)CHECK(pwfi_le(q->page.data+PWMA_SOURCE_OFFSET+4,4)==15);
        if(n==0){CHECK(metadata_owner==3&&!mprotect(shadow+0x100000,host_page,PROT_NONE));metadata_owner=15;}
        if(n==1)CHECK(metadata_owner==15&&auth_owner->metadata.phase==2&&metadata_polls>=2);
        if(n==2)CHECK(metadata_owner==3&&modem_owner==3&&auth_owner->metadata.phase==3);
        if(n==3){CHECK(modem_owner==1&&peer_segments==28);verify_modem_bank();CHECK(!mprotect(auth_modem,0x7800000,PROT_NONE));}
        if(n==4)CHECK(target_protected&&modem_owner==2&&auth_owner->modem.phase==5&&final_polls>=2);
        CHECK(!mprotect(&q->page,host_page,PROT_NONE));auth_protected[n]=1;
    }else{
        CHECK(auth_protected[n]&&r->x[0]==1);
        for(unsigned k=1;k<7;k++)CHECK(r->x[k]==UINT64_C(0x123400000)+100*n+10*(round-1)+k);
    }
    r->x[0]=round<=auth_continuations?1:0;
    for(unsigned k=1;k<7;k++)r->x[k]=r->x[0]?UINT64_C(0x123400000)+100*n+10*round+k:0;
    if(auth_fault_assignment==n){
        if(auth_fault==1)return 0;if(auth_fault==2)r->x[0]=UINT64_MAX;
        if(auth_fault==6)auth_owner->metadata.bytes^=1;
        if(auth_fault==7)owner->fp.q8_q15[0]^=1;
        if(auth_fault==8)owner_delay+=PWMT_TICKS+1;
    }
    if(!r->x[0]){
        if(n==1){CHECK(!mprotect(shadow+0x100000,host_page,PROT_READ|PROT_WRITE));metadata_owner=3;}
        if(n==2){CHECK(!mprotect(auth_modem,0x7800000,PROT_READ|PROT_WRITE));modem_owner=1;}
        if(n==3)modem_owner=2;
        if(n==4){CHECK(!mprotect(shadow,0x100000,PROT_READ|PROT_WRITE));target_protected=0;}
    }return 1;
}
static int auth_raw_hook(const struct pmni_command*c,unsigned*v)
{
#ifdef PMSN_TEST_RAW_HOOK
    int handled=PMSN_TEST_RAW_HOOK(c,v);if(handled>=0)return handled;
#endif
    if(!auth_owner||!auth_owner->pending)return -1;
    CHECK(!boot_owner->pending&&!aop_owner->pending&&!clock_owner->pending&&!power->pending);auth_io_calls++;
    if(auth_io_selected()){
        if(auth_io_fault==1)return 0;if(auth_io_fault==5)owner_delay+=PMSC_TOTAL+1;
        if(auth_io_fault==6)put(image_heap+0x3030,0,8);
        if(auth_io_fault==4){
            if(auth_owner->phase==PMSN_MD_IO)auth_owner->metadata.event[auth_owner->metadata.events-1].command.value^=4;
            else auth_owner->modem.event[auth_owner->modem.events-1].command.value^=4;
        }
    }
    if(c->kind==PMNI_FULL_ORDER){CHECK(!c->address&&!c->value);return 1;}
    if(c->kind==PMNI_READ){
        if(c->address==0x4180018){*v=rmb_length;return 1;}
        CHECK(c->address==0x418000c);
        if(rmb_command==1){CHECK(metadata_owner==15);*v=++metadata_polls<2?0:auth_bad_status==1?UINT32_MAX:3;}
        else if(modem_owner==1){CHECK(peer_segments<28);peer_segments++;*v=auth_bad_status==2?UINT32_MAX:2;}
        else{CHECK(modem_owner==2&&peer_segments==28&&full_bank_verified);*v=++final_polls<2?3:auth_bad_status==3?UINT32_MAX:4;}
        return 1;
    }
    CHECK(c->kind==PMNI_WRITE&&(owner->effects&PMSC_REMOTE));
    switch(c->address){
    case 0x4180018:
        if(auth_owner->phase==PMSN_MD_IO)CHECK(!c->value&&metadata_owner==15);
        else CHECK(modem_owner==1&&peer_segments<28&&c->value==rmb_length+pmsf_segments[peer_segments].memsz&&auth_copy->segment[peer_segments].published);
        rmb_length=c->value;break;
    case 0x4180010:CHECK(metadata_owner==15&&c->value==mss->memory.claim[2].requested);rmb_metadata=c->value;break;
    case 0x4180014:CHECK(modem_owner==1&&c->value==mss->memory.claim[0].requested&&auth_copies);rmb_start=c->value;break;
    case 0x4180008:
        if(c->value==1)CHECK(metadata_owner==15&&rmb_metadata==mss->memory.claim[2].requested&&!rmb_length);
        else CHECK(c->value==2&&modem_owner==1&&metadata_owner==3&&rmb_start==mss->memory.claim[0].requested);
        rmb_command=c->value;break;
    default:CHECK(0);
    }return 1;
}
/* Test-only reset of private host shadows between independent scenarios;
 * never an implementation-side recovery or secure ownership transition. */
static void auth_unprotect_fixture(void)
{
    if(auth_owner)for(unsigned n=0;n<5;n++)if(auth_protected[n]){
        CHECK(!mprotect(&auth_owner->assignment[n].page,host_page,PROT_READ|PROT_WRITE));auth_protected[n]=0;
    }
    if(shadow)CHECK(!mprotect(shadow+0x100000,host_page,PROT_READ|PROT_WRITE));
}
static void auth_setup(unsigned continuations)
{
    auth_unprotect_fixture();auth_owner=0;auth_continuations=continuations;auth_scenarios++;
    memset(auth_rounds,0,sizeof(auth_rounds));memset(auth_caches,0,sizeof(auth_caches));memset(auth_protected,0,sizeof(auth_protected));
    auth_fault=auth_fault_assignment=auth_io_fault=auth_io_trigger=auth_io_calls=auth_copy_fault=auth_copies=auth_cache_pages=auth_peers=0;
    auth_bad_status=peer_segments=metadata_polls=final_polls=full_bank_verified=0;metadata_owner=modem_owner=3;
    rmb_length=rmb_metadata=rmb_start=rmb_command=0;CHECK(!mprotect(auth_modem,0x7800000,PROT_NONE));
    boot_setup();CHECK(pmbn_begin(boot_owner,boot_records,aop_owner)&&boot_drive());
    uintptr_t at=(uintptr_t)arena+0x4000000;
    at+=(-(at+offsetof(struct pmsn_state,assignment)+offsetof(struct pmsn_assignment,page)))&(host_page-1);
    auth_owner=(void*)at;auth_records=(void*)(arena+0x4100000);auth_segments=(void*)(arena+0x42f0000);auth_copy=(void*)(arena+0x4300000);
    CHECK(at+sizeof(*auth_owner)<(uintptr_t)auth_records);
    CHECK((uintptr_t)auth_records+sizeof(*auth_records)*PMSN_RECORDS<(uintptr_t)auth_segments);
    CHECK((uintptr_t)auth_segments+sizeof(pmsf_segments)<(uintptr_t)auth_copy);
    CHECK(0x4300000+sizeof(*auth_copy)<PMMN_TEST_IMAGE_BYTES);
    memset(auth_owner,0,sizeof(*auth_owner));memset(auth_records,0,sizeof(*auth_records)*PMSN_RECORDS);memset(auth_copy,0,sizeof(*auth_copy));
    memcpy(auth_segments,pmsf_segments,sizeof(pmsf_segments));CHECK(pmsn_begin(auth_owner,auth_records,auth_copy,boot_owner,auth_segments));
}
static int auth_drive(void)
{
    for(unsigned n=0;n<4*PMSN_RECORDS;n++){
        int result=pmsn_step(auth_owner);if(!result)return 0;if(result==2)return 1;CHECK(result==1);
        uint64_t at=0;
        if(auth_owner->phase==PMSN_MD_IO)at=auth_owner->metadata.next_poll;
        if(auth_owner->phase==PMSN_AUTH)at=auth_owner->modem.next_poll;
        if(at)advance_to(at);
    }CHECK(0);return 0;
}
static void auth_success(void)
{
    int result=auth_drive();if(!result)fprintf(stderr,"auth refusal: phase=%u error=%u assignments=%u io=%u md=%u modem=%u copy=%u owner=%u\n",
        auth_owner->phase,auth_owner->error,auth_owner->assignments,auth_owner->deliveries,auth_owner->metadata.error,
        auth_owner->modem.error,auth_copy->error,owner->error);
    CHECK(result&&pmsn_current(auth_owner)&&auth_owner->assignments==5&&auth_owner->modem.length==124977057);
    CHECK(metadata_owner==3&&modem_owner==2&&!target_protected&&full_bank_verified&&auth_copies==30720&&owner->held);
    CHECK(!memcmp(shadow,auth_firmware,238304)&&!memcmp(shadow+0x100000,auth_firmware+pmsf_assets[1].offset,8412));
    CHECK(!pmsc_close_unused(owner));for(unsigned n=0;n<5;n++)CHECK(auth_rounds[n]==auth_continuations+1&&!auth_protected[n]&&auth_caches[n]==2);
}
static void auth_test_open(int argc,char**argv)
{
    CHECK(argc==6);CHECK(!posix_memalign((void**)&auth_payload,0x4000,PMMN_TEST_PAYLOAD_BYTES));auth_firmware=malloc(PMSF_BLOB_BYTES);CHECK(auth_firmware);
    FILE*f=fopen(argv[5],"rb");CHECK(f&&fread(auth_firmware,1,PMSF_BLOB_BYTES,f)==PMSF_BLOB_BYTES&&!fclose(f));
    aop_test_open(5,argv);auth_modem_mapping=mmap(0,0x7800000+2*host_page,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(auth_modem_mapping!=MAP_FAILED);
    auth_modem=auth_modem_mapping+host_page;
}
static void auth_test_close(void)
{
    auth_unprotect_fixture();CHECK(!munmap(auth_modem_mapping,0x7800000+2*host_page));aop_test_close();free(auth_firmware);free(auth_payload);
}
#ifndef PMSN_TEST_ENTRY
#define PMSN_TEST_ENTRY main
#endif
int PMSN_TEST_ENTRY(int argc,char**argv)
{
    auth_test_open(argc,argv);
    auth_setup(0);auth_success();fprintf(stderr,"native metadata/full modem copy/5 secure transitions PASS; checking protected continuations\n");
    auth_records[0].native.value^=1;CHECK(!pmsn_current(auth_owner));auth_records[0].native.value^=1;
    auth_setup(3);auth_success();fprintf(stderr,"all5 four-round descriptor-protected continuations PASS; checking failures\n");
    for(unsigned fault=1;fault<=8;fault++){
        auth_setup(1);auth_fault=fault;CHECK(!auth_drive()&&auth_owner->unknown&&!auth_owner->complete&&owner->held);
        unsigned before=auth_io_calls+auth_copies+auth_peers;CHECK(!pmsn_step(auth_owner)&&before==auth_io_calls+auth_copies+auth_peers);
    }
    for(unsigned fault=1;fault<=6;fault++){
        auth_setup(0);auth_io_fault=fault;auth_io_trigger=2;CHECK(!auth_drive()&&auth_owner->unknown&&!auth_owner->complete&&target_protected);
    }
    for(unsigned fault=1;fault<=2;fault++){
        auth_setup(0);auth_copy_fault=fault;CHECK(!auth_drive()&&auth_owner->unknown&&auth_copy->unknown&&!peer_segments&&target_protected);
    }
    for(unsigned n=1;n<5;n++){
        auth_setup(0);auth_fault=1;auth_fault_assignment=n;CHECK(!auth_drive()&&auth_owner->unknown&&auth_owner->assignments==n&&!auth_owner->complete);
    }
    for(unsigned status=1;status<=3;status++){
        auth_setup(0);auth_bad_status=status;CHECK(!auth_drive()&&auth_owner->unknown&&!auth_owner->complete);
    }
    auth_test_close();
    printf("PASS %u complete native MSS auth checks, %u scenarios; software privileged leaves, no hardware/provider/USB\n",checks,auth_scenarios);return 0;
}
