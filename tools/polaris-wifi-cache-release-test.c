/* SOFTWARE actual adapter body; the registered FreePool ABI is an explicit
 * peer. The peer makes returned target pages inaccessible to detect any
 * post-release read. This is not physical firmware or a whole parent model. */
#define POLARIS_CACHE_ALLOCATION_FIXTURE_ONLY 1
#include "polaris-wifi-cache-allocation-test.c"
#include <sys/mman.h>
#include <unistd.h>
#include "uefi-wifi-cache-release.h"
static struct pbhr_result*release_record;
static struct pbhr_input release_input;
static unsigned release_mode,release_calls,release_effect,inject_stage,inject_kind,inject_byte,release_hit,release_pages;
static unsigned release_geometry;
static void*protected_page;
static size_t protected_bytes;
static void mutate(unsigned stage)
{
    if(!release_mode||release_hit||stage!=inject_stage||!inject_kind)return;release_hit=1;
    if(inject_kind==1)((uint8_t*)&release_record->input)[inject_byte]^=1;
    else if(inject_kind==2)release_input.seed=(void*)8;
    else if(inject_kind==3){s->boot=(void*)8;release_record->BS[0][72]^=1;}
    else if(inject_kind==4)seed->call.input.system=(void*)8;
    else if(inject_kind==5)*native=1;
    else if(inject_kind==6)core[0x1000]^=1;
    else if(inject_kind==7)put(core+0x1d1a8,777,8);
    else if(inject_kind==8)release_record->fp.q8_q15[0]^=1;
    else if(inject_kind==10)core[0x1d1a0+inject_byte]^=1;
    else assert(0);
}
static int release_arch(void*o,struct pgcd_arch*a)
{
    int ok=clock_peer(o,a);if(release_mode){
        if(inject_kind==9&&!release_hit&&!release_record->arch_issued){a->cpu.ticks=allocation->clock[allocation->arch_returned-1].raw.cpu.ticks-100;release_hit=1;}
        else if(inject_kind!=9)mutate(release_record->arch_issued==0?0:release_record->arch_issued==1?1:5);
    }return ok;
}
static int release_page(struct ppli_at*a)
{
    int ok=page_peer(a);if(release_mode){release_pages++;if(inject_stage==7&&release_pages==inject_byte)mutate(7);}return ok;
}
static int release_save(void*o,struct pgcd_fp_guard*f)
{int ok=fp_save(o,f);mutate(2);return ok;}
static int release_restore(void*o,struct pgcd_fp_guard*f)
{int ok=fp_restore(o,f);mutate(6);return ok;}
static void release_order(void*o){order(o);mutate(3);}
static int free_peer(void*o,struct efi_system*system,uint64_t entry,uint64_t handles,struct pbhr_api*raw)
{
    (void)o;assert(system==s&&entry==(uintptr_t)core+0x3be0&&handles==(uintptr_t)block+24);release_calls++;
    if(release_effect==10)return 0;
    raw->issued=1;
    if(release_effect==11){raw->status=0x1234;return 0;}
    raw->status=release_effect==12?UINT64_C(0x8000000000000002):0;raw->returned=1;
    put(core+0x1d1a8,120,8);if(release_effect==1)put(core+0x1cdb0,1235,8);
    uint64_t head=(uintptr_t)core+0x1d1a0+24+16*6,link=(uintptr_t)block+8;
    put((void*)(uintptr_t)head,link,8);put((void*)(uintptr_t)(head+8),link,8);
    memset(block,0xcc,2088);put(block,0x30726670,4);put(block+4,6,4);put(block+8,head,8);put(block+16,head,8);
    size_t host_page=(size_t)sysconf(_SC_PAGESIZE);
    assert(host_page>=4096&&!(host_page&(host_page-1)));protected_page=(void*)((uintptr_t)block&~(uintptr_t)(host_page-1));
    protected_bytes=(((uintptr_t)block+2088-(uintptr_t)protected_page)+host_page-1)&~(host_page-1);
    assert(!mprotect(protected_page,protected_bytes,PROT_NONE));mutate(4);return 1;
}
/* Optional SOFTWARE fixture leaves are selected before the producer seed,
 * so the retained source and every later caller bind the same functions. */
#ifndef PBHR_FIXTURE_ARCH
#define PBHR_FIXTURE_ARCH release_arch
#endif
#ifndef PBHR_FIXTURE_PAGE
#define PBHR_FIXTURE_PAGE release_page
#endif
static void release_setup(void)
{
    if(protected_page){assert(!mprotect(protected_page,protected_bytes,PROT_READ|PROT_WRITE));protected_page=0;}
    release_mode=0;allocation_fixture_arch=PBHR_FIXTURE_ARCH;allocation_fixture_page=PBHR_FIXTURE_PAGE;
    allocation_fixture_fp_save=release_save;allocation_fixture_fp_restore=release_restore;allocation_fixture_order=release_order;
    allocation_fixture_target_offset=release_geometry==1||release_geometry==4?0:128;
    allocation_fixture_GCD_offset=release_geometry==1||release_geometry==2?0x10000:0x8000;
    allocation_fixture_empty_bins=release_geometry!=3;
    setup(3,2088,release_geometry==4);assert(run());release_record=(void*)(arena+0x300000);
    assert((uint8_t*)release_record+sizeof(*release_record)<arena+0x700000);
    release_input=(struct pbhr_input){.allocation=allocation,.seed=seed,.images=images,.system=s,.image=self,.native=native,
        .opening=1000,.io=seed->input.io,.page=PBHR_FIXTURE_PAGE,.release=free_peer};
    release_calls=release_effect=inject_stage=inject_kind=inject_byte=release_hit=release_pages=0;release_mode=1;
}
static int release_run(void){return pbhr_call(release_record,&release_input);}
#ifndef POLARIS_CACHE_RELEASE_FIXTURE_ONLY
int main(int argc,char**argv)
{
    assert(argc==3&&!posix_memalign((void**)&arena,4096,0x801000));
    assert(!posix_memalign((void**)&payload_page,4096,4096)&&!posix_memalign((void**)&log_page,4096,4096));
    original=malloc(PGCI_IMAGE_BYTES);assert(original);FILE*f=fopen(argv[1],"rb");assert(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));unsigned checks=0;
    for(unsigned effect=0;effect<2;effect++){
        release_setup();release_effect=effect;int ok=release_run();
        if(!ok&&!effect)fprintf(stderr,"release positive error%u relay%u/%u api%u/%u arch%u/%u FP%u/%u pages%u\n",release_record->error,release_record->issued,release_record->returned,release_record->api.issued,release_record->api.returned,release_record->arch_issued,release_record->arch_returned,release_record->fp_save_returned,release_record->fp_restore_returned,release_pages);
        assert(release_calls==1&&FWmaps==1&&protected_page);
        if(effect){assert(!ok&&release_record->unknown&&!release_record->complete&&release_record->error==6&&!release_record->fp_restore_issued);checks++;continue;}
        assert(ok&&release_record->complete&&!release_record->unknown);
        assert(release_record->api.issued==1&&release_record->api.returned==1&&!release_record->api.status&&release_record->native_issued==127&&release_record->native_returned==127);
        assert(release_record->source[0].roots.key==1234&&release_record->source[1].roots.key==1234+effect);
        for(unsigned h=0;h<5;h++)assert(release_record->hash_count[h]==5&&!release_record->hash_failed[h]);
        FILE*out=fopen(argv[2],"wb");assert(out&&fwrite(release_record,1,sizeof(*release_record),out)==sizeof(*release_record)&&!fclose(out));checks++;
        unsigned stopped=release_calls;assert(!release_run()&&release_calls==stopped);checks++;
    }
    const unsigned stages[3]={0,4,6};
    for(unsigned n=0;n<3;n++)for(unsigned k=0;k<sizeof(release_input);k++){
        release_setup();inject_stage=stages[n];inject_kind=1;inject_byte=k;
        assert(!release_run()&&release_hit&&release_record->unknown&&!release_record->complete&&release_calls==(stages[n]?1u:0u));
        if(!stages[n])assert(!release_pages&&!release_record->fp_save_issued);
        if(stages[n]==4)assert(!release_record->fp_restore_issued&&release_record->returned&&release_record->api.returned);
        checks++;
    }
    for(unsigned stage=1;stage<=6;stage++)for(unsigned kind=2;kind<=6;kind++){
        release_setup();inject_stage=stage;inject_kind=kind;
        assert(!release_run()&&release_hit&&release_record->unknown&&release_calls==(stage>=4?1u:0u));
        if(stage<6)assert(!release_record->fp_restore_issued);checks++;
    }
    for(unsigned stage=5;stage<=6;stage++){
        release_setup();inject_stage=stage;inject_kind=7;
        assert(!release_run()&&release_hit&&release_record->unknown&&(stage==6||!release_record->fp_restore_issued));checks++;
    }
    release_setup();inject_stage=6;inject_kind=8;assert(!release_run()&&release_hit&&release_record->unknown&&release_record->fp_restore_returned);checks++;
    for(unsigned point=1;point<=61;point++){
        /* The supported single-page case has60 ATs. Preserve the old61st
         * cross-page boundary using an independent unsupported geometry. */
        release_geometry=point==61?4:0;release_setup();inject_stage=7;inject_kind=1;inject_byte=point;
        /* Every trigger index is also a valid typed-input byte offset. */
        assert(!release_run()&&release_hit&&release_pages==point&&release_record->unknown&&!release_calls);checks++;
    }
    release_geometry=0;
    for(unsigned effect=10;effect<=12;effect++){
        release_setup();release_effect=effect;assert(!release_run()&&release_record->unknown&&release_calls==1&&!release_record->fp_restore_issued&&release_record->arch_issued==1);
        assert(release_record->api.issued==(effect!=10)&&release_record->api.returned==(effect==12)&&release_record->returned==(effect==12));
        assert(release_record->native_issued==15&&release_record->native_returned==15);checks++;
    }
    for(unsigned stage=0;stage<2;stage++){
        release_setup();unsigned before_calls=release_calls;
        if(stage)seed->call.boot_address=8;else release_input.opening++;
        assert(!release_run()&&!release_record->issued&&release_calls==before_calls);checks++;
    }
    release_setup();inject_kind=9;assert(!release_run()&&release_hit&&!release_calls&&!release_pages&&release_record->unknown);checks++;
    for(unsigned k=0;k<232;k++){
        release_setup();inject_stage=4;inject_kind=10;inject_byte=k;
        assert(!release_run()&&release_hit&&release_calls==1&&release_record->unknown&&
            !release_record->fp_restore_issued&&release_record->arch_issued==1);checks++;
    }
    for(unsigned variant=1;variant<=4;variant++){
        release_geometry=variant;release_setup();
        assert(!release_run()&&release_record->error==8&&release_record->unknown&&!release_calls&&
            !release_record->fp_save_issued&&!release_record->issued);checks++;
    }
    release_geometry=0;
    printf("{\"passed\":true,\"checks\":%u,\"record_bytes\":%zu,\"input_bytes\":%zu,\"archive_allocation\":%zu,\"archive_seed\":%zu,\"archive_images\":%zu,\"before_target\":%zu,\"images_offset\":%zu,\"BS_offset\":%zu,\"arch_offset\":%zu,\"FP_offset\":%zu,\"source_offset\":%zu,\"hash_offset\":%zu,\"API_offset\":%zu,\"flags_offset\":%zu,\"digest_offset\":%zu,\"SOFTWARE_only\":true,\"original_FW_executed\":false,\"retired_pages_PROT_NONE\":true,\"restricted_small_free_prefix_checked\":true,\"transition_qualified\":false}\n",checks,sizeof(*release_record),sizeof(release_input),offsetof(struct pbhr_result,allocation),offsetof(struct pbhr_result,seed),offsetof(struct pbhr_result,images),offsetof(struct pbhr_result,before_target),offsetof(struct pbhr_result,image),offsetof(struct pbhr_result,BS),offsetof(struct pbhr_result,arch),offsetof(struct pbhr_result,fp),offsetof(struct pbhr_result,source),offsetof(struct pbhr_result,hashes),offsetof(struct pbhr_result,api),offsetof(struct pbhr_result,attempted),offsetof(struct pbhr_result,digest));
    if(protected_page)assert(!mprotect(protected_page,protected_bytes,PROT_READ|PROT_WRITE));
    free(original);free(arena);free(payload_page);free(log_page);return 0;
}
#endif
