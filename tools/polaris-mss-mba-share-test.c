/* Actual allocation/staging/assignment caller with software privileged leaves.
 * Descriptor and MBA host shadows become PROT_NONE across secure returns. */
#define PMSI_TEST_ENTRY unused_stage_suite
#include "polaris-mss-stage-test.c"
static int share_arch(void*,struct pgcd_arch*);
static int share_save(void*,struct pgcd_fp_guard*);
static int share_restore_fp(void*,struct pgcd_fp_guard*);
#undef pgcd_actual_arch
#undef pgcd_actual_fp_save
#undef pgcd_actual_fp_restore
#define pgcd_actual_arch share_arch
#define pgcd_actual_fp_save share_save
#define pgcd_actual_fp_restore share_restore_fp
#define EFI_XNU_WIFI_MEM_ASSIGN_AVAILABLE 1
#define EFI_XNU_MSS_MBA_SHARE_AVAILABLE 1
#define POLARIS_MSS_MBA_SHARE_SOFTWARE_PEER 1
#include "uefi-mss-mba-share.h"
static struct pmsb_result*share;
static unsigned local_mask,share_fault,share_trigger,peers,cache_count,smcs,continuations,descriptor_protected,target_protected;
static int share_arch(void*p,struct pgcd_arch*a)
{
    int ok=early_arch(p,a);a->cpu.daif=local_mask?0xc0:0;a->cpu.group1=local_mask?0:1;
    if(smcs==share_trigger){if(share_fault==14)a->cpu.ttbr0^=4096;if(share_fault==15)a->cpu.ticks+=PGCD_FRESH_TICKS+1;}
    return ok;
}
static int share_save(void*p,struct pgcd_fp_guard*f)
{if(share_fault==16)return 0;return early_save(p,f);}
static int share_restore_fp(void*p,struct pgcd_fp_guard*f)
{if(share_fault==17)return 0;return early_restore(p,f);}
static int pmsb_affinity(uint64_t target,int64_t*raw)
{
    CHECK(local_mask&&target==0x100*(peers%7+1));peers++;*raw=1;
    if(peers==share_trigger){
        if(share_fault==1)*raw=0;
        if(share_fault==2)share->fp.q8_q15[0]^=1;
        if(share_fault==3)return 0;
    }return 1;
}
static int pmsb_mask(struct pwrpc_transition*t)
{
    CHECK(!local_mask&&t->target_daif==0xc0&&!t->target_group);
    t->group_before=1;t->daif_read=0xc0;t->daif_written=t->daif_observed=t->group_written=t->group_observed=1;
    local_mask=1;if(share_fault==4)t->daif_read=0x80;return 1;
}
static int pmsb_restore(struct pwrpc_transition*t)
{
    CHECK(local_mask&&t->target_group==1&&!t->target_daif&&share->assignment_returned_zero);
    t->daif_before=0xc0;t->group_read=1;t->daif_written=t->daif_observed=t->group_written=t->group_observed=1;
    if(share_fault==5){t->group_read=0;return 0;}local_mask=0;return 1;
}
static int pmsb_cache(struct pwma_page*p,unsigned op,struct pwmk_record*r)
{
    CHECK(local_mask&&p==&share->page);cache_count++;
    CHECK((cache_count==1&&op==PWMK_CLEAN_INVALIDATE)||(cache_count==2&&op==PWMK_INVALIDATE));
    *r=(struct pwmk_record){.address=(uintptr_t)p,.ctr_before=4u<<16,.ctr_after=4u<<16,.el=4,.sctlr=5,
        .operation=op,.line_bytes=64,.lines_issued=64,.lines_returned=64,.attempted=1,
        .barrier_issued=1,.barrier_returned=1,.complete=1};
    if(cache_count==share_trigger){if(share_fault==6)r->barrier_returned=0;if(share_fault==7)return 0;}
    if(op==PWMK_INVALIDATE){CHECK(descriptor_protected&&!mprotect(p,host_page,PROT_READ|PROT_WRITE));descriptor_protected=0;}
    if(share_fault==13&&cache_count==2)p->data[4095]^=1;
    return 1;
}
static int pmsb_round(struct pwma_registers*r)
{
    CHECK(local_mask&&peers==7&&cache_count==1&&stage_writes==259);smcs++;
    if(smcs==1){
        CHECK(r->x[0]==PWMA_FN&&r->x[1]==PWMA_ARGS);
        CHECK(pwfi_le(share->page.data+PWMA_REGION_OFFSET,8)==mss->memory.claim[1].requested);
        CHECK(pwfi_le(share->page.data+PWMA_REGION_OFFSET+8,8)==0x100000);
        CHECK(pwfi_le(share->page.data+PWMA_SOURCE_OFFSET,4)==3);
        CHECK(pwfi_le(share->page.data+PWMA_DEST_OFFSET,4)==15&&pwfi_le(share->page.data+PWMA_DEST_OFFSET+4,4)==6);
        CHECK(!memcmp(shadow,blob,238304));CHECK(!mprotect(shadow,0x100000,PROT_NONE));target_protected=1;
    }else CHECK(r->x[0]==1&&r->x[1]==0x12340000+smcs-1);
    if(!descriptor_protected){CHECK(!mprotect(&share->page,host_page,PROT_NONE));descriptor_protected=1;}
    r->x[0]=smcs<=continuations?1:0;r->x[1]=r->x[0]?0x12340000+smcs:0;
    if(share_fault==8)r->x[0]=UINT64_MAX;
    if(share_fault==10)stage->copied_hash[0][0]^=1;
    if(share_fault==11)share->stage=8;
    if(share_fault==12)share->fp.q8_q15[0]^=1;
    return share_fault==9?0:1;
}
static void share_setup(unsigned f,unsigned trigger_at,unsigned interrupted)
{
    if(descriptor_protected){CHECK(!mprotect(&share->page,host_page,PROT_READ|PROT_WRITE));descriptor_protected=0;}
    if(target_protected){CHECK(!mprotect(shadow,0x100000,PROT_READ|PROT_WRITE));target_protected=0;}
    stage_setup(0,0);CHECK(stage_run());
    uintptr_t at=(uintptr_t)arena+0x180000;at+=(-(at+offsetof(struct pmsb_result,page)))&(host_page-1);
    share=(void*)at;CHECK(at+sizeof(*share)+host_page<=(uintptr_t)arena+0x1c0000);memset(share,0,sizeof(*share));
    local_mask=peers=cache_count=smcs=0;share_fault=f;share_trigger=trigger_at;continuations=interrupted;
}
static void write_records(const char*path,const char*tag)
{
    const char*suffix[]={"",".stage",".memory",".early",".retained"};
    const void*data[]={share,stage,mss,early,held};
    const size_t sizes[]={PMSB_RAW_BYTES,sizeof(*stage),sizeof(*mss),sizeof(*early),sizeof(*held)};
    for(unsigned n=0;n<5;n++){
        char name[4096];CHECK(snprintf(name,sizeof(name),"%s%s%s",path,tag,suffix[n])<(int)sizeof(name));
        FILE*out=fopen(name,"wb");CHECK(out&&fwrite(data[n],1,sizes[n],out)==sizes[n]&&!fclose(out));
    }
}
#ifndef PMSB_TEST_ENTRY
#define PMSB_TEST_ENTRY main
#endif
int PMSB_TEST_ENTRY(int argc,char**argv)
{
    assert(argc==2||argc==3);CHECK(!posix_memalign((void**)&arena,0x4000,0x200000));original=malloc(PGCI_IMAGE_BYTES);assert(original);
    FILE*f=fopen(argv[1],"rb");CHECK(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));
    host_page=(size_t)sysconf(_SC_PAGESIZE);CHECK(host_page&&host_page<=0x4000&&!(host_page&(host_page-1)));
    shadow_mapping=mmap(0,0x104000+2*host_page,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(shadow_mapping!=MAP_FAILED);
    shadow=shadow_mapping+host_page;CHECK(!mprotect(shadow,0x104000,PROT_READ|PROT_WRITE));
    for(unsigned n=0;n<4;n++){
        share_setup(0,0,n);CHECK(pmsb_share(share,stage));
        CHECK(share->complete&&!share->unknown&&!share->cpu_held&&!local_mask&&share->assignment_returned_zero);
        CHECK(peers==14&&cache_count==2&&smcs==n+1&&!descriptor_protected&&target_protected);
        if(n==3&&argc==3)write_records(argv[2],"");
        CHECK(!pmsb_share(share,stage)&&smcs==n+1);
    }
    for(unsigned kind=1;kind<=3;kind++)for(unsigned n=1;n<=14;n++){
        share_setup(kind,n,0);CHECK(!pmsb_share(share,stage)&&share->unknown&&!share->complete&&peers==n);
    }
    for(unsigned kind=6;kind<=7;kind++)for(unsigned n=1;n<=2;n++){
        share_setup(kind,n,0);CHECK(!pmsb_share(share,stage)&&share->unknown&&!share->complete&&cache_count==n);
    }
    for(unsigned kind=4;kind<=17;kind++){
        if(kind==6||kind==7)continue;
        share_setup(kind,1,0);CHECK(!pmsb_share(share,stage)&&share->unknown&&!share->complete);
    }
    share_setup(0,0,4);CHECK(!pmsb_share(share,stage)&&share->unknown&&!share->complete&&smcs==4&&descriptor_protected&&target_protected);
    /* The actual RAM-log prefix remains safe while both areas are unreadable. */
    uint8_t exported_hash[32];pweh_digest(share,PMSB_RAW_BYTES,exported_hash);
    if(argc==3)write_records(argv[2],".unknown");
    for(unsigned kind=0;kind<6;kind++){
        share_setup(0,0,0);
        if(kind==0)stage->page[255].cache.barrier_returned=0;
        else if(kind==1)stage->page[0].target.page+=4096;
        else if(kind==2)stage->copied_hash[0][0]^=1;
        else if(kind==3)stage->unknown=1;
        else if(kind==4)mss->memory.claim[1].bytes++;
        else *native_flag=1;
        CHECK(!pmsb_share(share,stage)&&share->unknown&&!smcs&&!peers);
    }
    if(descriptor_protected)CHECK(!mprotect(&share->page,host_page,PROT_READ|PROT_WRITE));
    CHECK(!munmap(shadow_mapping,0x104000+2*host_page));free(original);free(arena);
    printf("PASS %u MBA assignment checks; software secure returns, protected descriptor/target RAM\n",checks);return 0;
}
