/* Native full MSS authentication then continuous guarded RMTFS sharing.
 * Only privileged leaves are replaced. Own firmware stays inert host DATA. */
#ifndef PMTF_TEST_EXISTING_AUTH
#define PMSN_TEST_ENTRY unused_auth_suite
#endif
#define EFI_XNU_MSS_RMTFS_NATIVE_AVAILABLE 1
#define POLARIS_MSS_RMTFS_SOFTWARE_PEER 1
#ifndef PMTF_TEST_EXISTING_AUTH
#include "polaris-mss-auth-native-test.c"
#endif
#include "uefi-mss-rmtfs-native.h"
static struct pmtf_state*rmtfs;
static uint8_t*rmtfs_shadow;
static unsigned rmtfs_rounds,rmtfs_continuations,rmtfs_protected,rmtfs_zeroes,rmtfs_caches,rmtfs_fault,rmtfs_scenarios;
static uint64_t rmtfs_peer_delay;
static int pmtf_write_zero(uint64_t at,struct pmtf_zero*z)
{
    CHECK(rmtfs&&rmtfs->pending==1&&at==rmtfs->base+4096*rmtfs_zeroes&&!rmtfs_rounds);
    rmtfs_zeroes++;uint64_t*p=(void*)(rmtfs_shadow+4096+at-rmtfs->base);
    for(unsigned n=0;n<512;n++){z->issued++;p[n]=0;if(rmtfs_fault==1&&rmtfs_zeroes==2)return 0;CHECK(!p[n]);z->returned++;}return 1;
}
static int pmtf_cache_page(uint64_t at,unsigned op,struct pwmk_record*r)
{
    CHECK(local_mask&&owner->held);rmtfs_caches++;
    if(at==(uintptr_t)&rmtfs->assignment.page){
        if(op==PWMK_CLEAN_INVALIDATE)CHECK(!rmtfs_protected&&rmtfs_zeroes==512&&rmtfs_caches==513);
        else{CHECK(op==PWMK_INVALIDATE&&rmtfs_protected&&!mprotect((void*)(uintptr_t)at,host_page,PROT_READ|PROT_WRITE));rmtfs_protected=0;
            if(rmtfs_fault==4)rmtfs->assignment.page.data[4095]^=1;}
    }else CHECK(op==PWMK_CLEAN_INVALIDATE&&at==rmtfs->base+4096*(rmtfs_zeroes-1));
    *r=(struct pwmk_record){.address=at,.ctr_before=4u<<16,.ctr_after=4u<<16,.el=4,.sctlr=5,.operation=op,
        .line_bytes=64,.lines_issued=64,.lines_returned=64,.attempted=1,.barrier_issued=1,.barrier_returned=1,.complete=1};
    if(rmtfs_fault==2&&rmtfs_zeroes==2)return 0;return 1;
}
static int pmtf_affinity(uint64_t target,int64_t*raw)
{CHECK(target>=0x100&&target<=0x700&&!(target&255)&&local_mask);*raw=rmtfs_fault==5?0:1;
 if(rmtfs_rounds)owner_delay+=rmtfs_peer_delay;return 1;}
static int pmtf_round(struct pwma_registers*r)
{
    CHECK(rmtfs->pending==2&&rmtfs->pages==512&&(owner->effects&PMSC_SECURE));rmtfs_rounds++;
    if(rmtfs_rounds==1){
        CHECK(r->x[0]==PWMA_FN&&r->x[1]==PWMA_ARGS&&r->x[2]==(uintptr_t)&rmtfs->assignment.page+64);
        const uint8_t*p=rmtfs->assignment.page.data;CHECK(pwfi_le(p+64,8)==rmtfs->base&&pwfi_le(p+72,8)==0x200000);
        CHECK(pwfi_le(p,4)==3&&pwfi_le(p+128,4)==3&&pwfi_le(p+132,4)==6&&pwfi_le(p+152,4)==15&&pwfi_le(p+156,4)==6);
        CHECK(pwmc_zero(rmtfs_shadow+4096,0x200000));for(unsigned n=0;n<4096;n++)CHECK(rmtfs_shadow[n]==0xa5&&rmtfs_shadow[0x201000+n]==0xa5);
        CHECK(!mprotect(&rmtfs->assignment.page,host_page,PROT_NONE));rmtfs_protected=1;
    }else{CHECK(rmtfs_protected&&r->x[0]==1);for(unsigned n=1;n<7;n++)CHECK(r->x[n]==0x1234000+10*(rmtfs_rounds-1)+n);}
    r->x[0]=rmtfs_rounds<=rmtfs_continuations?1:0;for(unsigned n=1;n<7;n++)r->x[n]=r->x[0]?0x1234000+10*rmtfs_rounds+n:0;
    if(rmtfs_fault==3)return 0;if(rmtfs_fault==6)r->x[0]=UINT64_MAX;
    if(rmtfs_fault==7)owner_delay+=PWMT_TICKS+1;if(rmtfs_fault==8)rmtfs->base^=4096;
    if(rmtfs_fault==9)owner->fp.q8_q15[0]^=1;if(rmtfs_fault==10)auth_owner->modem.phase^=1;return 1;
}
static void rmtfs_setup(unsigned continuation,unsigned fault)
{
    if(rmtfs_protected)CHECK(!mprotect(&rmtfs->assignment.page,host_page,PROT_READ|PROT_WRITE));rmtfs_protected=0;
    rmtfs=0;auth_setup(0);auth_success();rmtfs=(void*)(arena+0x7600000);CHECK(sizeof(*rmtfs)<0x100000);
    memset(rmtfs,0,sizeof(*rmtfs));memset(rmtfs_shadow,0xa5,0x202000);
    rmtfs_rounds=rmtfs_zeroes=rmtfs_caches=0;rmtfs_continuations=continuation;rmtfs_fault=fault;rmtfs_scenarios++;
    rmtfs_peer_delay=0;
    CHECK(pmtf_begin(rmtfs,auth_owner));
}
static int rmtfs_drive(void)
{for(unsigned n=0;n<514;n++){int result=pmtf_step(rmtfs);if(result!=1)return result;}return 1;}
#ifndef PMTF_TEST_ENTRY
#define PMTF_TEST_ENTRY main
#endif
int PMTF_TEST_ENTRY(int argc,char**argv)
{
    auth_test_open(argc,argv);rmtfs_shadow=malloc(0x202000);CHECK(rmtfs_shadow);
    for(unsigned continuation=0;continuation<=3;continuation+=3){
        rmtfs_setup(continuation,0);CHECK(rmtfs_drive()==2&&rmtfs_rounds==continuation+1&&rmtfs_zeroes==512&&!rmtfs_protected&&pmtf_current(rmtfs));
        struct pmtf_state*other=(void*)(arena+0x7700000);memset(other,0,sizeof(*other));CHECK(!pmtf_begin(other,auth_owner));
        CHECK(pmsn_current(auth_owner)&&owner->held&&!pmsc_close_unused(owner));
    }
    fprintf(stderr,"continuous native RMTFS guarded zero/share + protected4-round continuation PASS; checking faults\n");
    /* CPU-only peer work happens after the returned SMC has been accepted,
     * before the next issue. Descriptor remains PROT_NONE across all rounds. */
    for(unsigned continuation=0;continuation<=3;continuation+=3){
        rmtfs_setup(continuation,0);rmtfs_peer_delay=19200000/40; /*25ms/peer,175ms/round*/
#if EFI_XNU_WIFI_RMTFS_AUTH_ENVELOPE
        CHECK(rmtfs_drive()==2&&rmtfs_rounds==continuation+1&&!rmtfs_protected&&pmtf_current(rmtfs));
#else
        CHECK(!rmtfs_drive()&&rmtfs->unknown&&rmtfs->error==2&&rmtfs->assignment.transaction.error==PWMT_TIME&&rmtfs_rounds==1);
#endif
    }
    rmtfs_setup(0,0);rmtfs_peer_delay=PWMT_AUTH_TICKS/7+1;
    CHECK(!rmtfs_drive()&&rmtfs->unknown&&rmtfs->assignment.transaction.error==PWMT_TIME&&!rmtfs->complete);
    unsigned stopped=rmtfs_zeroes+rmtfs_rounds+rmtfs_caches;
    CHECK(!pmtf_step(rmtfs)&&stopped==rmtfs_zeroes+rmtfs_rounds+rmtfs_caches);
    for(unsigned fault=1;fault<=10;fault++){
        rmtfs_setup(0,fault);CHECK(!rmtfs_drive()&&rmtfs->unknown&&!rmtfs->complete&&owner->held);
        if(fault==7)CHECK(rmtfs->assignment.transaction.error==PWMT_TIME); /*issued SMC >100ms*/
        unsigned issued=rmtfs_zeroes+rmtfs_rounds+rmtfs_caches;CHECK(!pmtf_step(rmtfs)&&!pmtf_current(rmtfs)&&issued==rmtfs_zeroes+rmtfs_rounds+rmtfs_caches);
    }
    if(rmtfs_protected)CHECK(!mprotect(&rmtfs->assignment.page,host_page,PROT_READ|PROT_WRITE));
    free(rmtfs_shadow);auth_test_close();printf("PASS %u native continuous RMTFS checks, %u scenarios; software privileged leaves only\n",checks,rmtfs_scenarios);return 0;
}
