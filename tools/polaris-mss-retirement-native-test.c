/* Actual complete producer chain through native resource retirement.
 * Privileged leaves, UEFI, NV, remote firmware and registers are SOFTWARE. */
#define PMND_TEST_ENTRY unused_shutdown_native_suite
#include "polaris-mss-shutdown-native-test.c"
#define EFI_XNU_MSS_RETIREMENT_NATIVE_AVAILABLE 1
#include "uefi-mss-retirement-native.h"
static struct pmnr_state*resource_retirement;
static unsigned retire_scenarios;
static void retire_setup(unsigned fault)
{
    shutdown_setup(0);CHECK(shutdown_drive()==2&&pmnd_current(shutdown_owner));
    resource_retirement=(void*)(arena+0x7100000);
    CHECK(0x4300000+sizeof(*auth_copy)<0x7100000&&sizeof(*resource_retirement)<0x100000);
    memset(resource_retirement,0,sizeof(*resource_retirement));retire_scenarios++;
    CHECK(pmnr_begin(resource_retirement,shutdown_owner));
    CHECK(active_clocks->phase==3&&!pmsn_live(auth_owner)&&owner->held);
    if(fault==1){clock_fault=1;clock_trigger=clock_owner->deliveries+3;} /* first restore WRITE returned; barrier fails */
    if(fault==2){peer_fault=1;peer_request=power->requests+1;peer_trigger=1;}
    if(fault==3){aop_fault=1;aop_trigger=aop_owner->deliveries+1;}
    if(fault==4)shutdown_owner->shutdown.reset.event[0].value^=1;
    if(fault==5)owner_delay+=PMSC_TOTAL+1;
}
static int retire_drive(void)
{
    for(unsigned n=0;n<500;n++){
        int r=pmnr_step(resource_retirement);if(r!=1)return r;
        uint64_t next=resource_retirement->phase==1?active_clocks->not_before:
            resource_retirement->phase==2?proxy->not_before:
            resource_retirement->phase==5?aop_owner->notify[1].not_before:0;
        if(next)advance_to(next);
    }return 1;
}
#ifndef PMNR_TEST_ENTRY
#define PMNR_TEST_ENTRY main
#endif
int PMNR_TEST_ENTRY(int argc,char**argv)
{
    CHECK(argc==8);sm_original=malloc(PWFI_IMAGE_BYTES);sm_shadow=malloc(PMSQ_BYTES);rmtfs_shadow=malloc(0x202000);
    memory=aligned_alloc(4096,PNV_BYTES);CHECK(sm_original&&sm_shadow&&rmtfs_shadow&&memory);
    FILE*f=fopen(argv[6],"rb");CHECK(f&&fread(sm_original,1,PWFI_IMAGE_BYTES,f)==PWFI_IMAGE_BYTES&&!fclose(f));auth_test_open(6,argv);
    CHECK(!posix_memalign((void**)&msa_shadow,host_page,0x200000));
    load(argv[7],"gpt0-primary.bin",headers[0][0],4096);load(argv[7],"gpt0-backup.bin",headers[0][1],4096);load(argv[7],"gpt0-table.bin",tables[0],polaris_nv_plan.disk[0].table_bytes);
    load(argv[7],"gpt1-primary.bin",headers[1][0],4096);load(argv[7],"gpt1-backup.bin",headers[1][1],4096);load(argv[7],"gpt1-table.bin",tables[1],polaris_nv_plan.disk[1].table_bytes);
    for(unsigned fault=0;fault<=5;fault++){
        retire_setup(fault);unsigned before_responses=responses,before_rings=channel->rings;int done=retire_drive();
        if(!fault){
            if(done!=2)fprintf(stderr,"retirement result=%d error=%u phase=%u power=%u clock=%u AOP=%u owner=%u\n",done,resource_retirement->error,resource_retirement->phase,power->error,clock_owner->error,aop_owner->error,owner->error);
            CHECK(done==2&&pmnr_current(resource_retirement)&&power->restored&&clock_owner->restored&&aop_owner->restored);
            CHECK(!memcmp(clock_regs,clock_original,sizeof(clock_regs))&&!memcmp(votes,original_votes,sizeof(votes)));
            CHECK(aop_doorbells==2&&!aop_pending&&!memcmp(aop_memory,aop_original,0x100000));
            CHECK(owner->held&&!pmsc_close_unused(owner)&&wlan_memory_mask==3&&modem_owner==2);
            CHECK(responses==before_responses&&channel->rings==before_rings&&!pmnd_step(shutdown_owner));
            fprintf(stderr,"native retirement: current STOP/reset -> six clocks/proxy/supplies/AOP restored, frozen WLAN, CPU/VMIDs retained PASS\n");
        }else{
            CHECK(!done&&!resource_retirement->complete&&owner->held&&shutdown_owner->retirement==(uintptr_t)resource_retirement);
            if(fault!=5)CHECK(resource_retirement->unknown&&resource_retirement->error);
            if(fault==1)CHECK(active_clocks->write_returned[1]&32);
            if(fault==3)CHECK(power->restored&&clock_owner->restored&&!aop_owner->restored);
            unsigned issued=native_writes+clock_writes+aop_writes;CHECK(!pmnr_step(resource_retirement)&&issued==native_writes+clock_writes+aop_writes);
        }
    }
    wlan_unprotect();free(msa_shadow);free(memory);free(rmtfs_shadow);free(sm_shadow);free(sm_original);auth_test_close();
    printf("PASS %u native resource retirement checks, %u scenarios; software leaves only\n",checks+nv_checks,retire_scenarios);return 0;
}
