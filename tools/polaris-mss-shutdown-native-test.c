/* Entire native startup then actual STOP/halt/reset adapters. Own artifacts
 * remain inert; UEFI, privileged leaves, remote SMP/GLINK are SOFTWARE. */
struct pmni_command;struct pmni_translation;
static int shutdown_raw(const struct pmni_command*,unsigned*);
static void shutdown_at(struct pmni_translation*);
#define PMSX_TEST_RAW_HOOK shutdown_raw
#define PMSX_TEST_AT_HOOK shutdown_at
#define EFI_XNU_MSS_SHUTDOWN_NATIVE_AVAILABLE 1
#define PMWA_TEST_ENTRY unused_wlan_native_suite
#include "polaris-wifi-wlfw-native-test.c"
#include "uefi-mss-shutdown-native.h"
static struct pmnd_state*shutdown_owner;
static struct pmnd_delivery*shutdown_records;
static unsigned shutdown_fault,shutdown_raws,shutdown_stores,shutdown_rings,shutdown_scenarios;
static uint32_t shutdown_halt[3],shutdown_pdc,shutdown_alt,shutdown_restart;
static void shutdown_at(struct pmni_translation*t)
{
    if(shutdown_owner&&shutdown_owner->pending&&shutdown_fault==4&&t->page==pmh_base(0))t->write_par|=1;
}
static int shutdown_raw(const struct pmni_command*c,unsigned*out)
{
    if(!shutdown_owner||!shutdown_owner->pending)return -1;
    CHECK(owner->held&&local_mask&&!power->pending&&!clock_owner->pending&&!aop_owner->pending&&!boot_owner->pending&&!auth_owner->pending);
    shutdown_raws++;
    if(c->kind==PMNI_WRITE)shutdown_stores++;
    if(c->address==PMS_DOORBELL){
        CHECK(c->kind==PMNI_WRITE&&(c->value==0x4000||!c->value));
        if(c->value){
            shutdown_rings++;CHECK(pms_u32(sm_shadow+channel->item[0].data+36)==1);
            if(shutdown_fault!=1)put(sm_shadow+remote_at+36,10,4);
            if(shutdown_fault==5)sm_shadow[remote_at+20]^=1;
            uint8_t request[128];unsigned n=qopen(request,32,0);put(request+5,n-7,2);rx_qrtr(1,service_port,request,n);
        }return 1;
    }
    if(c->kind==PMNI_FULL_ORDER||c->kind==PMNI_STORE_ORDER)return 1;
    CHECK(shutdown_owner->quiesced&&shutdown_owner->shutdown.stop.stop.ack_held);
    for(unsigned j=0;j<3;j++){
        if(c->address==pmh_base(j)){
            if(c->kind==PMNI_READ)*out=shutdown_halt[j];else{CHECK(c->value==1&&!shutdown_halt[j]);shutdown_halt[j]=1;}return 1;
        }
        if(c->address==pmh_base(j)+4){CHECK(c->kind==PMNI_READ&&shutdown_halt[j]);*out=1;return 1;}
        if(c->address==pmh_base(j)+8){CHECK(c->kind==PMNI_READ&&shutdown_halt[j]);*out=shutdown_fault==2&&j==1?0:1;return 1;}
    }
    CHECK(shutdown_owner->shutdown.stop.halt.ports_held==7);
    if(c->address==PMSR_PDC){
        if(c->kind==PMNI_READ)*out=shutdown_pdc;
        else{CHECK(((shutdown_pdc^c->value)&~0x200u)==0);shutdown_pdc=c->value;}
    }else if(c->address==PMSR_ALT){CHECK(c->kind==PMNI_WRITE&&(shutdown_pdc&0x200)&&c->value<=1);shutdown_alt=c->value;}
    else if(c->address==PMSR_RESTART){
        CHECK(c->kind==PMNI_WRITE&&shutdown_alt&&c->value<=1);shutdown_restart=c->value;if(shutdown_fault==3)return 0;
    }else CHECK(0);
    return 1;
}
static int shutdown_drive(void)
{
    for(unsigned n=0;n<1500;n++){
        int result=pmnd_step(shutdown_owner);if(result!=1)return result;
        struct pmsd_shutdown*d=&shutdown_owner->shutdown;uint64_t next=0;
        if(d->phase==2)next=d->reset.not_before;
        else if(d->stop.phase==2)next=d->stop.halt.next_poll;
        else if(d->stop.stop.step==PMS_POLL)next=d->stop.stop.next_poll;
        if(next)advance_to(next);
    }return 1;
}
static void shutdown_setup(unsigned fault)
{
    shutdown_owner=0;wlan_setup(0);int ready=1;
    for(unsigned n=0;n<550&&ready==1;n++){ready=pmwa_step(wlan);if(ready==1&&wlan->pages==512)advance_to(wlan->next_poll);}CHECK(ready==2);
    put(sm_shadow+remote_at+36,2,4); /* Actual peer now asserts ERROR_READY. */
    shutdown_owner=(void*)(arena+0x7400000);shutdown_records=(void*)(arena+0x7200000);
    CHECK(sizeof(*shutdown_owner)<0x100000&&sizeof(*shutdown_records)*PMND_RECORDS<0x200000);
    memset(shutdown_owner,0,sizeof(*shutdown_owner));memset(shutdown_records,0,sizeof(*shutdown_records)*PMND_RECORDS);
    shutdown_fault=fault;shutdown_raws=shutdown_stores=shutdown_rings=0;memset(shutdown_halt,0,sizeof(shutdown_halt));
    shutdown_pdc=0xa5000001;shutdown_alt=shutdown_restart=0;shutdown_scenarios++;
    if(fault==6){put(sm_shadow+remote_at+36,10,4);CHECK(!pmnd_begin(shutdown_owner,shutdown_records,wlan)&&!negotiation->stopping);return;}
    CHECK(pmnd_begin(shutdown_owner,shutdown_records,wlan));
}
int main(int argc,char**argv)
{
    CHECK(argc==8);sm_original=malloc(PWFI_IMAGE_BYTES);sm_shadow=malloc(PMSQ_BYTES);rmtfs_shadow=malloc(0x202000);
    memory=aligned_alloc(4096,PNV_BYTES);CHECK(sm_original&&sm_shadow&&rmtfs_shadow&&memory);
    FILE*f=fopen(argv[6],"rb");CHECK(f&&fread(sm_original,1,PWFI_IMAGE_BYTES,f)==PWFI_IMAGE_BYTES&&!fclose(f));auth_test_open(6,argv);
    CHECK(!posix_memalign((void**)&msa_shadow,host_page,0x200000));
    load(argv[7],"gpt0-primary.bin",headers[0][0],4096);load(argv[7],"gpt0-backup.bin",headers[0][1],4096);load(argv[7],"gpt0-table.bin",tables[0],polaris_nv_plan.disk[0].table_bytes);
    load(argv[7],"gpt1-primary.bin",headers[1][0],4096);load(argv[7],"gpt1-backup.bin",headers[1][1],4096);load(argv[7],"gpt1-table.bin",tables[1],polaris_nv_plan.disk[1].table_bytes);
    for(unsigned fault=0;fault<=6;fault++){
        shutdown_setup(fault);if(fault==6)continue;unsigned before_responses=responses;int done=shutdown_drive();
        if(!fault){
            if(done!=2)fprintf(stderr,"shutdown result=%d error=%u phase=%u/%u SMP=%u/%u ACK=%u source=%u GLINK=%u owner=%u\n",done,shutdown_owner->error,shutdown_owner->shutdown.phase,shutdown_owner->shutdown.stop.phase,shutdown_owner->shutdown.stop.stop.step,shutdown_owner->shutdown.stop.stop.error,shutdown_owner->shutdown.stop.stop.ack_held,sm->error,glink->error,owner->error);
            CHECK(done==2&&pmnd_current(shutdown_owner)&&shutdown_rings==1&&responses==before_responses+1);
            CHECK(shutdown_owner->shutdown.stop.halt.ports_held==7&&shutdown_pdc==0xa5000001&&!shutdown_alt&&!shutdown_restart&&wlan_memory_mask==3&&owner->held);
            CHECK(!pmsc_close_unused(owner));
            fprintf(stderr,"native shutdown: RMTFS through fresh STOP ACK, then frozen transport/three AXI halts/reset PASS; no power/VMID handback\n");
        }else{
            CHECK(!done&&shutdown_owner->unknown&&shutdown_owner->error&&!shutdown_owner->complete&&owner->held&&negotiation->stopping==(uintptr_t)shutdown_owner);
            if(fault==1)CHECK(!shutdown_owner->quiesced&&!shutdown_halt[0]);
            if(fault==2)CHECK(shutdown_halt[0]&&shutdown_halt[1]&&!shutdown_halt[2]&&!shutdown_alt);
            if(fault==3)CHECK(shutdown_restart&&shutdown_alt&&(shutdown_pdc&0x200));
            if(fault==4)CHECK(!shutdown_halt[0]&&!shutdown_alt);
            unsigned issued=shutdown_raws;CHECK(!pmnd_step(shutdown_owner)&&issued==shutdown_raws);
        }
    }
    wlan_unprotect();free(msa_shadow);free(memory);free(rmtfs_shadow);free(sm_shadow);free(sm_original);auth_test_close();
    printf("PASS %u native shutdown checks, %u scenarios; software hardware/modem only\n",checks+nv_checks,shutdown_scenarios);return 0;
}
