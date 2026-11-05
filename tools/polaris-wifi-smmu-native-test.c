/* Current native full WLAN producer plus real typed SMMU read adapter.
 * All privileged/UEFI/firmware/register leaves remain SOFTWARE. */
struct pmni_command;struct pmni_translation;
static int smmu_raw(const struct pmni_command*,unsigned*);
static void smmu_at(struct pmni_translation*);
#define PMSX_TEST_RAW_HOOK smmu_raw
#define PMSX_TEST_AT_HOOK smmu_at
#define EFI_XNU_WIFI_SMMU_NATIVE_AVAILABLE 1
#define PMWA_TEST_ENTRY unused_wlan_native_suite
#include "polaris-wifi-wlfw-native-test.c"
#include "uefi-wifi-smmu-native.h"
static struct pmws_state*smmu_owner;
static struct pmws_delivery*smmu_records;
static unsigned smmu_fault,smmu_reads,smmu_scenarios;
static void smmu_at(struct pmni_translation*t)
{if(smmu_owner&&smmu_owner->pending&&smmu_fault==6&&t->page==PWSU_BASE)t->write_par|=1;}
static int smmu_raw(const struct pmni_command*c,unsigned*out)
{
    if(!smmu_owner||!smmu_owner->pending)return -1;
    CHECK(c->kind==PMNI_READ&&pwsu_readable(c->address)&&local_mask&&owner->held);smmu_reads++;
    unsigned at=(unsigned)(c->address-PWSU_BASE);*out=0;
    if(at==0x20)*out=(1u<<30)|(1u<<27)|128;
    else if(at==0x24)*out=(5u<<28)|64;
    else if(at==0x28)*out=0x35;
    else if(at==0)*out=smmu_fault==7?1:0x400;
    else if(at>=0x800&&at<0xa00){
        unsigned n=(at-0x800)/4;
        if(n==3)*out=0x80010040;
        if(n==4&&smmu_fault==2)*out=0x80000040;
        if(n==5)*out=0x800000a0; /* Existing unrelated client must be untouched. */
        if(smmu_fault==5&&smmu_owner->route.pass==1&&n==5)*out^=1;
    }else if(at>=0xc00&&at<0xe00){
        unsigned n=(at-0xc00)/4;if(n==3)*out=smmu_fault==1?0x10000:7;
        if(n==5)*out=0x10000;
    }else if(at==0x101c)*out=0x1f300;
    else if(at==0x181c)*out=1;
    else if(at==0x47000)*out=0xc010e4|(smmu_fault==3?1:0);
    else if(at==0x47058)*out=smmu_fault==4?2:0;
    else CHECK(at==0x48||at==0x74||at==0x477f4);
    return 1;
}
static void smmu_setup(unsigned fault)
{
    smmu_owner=0;wlan_setup(0);int ready=1;
    for(unsigned n=0;n<550&&ready==1;n++){ready=pmwa_step(wlan);if(ready==1&&wlan->pages==512)advance_to(wlan->next_poll);}CHECK(ready==2);
    smmu_owner=(void*)(arena+0x6c00000);smmu_records=(void*)(arena+0x6d00000);
    CHECK(0x4300000+sizeof(*auth_copy)<0x6c00000&&sizeof(*smmu_owner)<0x100000&&sizeof(*smmu_records)*PWSU_READS<0x300000);
    memset(smmu_owner,0,sizeof(*smmu_owner));memset(smmu_records,0,sizeof(*smmu_records)*PWSU_READS);
    smmu_fault=fault;smmu_reads=0;smmu_scenarios++;CHECK(pmws_begin(smmu_owner,smmu_records,wlan));
}
int main(int argc,char**argv)
{
    CHECK(argc==8);sm_original=malloc(PWFI_IMAGE_BYTES);sm_shadow=malloc(PMSQ_BYTES);rmtfs_shadow=malloc(0x202000);
    memory=aligned_alloc(4096,PNV_BYTES);CHECK(sm_original&&sm_shadow&&rmtfs_shadow&&memory);
    FILE*f=fopen(argv[6],"rb");CHECK(f&&fread(sm_original,1,PWFI_IMAGE_BYTES,f)==PWFI_IMAGE_BYTES&&!fclose(f));auth_test_open(6,argv);
    CHECK(!posix_memalign((void**)&msa_shadow,host_page,0x200000));
    load(argv[7],"gpt0-primary.bin",headers[0][0],4096);load(argv[7],"gpt0-backup.bin",headers[0][1],4096);load(argv[7],"gpt0-table.bin",tables[0],polaris_nv_plan.disk[0].table_bytes);
    load(argv[7],"gpt1-primary.bin",headers[1][0],4096);load(argv[7],"gpt1-backup.bin",headers[1][1],4096);load(argv[7],"gpt1-table.bin",tables[1],polaris_nv_plan.disk[1].table_bytes);
    for(unsigned fault=0;fault<=7;fault++){
        smmu_setup(fault);int done=1;for(unsigned n=0;n<PWSU_READS+2&&done==1;n++)done=pmws_step(smmu_owner);
        if(fault<2){
            if(done!=2)fprintf(stderr,"SMMU result=%d error=%u route=%u pass=%u stage=%u index=%u raw=%u reads=%u owner=%u\n",done,smmu_owner->error,smmu_owner->route.error,smmu_owner->route.pass,smmu_owner->route.stage,smmu_owner->route.index,smmu_reads,smmu_owner->reads,owner->error);
            CHECK(done==2&&pmws_current(smmu_owner)&&smmu_reads==(fault?524:544));
            for(unsigned sid=0;sid<2;sid++)CHECK(smmu_owner->route.sample[1].selected[sid]==3&&smmu_owner->route.sample[1].type[sid]==fault);
            for(unsigned n=0;n<smmu_owner->reads;n++){
                struct pmni_command bad={smmu_records[n].command.address,PMNI_WRITE,0};CHECK(!pmni_allowed(&bad));
            }
            if(!fault)fprintf(stderr,"native SMMU: complete producer, two current128-group passes, exact SID40/41 S1-bypass CB7, no writes PASS\n");
            advance_to(owner->last+PGCD_FRESH_TICKS+1);CHECK(!pmws_current(smmu_owner));
        }else{
            CHECK(!done&&smmu_owner->unknown&&smmu_owner->error&&!smmu_owner->complete&&owner->held);
            if(fault==6)CHECK(!smmu_reads);
            unsigned reads=smmu_reads;CHECK(!pmws_step(smmu_owner)&&reads==smmu_reads);
        }
    }
    wlan_unprotect();free(msa_shadow);free(memory);free(rmtfs_shadow);free(sm_shadow);free(sm_original);auth_test_close();
    printf("PASS %u native SMMU route checks, %u scenarios; SOFTWARE leaves, no SMMU writes/DMA\n",checks+nv_checks,smmu_scenarios);return 0;
}
