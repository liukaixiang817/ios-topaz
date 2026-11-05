/* Complete pre-native allocation -> MSS/WLFW -> SMMU -> actual CE adapter.
 * All architecture, UEFI, MMIO and firmware peers remain SOFTWARE. */
struct pwea_map;struct pmni_command;struct pmni_translation;
static void ce_pre_native(void),ce_map_extra(struct pwea_map*),ce_at(struct pmni_translation*);
static int ce_raw(const struct pmni_command*,unsigned*),ce_qrtr(const unsigned char*,unsigned);
#define EFI_XNU_WIFI_CE_MEMORY_AVAILABLE 1
#define EFI_XNU_WIFI_CE_NATIVE_AVAILABLE 1
#define POLARIS_WIFI_CE_MEMORY_SOFTWARE_PEER 1
#define POLARIS_WIFI_CE_SOFTWARE_PEER 1
#define PMRF_TEST_CE_MEMORY 1
#define PMRF_TEST_PRE_NATIVE ce_pre_native
#define PMRF_TEST_MAP_EXTRA ce_map_extra
#define PMWA_TEST_QRTR_HOOK ce_qrtr
#define PMWS_TEST_RAW_HOOK ce_raw
#define PMWS_TEST_AT_HOOK ce_at
#define PMWS_TEST_ENTRY unused_smmu_suite
#include "polaris-wifi-smmu-native-test.c"
#include "uefi-wifi-ce-native.h"
static struct pcdm_state*ce_memory;
static struct pmce_state*ce;
static uint8_t*ce_shadow;
static unsigned ce_maps,ce_allocations,ce_zeroes,ce_reads,ce_writes,ce_orders,ce_fault,ce_scenarios;
static uint32_t ce_regs[13][1024];
#define CE_ALLOCATION UINT64_C(0xb0200000)
static efi_status pcdm_map(struct efi_system*system,struct pwea_map*m)
{
    CHECK(system==s&&ce_maps<2&&m==&ce_memory->map[ce_maps]);ce_maps++;
    unsigned n=0;emit_descriptor(m->data+40*n++,3,(uintptr_t)arena,PMMN_TEST_ARENA_BYTES);
    emit_descriptor(m->data+40*n++,2,0x180000000,0x10000000);
    for(unsigned j=0;j<2;j++)emit_descriptor(m->data+40*n++,2,early->memory.claim[j].requested,early->memory.claim[j].bytes);
    emit_descriptor(m->data+40*n++,2,(uintptr_t)memory,PNV_BYTES);
    emit_descriptor(m->data+40*n++,ce_allocations?2:7,CE_ALLOCATION,PWDM_BYTES);
    m->map.bytes=40*n;m->map.stride=40;m->map.version=1;m->map.key=80+ce_maps;return 0;
}
static efi_status pcdm_allocate(struct efi_system*system,uint64_t*at)
{CHECK(system==s&&!ce_allocations&&*at==PWDM_LIMIT-1);ce_allocations++;*at=CE_ALLOCATION;return 0;}
static void ce_pre_native(void)
{
    ce_memory=(void*)(arena+0x7fc0000);CHECK(sizeof(*ce_memory)<0x40000);memset(ce_memory,0,sizeof(*ce_memory));ce_maps=ce_allocations=0;
    CHECK(pcdm_run(ce_memory,early)&&ce_memory->complete&&ce_maps==2&&ce_allocations==1);
}
static void ce_map_extra(struct pwea_map*m)
{CHECK(ce_memory->complete&&m->map.bytes+40<=sizeof(m->data));emit_descriptor(m->data+m->map.bytes,2,CE_ALLOCATION,PWDM_BYTES);m->map.bytes+=40;}
static void ce_at(struct pmni_translation*t)
{if(ce&&ce->pending&&ce->phase==3&&ce_fault==4&&t->page==PWCE_BASE)t->write_par|=1;}
static int ce_raw(const struct pmni_command*c,unsigned*out)
{
    if(!ce||!ce->pending||ce->phase!=3)return -1;
    CHECK(local_mask&&owner->held&&wlan->client.enabled&&ce->admitted&&ce_zeroes==PWDM_BYTES/4096&&(owner->effects&PMSC_DMA));
    if(c->kind==PMNI_FULL_ORDER){ce_orders++;return ce_fault!=7;}
    CHECK(pwce_register(c->address,c->kind==PMNI_WRITE));
    unsigned pipe=(unsigned)((c->address-PWCE_BASE)/4096),index=(unsigned)((c->address&4095)/4);
    if(c->kind==PMNI_WRITE){ce_writes++;ce_regs[pipe][index]=c->value;return 1;}
    CHECK(c->kind==PMNI_READ);ce_reads++;*out=ce_regs[pipe][index];if(ce_fault==6&&ce_writes)*out^=1;return 1;
}
static int ce_qrtr(const uint8_t*p,unsigned size)
{
    if(pms_u32(p+4)!=1||pms_u32(p+28)!=77||p[32]!=0)return 0;
    unsigned msg=psm_u16(p+35);if(msg!=0x23&&msg!=0x22)return 0;
    CHECK(ce&&size>=39&&ce->admitted&&!ce_writes&&ce_zeroes==PWDM_BYTES/4096);
    unsigned request=++wlan_requests;CHECK(request==5||request==6);CHECK(psm_u16(p+33)==request);
    if(request==5)CHECK(msg==0x23&&pms_u32(p+20)==559);
    else CHECK(msg==0x22&&pms_u32(p+20)==14&&pms_u32(p+42)==0);
    uint8_t reply[14]={2,p[33],p[34],p[35],p[36],7,0,2,4,0,0,0,0,0};
    if(ce_fault==5&&request==6){reply[10]=1;reply[12]=1;}
    rx_qrtr(1,pms_u32(p+12),reply,sizeof(reply));return 1;
}
static int pmce_zero(uint64_t at,struct pmtf_zero*z)
{
    CHECK(ce&&local_mask&&owner->held&&ce->pending&&at==CE_ALLOCATION+4096*ce_zeroes&&!ce_writes&&!wlan->client.enable_requested);
    uint64_t*p=(void*)(ce_shadow+at-CE_ALLOCATION);ce_zeroes++;
    for(unsigned n=0;n<512;n++){z->issued++;p[n]=0;CHECK(!p[n]);z->returned++;if(ce_fault==1&&n==31)return 0;}return 1;
}
static int pmce_cache(uint64_t at,unsigned op,struct pwmk_record*r)
{
    CHECK(local_mask&&at==CE_ALLOCATION+4096*(ce_zeroes-1)&&op==PWMK_CLEAN_INVALIDATE);
    *r=(struct pwmk_record){.address=at,.ctr_before=4u<<16,.ctr_after=4u<<16,.el=4,.sctlr=5,.operation=op,
        .line_bytes=64,.lines_issued=64,.lines_returned=64,.attempted=1,.barrier_issued=1,.barrier_returned=1,.complete=1};
    return ce_fault!=2;
}
static void ce_setup(unsigned fault_kind)
{
    ce=0;smmu_owner=0;wlan_setup(0);int ready=1;
    for(unsigned n=0;n<550&&ready==1;n++){ready=pmwa_step(wlan);if(ready==1&&wlan->pages==512)advance_to(wlan->next_poll);}CHECK(ready==2);
    ce=(void*)(arena+0x7000000);CHECK(sizeof(*ce)<0x200000);memset(ce,0,sizeof(*ce));memset(ce_shadow,0xa5,PWDM_BYTES);
    smmu_owner=(void*)(arena+0x6c00000);smmu_records=(void*)(arena+0x6d00000);
    memset(smmu_owner,0,sizeof(*smmu_owner));memset(smmu_records,0,sizeof(*smmu_records)*PWSU_READS);
    ce_fault=fault_kind;ce_zeroes=ce_reads=ce_writes=ce_orders=smmu_reads=0;smmu_fault=fault_kind==3?2:0;ce_scenarios++;
    memset(ce_regs,0,sizeof(ce_regs));
    for(unsigned n=0;n<12;n++)ce_regs[n][0x18/4]=0x40e0000,ce_regs[n][0x2c/4]=0x8000001f,ce_regs[n][0x34/4]=0x800003e0;
    CHECK(pmce_begin(ce,ce_memory,wlan,smmu_owner,smmu_records));
}
int main(int argc,char**argv)
{
    CHECK(argc==8);sm_original=malloc(PWFI_IMAGE_BYTES);sm_shadow=malloc(PMSQ_BYTES);rmtfs_shadow=malloc(0x202000);
    memory=aligned_alloc(4096,PNV_BYTES);ce_shadow=aligned_alloc(4096,PWDM_BYTES);CHECK(sm_original&&sm_shadow&&rmtfs_shadow&&memory&&ce_shadow);
    FILE*f=fopen(argv[6],"rb");CHECK(f&&fread(sm_original,1,PWFI_IMAGE_BYTES,f)==PWFI_IMAGE_BYTES&&!fclose(f));auth_test_open(6,argv);
    CHECK(!posix_memalign((void**)&msa_shadow,host_page,0x200000));
    load(argv[7],"gpt0-primary.bin",headers[0][0],4096);load(argv[7],"gpt0-backup.bin",headers[0][1],4096);load(argv[7],"gpt0-table.bin",tables[0],polaris_nv_plan.disk[0].table_bytes);
    load(argv[7],"gpt1-primary.bin",headers[1][0],4096);load(argv[7],"gpt1-backup.bin",headers[1][1],4096);load(argv[7],"gpt1-table.bin",tables[1],polaris_nv_plan.disk[1].table_bytes);
    for(unsigned fault_kind=0;fault_kind<=7;fault_kind++){
        ce_setup(fault_kind);int done=1;
        for(unsigned n=0;n<4000&&done==1;n++){done=pmce_step(ce);if(done==1&&ce->phase==2)advance_to(owner->last+192000);}
        if(!fault_kind){
            if(done!=2)fprintf(stderr,"CE result=%d err=%u phase=%u pages=%u events=%u init=%u smmu=%u client=%u owner=%u reads=%u elapsed=%llu\n",done,ce->error,ce->phase,ce->pages,ce->events,ce->init.error,smmu_owner->error,wlan->client.error,owner->error,sm->reads,(unsigned long long)(owner->last-owner->opening));
            CHECK(done==2&&ce->complete&&ce->init.complete&&wlan->client.enabled&&wlan_requests==6&&ce_writes&&ce_orders==ce_writes&&smmu_reads==544);
            CHECK(pwmc_zero(ce_shadow,PWDM_BYTES)&&ce_memory->consumer==(uintptr_t)ce&&owner->held);
            CHECK(ce_regs[12][1]==CE_ALLOCATION+ce_memory->layout.rri&&ce_regs[12][2]==0);
            fprintf(stderr,"native CE: independent current allocation, zero/CIVAC, SID40/41 route, CFG/MISSION, empty host rings PASS\n");
        }else{
            CHECK(!done&&ce->unknown&&ce->error&&!ce->complete&&owner->held);
            if(fault_kind<=3)CHECK(!wlan->client.enable_requested&&!ce_writes);
            if(fault_kind==4)CHECK(!ce_reads&&!ce_writes);
            if(fault_kind==5)CHECK(!ce_writes&&!wlan->client.enabled);
            if(fault_kind>=6)CHECK(ce_writes==1);
            unsigned prior=ce_zeroes+ce_reads+ce_writes+ce_orders;CHECK(!pmce_step(ce)&&prior==ce_zeroes+ce_reads+ce_writes+ce_orders);
        }
    }
    wlan_unprotect();free(msa_shadow);free(ce_shadow);free(memory);free(rmtfs_shadow);free(sm_shadow);free(sm_original);auth_test_close();
    printf("PASS %u native CE checks, %u scenarios; SOFTWARE leaves, no real DMA/scan\n",checks+nv_checks,ce_scenarios);return 0;
}
