#include <stdint.h>
struct efi_system;struct pwea_map;struct pccl_record;
static uint64_t htt_map(struct efi_system*,struct pwea_map*),htt_allocate(struct efi_system*,uint64_t*);
static void htt_prepare(void),htt_retain(struct pwea_map*),htt_target_tx(unsigned,const unsigned char*,unsigned);
static int htt_cache(uint64_t,unsigned,unsigned,struct pccl_record*);
#define EFI_XNU_WIFI_HTT_NATIVE_AVAILABLE 1
#define POLARIS_WIFI_HTT_SOFTWARE_PEER 1
#define PMCE_TEST_SECOND_MAP htt_map
#define PMCE_TEST_SECOND_ALLOCATE htt_allocate
#define PMCE_TEST_SECOND_PREPARE htt_prepare
#define PMCE_TEST_SECOND_RETAIN htt_retain
#define PMCT_TEST_CACHE_HOOK htt_cache
#define PMHC_TEST_DATA_HOOK htt_target_tx
#define PMWI_TEST_ENTRY unused_wmi_suite
#include "polaris-wifi-wmi-native-test.c"
#include "uefi-wifi-htt-native.h"
#define HTT_ALLOCATION UINT64_C(0xb1200000)
static struct pcdm_state*htt_memory;
static struct pmht_state*htt;
static uint8_t*htt_cpu,*htt_device;
static unsigned htt_maps,htt_allocations,htt_fault,htt_commands,htt_scenarios,htt_copies,htt_caches;
static uint64_t htt_map(struct efi_system*system,struct pwea_map*m)
{
    CHECK(system==s&&htt_maps<2&&m==&htt_memory->map[htt_maps]);htt_maps++;
    unsigned n=0;emit_descriptor(m->data+40*n++,3,(uintptr_t)arena,PMMN_TEST_ARENA_BYTES);
    emit_descriptor(m->data+40*n++,2,0x180000000,0x10000000);
    for(unsigned j=0;j<2;j++)emit_descriptor(m->data+40*n++,2,early->memory.claim[j].requested,early->memory.claim[j].bytes);
    emit_descriptor(m->data+40*n++,2,(uintptr_t)memory,PNV_BYTES);emit_descriptor(m->data+40*n++,2,CE_ALLOCATION,PWDM_BYTES);
    emit_descriptor(m->data+40*n++,htt_allocations?2:7,HTT_ALLOCATION,PHTM_BYTES);
    m->map.bytes=40*n;m->map.stride=40;m->map.version=1;m->map.key=90+htt_maps;return 0;
}
static uint64_t htt_allocate(struct efi_system*system,uint64_t*at)
{CHECK(system==s&&!htt_allocations&&*at==PWDM_LIMIT-1);htt_allocations++;*at=HTT_ALLOCATION;return 0;}
static void htt_prepare(void)
{
    htt_memory=(void*)(arena+0x7400000);CHECK(sizeof(*htt_memory)<0x40000);memset(htt_memory,0,sizeof(*htt_memory));htt_maps=htt_allocations=0;
    CHECK(pcdm_run(htt_memory,early)&&htt_memory->complete&&htt_maps==2&&htt_allocations==1);
}
static void htt_retain(struct pwea_map*m)
{CHECK(htt_memory->complete&&m->map.bytes+40<=sizeof(m->data));emit_descriptor(m->data+m->map.bytes,2,HTT_ALLOCATION,PHTM_BYTES);m->map.bytes+=40;}
static int pmht_copy(uint64_t at,void*private,unsigned bytes,unsigned write,struct pmct_memory*r)
{
    CHECK(htt&&htt->busy&&local_mask&&owner->held&&at>=HTT_ALLOCATION&&bytes<=PHTM_BYTES-(at-HTT_ALLOCATION));
    CHECK(r->address==at&&r->bytes==bytes&&r->write==write);htt_copies++;uint8_t*p=private,*q=htt_cpu+at-HTT_ALLOCATION;
    for(unsigned n=0;n<bytes;n++){r->issued++;if(write)q[n]=p[n];else p[n]=q[n];r->returned++;if(htt_fault==1&&n==31)return 0;}return 1;
}
static int htt_cache(uint64_t at,unsigned bytes,unsigned op,struct pccl_record*r)
{
    if(at<HTT_ALLOCATION||at>=HTT_ALLOCATION+PHTM_BYTES)return -1;
    CHECK(htt&&htt->busy&&owner->held&&local_mask&&!(at&63)&&!(bytes&63)&&bytes<=4096&&bytes<=PHTM_BYTES-(at-HTT_ALLOCATION));htt_caches++;
    if(htt_fault==2)return 0;uint8_t*c=htt_cpu+at-HTT_ALLOCATION,*d=htt_device+at-HTT_ALLOCATION;
    if(op==PWMK_CLEAN_INVALIDATE)memcpy(d,c,bytes);else{CHECK(op==PWMK_INVALIDATE);memcpy(c,d,bytes);}
    *r=(struct pccl_record){.cache={.address=at,.ctr_before=4u<<16,.ctr_after=4u<<16,.el=4,.sctlr=5,.operation=op,
        .line_bytes=64,.lines_issued=bytes/64,.lines_returned=bytes/64,.attempted=1,.barrier_issued=1,.barrier_returned=1,.complete=1},.bytes=bytes};return 1;
}
static void htt_target_tx(unsigned pipe,const unsigned char*frame,unsigned bytes)
{
    CHECK(htt&&pmht_live(htt)&&pipe==4&&frame[0]==htc->client.htt&&htt->prepared);htt_commands++;
    const uint8_t*p=frame+8;
    if(htt_commands==1){
        CHECK(bytes==12&&!pwmi_get(p));if(htt_fault==4)return;
        uint8_t response[]={1,0,4,0,0,0,0,0,0,4,3,0};if(htt_fault==3)response[10]=4;target_frame(1,response,sizeof(response));return;
    }
    if(htt_commands==2){CHECK(bytes==72&&p[0]==6&&p[2]==1&&p[3]==72&&pwcr_get(p+4,8)==HTT_ALLOCATION+htt->layout.fragments);return;}
    if(htt_commands==3){
        CHECK(bytes==56&&p[0]==2&&p[1]==1&&pwcr_get(p+4,8)==HTT_ALLOCATION+htt->layout.index&&pwcr_get(p+12,8)==HTT_ALLOCATION+htt->layout.ring);
        CHECK(pwmi_get(htt_device+htt->layout.index)==2047);
        for(unsigned n=0;n<2048;n++)CHECK(pwcr_get(htt_device+htt->layout.ring+8*n,8)==(n<2047?HTT_ALLOCATION+htt->layout.receive+(uint64_t)2048*n:0));
        CHECK(pwmc_zero(htt_device+htt->layout.receive,2048*2048));return;
    }
    CHECK(htt_commands==4&&bytes==12&&pwmi_get(p)==0x00034005);
}
int main(int argc,char**argv)
{
    CHECK(argc==8);sm_original=malloc(PWFI_IMAGE_BYTES);sm_shadow=malloc(PMSQ_BYTES);rmtfs_shadow=malloc(0x202000);
    memory=aligned_alloc(4096,PNV_BYTES);ce_shadow=aligned_alloc(4096,PWDM_BYTES);device_memory=aligned_alloc(4096,PWDM_BYTES);
    htt_cpu=aligned_alloc(4096,PHTM_BYTES);htt_device=aligned_alloc(4096,PHTM_BYTES);CHECK(htt_cpu&&htt_device);
    CHECK(sm_original&&sm_shadow&&rmtfs_shadow&&memory&&ce_shadow&&device_memory);
    FILE*f=fopen(argv[6],"rb");CHECK(f&&fread(sm_original,1,PWFI_IMAGE_BYTES,f)==PWFI_IMAGE_BYTES&&!fclose(f));auth_test_open(6,argv);
    CHECK(!posix_memalign((void**)&msa_shadow,host_page,0x200000));
    load(argv[7],"gpt0-primary.bin",headers[0][0],4096);load(argv[7],"gpt0-backup.bin",headers[0][1],4096);load(argv[7],"gpt0-table.bin",tables[0],polaris_nv_plan.disk[0].table_bytes);
    load(argv[7],"gpt1-primary.bin",headers[1][0],4096);load(argv[7],"gpt1-backup.bin",headers[1][1],4096);load(argv[7],"gpt1-table.bin",tables[1],polaris_nv_plan.disk[1].table_bytes);
    for(unsigned kind=0;kind<5;kind++){
        htt=0;wmi=0;htc_setup(0);wmi=(void*)(arena+0x7340000);memset(wmi,0,sizeof(*wmi));wmi_fault=wmi_requests=0;CHECK(pmwi_begin(wmi,htc));
        for(unsigned n=0;n<40&&htc->client.phase!=8;n++){CHECK(pmwi_step(wmi)==1);advance_to(owner->last+19200);}
        CHECK(htc->client.phase==8);wmi_service();int result=1;
        for(unsigned n=0;n<30&&result==1;n++){advance_to(owner->last+19200);result=pmwi_step(wmi);}CHECK(result==3);
        htt=(void*)(arena+0x7380000);CHECK(sizeof(*htt)<0x20000);memset(htt,0,sizeof(*htt));memset(htt_cpu,0xa5,PHTM_BYTES);memset(htt_device,0xa5,PHTM_BYTES);
        htt_fault=kind;htt_commands=htt_copies=htt_caches=0;htt_scenarios++;CHECK(pmht_begin(htt,htt_memory,wmi));result=1;
        for(unsigned n=0;n<2200&&result==1;n++){
            if(htt->prepared)advance_to(owner->last+19200);result=pmht_step(htt);
            if(kind==4&&htt->client.phase==1)advance_to(htt->client.deadline+1);
        }
        if(!kind){
            if(result!=3)fprintf(stderr,"HTT result=%d err=%u client=%u phase=%u CE=%u pages=%u commands=%u\n",result,htt->error,htt->client.error,htt->client.phase,transport->error,htt->zeroed,htt_commands);
            CHECK(result==3&&pmht_live(htt)&&htt_commands==4&&htt->zeroed==2050&&htt->ring_pages==4&&htt_memory->consumer==(uintptr_t)htt&&ce_memory->consumer==(uintptr_t)ce);
            CHECK(htt->client.major==3&&htt->client.minor==4&&owner->held);
            fprintf(stderr,"native HTT: distinct actual allocation, zero/CIVAC,2047 RX addresses/index, VERSION/FRAG/RX/AGGR PASS\n");
        }else{
            CHECK(result==-1&&htt->unknown&&htt->error&&owner->held);CHECK(htt_commands==(kind<3?0u:1u));
            unsigned calls=htt_copies+htt_caches+transport_writes;CHECK(pmht_step(htt)==-1&&calls==htt_copies+htt_caches+transport_writes);
        }
    }
    wlan_unprotect();free(htt_cpu);free(htt_device);free(msa_shadow);free(device_memory);free(ce_shadow);free(memory);free(rmtfs_shadow);free(sm_shadow);free(sm_original);auth_test_close();
    printf("PASS %u native HTT checks, %u scenarios; SOFTWARE target/cache/MMIO/UEFI, no actual packets\n",checks+nv_checks,htt_scenarios);return 0;
}
