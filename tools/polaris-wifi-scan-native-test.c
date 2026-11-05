static void scan_target_tx(unsigned,const unsigned char*,unsigned);
#define EFI_XNU_WIFI_SCAN_NATIVE_AVAILABLE 1
#define PMWI_TEST_TX_HOOK scan_target_tx
#define PMWI_TEST_ENTRY unused_wmi_suite
#include "polaris-wifi-wmi-native-test.c"
#include "uefi-wifi-scan-native.h"
static struct pmwsn_state*scan;
static unsigned scan_fault,scan_scenarios,scan_requests;
static void scan_event(unsigned type,unsigned id,unsigned reason)
{
    uint8_t p[32]={0};pwmi_put(p,0x3001);pwmi_header(p+4,36,24);pwmi_put(p+8,type);pwmi_put(p+12,reason);
    pwmi_put(p+16,2437);pwmi_put(p+20,0xa001);pwmi_put(p+24,id);wmi_frame(p,sizeof(p),2);
}
static void scan_beacon(void)
{
    uint8_t p[100]={0};pwmi_put(p,0x7001);pwmi_header(p+4,44,40);pwmi_put(p+8,6);pwmi_put(p+12,42);
    pwmi_put(p+24,48);pwmi_header(p+48,17,48);uint8_t*b=p+52;b[0]=0x80;b[16]=2;b[21]=7;b[32]=100;b[34]=0x11;
    b[36]=0;b[37]=7;memcpy(b+38,"fixture",7);b[45]=3;b[46]=1;b[47]=6;
    if(scan_fault==2)b[37]=255;wmi_frame(p,sizeof(p),1);
}
static void scan_target_tx(unsigned pipe,const unsigned char*frame,unsigned bytes)
{
    CHECK(scan&&pmwsn_live(scan)&&pipe==3&&frame[0]==htc->client.wmi);scan_requests++;
    unsigned cmd=pwmi_get(frame+8);
    if(scan_requests==1){CHECK(cmd==0x5001&&bytes==36&&!memcmp(frame+28,wmi->client.mac,6));wmi_frame(frame,0,2);return;}
    if(scan_requests==2){CHECK(cmd==0x3003&&bytes==332&&pwmi_get(frame+16)==11);wmi_frame(frame,0,2);return;}
    CHECK(scan_requests==3&&cmd==0x3001&&bytes==184&&pwmi_get(frame+16)==0xa007&&pwmi_get(frame+72)==0x31);
    if(scan_fault==4)return;
    if(scan_fault==3){scan_event(64,0xa007,4);return;}
    if(scan_fault==1)scan_event(2,0xa006,0);
    scan_event(1,0xa007,0);if(scan_fault!=5)scan_beacon();scan_event(2,0xa007,0);
}
int main(int argc,char**argv)
{
    CHECK(argc==8);sm_original=malloc(PWFI_IMAGE_BYTES);sm_shadow=malloc(PMSQ_BYTES);rmtfs_shadow=malloc(0x202000);
    memory=aligned_alloc(4096,PNV_BYTES);ce_shadow=aligned_alloc(4096,PWDM_BYTES);device_memory=aligned_alloc(4096,PWDM_BYTES);
    CHECK(sm_original&&sm_shadow&&rmtfs_shadow&&memory&&ce_shadow&&device_memory);
    FILE*f=fopen(argv[6],"rb");CHECK(f&&fread(sm_original,1,PWFI_IMAGE_BYTES,f)==PWFI_IMAGE_BYTES&&!fclose(f));auth_test_open(6,argv);
    CHECK(!posix_memalign((void**)&msa_shadow,host_page,0x200000));
    load(argv[7],"gpt0-primary.bin",headers[0][0],4096);load(argv[7],"gpt0-backup.bin",headers[0][1],4096);load(argv[7],"gpt0-table.bin",tables[0],polaris_nv_plan.disk[0].table_bytes);
    load(argv[7],"gpt1-primary.bin",headers[1][0],4096);load(argv[7],"gpt1-backup.bin",headers[1][1],4096);load(argv[7],"gpt1-table.bin",tables[1],polaris_nv_plan.disk[1].table_bytes);
    for(unsigned kind=0;kind<6;kind++){
        wmi=0;scan=0;htc_setup(0);wmi=(void*)(arena+0x7340000);memset(wmi,0,sizeof(*wmi));wmi_fault=wmi_requests=0;
        CHECK(pmwi_begin(wmi,htc));
        for(unsigned n=0;n<40&&htc->client.phase!=8;n++){CHECK(pmwi_step(wmi)==1);advance_to(owner->last+19200);}
        CHECK(htc->client.phase==8);wmi_service();int result=1;
        for(unsigned n=0;n<30&&result==1;n++){advance_to(owner->last+19200);result=pmwi_step(wmi);}CHECK(result==3&&wmi_requests==1);
        scan=(void*)(arena+0x7360000);CHECK(sizeof(*scan)<0x10000);memset(scan,0,sizeof(*scan));scan_fault=kind;scan_requests=0;scan_scenarios++;
        CHECK(pmwsn_begin(scan,wmi,7));result=1;
        for(unsigned n=0;n<80&&result==1;n++){
            advance_to(owner->last+19200);result=pmwsn_step(scan);
            if(kind==4&&scan->client.phase==3)advance_to(scan->client.deadline+1);
        }
        if(kind==3||kind==4){
            CHECK(result==-1&&scan->unknown&&scan->error&&owner->held);unsigned writes=transport_writes;CHECK(pmwsn_step(scan)==-1&&writes==transport_writes);
        }else{
            if(result!=3)fprintf(stderr,"scan result=%d error=%u client=%u phase=%u HTC=%u CE=%u commands=%u\n",result,scan->error,scan->client.error,scan->client.phase,htc->error,transport->error,scan_requests);
            CHECK(result==3&&pmwsn_live(scan)&&scan_requests==3&&scan->client.started&&scan->client.completed);
            CHECK(scan->client.count==((kind==2||kind==5)?0u:1u));
            if(scan->client.count)CHECK(scan->client.bss[0].frequency==2437&&scan->client.bss[0].ssid_bytes==7&&!memcmp(scan->client.bss[0].ssid,"fixture",7));
            if(kind==1)CHECK(scan->client.ignored==1);if(kind==2)CHECK(scan->client.dropped==1);
            fprintf(stderr,"native passive scan: variant%u published3 commands, returned STARTED/COMPLETED, retained%u BSS PASS\n",kind,scan->client.count);
        }
    }
    wlan_unprotect();free(msa_shadow);free(device_memory);free(ce_shadow);free(memory);free(rmtfs_shadow);free(sm_shadow);free(sm_original);auth_test_close();
    printf("PASS %u native scan checks, %u scenarios; SOFTWARE target/cache/MMIO/UEFI, no actual AP discovery\n",checks+nv_checks,scan_scenarios);return 0;
}
