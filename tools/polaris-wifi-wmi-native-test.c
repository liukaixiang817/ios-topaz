/* Full native startup/HTC/WMI. Privileged leaves and target responses are
 * SOFTWARE; separate CPU/device memory views enforce DMA publication. */
static void wmi_target_tx(unsigned,const unsigned char*,unsigned);
#define EFI_XNU_WIFI_WMI_NATIVE_AVAILABLE 1
#define PMHC_TEST_WMI_HOOK wmi_target_tx
#define PMHC_TEST_ENTRY unused_htc_suite
#include "polaris-wifi-htc-native-test.c"
#include "uefi-wifi-wmi-native.h"
static struct pmwi_state*wmi;
static unsigned wmi_fault,wmi_scenarios,wmi_requests;
static void wmi_frame(const uint8_t*p,unsigned bytes,unsigned credits)
{
    uint8_t frame[1024]={0};CHECK(bytes+16<=sizeof(frame));frame[0]=(uint8_t)htc->client.wmi;frame[1]=2;frame[4]=8;
    phtc_put(frame+2,bytes+8);memcpy(frame+8,p,bytes);frame[8+bytes]=1;frame[9+bytes]=4;frame[12+bytes]=frame[0];frame[13+bytes]=(uint8_t)credits;
    target_frame(2,frame,bytes+16);
}
static void wmi_abi(uint8_t*p)
{pwmi_put(p,0x01000000);pwmi_put(p+4,53);pwmi_put(p+8,0x5f414351);pwmi_put(p+12,0x4c4d);}
static void wmi_target_tx(unsigned pipe,const unsigned char*frame,unsigned bytes)
{
    CHECK(wmi&&pipe==3&&frame[0]==htc->client.wmi&&pwmi_get(frame+8)==1);wmi_requests++;
    unsigned count=wmi_fault==5?0:2;CHECK(bytes==228+20*count&&pwmi_get(frame+40)==count);
    for(unsigned n=0;n<count;n++){
        const uint8_t*c=frame+228+20*n;CHECK(pwmi_get(c)==0x004c0010&&pwmi_get(c+4)==n+1);
        uint64_t address=pwmi_get(c+8)|((uint64_t)pwmi_get(c+16)<<32);unsigned size=pwmi_get(c+12);
        CHECK(address==wmi->client.chunk[n].address&&size==(n?680u:100u));
        uint8_t*mem=device_at(address,(size+4095)&~4095u);for(unsigned j=0;j<((size+4095)&~4095u);j++)CHECK(!mem[j]);
    }
    if(wmi_fault==4)return;
    uint8_t ready[44]={0};pwmi_put(ready,2);pwmi_header(ready+4,35,36);wmi_abi(ready+8);ready[32]=2;ready[37]=7;
    if(wmi_fault==3)pwmi_put(ready+40,9);wmi_frame(ready,sizeof(ready),2);
}
static void wmi_service(void)
{
    uint8_t p[512]={0};unsigned count=wmi_fault==5?0:2;pwmi_put(p,1);pwmi_header(p+4,32,104);wmi_abi(p+12);pwmi_put(p+44,2);pwmi_put(p+80,count);
    pwmi_header(p+112,33,36);pwmi_put(p+116,0x64);pwmi_header(p+152,16,128);pwmi_put(p+156+64,2);
    pwmi_header(p+284,18,20*count);
    for(unsigned n=0;n<count;n++){uint8_t*q=p+288+20*n;pwmi_header(q,34,16);pwmi_put(q+4,n+1);pwmi_put(q+8,wmi_fault==1?UINT32_MAX:17);pwmi_put(q+12,n?2:1);pwmi_put(q+16,123);}
    wmi_frame(p,288+20*count,3);
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
        wmi=0;htc_setup(0);wmi=(void*)(arena+0x7340000);CHECK(sizeof(*wmi)<0x10000);memset(wmi,0,sizeof(*wmi));
        wmi_fault=kind;wmi_requests=0;wmi_scenarios++;CHECK(pmwi_begin(wmi,htc));
        for(unsigned n=0;n<40&&htc->client.phase!=8;n++){CHECK(pmwi_step(wmi)==1);advance_to(owner->last+19200);}
        CHECK(htc->client.phase==8&&wmi->opened&&!wmi->client.phase);
        uint64_t tail=(transport->rings.layout.used+4095u)&~UINT64_C(4095);
        memset(ce_shadow+tail,0xa5,8192);memset(device_memory+tail,0xa5,8192);
        wmi_service();if(kind==2)transport_fault=1;
        int result=1;
        for(unsigned n=0;n<30&&result==1;n++){
            advance_to(owner->last+19200);result=pmwi_step(wmi);
            if(kind==4&&wmi->client.phase==3)advance_to(wmi->client.deadline+1);
        }
        if(!kind||kind==5){
            if(result!=3)fprintf(stderr,"WMI result=%d error=%u client=%u phase=%u HTC=%u CE=%u requests=%u\n",result,wmi->error,wmi->client.error,wmi->client.phase,htc->error,transport->error,wmi_requests);
            CHECK(result==3&&pmwi_live(wmi)&&wmi_requests==1&&wmi->client.mac[5]==7&&wmi->zeroed==(kind?0u:8192u));
            uint8_t unknown[8]={0x34,0x12,0,0,0x55,0x66,0,0};wmi_frame(unknown,sizeof(unknown),1);
            for(unsigned n=0;n<10&&result!=2;n++){advance_to(owner->last+19200);result=pmwi_step(wmi);CHECK(result>0);}
            CHECK(result==2&&htc->frame_kind==1&&htc->client.rx_bytes==8&&!memcmp(htc->client.rx,unknown,8)&&pmhc_ack(htc));
            fprintf(stderr,"native WMI: requests=%u zeroed=%llu INIT published, unified READY and unconsumed event retention PASS\n",wmi->client.requests,(unsigned long long)wmi->zeroed);
        }else{
            CHECK(result==-1&&wmi->unknown&&wmi->error&&owner->held);
            if(kind<3)CHECK(!wmi_requests);else CHECK(wmi_requests==1);
            unsigned writes=transport_writes;CHECK(pmwi_step(wmi)==-1&&transport_writes==writes);
        }
    }
    wlan_unprotect();free(msa_shadow);free(device_memory);free(ce_shadow);free(memory);free(rmtfs_shadow);free(sm_shadow);free(sm_original);auth_test_close();
    printf("PASS %u native WMI checks, %u scenarios; SOFTWARE target/cache/MMIO/UEFI, no actual scan\n",checks+nv_checks,wmi_scenarios);return 0;
}
