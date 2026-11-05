static void station_target_wmi(unsigned,const unsigned char*,unsigned),station_target_data(unsigned,const unsigned char*,unsigned);
#define EFI_XNU_WIFI_STATION_NATIVE_AVAILABLE 1
#define EFI_XNU_WIFI_SCAN_NATIVE_AVAILABLE 1
#define EFI_XNU_WIFI_HTT_DATA_AVAILABLE 1
#define PMWI_TEST_TX_HOOK station_target_wmi
#define PMHT_TEST_TX_HOOK station_target_data
#define PMHT_TEST_ENTRY unused_htt_suite
#include "polaris-wifi-htt-native-test.c"
#include "uefi-wifi-station-native.h"
static struct pmwsn_state*scan;
static struct pmhd_state*data;
static struct pmst_state*station;
static unsigned station_fault,station_scenarios,scan_commands,station_commands,mgmt_commands;
static const uint8_t ap[6]={2,0,0,0,0,9};
static void station_htt_event(const uint8_t*p,unsigned bytes)
{
    uint8_t f[256]={0};CHECK(bytes+8<=sizeof(f));f[0]=(uint8_t)htc->client.htt;phtc_put(f+2,bytes);memcpy(f+8,p,bytes);target_frame(1,f,bytes+8);
}
static void scan_event(unsigned type)
{
    uint8_t p[32]={0};pwmi_put(p,0x3001);pwmi_header(p+4,36,24);pwmi_put(p+8,type);pwmi_put(p+16,2437);pwmi_put(p+20,0xa001);pwmi_put(p+24,0xa007);wmi_frame(p,32,2);
}
static void station_beacon(void)
{
    uint8_t p[192]={0};pwmi_put(p,0x7001);pwmi_header(p+4,44,40);pwmi_put(p+8,6);pwmi_put(p+12,42);
    uint8_t*b=p+52;b[0]=0x80;memcpy(b+16,ap,6);b[32]=100;psta_put16(b+34,0x431);
    const uint8_t ies[]={0,7,'f','i','x','t','u','r','e',1,8,0x82,0x84,0x8b,0x96,12,18,24,36,50,4,48,72,96,108,3,1,6,5,4,0,2,0,0,
        48,20,1,0,0,15,172,4,1,0,0,15,172,4,1,0,0,15,172,2,0,0};
    memcpy(b+36,ies,sizeof(ies));unsigned bytes=36+sizeof(ies);pwmi_put(p+24,bytes);pwmi_header(p+48,17,bytes);wmi_frame(p,52+bytes,1);
}
static void station_target_wmi(unsigned pipe,const unsigned char*f,unsigned bytes)
{
    CHECK(pipe==3&&f[0]==htc->client.wmi);const uint8_t*p=f+8;unsigned cmd=pwmi_get(p);
#ifdef PMST_TEST_WMI_HOOK
    if(cmd==0x5009||cmd==0x6004){PMST_TEST_WMI_HOOK(pipe,f,bytes);return;}
#endif
    if(!station){
        CHECK(scan&&pmwsn_live(scan));scan_commands++;
        if(scan_commands==1){CHECK(cmd==0x5001);wmi_frame(f,0,2);return;}
        if(scan_commands==2){CHECK(cmd==0x3003);wmi_frame(f,0,2);return;}
        CHECK(scan_commands==3&&cmd==0x3001);scan_event(1);station_beacon();scan_event(2);return;
    }
    CHECK(pmst_live(station));station_commands++;
    if(station_commands==1){CHECK(cmd==0x3003&&bytes==52&&pwmi_get(p+8)==1&&pwmi_get(p+32)==1);wmi_frame(f,0,2);return;}
    if(station_commands==2){
        CHECK(cmd==0x5003&&bytes==120&&pwmi_get(p+12)==1&&pwmi_get(p+16)==100);
        uint8_t r[24]={0};pwmi_put(r,0x5001);pwmi_header(r+4,40,16);pwmi_put(r+12,1);if(station_fault==1)pwmi_put(r+20,7);wmi_frame(r,24,2);return;
    }
    if(station_commands==3){
        CHECK(cmd==0x6001&&bytes==32&&!memcmp(p+12,ap,6));wmi_frame(f,0,2);
        if(station_fault==2)return;uint8_t peer[12]={3,0,17,0};memcpy(peer+4,ap,6);station_htt_event(peer,12);return;
    }
    if(station_commands==4){CHECK(cmd==0x6005&&pwmi_get(p+24)==0x123&&pwmi_get(p+28)==5&&pwmi_get(p+76)==12);wmi_frame(f,0,2);return;}
    CHECK(station_commands==5&&cmd==0x5005&&pwmi_get(p+12)==0x123&&!memcmp(p+16,ap,6));wmi_frame(f,0,2);
}
static void station_target_data(unsigned pipe,const unsigned char*f,unsigned bytes)
{
#ifdef PMST_TEST_DATA_HOOK
    if(bytes>=28&&((f[9]>>5)&7)==2){PMST_TEST_DATA_HOOK(pipe,f,bytes);return;}
#endif
    CHECK(station&&pmst_live(station)&&pipe==4&&f[0]==htc->client.htt);mgmt_commands++;
    const uint8_t*p=f+8;unsigned id=phtr_u16(p+6),length=phtr_u16(p+4);
    CHECK(id==data->rings.tx_id&&data->rings.tx_owner[id]==1&&p[0]==1&&p[1]==0x65&&((phtr_u16(p+2)>>6)&31)==17);
    uint64_t at=phtr_u64(p+8);CHECK(at==HTT_ALLOCATION+htt->layout.transmit+2048u*id&&length<=256&&bytes==28+((length<50?length:50)+3u&~3u));
    const uint8_t*packet=htt_device+at-HTT_ALLOCATION;CHECK(!memcmp(packet+4,ap,6)&&!memcmp(packet+10,wmi->client.mac,6)&&!memcmp(packet+16,ap,6));
    uint8_t completion[8]={7,0,1,0,0,0,255,255};phtt_put16(completion+4,id);station_htt_event(completion,8);
    uint8_t r[160]={0};pwmi_put(r,0x7001);pwmi_header(r+4,44,40);pwmi_put(r+8,6);uint8_t*b=r+52;
    memcpy(b+4,wmi->client.mac,6);memcpy(b+10,ap,6);memcpy(b+16,ap,6);unsigned received;
    if(mgmt_commands==1){CHECK(packet[0]==0xb0&&length==30);b[0]=0xb0;b[26]=2;if(station_fault==3)b[28]=13;received=30;}
    else{
        CHECK(mgmt_commands==2&&!packet[0]&&length==75);b[0]=0x10;psta_put16(b+24,0x431);psta_put16(b+28,0xc123);
        const uint8_t rates[]={1,8,0x82,0x84,0x8b,0x96,12,18,24,36,50,4,48,72,96,108};memcpy(b+30,rates,sizeof(rates));received=30+sizeof(rates);
    }
    pwmi_put(r+24,received);pwmi_header(r+48,17,received);
#ifdef PMST_TEST_ASSOC_HOOK
    if(mgmt_commands==2){PMST_TEST_ASSOC_HOOK(r,52+received);return;}
#endif
    wmi_frame(r,52+received,1);
}
static void station_test_open(int argc,char**argv)
{
    CHECK(argc==8);sm_original=malloc(PWFI_IMAGE_BYTES);sm_shadow=malloc(PMSQ_BYTES);rmtfs_shadow=malloc(0x202000);
    memory=aligned_alloc(4096,PNV_BYTES);ce_shadow=aligned_alloc(4096,PWDM_BYTES);device_memory=aligned_alloc(4096,PWDM_BYTES);
    htt_cpu=aligned_alloc(4096,PHTM_BYTES);htt_device=aligned_alloc(4096,PHTM_BYTES);CHECK(htt_cpu&&htt_device);
    CHECK(sm_original&&sm_shadow&&rmtfs_shadow&&memory&&ce_shadow&&device_memory);
    FILE*f=fopen(argv[6],"rb");CHECK(f&&fread(sm_original,1,PWFI_IMAGE_BYTES,f)==PWFI_IMAGE_BYTES&&!fclose(f));auth_test_open(6,argv);
    CHECK(!posix_memalign((void**)&msa_shadow,host_page,0x200000));
    load(argv[7],"gpt0-primary.bin",headers[0][0],4096);load(argv[7],"gpt0-backup.bin",headers[0][1],4096);load(argv[7],"gpt0-table.bin",tables[0],polaris_nv_plan.disk[0].table_bytes);
    load(argv[7],"gpt1-primary.bin",headers[1][0],4096);load(argv[7],"gpt1-backup.bin",headers[1][1],4096);load(argv[7],"gpt1-table.bin",tables[1],polaris_nv_plan.disk[1].table_bytes);
}
static void station_test_setup(unsigned kind)
{
        station=0;scan=0;data=0;htt=0;wmi=0;htc_setup(0);wmi=(void*)(arena+0x7340000);memset(wmi,0,sizeof(*wmi));wmi_fault=wmi_requests=0;CHECK(pmwi_begin(wmi,htc));
        for(unsigned n=0;n<40&&htc->client.phase!=8;n++){CHECK(pmwi_step(wmi)==1);advance_to(owner->last+19200);}
        CHECK(htc->client.phase==8);wmi_service();int result=1;
        for(unsigned n=0;n<30&&result==1;n++){advance_to(owner->last+19200);result=pmwi_step(wmi);}CHECK(result==3);
        htt=(void*)(arena+0x7380000);memset(htt,0,sizeof(*htt));memset(htt_cpu,0xa5,PHTM_BYTES);memset(htt_device,0xa5,PHTM_BYTES);
        htt_fault=htt_commands=htt_copies=htt_caches=0;CHECK(pmht_begin(htt,htt_memory,wmi));result=1;
        for(unsigned n=0;n<2200&&result==1;n++){if(htt->prepared)advance_to(owner->last+19200);result=pmht_step(htt);}CHECK(result==3);
        data=(void*)(arena+0x73a0000);memset(data,0,sizeof(*data));CHECK(pmhd_begin(data,htt));
        scan=(void*)(arena+0x7360000);memset(scan,0,sizeof(*scan));scan_commands=0;CHECK(pmwsn_begin(scan,wmi,7));result=1;
        for(unsigned n=0;n<80&&result==1;n++){advance_to(owner->last+19200);result=pmwsn_step(scan);}CHECK(result==3&&scan->client.count==1);
        station=(void*)(arena+0x73c0000);CHECK(sizeof(*station)<0x20000);memset(station,0,sizeof(*station));station_fault=kind;station_commands=mgmt_commands=0;station_scenarios++;
        struct pwst_channel c={2437,0,20,30,0,0,0}; /* explicit SOFTWARE regulatory input */
        CHECK(pmst_begin(station,scan,data,0,2,&c));result=1;
}
static void station_test_close(void)
{
    wlan_unprotect();free(htt_cpu);free(htt_device);free(msa_shadow);free(device_memory);free(ce_shadow);free(memory);free(rmtfs_shadow);free(sm_shadow);free(sm_original);auth_test_close();
}
#ifndef PMST_TEST_ENTRY
#define PMST_TEST_ENTRY main
#endif
int PMST_TEST_ENTRY(int argc,char**argv)
{
    station_test_open(argc,argv);
    for(unsigned kind=0;kind<5;kind++){
        station_test_setup(kind);int result=1;
        for(unsigned n=0;n<160&&result==1;n++){
            advance_to(owner->last+19200);
            if(kind==2&&station->client.phase==4)advance_to(station->client.deadline+1);
            if(kind==4&&station->client.phase==5)htt_fault=2;
            result=pmst_step(station);
        }
        if(!kind){
            if(result!=5)fprintf(stderr,"station result%d err%u wire%u phase%u MAC%u commands%u mgmt%u\n",result,station->error,station->client.error,station->client.phase,station->client.station.phase,station_commands,mgmt_commands);
            CHECK(result==5&&pmst_live(station)&&station_commands==5&&mgmt_commands==2&&station->client.station.associated&&station->client.peer_valid&&station->client.up_published);
            for(unsigned n=0;n<20&&station->mgmt_wait;n++){advance_to(owner->last+19200);CHECK(pmst_step(station)==5);}
            CHECK(station->mgmt_completed==2&&!station->mgmt_wait&&!station->mgmt_status);
            uint8_t unmap[4]={4,0,17,0};station_htt_event(unmap,4);result=5;
            for(unsigned n=0;n<20&&result==5;n++){advance_to(owner->last+19200);result=pmst_step(station);}
            CHECK(result==4&&!station->client.up_published&&!station->client.station.associated);
            fprintf(stderr,"native station: actual scan/HTT bank -> channel/start/map/auth/assoc/up -> unmap disconnect PASS\n");
        }else if(kind==3){CHECK(result==4&&station->client.station.reason==13&&!station->client.up_published&&!station->unknown);}
        else{
            CHECK(result==-1&&station->unknown&&station->error&&owner->held);
            unsigned calls=htt_copies+htt_caches+transport_writes;CHECK(pmst_step(station)==-1&&calls==htt_copies+htt_caches+transport_writes);
        }
    }
    station_test_close();
    printf("PASS %u native station checks, %u scenarios; SOFTWARE target/cache/MMIO/UEFI, no actual association or WPA success\n",checks+nv_checks,station_scenarios);return 0;
}
