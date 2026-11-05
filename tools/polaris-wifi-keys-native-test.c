static void keys_target_tx(unsigned,const unsigned char*,unsigned);
#define EFI_XNU_WIFI_KEYS_NATIVE_AVAILABLE 1
#define PMST_TEST_ENTRY unused_station_suite
#define PMST_TEST_WMI_HOOK keys_target_tx
#include "polaris-wifi-station-native-test.c"
#include "uefi-wifi-keys-native.h"
static struct pmky_state*keys;
static struct pwpa_state*handshake;
static unsigned key_fault,key_commands,key_scenarios;
static uint8_t test_pmk[32],test_nonce[32],test_ptk[48],test_gtk[16],test_message[9][640];
static unsigned test_length[9];
static void keys_target_tx(unsigned pipe,const unsigned char*f,unsigned bytes)
{
    CHECK(keys&&pmky_live(keys)&&pipe==3&&bytes==128);key_commands++;CHECK(key_commands<=2);
    const uint8_t*p=f+8;unsigned group=key_commands==2;
    CHECK(pwmi_get(p)==0x5009&&pwmi_get(p+4)==0x0060005c&&!memcmp(p+12,ap,6)&&pwmi_get(p+24)==group&&pwmi_get(p+28)==4&&pwmi_get(p+88)==16);
    CHECK(!memcmp(p+104,group?test_gtk:test_ptk+32,16));wmi_frame(f,0,2);
    if(key_fault==2)return;
    uint8_t sec[28]={11,0,17,0};sec[1]=(uint8_t)((group?0:128)|(key_fault==1?4:6));station_htt_event(sec,28);
    if(!group&&!key_fault)station_htt_event(sec,28); /* duplicate must not ACK GTK */
}
static void handshake_ready(void)
{
    handshake=(void*)(arena+0x73e0000);CHECK(sizeof(*handshake)<0x20000);memset(handshake,0,sizeof(*handshake));
    CHECK(pwpa_open(handshake,&station->client.station,test_pmk,test_nonce,owner->last));
    /* This fixture composes the actual pure EAPOL algorithm with native key
     * transport. EAPOL packet publication is SOFTWARE, not yet native DMA. */
    CHECK(pwpa_receive(handshake,test_message[0],test_length[0],owner->last)==1&&pwpa_sent(handshake,owner->last,1)==1);
    CHECK(pwpa_receive(handshake,test_message[2],test_length[2],owner->last)==1);
    int result=1;for(unsigned n=0;n<64&&result==1;n++)result=pwpa_step(handshake,owner->last);
    CHECK(result==2&&pwpa_sent(handshake,owner->last,1)==1&&handshake->keys_ready&&!handshake->authorized);
}
int main(int argc,char**argv)
{
    CHECK(argc==9);station_test_open(8,argv);FILE*f=fopen(argv[8],"rb");CHECK(f);uint8_t magic[8];
    CHECK(fread(magic,1,8,f)==8&&!memcmp(magic,"PWPA001",8));
    CHECK(fread(test_pmk,1,32,f)==32&&fread(test_nonce,1,32,f)==32&&fread(test_ptk,1,48,f)==48&&fread(test_gtk,1,16,f)==16);
    for(unsigned n=0;n<9;n++){uint8_t b[4];CHECK(fread(b,1,4,f)==4);test_length[n]=pwmi_get(b);CHECK(test_length[n]<=640&&fread(test_message[n],1,test_length[n],f)==test_length[n]);}
    CHECK(fgetc(f)==EOF&&!fclose(f));
    for(unsigned kind=0;kind<4;kind++){
        keys=0;station_test_setup(0);int result=1;
        for(unsigned n=0;n<160&&result==1;n++){advance_to(owner->last+19200);result=pmst_step(station);}CHECK(result==5);
        for(unsigned n=0;n<20&&station->mgmt_wait;n++){advance_to(owner->last+19200);CHECK(pmst_step(station)==5);}CHECK(!station->mgmt_wait);
        handshake_ready();keys=(void*)(arena+0x73d0000);CHECK(sizeof(*keys)<0x10000);memset(keys,0,sizeof(*keys));key_fault=kind;key_commands=0;key_scenarios++;
        CHECK(pmky_begin(keys,station,handshake)&&handshake->install_issued&&!handshake->authorized);result=1;
        for(unsigned n=0;n<60&&result==1;n++){
            advance_to(owner->last+19200);
            if(kind==2&&keys->client.phase==1)advance_to(keys->client.deadline+1);
            if(kind==3)transport_fault=3;
            result=pmky_step(keys);
        }
        if(!kind){
            if(result!=5)fprintf(stderr,"keys result%d err%u wire%u phase%u sent%u parent%u\n",result,keys->error,keys->client.error,keys->client.phase,key_commands,station->error);
            CHECK(result==5&&keys->completed&&keys->client.confirmed==3&&key_commands==2&&keys->client.ignored==1&&handshake->authorized&&handshake->installed);
            CHECK(!pwpa_nonzero(keys->client.tk,16)&&!pwpa_nonzero(keys->client.gtk,16)&&keys->client.group_floor[0]==1);
            uint8_t unmap[4]={4,0,17,0};station_htt_event(unmap,4);result=5;
            for(unsigned n=0;n<20&&result==5;n++){advance_to(owner->last+19200);result=pmky_step(keys);}
            CHECK(result==4&&!handshake->authorized&&handshake->phase==5&&!pwpa_nonzero(handshake->tk,16)&&!pwpa_nonzero(handshake->kck,16));
            fprintf(stderr,"native keys:2 actual WMI installs -> matching HTT security indications, duplicate ignored, unmap closes port/wipes keys PASS\n");
        }else{
            CHECK(result==-1&&keys->unknown&&keys->error&&!handshake->authorized&&owner->held);
            unsigned writes=transport_writes;CHECK(pmky_step(keys)==-1&&writes==transport_writes);
        }
    }
    station_test_close();printf("PASS %u native key checks, %u scenarios; SOFTWARE EAPOL/target/cache/MMIO/UEFI, no physical WPA success\n",checks+nv_checks,key_scenarios);return 0;
}
