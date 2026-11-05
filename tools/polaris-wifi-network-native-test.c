#if defined(POLARIS_WIFI_NETWORK_NONCE_TEST)
#define EFI_XNU_WIFI_NONCE_NATIVE_AVAILABLE 1
#endif
static void network_target_keys(unsigned,const unsigned char*,unsigned),network_target_data(unsigned,const unsigned char*,unsigned);
static void network_association(const unsigned char*,unsigned);
#define EFI_XNU_WIFI_NETWORK_NATIVE_AVAILABLE 1
#define EFI_XNU_WIFI_KEYS_NATIVE_AVAILABLE 1
#define PMST_TEST_ENTRY unused_station_suite
#define PMST_TEST_WMI_HOOK network_target_keys
#define PMST_TEST_DATA_HOOK network_target_data
#define PMST_TEST_ASSOC_HOOK network_association
#include "polaris-wifi-station-native-test.c"
#include "uefi-wifi-network-native.h"
static struct pmwn_state*network;
static unsigned net_fault,net_scenarios,key_commands,eapol_commands,ethernet_commands,rx_next;
static uint8_t pmk_vector[32],nonce_vector[32],ptk_vector[48],gtk_vector[16],messages[9][640],held_assoc[192];
static unsigned lengths[9],held_bytes,group_lengths[9];
static uint8_t group_messages[9][640],new_gtk[16],next_gtk[16];
static void network_receive(unsigned type,const uint8_t*payload,unsigned length,unsigned encrypted,unsigned group,uint64_t pn)
{
    unsigned slot=rx_next++;CHECK(slot<2047&&length<=1500&&data->rings.rx_owner[slot]==1);
    uint8_t*r=htt_device+htt->layout.receive+2048u*slot;memset(r,0,2048);
    pwmi_put(r+4,(1u<<31)|(1u<<6)|(group?4u:1u<<25));pwmi_put(r+16,17|0x800|(encrypted?0x2000:0)|((encrypted?6u:7u)<<28));
    for(unsigned n=0;n<6;n++)r[20+n]=(uint8_t)(pn>>(8*n));pwmi_put(r+36,1u<<8);pwmi_put(r+64,0xc000);
    uint8_t*h=r+296,*p=r+360;h[0]=8;h[1]=(uint8_t)(2|(encrypted?64:0));
    if(group)memset(h+4,255,6);else memcpy(h+4,wmi->client.mac,6);memcpy(h+10,ap,6);memcpy(h+16,ap,6);
    if(type!=0x888e)h[21]=66;memcpy(p,h,24);p[1]&=~64u;
    if(encrypted){h[24]=(uint8_t)pn;h[25]=(uint8_t)(pn>>8);h[27]=(uint8_t)(0x20|(group?(network->ethernet.gtk_id<<6):0));r[52]=h[27];for(unsigned n=0;n<4;n++)h[28+n]=(uint8_t)(pn>>(16+8*n));}
    const uint8_t snap[6]={170,170,3,0,0,0};memcpy(p+24,snap,6);pwpa_put16(p+30,type);memcpy(p+32,payload,length);
    uint8_t indication[20]={0x12,0,17,0,0,0,1,0};phtt_put64(indication+8,HTT_ALLOCATION+htt->layout.receive+2048u*slot);phtt_put16(indication+16,32+length);
    station_htt_event(indication,20);
}
static void network_association(const unsigned char*r,unsigned bytes)
{
    CHECK(network&&bytes<=sizeof(held_assoc));memcpy(held_assoc,r,bytes);held_bytes=bytes;
    /* The AP accepted association but its management event is delayed. M1
     * really arrives through HTT before the host observes that association. */
    network_receive(0x888e,messages[0],lengths[0],0,0,0);
}
static void network_target_data(unsigned pipe,const unsigned char*f,unsigned bytes)
{
    CHECK(network&&pmwn_live(network)&&pipe==4&&f[0]==htc->client.htt);const uint8_t*p=f+8;
    unsigned id=phtr_u16(p+6),length=phtr_u16(p+4);CHECK(id==data->rings.tx_id&&data->rings.tx_owner[id]==1&&p[0]==1&&((phtr_u16(p+2)>>6)&31)==16);
    uint64_t desc=phtr_u64(p+8);CHECK(desc==HTT_ALLOCATION+htt->layout.fragments+72u*id);
    const uint8_t*fragment=htt_device+desc-HTT_ALLOCATION;uint64_t address=pwmi_get(fragment+24)|((uint64_t)phtr_u16(fragment+28)<<32);
    CHECK(address==HTT_ALLOCATION+htt->layout.transmit+2048u*id&&phtr_u16(fragment+30)==length&&bytes==28+((length<50?length:50)+3u&~3u));
    const uint8_t*packet=htt_device+address-HTT_ALLOCATION;CHECK(!memcmp(packet+6,wmi->client.mac,6));
    uint8_t completion[8]={7,0,1,0,0,0,255,255};phtt_put16(completion+4,id);station_htt_event(completion,8);
    if(pwpa_be16(packet+12)==0x888e){
        CHECK(p[1]==0x44&&!memcmp(packet,ap,6));eapol_commands++;
        unsigned index=eapol_commands==1?1:3;
        if(eapol_commands<=3)CHECK(length==14+lengths[index]&&!memcmp(packet+14,messages[index],lengths[index]));
        else{index=eapol_commands==6?3:1;CHECK(length==14+group_lengths[index]&&!memcmp(packet+14,group_messages[index],group_lengths[index])&&key_commands==5&&network->ethernet.group_generation==1);}
        CHECK(station->client.up_published);
        if(eapol_commands==1){
            if(net_fault==2){transport_fault=3;return;}
            uint8_t invalid[640];memcpy(invalid,messages[2],lengths[2]);invalid[81]^=1;
            network_receive(0x888e,invalid,lengths[2],0,0,0);
            if(net_fault!=3)network_receive(0x888e,messages[2],lengths[2],0,0,0);
        }else CHECK(eapol_commands<=6);
    }else{
        CHECK(p[1]==0x40&&network->ethernet.authorized&&network->keys.completed&&length==114&&pwpa_be16(packet+12)==0x800);
        for(unsigned n=14;n<114;n++)CHECK(packet[n]==(uint8_t)n);ethernet_commands++;
    }
}
static void network_target_keys(unsigned pipe,const unsigned char*f,unsigned bytes)
{
    CHECK(network&&pmky_live(&network->keys)&&pipe==3);key_commands++;CHECK(key_commands<=5);const uint8_t*p=f+8;
    if(key_commands==3||key_commands==5){CHECK(bytes==36&&pwmi_get(p)==0x6004&&pwmi_get(p+20)==3&&pwmi_get(p+24)==1);CHECK(key_commands==3?!network->ethernet.authorized:network->ethernet.group_blocked);wmi_frame(f,0,2);return;}
    if(key_commands==4){
        CHECK(bytes==128&&pwmi_get(p)==0x5009&&pwmi_get(p+20)==2&&pwmi_get(p+24)==1&&!memcmp(p+104,new_gtk,16)&&eapol_commands==3);
        CHECK(network->wpa.group_issued&&network->wpa.group_generation==0&&network->ethernet.gtk_id==1);wmi_frame(f,0,2);
        if(net_fault==7)return;
        uint8_t payload[8]={0};network_receive(0x806,payload,8,1,1,3);
        uint8_t sec[28]={11,6,17,0};station_htt_event(sec,28);return;
    }
    unsigned group=key_commands==2;CHECK(bytes==128&&pwmi_get(p)==0x5009&&pwmi_get(p+24)==group&&!memcmp(p+104,group?gtk_vector:ptk_vector+32,16));
    CHECK(eapol_commands==2&&!network->ethernet.authorized);wmi_frame(f,0,2);
    uint8_t security[28]={11,0,17,0};security[1]=(uint8_t)((group?0:128)|6);station_htt_event(security,28);
}
#if defined(POLARIS_WIFI_NETWORK_NONCE_TEST)
static struct pmnp_state*nonce_source;
static uint8_t nonce_bundle[PWNP_BYTES],nonce_digest[32];
#endif
static int network_poll(void){advance_to(owner->last+19200);return pmwn_step(network);}
#ifndef PMWN_TEST_ENTRY
#define PMWN_TEST_ENTRY main
#endif
int PMWN_TEST_ENTRY(int argc,char**argv)
{
#if defined(POLARIS_WIFI_NETWORK_NONCE_TEST)
    CHECK(argc==12);
#else
    CHECK(argc==10);
#endif
    station_test_open(8,argv);FILE*f=fopen(argv[8],"rb");CHECK(f);uint8_t magic[8];
    CHECK(fread(magic,1,8,f)==8&&!memcmp(magic,"PWPA001",8));
    CHECK(fread(pmk_vector,1,32,f)==32&&fread(nonce_vector,1,32,f)==32&&fread(ptk_vector,1,48,f)==48&&fread(gtk_vector,1,16,f)==16);
    for(unsigned n=0;n<9;n++){uint8_t b[4];CHECK(fread(b,1,4,f)==4);lengths[n]=pwmi_get(b);CHECK(lengths[n]<=640&&fread(messages[n],1,lengths[n],f)==lengths[n]);}CHECK(fgetc(f)==EOF&&!fclose(f));
    f=fopen(argv[9],"rb");CHECK(f);CHECK(fread(magic,1,8,f)==8&&!memcmp(magic,"PWPG001",8));
    CHECK(fread(new_gtk,1,16,f)==16&&fread(next_gtk,1,16,f)==16);
    for(unsigned n=0;n<9;n++){uint8_t b[4];CHECK(fread(b,1,4,f)==4);group_lengths[n]=pwmi_get(b);CHECK(group_lengths[n]<=640&&fread(group_messages[n],1,group_lengths[n],f)==group_lengths[n]);}CHECK(fgetc(f)==EOF&&!fclose(f));
    unsigned scenarios=8,first=0;
#if defined(POLARIS_WIFI_NETWORK_NONCE_TEST)
    f=fopen(argv[10],"rb");CHECK(f&&fread(nonce_bundle,1,PWNP_BYTES,f)==PWNP_BYTES&&fread(nonce_digest,1,32,f)==32&&fgetc(f)==EOF&&!fclose(f));
    /* Fault cases deliberately retain owners. Run each nonce scenario in a
     * fresh process, rather than exhausting the eight live GLINK slots or
     * inventing teardown after an unqualified DMA failure. */
    CHECK(argv[11][0]>='0'&&argv[11][0]<='8'&&!argv[11][1]);first=(unsigned)(argv[11][0]-'0');scenarios=first+1;
#endif
    for(unsigned kind=first;kind<scenarios;kind++){
        network=0;wmi_management_service=kind>=4;station_wmi_fault=kind==5?1:kind==6?2:0;station_test_setup(0);network=(void*)(arena+0x73e0000);CHECK(sizeof(*network)<0x20000);memset(network,0,sizeof(*network));
        net_fault=kind;key_commands=eapol_commands=ethernet_commands=rx_next=held_bytes=0;net_scenarios++;
#if defined(POLARIS_WIFI_NETWORK_NONCE_TEST)
        nonce_source=(void*)(arena+0x73b0000);CHECK(sizeof(*nonce_source)<0x4000);memset(nonce_source,0,sizeof(*nonce_source));
        uint8_t*source=arena+0x73b4000,*digest=arena+0x73b5000;memcpy(source,nonce_bundle,PWNP_BYTES);memcpy(digest,nonce_digest,32);
        if(kind==8)digest[0]^=1;
        int opened=pmnp_begin(nonce_source,wmi,source,digest);
        if(kind==8){CHECK(!opened&&nonce_source->unknown&&wmi->nonce==(uintptr_t)nonce_source&&!network->ready&&owner->held);continue;}
        CHECK(opened&&nonce_source->pages==1&&!nonce_source->pool.used&&!pmnp_begin(nonce_source,wmi,source,digest));
        CHECK(pmwn_begin_pool(network,station,pmk_vector,nonce_source)&&nonce_source->pool.used==1&&!pwnp_nonzero(nonce_source->pool.nonce[0],32));
#else
        CHECK(pmwn_begin(network,station,pmk_vector,nonce_vector));
#endif
        int result=1;unsigned saw_early=0;
        for(unsigned n=0;n<400&&result==1;n++){
            if(kind==1&&held_bytes)htt_fault=2;
            if(kind==5&&station->management.phase==2)advance_to(station->management.deadline+1);
            result=network_poll();
            if(network->early_ready&&held_bytes){
                CHECK(!network->wpa.opened&&!station->client.station.associated&&!data->frame_ready&&data->rings.rx_owner[0]==1);
                saw_early=1;wmi_frame(held_assoc,held_bytes,1);held_bytes=0;
            }
            if(kind==3&&network->wpa.bad){CHECK(!network->keys.ready&&!network->ethernet.authorized);advance_to(network->wpa.deadline+1);}
        }
        if(!kind||kind==4||kind==7){
            if(result!=5)fprintf(stderr,"network result%d err%u key%u station%u WPAphase%u pending%u M%u K%u\n",result,network->error,network->keys.error,station->error,network->wpa.phase,network->wpa.pending,eapol_commands,key_commands);
            CHECK(station->management_wmi==(kind>=4));
            CHECK(result==5&&saw_early&&key_commands==3&&eapol_commands==2&&network->wpa.bad==1&&network->ethernet.authorized&&network->keys.completed);
            CHECK(!pwpa_nonzero(network->pmk,32)&&!pwpa_nonzero(network->nonce,32));
            /* Authenticated retry through actual encrypted RX, no reinstall. */
            network_receive(0x888e,messages[2],lengths[2],1,0,1);
            for(unsigned n=0;n<60&&(eapol_commands<3||network->tx_wait);n++)CHECK(network_poll()==5);
            CHECK(eapol_commands==3&&key_commands==3&&network->ethernet.pn[0]==1&&network->wpa.retries==1);
            uint8_t payload[100];for(unsigned n=0;n<100;n++)payload[n]=(uint8_t)(n+14);
            network_receive(0x800,payload,100,1,0,2);result=5;
            for(unsigned n=0;n<40&&result==5;n++)result=network_poll();
            CHECK(result==3&&network->ethernet.rx_bytes==114&&!memcmp(network->ethernet.receive+14,payload,100)&&!data->frame_ready&&pmwn_ack(network));
            network_receive(0x800,payload,100,1,0,2);network_receive(0x806,payload,100,1,1,1);network_receive(0x806,payload,100,1,1,2);result=5;
            for(unsigned n=0;n<60&&result==5;n++)result=network_poll();
            CHECK(result==3&&network->ethernet.replayed==2&&network->ethernet.pn[1]==2&&pmwn_ack(network));
            network_receive(0x888e,group_messages[0],group_lengths[0],1,0,3);
            for(unsigned n=0;n<100&&(eapol_commands<4||network->tx_wait);n++){
                if(kind==7&&network->keys.group_client.phase==3)advance_to(network->keys.group_client.deadline+1);
                result=network_poll();if(result<0)break;CHECK(result==5);
            }
            if(kind==7){CHECK(result==-1&&network->unknown&&network->closed&&eapol_commands==3&&key_commands==4&&network->ethernet.pn[1]==2&&network->ethernet.group_generation==0&&owner->held);continue;}
            CHECK(eapol_commands==4&&key_commands==5&&network->ethernet.gtk_id==2&&network->ethernet.pn[1]==7&&network->ethernet.pn[0]==3&&!network->ethernet.group_blocked);
            network_receive(0x806,payload,100,1,1,8);result=5;for(unsigned n=0;n<40&&result==5;n++)result=network_poll();CHECK(result==3&&pmwn_ack(network));
            network_receive(0x888e,group_messages[0],group_lengths[0],1,0,4);
            for(unsigned n=0;n<60&&(eapol_commands<5||network->tx_wait);n++)CHECK(network_poll()==5);
            CHECK(eapol_commands==5&&key_commands==5&&network->ethernet.pn[1]==8);
            network_receive(0x888e,group_messages[2],group_lengths[2],1,0,5);
            for(unsigned n=0;n<100&&(eapol_commands<6||network->tx_wait);n++)CHECK(network_poll()==5);
            CHECK(eapol_commands==6&&key_commands==5&&network->ethernet.pn[1]==8&&network->ethernet.group_floor==7&&network->ethernet.group_generation==1);
            uint8_t outgoing[114];memset(outgoing,255,6);memcpy(outgoing+6,wmi->client.mac,6);outgoing[12]=8;outgoing[13]=0;memcpy(outgoing+14,payload,100);
            CHECK(pmwn_send(network,outgoing,114));
            for(unsigned n=0;n<40&&(!ethernet_commands||network->tx_wait);n++)CHECK(network_poll()==5);
            CHECK(ethernet_commands==1&&!network->tx_wait&&network->tx_completed==7);
            uint8_t unmap[4]={4,0,17,0};station_htt_event(unmap,4);result=5;for(unsigned n=0;n<30&&result==5;n++)result=network_poll();
            CHECK(result==4&&network->closed&&!network->ethernet.authorized&&!pwpa_nonzero(network->wpa.kck,16)&&!pmwn_send(network,outgoing,114));
#if defined(POLARIS_WIFI_NETWORK_NONCE_TEST)
            uint8_t emitted[32];for(unsigned n=1;n<PWNP_COUNT;n++)CHECK(pmnp_take(nonce_source,emitted)&&!memcmp(emitted,nonce_bundle+PWNP_HEADER+32*n,32));
            CHECK(!pmnp_take(nonce_source,emitted)&&nonce_source->pool.used==PWNP_COUNT);
            struct pmnp_state*replacement=(void*)(arena+0x73b8000);memset(replacement,0,sizeof(*replacement));CHECK(!pmnp_begin(replacement,wmi,source,digest));
#endif
            fprintf(stderr,"native network:early M1 DMA, exact M2/M4, CCMP confirmations/authorize, encrypted retry no reinstall, RX PN floor/replay, encrypted TX, GTK renewal/retries/no PN reset, disconnect PASS\n");
        }else if(kind==3){CHECK(result==4&&network->closed&&!network->unknown&&!key_commands&&!network->ethernet.authorized);}
        else{
            CHECK(result==-1&&network->unknown&&network->error&&!network->ethernet.authorized&&owner->held);
            unsigned calls=htt_copies+htt_caches+transport_writes;CHECK(pmwn_step(network)==-1&&calls==htt_copies+htt_caches+transport_writes);
        }
    }
    station_test_close();printf("PASS %u native network checks, %u scenarios; SOFTWARE target/cache/MMIO/UEFI, no phone Wi-Fi or IP success\n",checks+nv_checks,net_scenarios);return 0;
}
