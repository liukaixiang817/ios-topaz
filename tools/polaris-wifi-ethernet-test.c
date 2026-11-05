#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "polaris-wifi-ethernet.h"
static struct pwen_state net;
static struct psta_state station;
static struct pwki_state keys;
static struct pwpa_state wpa;
static uint8_t raw[2048],ethernet[1514];
static unsigned checks;
#define CHECK(x) do{assert(x);checks++;}while(0)
static void setup(unsigned security)
{
    memset(&net,0,sizeof(net));memset(&station,0,sizeof(station));memset(&keys,0,sizeof(keys));memset(&wpa,0,sizeof(wpa));
    station.opened=station.associated=1;station.phase=4;station.security=security;station.epoch=9;
    station.own[0]=2;station.own[5]=7;station.target.bssid[0]=2;station.target.bssid[5]=9;
    CHECK(pwen_open(&net,&station,17)&&net.authorized==(security==0));
    keys.opened=1;keys.epoch=9;keys.peer=17;keys.gtk_id=1;keys.group_floor[0]=5;memcpy(keys.mac,net.ap,6);
    wpa.opened=wpa.install_issued=wpa.have_m3=1;wpa.epoch=9;memcpy(wpa.peer,net.ap,6);memcpy(wpa.own,net.own,6);
}
static void authorize(void)
{
    keys.confirmed=3;keys.phase=5;wpa.authorized=wpa.installed=1;
    CHECK(pwen_keys(&net,&keys,&wpa)&&net.authorized&&net.keys_seen==3&&net.group_floor==5);
}
static unsigned frame(unsigned type,unsigned encrypted,unsigned group,uint64_t pn)
{
    memset(raw,0,sizeof(raw));pwmi_put(raw+4,(1u<<31)|(1u<<6)|(group?4u:1u<<25));
    pwmi_put(raw+16,17|0x800|(encrypted?0x2000:0)|((encrypted?6u:7u)<<28));
    for(unsigned n=0;n<6;n++)raw[20+n]=(uint8_t)(pn>>(8*n));pwmi_put(raw+36,1u<<8);pwmi_put(raw+64,0xc000);
    uint8_t*h=raw+296,*p=raw+360;h[0]=8;h[1]=(uint8_t)(2|(encrypted?64:0));
    if(group)memset(h+4,255,6);else memcpy(h+4,net.own,6);
    memcpy(h+10,net.ap,6);memcpy(h+16,net.ap,6);if(type!=0x888e)h[21]=66;
    memcpy(p,h,24);p[1]&=~64u; /* native header need not retain Protected */
    if(encrypted){h[24]=(uint8_t)pn;h[25]=(uint8_t)(pn>>8);h[27]=(uint8_t)(0x20|(group?64:0));raw[52]=h[27];for(unsigned n=0;n<4;n++)h[28+n]=(uint8_t)(pn>>(16+8*n));}
    const uint8_t llc[6]={170,170,3,0,0,0};memcpy(p+24,llc,6);pwpa_put16(p+30,type);
    for(unsigned n=0;n<100;n++)p[32+n]=(uint8_t)(n^55);return 132;
}
static int receive(unsigned bytes){return pwen_receive(&net,raw,sizeof(raw),bytes,17,0,0);}
int main(void)
{
    setup(2);unsigned bytes=frame(0x888e,0,0,0);
    CHECK(receive(bytes)==2&&net.rx_kind==2&&net.rx_bytes==114&&!net.authorized&&!memcmp(net.receive,net.own,6)&&!memcmp(net.receive+6,net.ap,6));
    CHECK(pwpa_be16(net.receive+12)==0x888e&&!memcmp(net.receive+14,raw+392,100));
    CHECK(receive(bytes)==-1&&pwen_ack(&net));
    bytes=frame(0x800,0,0,0);CHECK(!receive(bytes));bytes=frame(0x888e,1,0,1);CHECK(!receive(bytes));
    keys.confirmed=1;keys.phase=2;CHECK(pwen_keys(&net,&keys,&wpa)&&!net.authorized&&net.keys_seen==1);
    CHECK(receive(bytes)==2&&net.pn[0]==1&&pwen_ack(&net));
    authorize();bytes=frame(0x800,1,0,2);CHECK(receive(bytes)==1&&net.pn[0]==2&&pwen_ack(&net));
    CHECK(!receive(bytes)&&net.replayed==1&&net.pn[0]==2);
    bytes=frame(0x800,1,1,5);CHECK(!receive(bytes)&&net.replayed==2&&net.pn[1]==5);
    bytes=frame(0x806,1,1,6);CHECK(receive(bytes)==1&&net.pn[1]==6&&pwen_ack(&net));
    CHECK(pwen_keys(&net,&keys,&wpa)&&net.pn[1]==6&&net.pn[0]==2);
    /* All checks precede PN advancement and delivery. */
    for(unsigned fault=0;fault<23;fault++){
        bytes=frame(0x800,1,0,1000+fault);unsigned info=0,peer=17,vdev=0,raw_bytes=2048;
        if(fault==0)raw[296+10]^=2;
        if(fault==1)raw[296+4]^=2;
        if(fault==2)raw[296+1]|=1;
        if(fault==3)raw[296+1]|=4;
        if(fault==4)raw[296]=0x88;
        if(fault==5)raw[360+24]=0;
        if(fault==6)raw[20]^=1;
        if(fault==7)raw[296+27]=0x60;
        if(fault==8)raw[52]^=1;
        if(fault==9)raw[296+26]=1;
        if(fault==10)pwmi_put(raw+16,17|0x2800|(4u<<28));
        if(fault==11)pwmi_put(raw+64,0x4000);
        if(fault==12)pwmi_put(raw+4,pwmi_get(raw+4)|(1u<<29));
        if(fault==13)pwmi_put(raw+4,pwmi_get(raw+4)|(1u<<24));
        if(fault==14)raw[8]=1;
        if(fault==15)pwmi_put(raw+36,2u<<8);
        if(fault==16)bytes=31;
        if(fault==17)bytes=1689;
        if(fault==18)info=0x20;
        if(fault==19)info=0x40;
        if(fault==20)peer=18;
        if(fault==21)vdev=1;
        if(fault==22)raw_bytes=360;
        CHECK(!pwen_receive(&net,raw,raw_bytes,bytes,peer,vdev,info)&&!net.rx_ready&&net.pn[0]==2&&net.pn[1]==6);
    }
    bytes=frame(0x800,1,0,3);CHECK(receive(bytes)==1&&net.pn[0]==3&&pwen_ack(&net));
    bytes=frame(0x800,0,0,0);CHECK(!receive(bytes));
    bytes=frame(0x888e,0,0,0);pwmi_put(raw+4,pwmi_get(raw+4)|(1u<<24));
    CHECK(receive(bytes)==2&&pwen_ack(&net)); /* EAPOL controlled separately */
    bytes=frame(0x888e,0,1,0);CHECK(!receive(bytes));
    memset(ethernet,0,sizeof(ethernet));memset(ethernet,255,6);memcpy(ethernet+6,net.own,6);ethernet[12]=8;
    CHECK(pwen_data(&net,ethernet,114)&&net.tx_bytes==114&&!net.tx_plain&&!memcmp(net.transmit,ethernet,114));
    CHECK(!pwen_data(&net,ethernet,114)&&pwen_sent(&net));
    ethernet[6]^=2;CHECK(!pwen_data(&net,ethernet,114));ethernet[6]^=2;
    ethernet[12]=0x88;ethernet[13]=0x8e;CHECK(!pwen_data(&net,ethernet,114));
    const uint8_t eapol_start[4]={2,1,0,0};CHECK(pwen_eapol(&net,eapol_start,4)&&net.tx_plain&&net.tx_bytes==18&&!memcmp(net.transmit,net.ap,6)&&pwen_sent(&net));
    pwen_stop(&net);CHECK(net.closed&&!net.authorized&&!pwen_data(&net,ethernet,114)&&receive(bytes)==-1);
    setup(0);bytes=frame(0x806,0,1,0);CHECK(receive(bytes)==1&&pwen_ack(&net));
    memset(ethernet,255,6);memcpy(ethernet+6,net.own,6);ethernet[12]=8;ethernet[13]=6;
    CHECK(pwen_data(&net,ethernet,114)&&net.tx_plain&&pwen_sent(&net));
    printf("PASS %u Ethernet/EAPOL controlled-port and CCMP PN checks; SOFTWARE only\n",checks);return 0;
}
