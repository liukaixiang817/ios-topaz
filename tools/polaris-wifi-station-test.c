#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "polaris-wifi-station.h"
static struct psta_state station;
static struct pwsc_state scan;
static uint8_t frame[2048],event[2100];
static unsigned checks;
static uint64_t ticks;
#define CHECK(x) do{assert(x);checks++;}while(0)
static void candidate(unsigned security)
{
    memset(&station,0,sizeof(station));memset(&scan,0,sizeof(scan));ticks=100;
    scan.opened=scan.completed=1;scan.phase=5;scan.epoch=8;scan.last=ticks;scan.count=1;scan.mac[0]=2;scan.mac[5]=7;
    struct pwsc_bss*b=&scan.bss[0];b->bssid[0]=2;b->bssid[5]=9;b->frequency=2437;b->ssid_bytes=4;
    memcpy(b->ssid,"test",4);b->interval=100;b->capability=(uint16_t)(0x421|(security?16:0));b->observations=1;
    const uint8_t ies[]={0,4,'t','e','s','t',1,8,0x82,0x84,0x8b,0x96,12,18,24,36,50,4,48,72,96,108,3,1,6,5,4,0,2,0,0};
    memcpy(b->ies,ies,sizeof(ies));b->ie_bytes=sizeof(ies);
    if(security){const uint8_t rsn[]={48,20,1,0,0,15,172,4,1,0,0,15,172,4,1,0,0,15,172,2,0,0};memcpy(b->ies+b->ie_bytes,rsn,sizeof(rsn));b->ie_bytes+=sizeof(rsn);}
}
static void start(unsigned security)
{
    candidate(security);CHECK(psta_open(&station,&scan,0,security,++ticks));
    CHECK(station.opened&&station.dtim==2&&station.rate_count==12&&!station.associated&&!station.rejected);
}
static unsigned response(unsigned type,unsigned status)
{
    memset(frame,0,sizeof(frame));frame[0]=(uint8_t)type;
    memcpy(frame+4,scan.mac,6);memcpy(frame+10,scan.bss[0].bssid,6);memcpy(frame+16,scan.bss[0].bssid,6);
    if(type==0xb0){frame[26]=2;psta_put16(frame+28,status);return 30;}
    if(type==0x10){
        psta_put16(frame+24,scan.bss[0].capability);psta_put16(frame+26,status);psta_put16(frame+28,0xc123);
        const uint8_t rates[]={1,8,0x82,0x84,0x8b,0x96,12,18,24,36,50,4,48,72,96,108};memcpy(frame+30,rates,sizeof(rates));return 30+sizeof(rates);
    }psta_put16(frame+24,status);return 26;
}
static void auth(void)
{
    CHECK(psta_next(&station,++ticks)==1&&station.tx_bytes==30&&station.tx[0]==0xb0&&psta_u16(station.tx+26)==1&&!station.tx[1]);
    CHECK(!memcmp(station.tx+4,scan.bss[0].bssid,6)&&!memcmp(station.tx+10,scan.mac,6)&&!memcmp(station.tx+16,scan.bss[0].bssid,6));
    CHECK(psta_sent(&station,++ticks,1)==1&&station.phase==1&&station.attempts==1);
    unsigned bytes=response(0xb0,0);CHECK(psta_frame(&station,frame,bytes,2437,++ticks)==1&&station.phase==2&&!station.associated);
}
static void assoc(void)
{
    CHECK(psta_next(&station,++ticks)==1&&station.tx[0]==0&&psta_u16(station.tx+22)==16&&station.tx[29]==4&&!memcmp(station.tx+30,"test",4));
    CHECK(psta_u16(station.tx+24)==scan.bss[0].capability&&psta_u16(station.tx+26)==10);
    CHECK(station.tx_bytes==(station.security?72u:50u));
    if(station.security)CHECK(!memcmp(station.tx+50,station.rsn,22));
    CHECK(psta_sent(&station,++ticks,1)==1&&station.phase==3);
}
static unsigned wmi(unsigned bytes)
{
    memset(event,0,sizeof(event));pwmi_put(event,0x7001);pwmi_header(event+4,44,40);pwmi_put(event+8,6);
    pwmi_put(event+24,bytes);pwmi_header(event+48,17,bytes);memcpy(event+52,frame,bytes);return bytes+52;
}
int main(void)
{
    for(unsigned security=0;security<=2;security+=2){
        start(security);auth();assoc();unsigned bytes=response(0x10,0);
        CHECK(psta_wmi(&station,event,wmi(bytes),++ticks)==1&&station.phase==4&&station.associated&&station.aid==0x123);
        CHECK(!psta_next(&station,++ticks)&&!station.rejected);bytes=response(0xc0,3);
        CHECK(psta_frame(&station,frame,bytes,2437,++ticks)==1&&!station.associated&&station.rejected&&station.reason==3);
    }
    /* Candidate security/rate/IE validation, including explicit downgrade refusal. */
    for(unsigned fault=0;fault<21;fault++){
        candidate(2);struct pwsc_bss*b=&scan.bss[0];unsigned security=2;
        if(fault==0)security=0;
        if(fault==1)b->capability&=~16u;
        if(fault==2)b->ies[31+2+2+3]=2; /* group TKIP */
        if(fault==3)b->ies[31+2+8+3]=2; /* pairwise TKIP */
        if(fault==4)b->ies[31+2+14+3]=8; /* SAE only */
        if(fault==5)b->ies[31+2+18]=0x40; /* PMF required */
        if(fault==6)b->ies[31+2]=2; /* RSN version */
        if(fault==7)b->ies[31+2+6]=255; /* truncated cipher list */
        if(fault==8)b->ies[8]=255; /* unknown mandatory rate */
        if(fault==9)b->ies[7]=9; /* invalid supported-rates length */
        if(fault==10)b->ies[0]=2; /* no SSID */
        if(fault==11)b->ies[2]='z';
        if(fault==12)b->ies[24]=11; /* DS channel mismatch */
        if(fault==13)b->ies[28]=0; /* zero DTIM */
        if(fault==14)b->ie_bytes--;
        if(fault==15)b->bssid[0]=3;
        if(fault==16)b->frequency=2484;
        if(fault==17)b->capability|=2;
        if(fault==18)b->ssid_bytes=0;
        if(fault==19)b->ies[31]=49; /* privacy without RSN */
        if(fault==20)scan.completed=0;
        CHECK(!psta_open(&station,&scan,0,security,++ticks)&&!station.opened);
    }
    /* Late/foreign/fragmented/protected frames cannot advance authentication. */
    start(2);CHECK(psta_next(&station,++ticks)==1&&psta_sent(&station,++ticks,1)==1);
    for(unsigned fault=0;fault<10;fault++){
        unsigned bytes=response(0xb0,0),frequency=2437;
        if(fault==0)frame[4]^=2;if(fault==1)frame[10]^=2;if(fault==2)frame[16]^=2;
        if(fault==3)frame[1]=4;if(fault==4)frame[1]=0x40;if(fault==5)frame[22]=1;
        if(fault==6)frame[24]=1;if(fault==7)frame[26]=1;if(fault==8)bytes=29;if(fault==9)frequency=2462;
        CHECK(psta_frame(&station,frame,bytes,frequency,++ticks)==1&&station.phase==1&&!station.associated);
    }
    CHECK(station.ignored==4&&station.dropped==6);
    unsigned bytes=response(0xb0,13);CHECK(psta_frame(&station,frame,bytes,2437,++ticks)==1&&station.rejected&&station.reason==13);
    start(2);auth();assoc();
    for(unsigned fault=0;fault<7;fault++){
        bytes=response(0x10,0);
        if(fault==0)psta_put16(frame+28,0xc000);if(fault==1)psta_put16(frame+28,0xc800);
        if(fault==2)psta_put16(frame+28,123);if(fault==3)frame[24]&=~16u;
        if(fault==4)frame[31]=255;if(fault==5)frame[32]=255;if(fault==6)bytes=30;
        CHECK(psta_frame(&station,frame,bytes,2437,++ticks)==1&&station.phase==3&&!station.associated&&!station.error);
    }
    bytes=response(0x10,17);CHECK(psta_frame(&station,frame,bytes,2437,++ticks)==1&&station.rejected&&station.reason==17);
    /* Retries retain sequence and body; exhaustion is a connection failure. */
    start(0);CHECK(psta_next(&station,++ticks)==1&&psta_sent(&station,++ticks,1)==1);
    memcpy(frame,station.tx,station.tx_bytes);frame[1]|=8;
    for(unsigned n=0;n<2;n++){
        ticks=station.deadline+1;CHECK(psta_next(&station,ticks)==1&&!memcmp(frame,station.tx,30));
        CHECK(psta_sent(&station,++ticks,1)==1&&station.attempts==n+2);
    }
    ticks=station.deadline+1;CHECK(!psta_next(&station,ticks)&&station.rejected&&station.phase==5&&!station.unknown);
    start(0);CHECK(psta_next(&station,++ticks)==1&&psta_sent(&station,++ticks,0)==-1&&station.unknown);
    start(0);CHECK(psta_next(&station,station.last-1)==-1&&station.unknown);
    start(0);CHECK(!psta_next(&station,station.opening+PSTA_TOTAL+1)&&station.rejected);
    start(0);bytes=response(0xb0,0);bytes=wmi(bytes);pwmi_header(event+4,44,65535);
    CHECK(psta_wmi(&station,event,bytes,++ticks)==-1&&station.unknown);
    /* Exhaustive truncation/length mutations never read outside an RSN IE. */
    candidate(2);const uint8_t*rsn=scan.bss[0].ies+33;
    for(unsigned n=0;n<20;n++){memcpy(frame,rsn,n);CHECK(psta_rsn(frame,n)==(n==18));}
    for(unsigned n=0;n<256;n++){
        memcpy(frame,rsn,20);frame[6]=(uint8_t)n;CHECK(psta_rsn(frame,20)==(n==1));
        memcpy(frame,rsn,20);frame[12]=(uint8_t)n;CHECK(psta_rsn(frame,20)==(n==1));
    }
    printf("PASS %u station selection/authentication/association checks; SOFTWARE only\n",checks);return 0;
}
