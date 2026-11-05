#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "polaris-wifi-wmi-scan.h"
static struct pwsc_state scan;
static struct pwmi_state wmi;
static uint8_t packet[1200];
static unsigned checks;
static uint64_t ticks;
#define CHECK(x) do{assert(x);checks++;}while(0)
static void start(void)
{
    memset(&scan,0,sizeof(scan));memset(&wmi,0,sizeof(wmi));ticks=100;
    wmi.phase=4;wmi.epoch=8;wmi.last=ticks;wmi.mac[0]=2;wmi.mac[5]=7;
    CHECK(pwsc_open(&scan,&wmi,7,++ticks));
}
static void commands(void)
{
    CHECK(pwsc_next(&scan,++ticks)==1&&scan.tx_bytes==28&&pwmi_get(scan.tx)==0x5001&&pwmi_get(scan.tx+4)==0x00560014&&pwmi_get(scan.tx+12)==2&&!memcmp(scan.tx+20,wmi.mac,6));
    CHECK(pwsc_sent(&scan,++ticks,1)==1&&scan.phase==1);
    CHECK(pwsc_next(&scan,++ticks)==1&&scan.tx_bytes==324&&pwmi_get(scan.tx)==0x3003&&pwmi_get(scan.tx+8)==11&&pwmi_get(scan.tx+12)==0x00120134);
    for(unsigned n=0;n<11;n++){const uint8_t*p=scan.tx+16+28*n;CHECK(pwmi_get(p)==0x00500018&&pwmi_get(p+4)==2412+5*n&&pwmi_get(p+8)==2412+5*n&&pwmi_get(p+16)==0x81&&!pwmi_get(p+20)&&!pwmi_get(p+24));}
    CHECK(pwsc_sent(&scan,++ticks,1)==1&&scan.phase==2);
    CHECK(pwsc_next(&scan,++ticks)==1&&scan.tx_bytes==176&&pwmi_get(scan.tx)==0x3001&&pwmi_get(scan.tx+4)==0x004d0064);
    CHECK(pwmi_get(scan.tx+8)==0xa007&&pwmi_get(scan.tx+12)==0xa001&&pwmi_get(scan.tx+64)==0x31&&pwmi_get(scan.tx+72)==11&&pwmi_get(scan.tx+76)==1&&!pwmi_get(scan.tx+80));
    CHECK(pwmi_get(scan.tx+108)==0x0010002c&&pwmi_get(scan.tx+152)==2462&&pwmi_get(scan.tx+156)==0x00130000&&pwmi_get(scan.tx+160)==0x00130008&&pwmi_get(scan.tx+164)==UINT32_MAX&&pwmi_get(scan.tx+172)==0x00110000);
    CHECK(pwsc_sent(&scan,++ticks,1)==1&&scan.phase==3&&!pwsc_next(&scan,++ticks));
}
static unsigned event(unsigned type,unsigned reason,unsigned id)
{
    memset(packet,0,sizeof(packet));pwmi_put(packet,0x3001);pwmi_header(packet+4,36,24);
    pwmi_put(packet+8,type);pwmi_put(packet+12,reason);pwmi_put(packet+16,2437);pwmi_put(packet+20,0xa001);pwmi_put(packet+24,id);return 32;
}
static unsigned beacon(unsigned bssid,unsigned ssid_bytes)
{
    memset(packet,0,sizeof(packet));pwmi_put(packet,0x7001);pwmi_header(packet+4,44,40);pwmi_put(packet+8,6);pwmi_put(packet+12,42);
    uint8_t*p=packet+52;p[0]=0x80;p[16]=2;p[21]=(uint8_t)bssid;p[32]=100;p[34]=0x11;
    p[36]=0;p[37]=(uint8_t)ssid_bytes;for(unsigned n=0;n<ssid_bytes;n++)p[38+n]=(uint8_t)('a'+n);
    p[38+ssid_bytes]=3;p[39+ssid_bytes]=1;p[40+ssid_bytes]=6;
    unsigned length=41+ssid_bytes;pwmi_put(packet+24,length);pwmi_header(packet+48,17,length);return 52+length;
}
int main(void)
{
    start();commands();unsigned bytes=event(1,0,0xa007);CHECK(pwsc_receive(&scan,packet,bytes,++ticks)==1&&scan.phase==4&&scan.started);
    bytes=beacon(9,4);CHECK(pwsc_receive(&scan,packet,bytes,++ticks)==1&&scan.count==1&&scan.bss[0].frequency==2437&&scan.bss[0].snr==42&&scan.bss[0].ssid_bytes==4&&!memcmp(scan.bss[0].ssid,"abcd",4)&&scan.bss[0].capability==0x11);
    bytes=beacon(9,0);CHECK(pwsc_receive(&scan,packet,bytes,++ticks)==1&&scan.count==1&&scan.bss[0].ssid_bytes==4&&scan.bss[0].observations==2);
    bytes=beacon(9,4);packet[52]=0x50;CHECK(pwsc_receive(&scan,packet,bytes,++ticks)==1&&scan.count==1&&scan.bss[0].observations==3);
    bytes=event(8,0,0xa007);CHECK(pwsc_receive(&scan,packet,bytes,++ticks)==1&&scan.foreign==1);
    bytes=event(2,0,0xa008);CHECK(pwsc_receive(&scan,packet,bytes,++ticks)==1&&scan.ignored==1&&!scan.completed);
    bytes=event(2,0,0xa007);CHECK(pwsc_receive(&scan,packet,bytes,++ticks)==1&&scan.completed&&scan.phase==5&&scan.count==1);
    for(unsigned fault=0;fault<7;fault++){
        start();commands();bytes=event(1,0,0xa007);CHECK(pwsc_receive(&scan,packet,bytes,++ticks)==1);
        bytes=event(fault==0?64:fault==1?2:8,fault==1?3:0,0xa007);
        if(fault==2)pwmi_put(packet+16,5000);
        if(fault==3)bytes--;
        if(fault==4)pwmi_header(packet+4,36,65535);
        if(fault==5){CHECK(pwsc_next(&scan,scan.deadline+1)==-1&&scan.error);continue;}
        if(fault==6)pwmi_put(packet+8,1);
        CHECK(pwsc_receive(&scan,packet,bytes,++ticks)==-1&&scan.unknown&&scan.error);
    }
    start();commands();bytes=event(1,0,0xa007);CHECK(pwsc_receive(&scan,packet,bytes,++ticks)==1);
    for(unsigned bad=0;bad<8;bad++){
        bytes=beacon(9,4);
        if(bad==0)packet[52+37]=33;
        if(bad==1)packet[52+44]=11; /* DS channel differs */
        if(bad==2)pwmi_put(packet+28,1); /* CRC */
        if(bad==3)packet[52+16]=3; /* multicast BSSID */
        if(bad==4)packet[52+1]=0x40; /* protected beacon */
        if(bad==5)pwmi_put(packet+8,165); /* outside this scan */
        if(bad==6)packet[52+36]=255; /* missing SSID */
        if(bad==7)pwmi_put(packet+24,20); /* short management */
        CHECK(pwsc_receive(&scan,packet,bytes,++ticks)==1&&!scan.error&&!scan.count&&scan.dropped==bad+1);
    }
    for(unsigned n=0;n<40;n++){bytes=beacon(n+1,4);CHECK(pwsc_receive(&scan,packet,bytes,++ticks)==1&&scan.count==(n<32?n+1:32));}
    CHECK(scan.dropped==16);
    /* Unrelated management frames remain available for the station state machine. */
    bytes=beacon(1,4);packet[52]=0xb0;CHECK(!pwsc_receive(&scan,packet,bytes,++ticks));
    start();CHECK(!pwsc_restart(&scan,8,++ticks));commands();
    bytes=event(1,0,0xa007);CHECK(pwsc_receive(&scan,packet,bytes,++ticks)==1);
    bytes=event(2,0,0xa007);CHECK(pwsc_receive(&scan,packet,bytes,++ticks)==1&&scan.completed);
    CHECK(!pwsc_restart(&scan,7,++ticks));CHECK(!pwsc_restart(&scan,0,++ticks));
    CHECK(pwsc_restart(&scan,8,++ticks)&&scan.phase==1&&!scan.completed&&!scan.count&&scan.epoch==wmi.epoch&&!memcmp(scan.mac,wmi.mac,6));
    CHECK(pwsc_next(&scan,++ticks)==1&&pwmi_get(scan.tx)==0x3003); /* Same vdev, no duplicate CREATE. */
    CHECK(pwsc_sent(&scan,++ticks,1)==1&&pwsc_next(&scan,++ticks)==1&&pwmi_get(scan.tx)==0x3001&&pwmi_get(scan.tx+8)==0xa008);
    CHECK(pwsc_sent(&scan,++ticks,1)==1);
    bytes=event(2,0,0xa007);CHECK(pwsc_receive(&scan,packet,bytes,++ticks)==1&&!scan.completed&&scan.ignored==1);
    bytes=event(1,0,0xa008);CHECK(pwsc_receive(&scan,packet,bytes,++ticks)==1);
    bytes=event(2,0,0xa008);CHECK(pwsc_receive(&scan,packet,bytes,++ticks)==1&&scan.completed);
    printf("PASS %u passive scan/BSS checks; SOFTWARE only\n",checks);return 0;
}
