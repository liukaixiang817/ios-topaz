#define main station_protocol_main
#include "polaris-wifi-station-test.c"
#undef main
#include "polaris-wifi-wmi-station.h"
static struct pwst_state control;
static struct pwst_channel channel={2437,0,20,30,0,0,0}; /* SOFTWARE radio inputs */
static void setup(unsigned security)
{
    candidate(security);memset(&control,0,sizeof(control));
    CHECK(pwst_open(&control,&scan,0,security,&channel,++ticks));
}
static void startup(void)
{
    CHECK(pwst_next(&control,++ticks)==1&&control.kind==1&&control.tx_bytes==44&&pwmi_get(control.tx)==0x3003);
    CHECK(pwmi_get(control.tx+16)==0x00500018&&pwmi_get(control.tx+20)==2437&&pwmi_get(control.tx+32)==1);
    CHECK(control.tx[36]==0&&control.tx[37]==20&&control.tx[38]==30&&control.tx[41]==20);
    CHECK(pwst_sent(&control,++ticks,1)==1&&control.phase==1);
    CHECK(pwst_next(&control,++ticks)==1&&control.tx_bytes==112&&pwmi_get(control.tx)==0x5003&&pwmi_get(control.tx+4)==0x00580048);
    CHECK(pwmi_get(control.tx+12)==1&&pwmi_get(control.tx+16)==100&&pwmi_get(control.tx+20)==2&&pwmi_get(control.tx+28)==4&&!memcmp(control.tx+32,"test",4));
    CHECK(pwmi_get(control.tx+80)==0x00500018&&pwmi_get(control.tx+108)==0x00120000);
    CHECK(pwst_sent(&control,++ticks,1)==1&&control.phase==2&&!pwst_next(&control,++ticks));
}
static unsigned started(unsigned req,unsigned status)
{
    memset(event,0,sizeof(event));pwmi_put(event,0x5001);pwmi_header(event+4,40,16);
    pwmi_put(event+12,req);pwmi_put(event+20,status);return 24;
}
static void mapped(void)
{
    unsigned bytes=started(1,0);CHECK(pwst_wmi(&control,event,bytes,++ticks)==1&&control.start_received&&control.phase==3);
    CHECK(pwst_next(&control,++ticks)==1&&control.tx_bytes==24&&pwmi_get(control.tx)==0x6001&&pwmi_get(control.tx+4)==0x00610010);
    CHECK(!memcmp(control.tx+12,scan.bss[0].bssid,6)&&pwmi_get(control.tx+20)==1);
    CHECK(pwst_sent(&control,++ticks,1)==1&&control.phase==4&&!pwst_next(&control,++ticks));
    CHECK(pwst_peer(&control,17,0,scan.bss[0].bssid,1,++ticks)==1&&control.phase==5&&control.peer_valid&&control.peer_id==17);
}
static void management(void)
{
    CHECK(pwst_next(&control,++ticks)==1&&control.kind==2&&control.tx_bytes==30&&control.tx[0]==0xb0);
    CHECK(pwst_sent(&control,++ticks,1)==1&&control.phase==5&&!control.up_published);
    unsigned bytes=response(0xb0,0);bytes=wmi(bytes);CHECK(pwst_wmi(&control,event,bytes,++ticks)==1&&control.station.phase==2);
    CHECK(pwst_next(&control,++ticks)==1&&control.kind==2&&control.tx[0]==0);
    CHECK(pwst_sent(&control,++ticks,1)==1);bytes=response(0x10,0);bytes=wmi(bytes);
    CHECK(pwst_wmi(&control,event,bytes,++ticks)==1&&control.station.associated&&!control.up_published);
}
int main(void)
{
    CHECK(!station_protocol_main());
    for(unsigned sec=0;sec<=2;sec+=2){
        setup(sec);startup();mapped();management();
        CHECK(pwst_next(&control,++ticks)==1&&control.kind==1&&control.tx_bytes==124&&pwmi_get(control.tx)==0x6005);
        CHECK(pwmi_get(control.tx+4)==0x0065004c&&!memcmp(control.tx+8,scan.bss[0].bssid,6));
        CHECK(pwmi_get(control.tx+20)==1&&pwmi_get(control.tx+24)==0x123&&pwmi_get(control.tx+28)==(sec?5u:1u));
        CHECK(pwmi_get(control.tx+32)==control.station.assoc_caps&&pwmi_get(control.tx+36)==10&&pwmi_get(control.tx+56)==1&&pwmi_get(control.tx+64)==1&&pwmi_get(control.tx+76)==12);
        CHECK(pwmi_get(control.tx+84)==0x0011000c&&control.tx[88]==2&&control.tx[99]==108&&pwmi_get(control.tx+100)==0x00110000&&pwmi_get(control.tx+104)==0x00660010);
        CHECK(pwst_sent(&control,++ticks,1)==1&&control.phase==7&&!control.up_published);
        CHECK(pwst_next(&control,++ticks)==1&&pwmi_get(control.tx)==0x5005&&pwmi_get(control.tx+4)==0x005c0010&&control.tx_bytes==24);
        CHECK(pwmi_get(control.tx+12)==0x123&&!memcmp(control.tx+16,scan.bss[0].bssid,6));
        CHECK(pwst_sent(&control,++ticks,1)==1&&control.phase==8&&control.up_published&&!pwst_next(&control,++ticks));
        CHECK(pwst_peer(&control,17,0,scan.bss[0].bssid,0,++ticks)==1&&control.phase==9&&!control.peer_valid&&!control.up_published&&!control.station.associated);
    }
    for(unsigned fault=0;fault<8;fault++){
        setup(2);startup();unsigned bytes=started(1,0);
        if(fault==0)pwmi_put(event+20,1);
        if(fault==1)pwmi_put(event+16,1);
        if(fault==2)pwmi_header(event+4,40,65535);
        if(fault==3)bytes--;
        if(fault==4){CHECK(pwst_next(&control,control.deadline+1)==-1&&control.unknown);continue;}
        if(fault==5){mapped();CHECK(pwst_peer(&control,18,0,scan.bss[0].bssid,1,++ticks)==-1&&control.unknown);continue;}
        if(fault==6){mapped();CHECK(pwst_peer(&control,18,0,scan.bss[0].bssid,0,++ticks)==-1&&control.unknown);continue;}
        if(fault==7){CHECK(pwst_wmi(&control,event,bytes,control.last-1)==-1&&control.unknown);continue;}
        CHECK(pwst_wmi(&control,event,bytes,++ticks)==-1&&control.unknown);
    }
    setup(2);startup();unsigned bytes=started(7,0);
    CHECK(pwst_wmi(&control,event,bytes,++ticks)==1&&control.ignored==1&&control.phase==2);
    mapped();uint8_t foreign[6]={2,0,0,0,0,11};CHECK(!pwst_peer(&control,5,0,foreign,1,++ticks)&&control.peer_id==17);
    management();bytes=response(0xa0,8);bytes=wmi(bytes);
    CHECK(pwst_wmi(&control,event,bytes,++ticks)==1&&control.phase==9&&!control.up_published&&!control.station.associated);
    setup(2);CHECK(pwst_next(&control,++ticks)==1&&pwst_sent(&control,++ticks,0)==-1&&control.unknown);
    candidate(2);memset(&control,0,sizeof(control));channel.max_power=31;
    CHECK(!pwst_open(&control,&scan,0,2,&channel,++ticks));channel.max_power=20;
    printf("PASS %u combined WMI station checks; SOFTWARE only\n",checks);return 0;
}
