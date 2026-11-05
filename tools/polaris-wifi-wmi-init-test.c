#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "polaris-wifi-wmi-init.h"
static struct pwmi_state state;
static uint8_t packet[2040];
static unsigned checks,bytes;
static uint64_t tick;
#define CHECK(x) do{assert(x);checks++;}while(0)
static void start(void)
{memset(&state,0,sizeof(state));memset(packet,0,sizeof(packet));tick=100;CHECK(pwmi_open(&state,3,tick));}
static uint8_t*tlv(unsigned tag,unsigned length)
{CHECK(bytes+4+length<=sizeof(packet));uint8_t*p=packet+bytes;pwmi_header(p,tag,length);bytes+=4+length;return p+4;}
static void abi(uint8_t*p)
{pwmi_put(p,0x01000000);pwmi_put(p+4,71);pwmi_put(p+8,0x5f414351);pwmi_put(p+12,0x4c4d);}
static void service(unsigned count)
{
    memset(packet,0,sizeof(packet));bytes=4;pwmi_put(packet,1);uint8_t*p=tlv(32,104);abi(p+4);pwmi_put(p+36,2);pwmi_put(p+72,count);
    p=tlv(33,36);pwmi_put(p,0x64);pwmi_put(p+20,1);pwmi_put(p+24,14);pwmi_put(p+28,36);pwmi_put(p+32,165);
    p=tlv(16,128);pwmi_put(p+4*(65/4),1u<<(65%4));p=tlv(18,20*count);
    for(unsigned n=0;n<count;n++){pwmi_header(p+20*n,34,16);pwmi_put(p+20*n+4,n+1);pwmi_put(p+20*n+8,17);pwmi_put(p+20*n+12,n?2:1);pwmi_put(p+20*n+16,123);}
}
static void extension(void)
{
    memset(packet,0,sizeof(packet));bytes=4;pwmi_put(packet,3);uint8_t*p=tlv(559,20);pwmi_put(p,128);
    pwmi_put(p+8,(1u<<(179-160))|(1u<<(174-160)));
    CHECK(pwmi_receive(&state,packet,bytes,++tick)==1&&pwmi_service(&state,179)&&pwmi_service(&state,174));
}
static void ready(unsigned status)
{
    memset(packet,0,sizeof(packet));bytes=4;pwmi_put(packet,2);uint8_t*p=tlv(35,36);abi(p);p[24]=2;p[25]=0xaa;p[29]=7;pwmi_put(p+32,status);
}
int main(void)
{
    start();extension();service(2);CHECK(pwmi_receive(&state,packet,bytes,++tick)==1&&state.phase==1&&pwmi_service(&state,65));
    CHECK(pwmi_plan(&state,UINT64_C(0x120000000),0x10000,++tick)==1&&state.used==8192);
    CHECK(state.chunk[0].bytes==100&&state.chunk[1].bytes==680&&state.chunk[1].address==UINT64_C(0x120001000));
    CHECK(pwmi_init(&state,++tick)==1&&state.tx_bytes==260&&state.phase==2);
    CHECK(pwmi_get(state.tx)==1&&pwmi_get(state.tx+4)==0x004a001c&&pwmi_get(state.tx+32)==2);
    CHECK(pwmi_get(state.tx+36)==0x004b00b0&&pwmi_get(state.tx+48)==4&&pwmi_get(state.tx+52)==4&&pwmi_get(state.tx+212)==0x40200);
    CHECK(pwmi_get(state.tx+216)==0x00120028&&pwmi_get(state.tx+220)==0x004c0010&&pwmi_get(state.tx+228)==0x20000000&&pwmi_get(state.tx+232)==100&&pwmi_get(state.tx+236)==1);
    CHECK(pwmi_sent(&state,++tick,1)==1);ready(0);CHECK(pwmi_receive(&state,packet,bytes,++tick)==1&&state.phase==4&&state.mac[5]==7);
    CHECK(pwmi_receive(&state,packet,bytes,++tick)==-1&&state.unknown);
    start();service(0);CHECK(pwmi_receive(&state,packet,bytes,++tick)==1&&pwmi_plan(&state,0xfffff000,4096,++tick)==1&&pwmi_init(&state,++tick)==1&&state.tx_bytes==220&&pwmi_sent(&state,++tick,1)==1);ready(9);CHECK(pwmi_receive(&state,packet,bytes,++tick)==-1);
    for(unsigned fault=0;fault<12;fault++){
        start();service(2);
        if(fault==0)packet[15]=0; /* incompatible ABI major */
        if(fault==1)pwmi_put(packet+80,3); /* count mismatch */
        if(fault==2)pwmi_put(packet+bytes-16,1); /* duplicate req id */
        if(fault==3)pwmi_put(packet+bytes-12,UINT32_MAX); /* unit overflow */
        if(fault==4)pwmi_put(packet+bytes-8,8); /* unknown unit semantics */
        if(fault==5)bytes--; /* truncated nested TLV */
        if(fault<6){CHECK(pwmi_receive(&state,packet,bytes,++tick)==-1&&state.error);continue;}
        CHECK(pwmi_receive(&state,packet,bytes,++tick)==1);
        if(fault==6)CHECK(pwmi_plan(&state,UINT64_C(0x100000000),8192,++tick)==-1&&state.error);
        if(fault==7)CHECK(pwmi_plan(&state,0xfff00000,4096,++tick)==-1&&state.error);
        if(fault==8){state.request[0].flags=0;state.request[0].units=UINT32_MAX;CHECK(pwmi_plan(&state,0xfff00000,8192,++tick)==-1&&state.error);}
        if(fault==9)CHECK(pwmi_init(&state,++tick)==-1&&!state.pending);
        if(fault==10)CHECK(pwmi_plan(&state,0xfff00000,8192,state.deadline+1)==-1&&state.error);
        if(fault==11){CHECK(pwmi_plan(&state,0xfff00000,8192,++tick)==1&&pwmi_init(&state,++tick)==1&&pwmi_sent(&state,++tick,0)==-1&&state.error);}
    }
    /* Every truncation of an otherwise complete event must be rejected. */
    service(2);unsigned full=bytes;
    for(unsigned n=0;n<full;n++){start();service(2);CHECK(pwmi_receive(&state,packet,n,++tick)==-1&&state.phase==0);}
    /* Varied bounded malformed TLVs exercise cursor arithmetic under sanitizers. */
    uint32_t rng=0x71524613;
    for(unsigned n=0;n<4096;n++){
        start();service(2);rng=rng*1664525+1013904223;unsigned offset=4+rng%(bytes-4);packet[offset]^=(uint8_t)(1+(rng>>24));
        int result=pwmi_receive(&state,packet,bytes,++tick);CHECK(result==1||result==-1);CHECK(state.requests<=16);
        if(result==1){result=pwmi_plan(&state,0xb0700000,0x100000,++tick);CHECK(result==1||result==-1);}
    }
    printf("PASS %u WMI TLV bootstrap checks; SOFTWARE only\n",checks);return 0;
}
