#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "polaris-wifi-htc.h"
static struct phtc_state state;
static unsigned checks;
static uint64_t ticks;
#define CHECK(x) do{assert(x);checks++;}while(0)
static int control(const uint8_t*body,unsigned bytes)
{
    uint8_t frame[264]={0};CHECK(bytes<=256);phtc_put(frame+2,bytes);memcpy(frame+8,body,bytes);
    return phtc_receive(&state,2,frame,8+bytes,++ticks);
}
static void setup(void)
{memset(&state,0,sizeof(state));ticks=1000;CHECK(phtc_open(&state,7,ticks)==1);}
static void ready(void)
{
    const uint8_t ready_message[]={1,0,32,0,0,1,9,0,1,32,0x80,0};
    CHECK(control(ready_message,sizeof(ready_message))==1&&state.phase==1&&state.credit_size==256&&state.target_credits==32&&state.alt_credit_size==128);
}
static void request(unsigned service,unsigned flags)
{
    CHECK(phtc_next(&state,++ticks)==1&&state.pending&&state.tx_bytes==16&&state.tx[0]==0&&state.tx[1]==0);
    CHECK(phtc_u16(state.tx+8)==2&&phtc_u16(state.tx+10)==service&&phtc_u16(state.tx+12)==flags);
    CHECK(phtc_sent(&state,++ticks,1)==1);
}
static int connected(unsigned service,unsigned eid,unsigned maximum,unsigned status)
{
    uint8_t body[8]={3,0,0,0,0,0,0,0};phtc_put(body+2,service);body[4]=(uint8_t)status;body[5]=(uint8_t)eid;phtc_put(body+6,maximum);
    return control(body,sizeof(body));
}
static void active(void)
{
    setup();ready();request(0x300,8);CHECK(connected(0x300,1,256,0)==1&&state.htt==1);
    request(0x100,0x100);CHECK(connected(0x100,2,2048,0)==1&&state.wmi==2&&state.endpoint[2].credits==1);
    CHECK(phtc_next(&state,++ticks)==1&&state.tx_bytes==20&&phtc_u16(state.tx+8)==5);
    for(unsigned n=10;n<20;n++)CHECK(!state.tx[n]);CHECK(phtc_sent(&state,++ticks,1)==1);
    request(0x600,8);CHECK(connected(0x600,3,2048,0)==1&&state.pktlog==3&&state.phase==8);
    CHECK(!phtc_next(&state,++ticks));
}
int main(void)
{
    active();uint8_t payload[300];for(unsigned n=0;n<sizeof(payload);n++)payload[n]=(uint8_t)n;
    CHECK(phtc_data(&state,state.wmi,payload,200,++ticks)==1&&state.tx_bytes==208&&state.tx[0]==2&&state.tx[1]==1&&!memcmp(state.tx+8,payload,200));
    CHECK(phtc_sent(&state,++ticks,1)==1&&!state.endpoint[2].credits&&state.endpoint[2].sequence==1);
    CHECK(!phtc_data(&state,2,payload,200,++ticks)&&!state.pending);
    uint8_t credit[]={2,2,8,0,8,0,0,0,1,4,0,0,2,3,0,0};
    CHECK(!phtc_receive(&state,2,credit,sizeof(credit),++ticks)&&state.endpoint[2].credits==3);
    CHECK(phtc_data(&state,2,payload,300,++ticks)==1&&state.tx_credit==2&&state.tx[5]==1&&phtc_sent(&state,++ticks,1)==1&&state.endpoint[2].credits==1);
    CHECK(phtc_data(&state,1,payload,249,++ticks)==-1&&!state.pending);
    CHECK(phtc_data(&state,1,payload,200,++ticks)==1&&state.tx_credit==0&&state.tx[1]==0&&phtc_sent(&state,++ticks,1)==1);
    uint8_t frame[]={1,0,4,0,0,0,0,0,0x12,0x34,0x56,0x78};
    CHECK(phtc_receive(&state,1,frame,sizeof(frame),++ticks)==2&&state.frame_ready&&state.rx_eid==1&&state.rx_bytes==4&&!memcmp(state.rx,frame+8,4)&&phtc_ack(&state));
    CHECK(phtc_receive(&state,9,frame,sizeof(frame),++ticks)==2&&phtc_ack(&state));
    CHECK(phtc_receive(&state,10,frame,sizeof(frame),++ticks)==2&&phtc_ack(&state));
    for(unsigned fault=0;fault<6;fault++){
        setup();ready();request(0x300,8);
        if(!fault)CHECK(connected(0x100,1,256,0)==-1);
        if(fault==1)CHECK(connected(0x300,0,256,0)==-1);
        if(fault==2)CHECK(connected(0x300,1,0,0)==-1);
        if(fault==3)CHECK(connected(0x300,1,256,1)==-1);
        if(fault==4)CHECK(phtc_next(&state,state.deadline+1)==-1);
        if(fault==5){CHECK(connected(0x300,1,256,0)==1);request(0x100,0x100);CHECK(connected(0x100,1,2048,0)==-1);}
        CHECK(state.unknown&&state.error&&phtc_next(&state,++ticks)==-1);
    }
    active();credit[9]=5;CHECK(phtc_receive(&state,2,credit,sizeof(credit),++ticks)==-1&&state.unknown);
    active();credit[9]=4;state.endpoint[2].credits=65535;CHECK(phtc_receive(&state,2,credit,sizeof(credit),++ticks)==-1&&state.endpoint[2].credits==65535);
    active();CHECK(phtc_receive(&state,2,frame,sizeof(frame),++ticks)==-1&&state.unknown); /* wrong CE pipe */
    setup();CHECK(phtc_next(&state,state.deadline+1)==-1&&state.unknown);
    setup();ready();CHECK(phtc_next(&state,++ticks)==1&&phtc_sent(&state,++ticks,0)==-1&&state.unknown);
    setup();CHECK(phtc_receive(&state,2,frame,7,++ticks)==-1&&state.unknown);
    printf("PASS %u HTC checks: READY, HTT/WMI/pktlog, setup, credit flow, frames and rejection paths; SOFTWARE only\n",checks);return 0;
}
