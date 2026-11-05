#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "polaris-wifi-htt-init.h"
static unsigned checks;
static struct phtt_state state;
static struct phtm_layout memory;
static uint64_t tick;
#define CHECK(x) do{assert(x);checks++;}while(0)
static uint64_t get64(const uint8_t*p){return pwmi_get(p)|((uint64_t)pwmi_get(p+4)<<32);}
static void start(void)
{
    memset(&state,0,sizeof(state));memset(&memory,0,sizeof(memory));tick=100;
    CHECK(phtm_plan(&memory,UINT64_C(0x130000000))&&phtt_open(&state,&memory,7,tick));
}
int main(void)
{
    start();uint32_t offsets[]={memory.index,memory.ring,memory.fragments,memory.receive,memory.transmit,memory.management};
    uint32_t sizes[]={4096,8*PHTM_RX,PHTM_TX*72,PHTM_RX*2048,PHTM_TX*2048,4096};
    for(unsigned n=0;n<6;n++){
        CHECK(!(offsets[n]&4095)&&offsets[n]>=4096&&offsets[n]+sizes[n]<=PHTM_BYTES-4096);
        for(unsigned j=0;j<n;j++)CHECK(offsets[j]+sizes[j]<=offsets[n]);
    }
    CHECK(phtt_next(&state,++tick)==1&&state.tx_bytes==4&&!pwmi_get(state.tx)&&phtt_sent(&state,++tick,1)==1&&state.phase==1);
    CHECK(!phtt_next(&state,++tick));uint8_t version[]={0,4,3,0};CHECK(phtt_receive(&state,version,4,++tick)==1&&state.major==3&&state.minor==4);
    CHECK(phtt_next(&state,++tick)==1&&state.tx_bytes==64&&state.tx[0]==6&&state.tx[2]==1&&state.tx[3]==72&&get64(state.tx+4)==memory.allocation+memory.fragments);
    CHECK(state.tx[38]==0x1f&&state.tx[39]==4&&state.tx[60]==1&&!pwmi_get(state.tx+52)&&phtt_sent(&state,++tick,1)==1);
    CHECK(phtt_next(&state,++tick)==1&&state.tx_bytes==48&&state.tx[0]==2&&state.tx[1]==1&&get64(state.tx+4)==memory.allocation+memory.index&&get64(state.tx+12)==memory.allocation+memory.ring);
    CHECK(pwmi_get(state.tx+20)==0x08000800&&pwmi_get(state.tx+24)==0x07ffffff&&pwmi_get(state.tx+28)==0x005a004a&&pwmi_get(state.tx+44)==0x00020001);
    CHECK(phtt_sent(&state,++tick,1)==1&&phtt_next(&state,++tick)==1&&state.tx_bytes==4&&pwmi_get(state.tx)==0x00034005&&phtt_sent(&state,++tick,1)==1&&state.phase==5&&state.published==4);
    CHECK(!phtt_next(&state,++tick));uint8_t peer[]={3,0,1,0};CHECK(!phtt_receive(&state,peer,sizeof(peer),++tick));
    for(unsigned fault=0;fault<6;fault++){
        start();CHECK(phtt_next(&state,++tick)==1);
        if(fault==0){CHECK(phtt_sent(&state,++tick,0)==-1&&state.error);continue;}
        if(fault==1){CHECK(phtt_receive(&state,version,4,++tick)==-1&&state.error);continue;}
        CHECK(phtt_sent(&state,++tick,1)==1);
        if(fault==2){CHECK(phtt_next(&state,state.deadline+1)==-1&&state.error);continue;}
        uint8_t response[]={0,5,3,0};if(fault==3)response[2]=4;
        CHECK(phtt_receive(&state,response,fault==4?3:4,fault==5?tick-1:++tick)==-1&&state.error);
    }
    memset(&memory,0,sizeof(memory));CHECK(phtm_plan(&memory,(UINT64_C(1)<<35)-PHTM_BYTES));
    memset(&memory,0,sizeof(memory));CHECK(!phtm_plan(&memory,(UINT64_C(1)<<35)-PHTM_BYTES+4096));
    start();memset(&state,0,sizeof(state));memory.receive=memory.fragments;CHECK(!phtt_open(&state,&memory,7,++tick));
    printf("PASS %u HTT layout/setup checks; SOFTWARE only\n",checks);return 0;
}
