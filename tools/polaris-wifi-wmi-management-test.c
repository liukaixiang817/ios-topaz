#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "polaris-wifi-wmi-management.h"
static struct pwmg_state state;
static struct phtm_layout layout;
static unsigned checks;
#define CHECK(x) do{assert(x);checks++;}while(0)
static void setup(void)
{
    memset(&state,0,sizeof(state));memset(&layout,0,sizeof(layout));
    CHECK(phtm_plan(&layout,0x130000000)&&pwmg_open(&state,&layout,7,100));
}
static void event(uint8_t*p,unsigned id)
{memset(p,0,40);pwmi_put(p,0x7006);pwmi_header(p+4,423,16);pwmi_put(p+8,id);}
int main(void)
{
    uint8_t frame[256]={0xb0},reply[40];setup();
    for(unsigned n=1;n<256;n++)frame[n]=(uint8_t)n;
    CHECK(pwmg_prepare(&state,frame,30,101)==1&&state.tx_bytes==72&&state.frame_bytes==30&&state.id==1);
    CHECK(pwmi_get(state.tx)==0x7008&&pwmi_get(state.tx+4)==0x01a6001c&&pwmi_get(state.tx+12)==1&&!pwmi_get(state.tx+16));
    CHECK((pwmi_get(state.tx+20)|((uint64_t)pwmi_get(state.tx+24)<<32))==state.buffer&&pwmi_get(state.tx+28)==30&&pwmi_get(state.tx+32)==32);
    CHECK(!memcmp(state.tx+40,frame,30)&&!state.tx[70]&&!state.tx[71]);
    CHECK(pwmg_sent(&state,102,1)==1&&!pwmg_ack(&state,103));event(reply,2);
    CHECK(!pwmg_event(&state,reply,24,104)&&state.phase==2);event(reply,1);
    CHECK(pwmg_event(&state,reply,24,105)==1&&state.phase==3&&!state.status&&pwmg_ack(&state,106));
    CHECK(!pwmg_event(&state,reply,24,107));frame[0]=0;
    CHECK(pwmg_prepare(&state,frame,75,108)==1&&state.id==2&&state.tx_bytes==104&&pwmi_get(state.tx+32)==64&&!memcmp(state.tx+40,frame,64));
    CHECK(pwmg_sent(&state,109,1)==1);memset(reply,0,40);pwmi_put(reply,0x7007);pwmi_header(reply+4,552,4);pwmi_put(reply+8,1);
    pwmi_header(reply+12,16,4);pwmi_put(reply+16,2);pwmi_header(reply+20,16,4);pwmi_put(reply+24,3);
    CHECK(pwmg_event(&state,reply,28,110)==1&&state.status==3&&state.completed==2&&pwmg_ack(&state,111));
    for(unsigned fault=0;fault<7;fault++){
        setup();CHECK(pwmg_prepare(&state,frame,75,101)==1);
        if(fault==0){CHECK(pwmg_sent(&state,102,0)==-1&&state.unknown);continue;}
        CHECK(pwmg_sent(&state,102,1)==1);event(reply,1);
        if(fault==1){CHECK(!pwmg_live(&state,state.deadline+1)&&state.unknown&&state.phase==2);continue;}
        if(fault==2){CHECK(pwmg_event(&state,reply,24,101)==-1&&state.unknown);continue;}
        unsigned bytes=24;if(fault==3)bytes=23;if(fault==4)pwmi_header(reply+4,423,12);
        if(fault==5)pwmi_header(reply+4,423,18);if(fault==6)pwmi_header(reply+4,99,16);
        CHECK(pwmg_event(&state,reply,bytes,103)==-1&&state.unknown&&state.phase==2);
    }
    printf("PASS %u WMI management publication/completion checks; SOFTWARE only\n",checks);return 0;
}
