#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "polaris-wifi-ce-init.h"
static unsigned checks,reads,writes,scenarios;
#define CHECK(x) do{assert(x);checks++;}while(0)
static struct pwce_init state;
static uint32_t regs[13][1024];
static void setup(void)
{
    memset(&state,0,sizeof(state));memset(regs,0,sizeof(regs));reads=writes=0;scenarios++;
    struct pwdm_layout layout={0};CHECK(pwdm_plan(&layout,UINT64_C(0x701000000)));
    for(unsigned n=0;n<12;n++){
        regs[n][0x18/4]=0x40e0000;regs[n][0x2c/4]=0x8000001f;regs[n][0x34/4]=0x800003e0;
        if(layout.pipe[n].sources)regs[n][0x44/4]=regs[n][0x3c/4]=3;
        if(layout.pipe[n].destinations)regs[n][0x48/4]=regs[n][0x40/4]=3;
        /* Firmware-owned side is intentionally nonzero and must survive. */
        if(!layout.pipe[n].sources){regs[n][0]=0xdead1000;regs[n][1]=5;regs[n][2]=32;}
        if(!layout.pipe[n].destinations){regs[n][3]=0xdead2000;regs[n][4]=5;regs[n][5]=64;}
    }
    CHECK(pwce_begin(&state,&layout,17,1000)==1);
}
static int run(unsigned fault_kind)
{
    for(unsigned n=0;n<PWCE_EVENTS;n++){
        struct pwce_command c;int next=pwce_next(&state,1001+n,&c);if(next!=1)return next;
        if(c.operation==PWCE_ORDER){CHECK(!c.address&&!c.value);int done=pwce_complete(&state,&c,1001+n,1,0);if(done!=1)return done;continue;}
        CHECK(c.address>=PWCE_BASE&&c.address<PWCE_WRAPPER+4096&&!(c.address&3));
        unsigned pipe=(unsigned)((c.address-PWCE_BASE)/4096),index=(unsigned)((c.address&4095)/4);
        uint32_t value=regs[pipe][index];
        if(c.operation==PWCE_WRITE){CHECK(state.stage&&state.current<12);regs[pipe][index]=c.value;writes++;}
        else reads++;
        if(fault_kind==1&&c.stage==0&&c.pipe==0&&c.index==4)value=0x1000;
        if(fault_kind==2&&c.stage==0&&c.pipe==0&&c.index==8)value=4;
        if(fault_kind==3&&c.stage==0&&c.pipe==11&&c.index==3)value=0x100;
        if(fault_kind==4&&writes&&c.operation==PWCE_READ)value^=1;
        if(fault_kind==5&&writes)c.sequence++;
        int result=pwce_complete(&state,&c,1001+n,fault_kind==6&&writes?0:1,value);
        if(result!=1)return result;
    }return -2;
}
int main(void)
{
    setup();CHECK(run(0)==2&&state.complete&&!state.unknown);
    CHECK(regs[12][1]==(uint32_t)(state.layout.allocation+state.layout.rri)&&regs[12][2]==7);
    for(unsigned n=0;n<12;n++){
        const struct pwdm_pipe*p=&state.layout.pipe[n];
        CHECK(regs[n][0x2c/4]==0x80000000&&regs[n][0x34/4]==0x80000000);
        CHECK((regs[n][6]&0x80000)&&((regs[n][6]^0x40e0000)&~0xeffffu)==0);
        if(p->sources){CHECK(regs[n][0]==(uint32_t)(state.layout.allocation+p->source)&&regs[n][1]==7&&regs[n][2]==p->sources);CHECK((regs[n][6]&0x2ffffu)==p->buffer_bytes&&regs[n][0x4c/4]==p->sources);}
        else CHECK(regs[n][0]==0xdead1000&&regs[n][1]==5&&regs[n][2]==32);
        if(p->destinations){CHECK(regs[n][3]==(uint32_t)(state.layout.allocation+p->destination)&&regs[n][4]==7&&regs[n][5]==p->destinations);CHECK(!(regs[n][6]&0x40000)&&regs[n][0x50/4]==p->destinations);}
        else CHECK(regs[n][3]==0xdead2000&&regs[n][4]==5&&regs[n][5]==64);
    }
    for(unsigned kind=1;kind<=6;kind++){
        setup();CHECK(run(kind)==-1&&state.unknown&&!state.complete);if(kind<=3)CHECK(!writes);
        struct pwce_command c;CHECK(pwce_next(&state,2000,&c)==-1);
    }
    setup();struct pwce_command c;CHECK(pwce_next(&state,19201001,&c)==-1&&state.unknown&&!writes);
    setup();state.index=100;CHECK(pwce_next(&state,1001,&c)==-1&&state.unknown);
    printf("PASS %u CE init checks, %u scenarios; SOFTWARE registers, no native DMA\n",checks,scenarios);return 0;
}
