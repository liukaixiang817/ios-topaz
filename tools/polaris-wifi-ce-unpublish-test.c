#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "polaris-wifi-ce-unpublish.h"
static unsigned checks;
#define CHECK(x) do{assert(x);checks++;}while(0)
static struct pwce_init initial;
static struct pwcx_state state;
static uint32_t registers[12][21],wrapper[2],before[12][21];
static uint64_t ticks;
static uint32_t*reg(uint64_t address)
{
    CHECK(pwce_register(address,0));
    if(address>=PWCE_WRAPPER)return &wrapper[(address-PWCE_WRAPPER-4)/4];
    return &registers[(address-PWCE_BASE)/4096][(address&4095)/4];
}
static void setup(void)
{
    memset(&initial,0,sizeof(initial));memset(&state,0,sizeof(state));ticks=100;
    struct pwdm_layout layout={0};CHECK(pwdm_plan(&layout,UINT64_C(0xb0800000)));
    for(unsigned pipe=0;pipe<12;pipe++){
        const struct pwdm_pipe*p=&layout.pipe[pipe];
        for(unsigned n=0;n<21;n++)registers[pipe][n]=0x55000000|pipe<<16|n;
        registers[pipe][0x18/4]=0x100000;registers[pipe][0x2c/4]=0x1001f;registers[pipe][0x34/4]=0x103e0;registers[pipe][0x38/4]=0;
        if(p->sources){registers[pipe][0]=registers[pipe][1]=registers[pipe][2]=0;registers[pipe][0x44/4]=registers[pipe][0x3c/4]=0;}
        if(p->destinations){registers[pipe][3]=registers[pipe][4]=registers[pipe][5]=0;registers[pipe][0x48/4]=registers[pipe][0x40/4]=0;}
    }
    CHECK(pwce_begin(&initial,&layout,17,++ticks)==1);struct pwce_command c;
    while(!initial.complete){CHECK(pwce_next(&initial,++ticks,&c)==1);uint32_t value=0;
        if(c.operation==PWCE_WRITE)*reg(c.address)=c.value;
        if(c.operation==PWCE_READ)value=*reg(c.address);
        CHECK(pwce_complete(&initial,&c,++ticks,1,value)>0);
    }
    memcpy(before,registers,sizeof(before));CHECK(pwcx_begin(&state,&initial,++ticks));
}
static unsigned run(unsigned fail,unsigned mode)
{
    unsigned actions=0,writes=0;struct pwce_command c;
    while(!state.complete){
        CHECK(pwcx_next(&state,++ticks,&c)==1);actions++;uint32_t value=0;
        if(c.operation==PWCE_WRITE){CHECK(state.stage>=2);*reg(c.address)=c.value;writes++;}
        else if(c.operation==PWCE_READ)value=*reg(c.address);
        int returned=1;
        if(actions==fail){if(mode==1)returned=0;else if(mode==2&&c.operation==PWCE_READ)value^=1;else if(mode==3)ticks=state.opening+19200001;else if(mode==4)c.sequence++;}
        int result=pwcx_complete(&state,&c,++ticks,returned,value);
        if(result<0){CHECK(state.unknown&&state.error&&!state.complete);CHECK(pwcx_next(&state,++ticks,&c)==-1);return actions;}
    }
    CHECK(!state.unknown&&!state.error&&writes&&pwcx_next(&state,++ticks,&c)==2);
    CHECK(!wrapper[0]&&!wrapper[1]);
    for(unsigned pipe=0;pipe<12;pipe++){
        const struct pwdm_pipe*p=&initial.layout.pipe[pipe];
        CHECK(!(registers[pipe][0x18/4]&0x80000));
        for(unsigned n=0;n<21;n++){
            unsigned offset=n*4,owned=offset==0x18||offset==0x2c||offset==0x34||
                (p->sources&&(offset==0||offset==4||offset==8||offset==0x4c))||
                (p->destinations&&(offset==0xc||offset==0x10||offset==0x14||offset==0x50));
            if(!owned)CHECK(registers[pipe][n]==before[pipe][n]);
            else if(offset!=0x18&&offset!=0x2c&&offset!=0x34)CHECK(!registers[pipe][n]);
        }
    }return actions;
}
int main(void)
{
    setup();unsigned total=run(0,0);CHECK(total<PWCE_EVENTS);
    for(unsigned mode=1;mode<=4;mode++)for(unsigned fail=1;fail<=total;fail++){
        setup();unsigned actions=run(fail,mode);CHECK(actions==fail||mode==2);
    }
    /* Changed ownership is found in the observation pass before any stores. */
    setup();wrapper[0]^=4096;CHECK(run(0,0)==1&&state.unknown);
    setup();registers[3][0]^=4096;unsigned n=run(0,0);CHECK(n<total&&state.stage==1&&state.unknown);
    printf("PASS %u CE unpublication checks, %u actions; SOFTWARE registers, not DMA retirement\n",checks,total);return 0;
}
