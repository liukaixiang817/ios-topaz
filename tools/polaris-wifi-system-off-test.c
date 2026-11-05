/* Pure policy evidence only; no PSCI, kernel, cache or physical power action. */
#include "polaris-wifi-system-off.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static unsigned checks;
#define CHECK(x) do{checks++;assert(x);}while(0)
static struct pwof_state state;
static struct polaris_shutdown_status kernel;
static struct pwof_command command;
static uint64_t tick;
static void step(int64_t value)
{
    CHECK(pwof_next(&state,++tick,&command)==1);
    CHECK(pwof_complete(&state,&command,++tick,1,value,&kernel)==1);
}
static void initial(void)
{
    memset(&state,0,sizeof(state));memset(&kernel,0,sizeof(kernel));tick=100;
    CHECK(pwof_begin(&state,tick,19200000));CHECK(!pwof_begin(&state,tick,19200000));
    step(0x10000);step(0);kernel.cookie=77;kernel.phase=POLARIS_Q_RUNNING;kernel.capabilities=POLARIS_Q_RAM_CONFIG;
    step(0);CHECK(state.request.cookie==77&&state.request.sequence==1&&state.request.mode==2&&pwmb_zero(state.request.reserved,112));step(0);
}
static void drained(void)
{kernel.sequence=1;kernel.mode=2;kernel.phase=POLARIS_Q_SEALED;kernel.capabilities=POLARIS_Q_RAM_DRAINED;step(0);}
int main(void)
{
    initial();step(0);CHECK(pwof_next(&state,++tick,&command)==0);tick=state.next_poll;
    kernel.phase=POLARIS_Q_REQUESTED;kernel.sequence=1;kernel.mode=2;step(0);tick=state.next_poll;drained();
    for(unsigned n=0;n<7;n++)step(n==6?0:1);
    CHECK(pwof_next(&state,++tick,&command)==1&&command.kind==PWOF_POWER_OFF&&command.function==0x84000008&&!command.argument);
    CHECK(pwof_complete(&state,&command,++tick,1,0,&kernel)==-1&&state.error==9);
    for(unsigned bit=0;bit<128*8;bit++){
        initial();drained();((uint8_t*)&kernel)[bit/8]^=1u<<(bit%8);
        CHECK(pwof_next(&state,++tick,&command)==1);CHECK(pwof_complete(&state,&command,++tick,1,1,&kernel)==-1);
    }
    for(unsigned target=0;target<7;target++)for(int value=-1;value<=2;value++){
        if(value==(target==6?0:1))continue;initial();drained();for(unsigned n=0;n<target;n++)step(1);
        CHECK(pwof_next(&state,++tick,&command)==1);CHECK(pwof_complete(&state,&command,++tick,1,value,&kernel)==-1);
    }
    initial();CHECK(pwof_next(&state,state.opening+PWOF_LIMIT+1,&command)==-1&&state.error==1);
    initial();CHECK(pwof_next(&state,tick-1,&command)==-1&&state.error==1);
    initial();CHECK(pwof_next(&state,++tick,&command)==1);command.function=0x84000009;
    CHECK(pwof_complete(&state,&command,++tick,1,0,&kernel)==-1&&state.error==3);
    for(unsigned field=0;field<6;field++){
        initial();drained();memset(&state,0,sizeof(state));CHECK(pwof_begin(&state,1,19200000));tick=1;
        if(field<2){CHECK(pwof_next(&state,++tick,&command)==1);CHECK(pwof_complete(&state,&command,++tick,1,field?0x20000:0x00002,NULL)==-1);}
        else{step(0x10000);CHECK(pwof_next(&state,++tick,&command)==1);CHECK(pwof_complete(&state,&command,++tick,1,field==2?-1:1,NULL)==-1);}
    }
    printf("PASS %u terminal-system-off policy checks; no native or power-off claim\n",checks);return 0;
}
