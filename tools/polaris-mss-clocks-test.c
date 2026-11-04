/* Integer register peers; no hardware addresses are dereferenced. */
#pragma push_macro("main")
#undef main
#define main legacy_shutdown_test
#include "polaris-mss-shutdown-test.c"
#pragma pop_macro("main")
#include "polaris-mss-clocks.h"
static struct pmck_lifecycle clocks;
static uint32_t regs[7],initial[7],writes[2],reads,barriers;
static const uint64_t addresses[7]={0x18a000,0x18a154,0x152004,0x138004,0x18a150,0x18a004,0};
static const uint64_t enables[6]={0x18a000,0x18a154,0x152004,0x152004,0x18a150,0x18a004};
static const uint32_t masks[6]={1,1,0x400,0x20000,1,1};
static uint64_t clock_fixture(unsigned enabled,unsigned hwcg)
{
    memset(&clocks,0,sizeof(clocks));memset(regs,0,sizeof(regs));memset(writes,0,sizeof(writes));reads=barriers=0;
    regs[0]=(hwcg&1)?2:0;regs[3]=(hwcg&2)?2:0;regs[5]=(hwcg&4)?2:0;
    regs[2]=0x10002000; /* unrelated vote bits must survive every RMW */
    for(unsigned n=0;n<6;n++)for(unsigned r=0;r<6;r++)if(addresses[r]==enables[n]&&(enabled&(1u<<n)))regs[r]|=masks[n];
    memcpy(initial,regs,sizeof(regs));CHECK(pmck_begin(&clocks,1,100,19200000)==PMCK_WAIT);return 101;
}
static uint32_t register_read(uint64_t address,int stuck)
{
    unsigned i;for(i=0;i<6&&addresses[i]!=address;i++){}CHECK(i<6);reads++;
    uint32_t value=regs[i];if(i==2)return value;
    unsigned on=i==3?!!(regs[2]&0x400):!!(value&1);
    if(stuck)on=!on;
    /* HWCG may legitimately show CLK_OFF even with software enable. */
    if(value&2)on=0;
    return (value&0x0fffffff)|(on?0:0x80000000);
}
static uint32_t clock_peer(const struct pmck_command*c,int stuck)
{
    CHECK(c->clock<6&&c->phase==clocks.phase&&c->step==clocks.step);
    if(c->kind==PMCK_READ)return register_read(c->address,stuck);
    if(c->kind==PMCK_ORDER){CHECK(!c->address&&!c->value);barriers++;return 0;}
    CHECK(c->kind==PMCK_WRITE&&c->address==enables[c->clock]);
    unsigned i;for(i=0;i<6&&addresses[i]!=c->address;i++){}CHECK(i<6);
    uint32_t stable=i==2?UINT32_MAX:0x0fffffff;
    CHECK(((c->value^regs[i])&stable)==masks[c->clock]);
    CHECK((c->value&masks[c->clock])==(c->phase==1?masks[c->clock]:0));
    regs[i]=c->value&stable;writes[c->phase==3]|=1u<<c->clock;return 0;
}
static uint64_t run_transition(uint64_t now,int fail_event,unsigned fault)
{
    unsigned event=0;
    for(;;){
        struct pmck_command c={0};int result=pmck_next(&clocks,now,&c);
        if(result==PMCK_WAIT){
            CHECK(now<clocks.not_before);unsigned events=clocks.events;
            CHECK(pmck_next(&clocks,clocks.not_before-1,&c)==PMCK_WAIT&&events==clocks.events);
            now=clocks.not_before;continue;
        }
        if(result==PMCK_HELD||result==PMCK_RESTORED)return now;
        CHECK(result==PMCK_IO);now++;
        if((int)event==fail_event){
            if(fault==1)CHECK(pmck_complete(&clocks,&c,now,-3,0)==PMCK_FAILED);
            else if(fault==2){c.address^=4;CHECK(pmck_complete(&clocks,&c,now,1,0)==PMCK_FAILED);}
            else if(fault==3)CHECK(pmck_next(&clocks,now,&c)==PMCK_FAILED);
            else if(fault==4)CHECK(pmck_complete(&clocks,&c,now-2,1,0)==PMCK_FAILED);
            else if(fault==5)CHECK(pmck_complete(&clocks,&c,clocks.transition_opening+PMCK_LIMIT+1,1,0)==PMCK_FAILED);
            CHECK(clocks.unknown&&pmck_next(&clocks,now,&c)==PMCK_FAILED);return now;
        }
        uint32_t value=clock_peer(&c,0);
        result=pmck_complete(&clocks,&c,now++,1,value);CHECK(result>=0);
        event++;CHECK(event<100);
    }
}
static uint64_t stopped(uint64_t now)
{
    shutdown_start=now+100;reset_to(13,0);return shutdown_state.reset.last+100;
}
static void all_saved_combinations(void)
{
    for(unsigned enabled=0;enabled<64;enabled++)for(unsigned hwcg=0;hwcg<8;hwcg++){
        uint64_t now=clock_fixture(enabled,hwcg);now=run_transition(now,-1,0);
        CHECK(clocks.phase==2&&clocks.held==0x3f&&!clocks.unknown);
        CHECK(writes[0]==(enabled^63)&&clocks.changed==(enabled^63));
        unsigned events=clocks.events;struct pmck_command c={0};
        CHECK(pmck_next(&clocks,now+19200000,&c)==PMCK_HELD&&clocks.events==events);
        now=stopped(now+19200000);
        CHECK(pmck_release(&clocks,&shutdown_state,now)==PMCK_WAIT);
        run_transition(now,-1,0);
        CHECK(clocks.phase==4&&clocks.restored==63&&!clocks.unknown);
        CHECK(writes[1]==writes[0]&&pmsr_equal(regs,initial,sizeof(regs)));
    }
}
static void all_access_failures(void)
{
    unsigned count[2];uint64_t now=clock_fixture(0,0);now=run_transition(now,-1,0);count[0]=clocks.events;
    now=stopped(now);CHECK(pmck_release(&clocks,&shutdown_state,now)==PMCK_WAIT);run_transition(now,-1,0);
    count[1]=clocks.events-count[0];
    for(unsigned phase=0;phase<2;phase++)for(unsigned event=0;event<count[phase];event++)for(unsigned fault=1;fault<=5;fault++){
        now=clock_fixture(0,0);
        if(phase){now=run_transition(now,-1,0);now=stopped(now);CHECK(pmck_release(&clocks,&shutdown_state,now)==PMCK_WAIT);}
        run_transition(now,(int)event,fault);CHECK(clocks.unknown&&clocks.phase!=4);
    }
}
static void release_refusals(void)
{
    for(unsigned fault=0;fault<15;fault++){
        uint64_t now=clock_fixture(0,0);now=run_transition(now,-1,0);now=stopped(now);
        switch(fault){
        case 0:shutdown_state.complete=0;break;case 1:shutdown_state.unknown=1;break;
        case 2:shutdown_state.pending=1;break;case 3:shutdown_state.stop.stop.config.epoch=2;break;
        case 4:shutdown_state.stop.stop.ack_held=0;break;case 5:shutdown_state.stop.stop.opening=clocks.held_at-1;break;
        case 6:shutdown_state.stop.halt.ports_held=3;break;case 7:shutdown_state.stop.halt.pending=1;break;
        case 8:shutdown_state.reset.complete=0;break;case 9:shutdown_state.reset.unknown=1;break;
        case 10:shutdown_state.reset.write_returned=31;break;case 11:shutdown_state.reset.last=shutdown_state.reset.not_before-1;break;
        case 12:shutdown_state.reset.opening=shutdown_state.stop.halt.last-1;break;
        case 13:now=shutdown_state.reset.last-1;break;case 14:now=UINT64_MAX;break;
        }
        unsigned before=clocks.events;CHECK(pmck_release(&clocks,&shutdown_state,now)==PMCK_FAILED);
        struct pmck_command c;CHECK(pmck_next(&clocks,now,&c)==PMCK_FAILED&&clocks.events==before);
    }
}
static void status_and_readback(void)
{
    for(unsigned failure=0;failure<4;failure++){
        uint64_t now=clock_fixture(0,0);unsigned loops=0;
        while(!clocks.unknown){
            struct pmck_command c;int next=pmck_next(&clocks,now,&c);
            if(next==PMCK_FAILED)break;
            if(next==PMCK_WAIT){now=clocks.not_before;continue;}
            CHECK(next==PMCK_IO);now++;
            uint32_t value=clock_peer(&c,failure==0&&c.step==PMCK_STATUS);
            if(failure==1&&c.step==PMCK_READBACK)value^=1;
            if(failure==2&&c.step==PMCK_STATUS)value^=4;
            if(failure==3&&c.step==PMCK_READBACK)value^=4;
            int result=pmck_complete(&clocks,&c,now++,1,value);
            if(result<0)break;CHECK(++loops<600);
        }
        CHECK(clocks.unknown&&clocks.phase==1);
        if(!failure)CHECK(clocks.polls==500&&clocks.error==PMCK_STATUS_ERROR);
    }
    uint64_t now=clock_fixture(0,0);now=run_transition(now,-1,0);now=stopped(now);
    CHECK(pmck_release(&clocks,&shutdown_state,now)==PMCK_WAIT);regs[5]^=4;
    struct pmck_command c;CHECK(pmck_next(&clocks,now,&c)==PMCK_IO);
    CHECK(pmck_complete(&clocks,&c,now+1,1,clock_peer(&c,0))==PMCK_FAILED);
    CHECK(!writes[1]);
}
int main(void)
{
    legacy_shutdown_test();unsigned before=checks;
    all_saved_combinations();all_access_failures();release_refusals();status_and_readback();
    printf("PASS %u new clock lifecycle checks, %u total (software only)\n",checks-before,checks);return 0;
}
