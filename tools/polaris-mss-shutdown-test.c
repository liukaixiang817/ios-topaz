/* Software peers only. Hardware addresses remain integers. */
#pragma push_macro("main")
#undef main
#define main legacy_stop_test
#include "polaris-mss-stop-test.c"
#pragma pop_macro("main")
#include "polaris-mss-shutdown.h"
static struct pmsd_shutdown shutdown_state;
static uint64_t shutdown_start=100;
static const uint64_t expected_address[14]={
    0xb2e0100,0xb2e0100,0,0x4180044,0,0xc2b0000,0,
    0xc2b0000,0,0x4180044,0,0xb2e0100,0xb2e0100,0};
static const uint32_t expected_kind[14]={1,2,3,2,3,2,4,2,4,2,3,1,2,3};
static const uint32_t expected_value[14]={0,0xa5000201,0,1,0,1,0,0,0,0,0,0,0x5a000080,0};
static const uint64_t expected_delay[14]={0,0,39,0,39,0,3879,0,3879,0,39,0,0,39};
static uint64_t shutdown_begin(void)
{
    fixture();memset(&shutdown_state,0,sizeof(shutdown_state));struct pms_config c=config();
    CHECK(pmsd_begin(&shutdown_state,&c,shutdown_start,19200000)==PMSD_WAIT);return shutdown_start+1;
}
static struct pmsd_command shutdown_next(uint64_t now)
{
    struct pmsd_command c={0};CHECK(pmsd_next(&shutdown_state,now,&c)==PMSD_IO);return c;
}
/* Complete the actual nested protocol. Each failed operation must stop before
 * any later MMIO command; fresh ACK and final AXI readback are indispensable. */
static uint64_t shutdown_prefix(int fail_event)
{
    uint64_t now=shutdown_begin();unsigned event=0;
    while(shutdown_state.phase==1){
        struct pmsd_command c=shutdown_next(now++);CHECK(c.phase==1);
        const struct pms_sample*data=NULL;uint32_t value=0;
        if(c.command.stop.phase==1){
            unsigned step=c.command.stop.command.stop.step;
            if(step==PMS_INITIAL)data=&sample;
            if(step==PMS_SET_STOP)put(sample.out+96,0xa1);
            if(step==PMS_READBACK)value=0xa1;
            if(step==PMS_POLL){put(sample.in+96,8);data=&sample;}
        }else{
            CHECK(c.command.stop.phase==2&&shutdown_state.stop.stop.ack_held);
            value=c.command.stop.command.halt.step==PMH_INITIAL_REQ?0:1;
        }
        int failed=(int)event==fail_event;
        CHECK(pmsd_complete(&shutdown_state,&c,now++,failed?0:1,value,data)==(failed?PMSD_FAILED:PMSD_WAIT));
        if(failed){
            CHECK(shutdown_state.unknown&&!shutdown_state.complete&&!shutdown_state.reset.started);
            CHECK(pmsd_next(&shutdown_state,now,&c)==PMSD_FAILED);return now;
        }
        event++;
        if(shutdown_state.phase==1)CHECK(!shutdown_state.reset.started);
        CHECK(event<=26);
    }
    CHECK(event==26&&shutdown_state.phase==2&&shutdown_state.reset.started);
    CHECK(shutdown_state.stop.complete&&shutdown_state.stop.halt.ports_held==7&&shutdown_state.stop.stop.ack_held);
    return now;
}
static void reset_to(unsigned stop_at,unsigned fault)
{
    uint64_t now=shutdown_prefix(-1);
    for(unsigned step=0;step<=stop_at;step++){
        struct pmsd_command c=shutdown_next(now++);
        CHECK(c.phase==2&&c.command.reset.step==step&&c.command.reset.sequence==step+1);
        CHECK(c.command.reset.address==expected_address[step]&&c.command.reset.kind==expected_kind[step]);
        CHECK(c.command.reset.value==expected_value[step]);
        uint32_t value=step==0?0xa5000001:step==11?0x5a000280:0;
        if(step==stop_at&&fault){
            if(fault==1){
                CHECK(pmsd_complete(&shutdown_state,&c,now,-7,value,NULL)==PMSD_FAILED);
                CHECK(shutdown_state.reset.event[step].return_raw==-7);
            }else if(fault==2){c.command.reset.address^=4;CHECK(pmsd_complete(&shutdown_state,&c,now,1,value,NULL)==PMSD_FAILED);}
            else if(fault==3){CHECK(pmsd_next(&shutdown_state,now,&c)==PMSD_FAILED);}
            else if(fault==4){CHECK(pmsd_complete(&shutdown_state,&c,now-2,1,value,NULL)==PMSD_FAILED);}
            else if(fault==5){CHECK(pmsd_complete(&shutdown_state,&c,shutdown_state.reset.opening+PMSR_LIMIT+1,1,value,NULL)==PMSD_FAILED);}
            else if(fault==6){CHECK(pmsd_complete(&shutdown_state,&c,now,1,value^0x200,NULL)==PMSD_FAILED);}
            else if(fault==7){CHECK(pmsd_complete(&shutdown_state,&c,now,1,value,&sample)==PMSD_FAILED);}
            CHECK(shutdown_state.unknown&&!shutdown_state.complete);
            unsigned events=shutdown_state.reset.events;CHECK(pmsd_next(&shutdown_state,now,&c)==PMSD_FAILED);
            CHECK(shutdown_state.reset.events==events);return;
        }
        CHECK(pmsd_complete(&shutdown_state,&c,now,1,value,NULL)==PMSD_WAIT);
        CHECK(!shutdown_state.complete);
        CHECK(shutdown_state.reset.not_before==now+expected_delay[step]);
        if(expected_delay[step]){
            unsigned events=shutdown_state.reset.events;struct pmsd_command sentinel;
            memset(&sentinel,0xa5,sizeof(sentinel));c=sentinel;
            CHECK(pmsd_next(&shutdown_state,now+expected_delay[step]-1,&c)==PMSD_WAIT);
            CHECK(pmsr_equal(&c,&sentinel,sizeof(c))&&events==shutdown_state.reset.events);
        }
        now+=expected_delay[step]+1;
    }
    if(stop_at==13){
        struct pmsd_command c={0};CHECK(pmsd_next(&shutdown_state,now,&c)==PMSD_RESET_PULSED);
        CHECK(shutdown_state.complete&&shutdown_state.reset.complete&&!shutdown_state.unknown);
        CHECK(shutdown_state.reset.write_intent==0x3f&&shutdown_state.reset.write_returned==0x3f);
        CHECK(shutdown_state.stop.stop.ack_held&&shutdown_state.stop.halt.ports_held==7);
        CHECK(pmsd_next(&shutdown_state,now,&c)==PMSD_RESET_PULSED);
    }
}
static void direct_boundaries(void)
{
    struct pmsr_reset r={0};struct pmsr_command c={0};
    CHECK(pmsr_begin(NULL,1,19200000)==PMSR_FAILED);
    CHECK(pmsr_begin(&r,0,19200000)==PMSR_FAILED);
    CHECK(pmsr_begin(&r,1,19200001)==PMSR_FAILED);
    CHECK(pmsr_begin(&r,UINT64_MAX,19200000)==PMSR_FAILED);
    CHECK(pmsr_begin(&r,1,19200000)==PMSR_WAIT);
    CHECK(pmsr_begin(&r,1,19200000)==PMSR_FAILED);
    CHECK(pmsr_next(&r,1,(void*)&r)==PMSR_FAILED&&r.unknown);
    memset(&r,0,sizeof(r));CHECK(pmsr_begin(&r,1,19200000)==PMSR_WAIT);
    CHECK(pmsr_next(&r,2,&c)==PMSR_IO);
    CHECK(pmsr_complete(&r,&r.event[0].command,3,1,0)==PMSR_FAILED);
    memset(&r,0,sizeof(r));CHECK(pmsr_begin(&r,1,19200000)==PMSR_WAIT);
    CHECK(pmsr_next(&r,PMSR_LIMIT+2,&c)==PMSR_FAILED);
    shutdown_begin();CHECK(pmsd_next(&shutdown_state,102,(void*)&shutdown_state)==PMSD_FAILED);
}
int main(void)
{
    legacy_stop_test();unsigned before=checks;
    reset_to(13,0);
    for(int event=0;event<26;event++)shutdown_prefix(event);
    for(unsigned step=0;step<14;step++)for(unsigned fault=1;fault<=5;fault++)reset_to(step,fault);
    reset_to(0,6);reset_to(11,6);reset_to(5,7);direct_boundaries();
    printf("PASS %u new shutdown/reset checks, %u total (software only)\n",checks-before,checks);return 0;
}
