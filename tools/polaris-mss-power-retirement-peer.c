/* Independent software clock/stop/halt/reset producers for native-power
 * composition tests. No fabricated completed lifecycle and no hardware IO. */
#define main unused_clock_suite
#include "polaris-mss-clocks-test.c"
#undef main
uint64_t pmpn_test_stop(struct pmsd_shutdown*out,uint64_t epoch,uint64_t now,unsigned*count)
{
    unsigned before=checks;
    fixture();memset(&shutdown_state,0,sizeof(shutdown_state));struct pms_config cfg=config();cfg.epoch=epoch;
    now+=19200000;CHECK(pmsd_begin(&shutdown_state,&cfg,now++,19200000)==PMSD_WAIT);
    for(unsigned events=0;events<100;){
        struct pmsd_command c={0};int result=pmsd_next(&shutdown_state,now,&c);
        if(result==PMSD_RESET_PULSED)break;
        if(result==PMSD_WAIT){CHECK(shutdown_state.phase==2&&shutdown_state.reset.not_before>now);now=shutdown_state.reset.not_before;continue;}
        CHECK(result==PMSD_IO);events++;uint32_t value=0;const struct pms_sample*data=0;
        if(c.phase==1){
            if(c.command.stop.phase==1){
                unsigned step=c.command.stop.command.stop.step;
                if(step==PMS_INITIAL)data=&sample;
                if(step==PMS_SET_STOP)put(sample.out+96,0xa1);
                if(step==PMS_READBACK)value=0xa1;
                if(step==PMS_POLL){put(sample.in+96,8);data=&sample;}
            }else value=c.command.stop.command.halt.step==PMH_INITIAL_REQ?0:1;
        }else{
            CHECK(c.phase==2);unsigned step=c.command.reset.step;
            CHECK(step<14&&c.command.reset.address==expected_address[step]&&c.command.reset.kind==expected_kind[step]);
            value=step==0?0xa5000001:step==11?0x5a000280:0;
        }
        CHECK(pmsd_complete(&shutdown_state,&c,++now,1,value,data)==PMSD_WAIT);now++;
    }
    CHECK(shutdown_state.complete&&shutdown_state.stop.stop.ack_held&&shutdown_state.stop.halt.ports_held==7&&shutdown_state.reset.complete);
    *out=shutdown_state;*count+=checks-before;return now;
}
uint64_t pmpn_test_retire(struct pmck_lifecycle*out,uint64_t epoch,uint64_t now,unsigned*count)
{
    unsigned before=checks;(void)clock_fixture(0,0);memset(&clocks,0,sizeof(clocks));
    CHECK(pmck_begin(&clocks,epoch,now,19200000)==PMCK_WAIT);now=run_transition(now+1,-1,0);
    unsigned stop_checks=0;now=pmpn_test_stop(&shutdown_state,epoch,now,&stop_checks);
    CHECK(pmck_release(&clocks,&shutdown_state,now)==PMCK_WAIT);now=run_transition(now+1,-1,0);
    CHECK(clocks.phase==4&&clocks.restored==63&&!clocks.unknown&&pmsr_equal(regs,initial,sizeof(regs)));
    *out=clocks;*count+=checks-before;return now;
}
