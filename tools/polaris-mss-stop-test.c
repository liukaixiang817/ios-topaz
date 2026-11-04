/* Software only. Addresses below are protocol integers, never dereferenced. */
#include "polaris-mss-stop.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static struct pmss_stop state;
static struct pms_sample sample;
static unsigned checks;
#define CHECK(x) do{assert(x);checks++;}while(0)
static void put(uint8_t*p,uint32_t v)
{for(unsigned k=0;k<4;k++)p[k]=(uint8_t)(v>>(8*k));}
static struct pms_config config(void)
{return (struct pms_config){.epoch=1,.out_id=428,.in_id=435,.out_offset=0x4000,.in_offset=0x5000,.out_bytes=344,.in_bytes=344};}
static void fixture(void)
{
    memset(&state,0,sizeof(state));memset(&sample,0,sizeof(sample));
    sample.out_bytes=sample.in_bytes=PMS_ITEM_BYTES;
    for(unsigned in=0;in<2;in++){
        uint8_t*p=in?sample.in:sample.out;
        put(p,0x504d5324);put(p+4,0x101);put(p+8,in?1:0x10000);put(p+12,0x20010);
        memcpy(p+20,"another-entry",14);put(p+36,0x12340000);
        /* Deliberately non-prefix occupancy: header valid is a COUNT, not the
         * last populated index. The own driver scans all total entries. */
        memcpy(p+20+3*20,in?"slave-kernel":"master-kernel",in?13:14);
        put(p+36+3*20,in?2:0xa0);
    }
}
static void begin(void)
{fixture();struct pms_config c=config();CHECK(pmss_begin(&state,&c,100,19200000)==PMSS_WAIT);}
static struct pmss_command next(uint64_t now,unsigned phase,unsigned step)
{
    struct pmss_command command={0};CHECK(pmss_next(&state,now,&command)==PMSS_IO);
    CHECK(command.phase==phase);
    CHECK((phase==1?command.command.stop.step:command.command.halt.step)==step);return command;
}
static void stop_prefix(void)
{
    for(unsigned step=PMS_INITIAL;step<=PMS_RING_ORDER;step++){
        struct pmss_command command=next(100+step*2,1,step);uint32_t value=0;
        const struct pms_sample*data=step==PMS_INITIAL?&sample:NULL;
        if(step==PMS_INITIAL){CHECK(command.command.stop.address==0x86004000&&command.command.stop.second==0x86005000&&command.command.stop.bytes==340);}
        if(step==PMS_SET_STOP){
            CHECK(command.command.stop.address==0x86004060&&command.command.stop.value==0xa1);
            put(sample.out+96,0xa1);
        }
        if(step==PMS_READBACK){CHECK(command.command.stop.address==0x86004060);value=0xa1;}
        if(step==PMS_RING_SET||step==PMS_RING_CLEAR){
            CHECK(command.command.stop.address==0x1799000c);
            CHECK(command.command.stop.value==(step==PMS_RING_SET?0x4000:0));
        }
        if(step==PMS_PUBLISH||step==PMS_RING_ORDER)CHECK(!command.command.stop.address&&!command.command.stop.bytes);
        CHECK(pmss_complete(&state,&command,101+step*2,1,value,data)==PMSS_WAIT);
        CHECK(!state.halt.started);
    }
}
static void success(void)
{
    begin();stop_prefix();uint64_t now=120;
    struct pmss_command command=next(now++,1,PMS_POLL);
    CHECK(pmss_complete(&state,&command,now++,1,0,&sample)==PMSS_WAIT);
    unsigned events=state.stop.events;
    CHECK(pmss_next(&state,now,&command)==PMSS_WAIT&&state.stop.events==events);
    now=state.stop.next_poll;command=next(now++,1,PMS_POLL);
    put(sample.in+96,8); /* READY may fall during an acknowledged stop. */
    CHECK(pmss_complete(&state,&command,now++,1,0,&sample)==PMSS_WAIT);
    CHECK(state.phase==2&&state.halt.started&&state.stop.ack_held&&state.stop.ring_returned==3);
    const uint64_t ports[]={0x1f63000,0x1f65000,0x1f64000};
    for(unsigned port=0;port<3;port++)for(unsigned step=PMH_INITIAL_REQ;step<=PMH_FINAL_REQ;step++){
        command=next(now++,2,step);
        CHECK(command.command.halt.address==ports[port]+(step==PMH_ACK?4:step==PMH_IDLE?8:0));
        CHECK(command.command.halt.write==(step==PMH_SET_REQ));
        uint32_t value=step==PMH_INITIAL_REQ?0:1;
        CHECK(pmss_complete(&state,&command,now++,1,value,NULL)==
            (port==2&&step==PMH_FINAL_REQ?PMSS_HELD:PMSS_WAIT));
    }
    CHECK(state.complete&&!state.unknown&&state.phase==3&&state.halt.ports_held==7);
    CHECK(pms_u32(sample.out+96)==0xa1&&state.stop.write_intent&&state.halt.write_intent==7);
    CHECK(pmss_next(&state,now,&command)==PMSS_HELD);
}
static void parser_failures(void)
{
    for(unsigned kind=0;kind<11;kind++){
        fixture();struct pms_view view;
        switch(kind){
        case 0:sample.in[0]^=1;break;case 1:sample.in[4]=0;break;
        case 2:sample.in[5]=0;break;case 3:put(sample.in+8,0x10000);break;
        case 4:put(sample.in+12,0x20011);break;case 5:put(sample.in+12,0x110010);break;
        case 6:put(sample.in+12,0x10010);break;case 7:put(sample.in+16,4);break;
        case 8:memset(sample.in+20,'x',16);break;
        case 9:memcpy(sample.in+20,sample.in+80,16);break;
        case 10:sample.in[80]='X';break;
        }
        CHECK(!pms_parse(sample.in,1,&view));
    }
    fixture();struct pms_view view;CHECK(pms_parse(sample.out,0,&view)&&view.index==3&&view.value==0xa0);
    CHECK(!pms_parse(sample.out,2,&view));CHECK(!pms_parse(NULL,0,&view));CHECK(!pms_parse(sample.out,0,NULL));
}
static void stale_initial(void)
{
    for(unsigned kind=0;kind<7;kind++){
        begin();struct pmss_command command=next(101,1,PMS_INITIAL);
        switch(kind){case 0:put(sample.out+96,0xa1);break;case 1:put(sample.in+96,10);break;
        case 2:put(sample.in+96,0);break;case 3:put(sample.in+96,3);break;
        case 4:put(sample.in+16,1);break;case 5:sample.in_bytes--;break;
        case 6:sample.out_bytes--;break;}
        CHECK(pmss_complete(&state,&command,102,1,0,&sample)==PMSS_FAILED);
        CHECK(state.unknown&&!state.halt.started&&!state.stop.write_intent);
    }
}
static void changed_poll(void)
{
    for(unsigned kind=0;kind<9;kind++){
        begin();stop_prefix();struct pmss_command command=next(120,1,PMS_POLL);
        put(sample.in+96,8);
        switch(kind){case 0:put(sample.in+96,9);break;case 1:put(sample.out+96,0xa0);break;
        case 2:sample.out[36]^=2;break;case 3:sample.in[20]='A';break;
        case 4:put(sample.in+16,1);break;case 5:put(sample.out+16,3);put(sample.in+16,3);break;
        case 6:sample.in[12]=15;break;case 7:sample.out[4]=2;break;case 8:sample.in_bytes=0;break;}
        CHECK(pmss_complete(&state,&command,121,1,0,&sample)==PMSS_FAILED);
        CHECK(state.unknown&&!state.halt.started&&state.stop.write_intent);
        CHECK(pmss_next(&state,122,&command)==PMSS_FAILED);
    }
}
static void partial_failures(void)
{
    for(unsigned failed=PMS_INITIAL;failed<=PMS_RING_ORDER;failed++){
        begin();
        for(unsigned step=PMS_INITIAL;step<=failed;step++){
            struct pmss_command command=next(100+step*2,1,step);
            uint32_t value=step==PMS_READBACK?0xa1:0;
            int result=pmss_complete(&state,&command,101+step*2,step==failed?0:1,value,step==PMS_INITIAL?&sample:NULL);
            CHECK(result==(step==failed?PMSS_FAILED:PMSS_WAIT));
        }
        CHECK(state.unknown&&!state.halt.started&&!state.complete);
        CHECK(state.stop.event[failed-1].return_raw==0);
    }
    begin();stop_prefix();struct pmss_command command;
    CHECK(pmss_next(&state,101+PMS_TICKS,&command)==PMSS_FAILED&&!state.halt.started);
    begin();command=next(101,1,PMS_INITIAL);CHECK(pmss_next(&state,102,&command)==PMSS_FAILED);
    begin();command=next(101,1,PMS_INITIAL);command.command.stop.address+=4;
    CHECK(pmss_complete(&state,&command,102,1,0,&sample)==PMSS_FAILED&&!state.halt.started);
    begin();command=next(101,1,PMS_INITIAL);
    CHECK(pmss_complete(&state,&command,100,1,0,&sample)==PMSS_FAILED);
    begin();CHECK(pmss_next(&state,101,(void*)&state)==PMSS_FAILED);
    for(unsigned kind=0;kind<8;kind++){
        fixture();struct pms_config c=config();
        switch(kind){case 0:c.epoch=0;break;case 1:c.in_id=443;break;case 2:c.out_id=429;break;
        case 3:c.out_offset=0;break;case 4:c.in_offset=c.out_offset;break;
        case 5:c.in_bytes=339;break;case 6:c.in_offset=0x1ff000;break;case 7:c.out_offset++;break;}
        CHECK(pmss_begin(&state,&c,100,19200000)==PMSS_FAILED);
    }
}
static void halt_failures(void)
{
    /* Every AXI access can fail after the stop ACK. It must not create a
     * successful combined result or retract the already published STOP. */
    for(unsigned failed=0;failed<18;failed++){
        begin();stop_prefix();uint64_t now=120;
        struct pmss_command command=next(now++,1,PMS_POLL);put(sample.in+96,8);
        CHECK(pmss_complete(&state,&command,now++,1,0,&sample)==PMSS_WAIT);
        for(unsigned event=0;event<=failed;event++){
            unsigned step=event%6;command=next(now++,2,step);
            CHECK(pmss_complete(&state,&command,now++,event==failed?0:1,
                step==PMH_INITIAL_REQ?0:1,NULL)==(event==failed?PMSS_FAILED:PMSS_WAIT));
        }
        CHECK(state.unknown&&state.halt.unknown&&!state.complete&&state.stop.ack_held);
        CHECK(pms_u32(sample.out+96)==0xa1);
        CHECK(pmss_next(&state,now,&command)==PMSS_FAILED);
    }
}
int main(void)
{
    success();parser_failures();stale_initial();changed_poll();partial_failures();halt_failures();
    printf("PASS %u MSS stop/AXI ordering checks (software only)\n",checks);return 0;
}
