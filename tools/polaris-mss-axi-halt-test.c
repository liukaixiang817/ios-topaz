#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "polaris-mss-axi-halt.h"
static struct pmh_halt h;
static uint64_t ticks;
static unsigned checks;
static void begin(void){memset(&h,0,sizeof(h));ticks=100;assert(pmh_begin(&h,ticks,19200000));}
static uint32_t answer(const struct pmh_command*c)
{return c->step==PMH_INITIAL_REQ?0:1;}
static int run(unsigned fail_event,unsigned fault)
{
    struct pmh_command c;
    for(unsigned n=0;n<PMH_EVENTS;n++){
        int next=pmh_next(&h,++ticks,&c);
        if(next==PMH_HELD)return next;
        assert(next==PMH_IO&&c.sequence==n+1&&c.port==n/6&&c.step==n%6);
        assert(c.address==pmh_base(c.port)+(c.step==PMH_ACK?4:c.step==PMH_IDLE?8:0));
        assert(c.write==(c.step==PMH_SET_REQ)&&c.value==c.write&&!c.reserved);
        assert(h.pending==c.sequence&&h.event[n].issued&&!h.event[n].returned);
        if(c.write)assert(h.write_intent&(1u<<c.port));
        uint32_t value=answer(&c);int returned=1;uint64_t end=++ticks;
        if(n==fail_event){
            if(fault==1)returned=0;
            if(fault==2)end=h.last-1;
            if(fault==3)end=h.port_opening+PMH_PORT_TICKS+1;
            if(fault==4)c.address+=4;
            if(fault==5)value=c.step==PMH_INITIAL_REQ?1:0;
        }
        int done=pmh_complete(&h,&c,end,returned,value);
        if(done==PMH_FAILED)return done;
        assert(done==(n==17?PMH_HELD:PMH_WAIT));
    }assert(0);return PMH_FAILED;
}
static void frozen(void)
{
    unsigned events=h.events,writes=h.write_intent;struct pmh_command c={0};
    assert(pmh_next(&h,ticks+1,&c)==PMH_FAILED);
    assert(pmh_complete(&h,&c,ticks+2,1,1)==PMH_FAILED);
    assert(h.events==events&&h.write_intent==writes&&h.unknown&&h.error);
    for(unsigned n=0;n<h.events;n++)if(h.event[n].command.write)assert(h.event[n].command.value==1);
}
int main(void)
{
    begin();assert(run(UINT32_MAX,0)==PMH_HELD&&h.events==18&&h.ports_held==7&&
        h.write_intent==7&&h.write_returned==7&&!h.unknown&&!h.error&&!h.pending);checks++;
    struct pmh_command c={0};assert(pmh_next(&h,ticks+1,&c)==PMH_HELD&&h.events==18);checks++;
    assert(pmh_begin(&h,ticks,19200000)==PMH_FAILED);checks++;
    for(unsigned fault=1;fault<=4;fault++)for(unsigned n=0;n<18;n++){
        begin();assert(run(n,fault)==PMH_FAILED);frozen();checks++;
    }
    for(unsigned port=0;port<3;port++)for(unsigned step=0;step<6;step++){
        if(step==PMH_SET_REQ||step==PMH_ACK)continue;
        begin();assert(run(port*6+step,5)==PMH_FAILED);frozen();checks++;
    }
    begin();assert(pmh_next(&h,++ticks,&c)==PMH_IO);
    struct pmh_command duplicate=c;assert(pmh_next(&h,++ticks,&c)==PMH_FAILED&&h.pending==1);frozen();checks++;
    begin();assert(pmh_next(&h,++ticks,&c)==PMH_IO);duplicate=c;
    assert(pmh_complete(&h,&c,++ticks,1,0)==PMH_WAIT);
    assert(pmh_complete(&h,&duplicate,++ticks,1,0)==PMH_FAILED);frozen();checks++;
    begin();
    for(unsigned step=0;step<3;step++){
        assert(pmh_next(&h,++ticks,&c)==PMH_IO);
        assert(pmh_complete(&h,&c,++ticks,1,answer(&c))==PMH_WAIT);
    }
    for(unsigned n=0;n<PMH_MAX_ACK_READS;n++){
        assert(pmh_next(&h,ticks,&c)==PMH_IO&&c.step==PMH_ACK);
        assert(pmh_complete(&h,&c,ticks,1,0)==PMH_WAIT);
        struct pmh_command untouched={.address=0x123};
        assert(pmh_next(&h,ticks+PMH_POLL_TICKS-1,&untouched)==PMH_WAIT&&untouched.address==0x123);
        ticks+=PMH_POLL_TICKS;
    }
    assert(pmh_next(&h,ticks,&c)==PMH_FAILED&&h.error==PMH_LIMIT&&h.write_returned==1);frozen();checks++;
    begin();assert(pmh_next(&h,h.port_opening+PMH_PORT_TICKS+1,&c)==PMH_FAILED&&!h.events);frozen();checks++;
    begin();assert(pmh_next(&h,h.port_opening+PMH_PORT_TICKS,&c)==PMH_IO);checks++;
    begin();h.port=3;assert(pmh_next(&h,++ticks,&c)==PMH_FAILED);frozen();checks++;
    begin();h.step=6;assert(pmh_next(&h,++ticks,&c)==PMH_FAILED);frozen();checks++;
    for(unsigned bad=0;bad<4;bad++){
        begin();assert(pmh_next(&h,++ticks,&c)==PMH_IO);
        if(bad==0)h.port++;if(bad==1)h.step++;
        assert(pmh_complete(&h,&c,++ticks,bad==2?2:bad==3?-1:1,0)==PMH_FAILED);frozen();checks++;
    }
    begin();assert(pmh_next(&h,++ticks,(void*)&h)==PMH_FAILED);frozen();checks++;
    memset(&h,0,sizeof(h));assert(pmh_begin(&h,1,1)==PMH_FAILED&&!h.started);checks++;
    memset(&h,0,sizeof(h));assert(pmh_begin(&h,0,19200000)==PMH_FAILED&&!h.started);checks++;
    assert(pmh_base(3)==0);checks++;
    printf("{\"passed\":true,\"checks\":%u,\"events_success\":18,\"MMIO_executed\":false,\"DMA_retirement\":false}\n",checks);
}
