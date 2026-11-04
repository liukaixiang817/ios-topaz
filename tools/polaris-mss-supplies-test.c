/* Actual software RSC request, clock and stop/reset producers compose here.
 * No native instruction, firmware service, MMIO or phone is used. */
#define main legacy_clocks_test
#define checks clock_checks
#define initial clock_initial
#define clock_peer active_clock_peer
#include "polaris-mss-clocks-test.c"
#undef clock_peer
#undef initial
#undef checks
#undef main
#undef CHECK
#define main legacy_request_test
#include "polaris-mss-rail-request-test.c"
#undef main
#include "polaris-mss-supplies.h"
static struct pmsp_lifecycle supply,held_copy;
static struct pmck_lifecycle returned_clocks;
static unsigned supply_cases,logical_writes;
static const uint32_t levels[3]={7,4,7};
static void supply_fixture(void)
{
    reset(2,1,0,0);memset(&supply,0,sizeof(supply));logical_writes=0;supply_cases++;
    votes[0]=2;votes[1]=6;votes[2]=0;
    static const uint32_t mv[4]={0,1800,0,3200};
    for(unsigned k=0;k<4;k++){
        unsigned n=3+4*k;votes[n]=mv[k];votes[n+1]=k&1;votes[n+2]=5;votes[n+3]=17+k;
    }
    memcpy(before_votes,votes,sizeof(votes));
    CHECK(pmsp_begin(&supply,1,levels,tick,19200000)==PMSP_WAIT);
}
static int supply_request(const struct pmsp_command*c,unsigned fault)
{
    memset(&q,0,sizeof(q));actions=edges=acks=pending=0;fail_at=0;mode=0;
    if(fault==1)mode=2;
    if(fault==2)mode=1;
    if(c->write){
        static const unsigned order[22]={1,2,0,3,4,7,8,11,12,15,16,16,15,12,11,8,7,4,3,0,2,1};
        CHECK(logical_writes<22&&c->resource==order[logical_writes]);logical_writes++;
    }
    CHECK(pmrv_begin(&io,&q,1,1u<<slot,slot,c->resource,c->write,c->value));
    int ready=0;while(!ready)ready=pmrv_step(&io,&q);
    if(fault==3)q.epoch++;
    if(fault==4)q.io.started=c->sequence==1?supply.opening-1:supply.last-1;
    if(fault==5)q.io.history[0].returned=0;
    if(fault==6)q.resource=(q.resource+1)%19;
    if(fault==7)q.io.acknowledged=0;
    if(fault==8)q.io.unknown=1;
    (void)ready;return pmsp_complete(&supply,c,&q,++tick);
}
static int supply_run(int fail_event,unsigned fault)
{
    for(unsigned count=0;count<110;count++){
        struct pmsp_command c;int result=pmsp_next(&supply,++tick,&c);
        if(result!=PMSP_REQUEST)return result;
        int bad=(int)supply.events-1==fail_event;
        result=supply_request(&c,bad?fault:0);
        if(result!=PMSP_WAIT)return result;
    }
    CHECK(0);return -1;
}
static void make_stopped_clocks(void)
{
    uint64_t now=tick+10;(void)clock_fixture(0,0);memset(&clocks,0,sizeof(clocks));
    CHECK(pmck_begin(&clocks,1,now,19200000)==PMCK_WAIT);now=run_transition(now+1,-1,0);
    now=stopped(now+19200000*5);CHECK(pmck_release(&clocks,&shutdown_state,now)==PMCK_WAIT);
    tick=run_transition(now+1,-1,0);CHECK(clocks.phase==4&&clocks.restored==63);
}
static void complete_cycle(void)
{
    supply_fixture();CHECK(supply_run(-1,0)==PMSP_HELD);CHECK(supply.events==41&&logical_writes==11);
    CHECK(votes[0]==7&&votes[1]==6&&votes[2]==7&&votes[3]==800&&votes[7]==1800&&votes[11]==1304&&votes[15]==3200);
    for(unsigned k=0;k<4;k++){CHECK(votes[4+4*k]==1);CHECK(votes[5+4*k]==5&&votes[6+4*k]==17+k);}
    held_copy=supply;unsigned count=supply.events;struct pmsp_command c;
    tick+=19200000*3;CHECK(pmsp_next(&supply,tick,&c)==PMSP_HELD);CHECK(supply.events==count);
    make_stopped_clocks();returned_clocks=clocks;
    CHECK(pmsp_release(&supply,&clocks,++tick)==PMSP_WAIT);CHECK(supply_run(-1,0)==PMSP_RESTORED);
    CHECK(supply.events==101&&logical_writes==22&&pmsr_equal(votes,before_votes,sizeof(votes)));
    count=actions;CHECK(pmsp_next(&supply,++tick,&c)==PMSP_RESTORED);CHECK(actions==count);
}
int main(void)
{
    complete_cycle();
    for(unsigned f=0;f<101;f++){
        supply_fixture();int result=supply_run(f,1);
        if(f>=41){CHECK(result==PMSP_HELD);make_stopped_clocks();CHECK(pmsp_release(&supply,&clocks,++tick)==PMSP_WAIT);result=supply_run(f,1);}
        CHECK(result==PMSP_FAILED&&supply.unknown&&!supply.restored);
        unsigned count=actions;struct pmsp_command c;CHECK(pmsp_next(&supply,++tick,&c)==PMSP_FAILED);CHECK(actions==count);
    }
    for(unsigned fault=2;fault<=8;fault++){
        supply_fixture();CHECK(supply_run(19,fault)==PMSP_FAILED);CHECK(supply.unknown&&!supply.held);
    }
    for(unsigned fault=0;fault<13;fault++){
        supply=held_copy;clocks=returned_clocks;tick=clocks.last+1;supply_cases++;
        switch(fault){
        case 0:clocks.epoch++;break;case 1:clocks.unknown=1;break;case 2:clocks.pending=1;break;
        case 3:clocks.phase=2;break;case 4:clocks.restored=31;break;case 5:clocks.held=31;break;
        case 6:clocks.opening=supply.held_at-1;break;case 7:clocks.reset_at=0;break;
        case 8:clocks.reset_at=supply.held_at-1;break;case 9:clocks.release_at=clocks.reset_at-1;break;
        case 10:clocks.last=clocks.release_at-1;break;case 11:tick=clocks.last-1;break;
        case 12:tick=UINT64_MAX;break;
        }
        CHECK(pmsp_release(&supply,&clocks,tick)==PMSP_FAILED);CHECK(supply.unknown&&supply.phase==3);
    }
    /* Unsupported returned votes refuse before the first resource WRITE. */
    for(unsigned fault=0;fault<6;fault++){
        supply_fixture();
        if(fault==0)votes[0]=16;if(fault==1)votes[3]=801;if(fault==2)votes[4]=2;
        if(fault==3)votes[5]=3;if(fault==4)votes[6]=8192;if(fault==5)votes[15]=3313;
        CHECK(supply_run(-1,0)==PMSP_FAILED);CHECK(!logical_writes);
    }
    /* An external changed vote during HELD must not be overwritten by return. */
    for(unsigned n=0;n<19;n++){
        supply_fixture();CHECK(supply_run(-1,0)==PMSP_HELD);make_stopped_clocks();
        CHECK(pmsp_release(&supply,&clocks,++tick)==PMSP_WAIT);votes[n]^=1;
        CHECK(supply_run(-1,0)==PMSP_FAILED);CHECK(logical_writes==11&&!supply.restored);
    }
    supply_fixture();struct pmsp_command c;
    CHECK(pmsp_next(&supply,supply.opening+PMSP_TRANSITION+1,&c)==PMSP_FAILED);CHECK(!actions);
    printf("MSS persistent supplies: %u scenarios / %u checks plus %u clock/stop checks PASS; no hardware\n",supply_cases,checks,clock_checks);
    return 0;
}
