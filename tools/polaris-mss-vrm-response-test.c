/* Raw VRM RESP_REQ metadata through the actual request/retirement/supply
 * consumers. Transport and clock/stop leaves remain SOFTWARE only. */
#define main old_supplies_main
#include "polaris-mss-supplies-test.c"
#undef main
static unsigned pattern,inject_resource=UINT32_MAX,inject_bit,read_responses,raw_metadata;
static int response_read(void*unused,uint64_t at,uint32_t*v)
{
    int ok=read_peer(unused,at,v);
    if(ok&&at==PWRSC_BASE+slot*PWRSC_STRIDE+0x40&&q.io.phase==2&&!q.write){
        read_responses++;
        if(q.resource>=3&&q.resource<19){
            unsigned field=(q.resource-3)%4;
            if(pattern==1||(pattern==2&&field<2)||(pattern==3&&(supply.events&1))){*v|=UINT32_C(0x80000000);raw_metadata++;}
        }
        if(q.resource==inject_resource)*v|=UINT32_C(1)<<inject_bit;
    }
    return ok;
}
static const struct pwrsc_io response_io={0,response_read,write_peer,clock_peer,order_peer};
static int response_request(const struct pmsp_command*c)
{
    memset(&q,0,sizeof(q));actions=edges=acks=pending=0;fail_at=mode=0;
    if(c->write){CHECK(!(c->value&UINT32_C(0x80000000)));logical_writes++;}
    CHECK(pmrv_begin(&response_io,&q,1,1u<<slot,slot,c->resource,c->write,c->value));
    int result=0;while(!result)result=pmrv_step(&response_io,&q);CHECK(result==1&&pmrv_retired(&q));
    uint32_t raw=q.response;result=pmsp_complete(&supply,c,&q,++tick);
    CHECK(q.response==raw&&q.io.response_OR[0]==raw);
    CHECK(supply.event[supply.events-1].response==raw);
    return result;
}
static int response_run(void)
{
    for(unsigned n=0;n<110;n++){
        struct pmsp_command c;int result=pmsp_next(&supply,++tick,&c);
        if(result!=PMSP_REQUEST)return result;
        result=response_request(&c);if(result!=PMSP_WAIT)return result;
    }CHECK(0);return -1;
}
int main(void)
{
    CHECK(!old_supplies_main());unsigned scenarios=0;
    /* Explicit hardware field widths, with each reserved bit independently
     * rejected. ARC keeps its old four-bit response format. */
    for(unsigned resource=0;resource<19;resource++){
        unsigned bits=resource<3?4:(resource-3)%4==0?13:(resource-3)%4==1?1:(resource-3)%4==2?3:9;
        uint32_t mask=(1u<<bits)-1;
        for(unsigned flag=0;flag<2;flag++)for(uint32_t value=0;value<=mask;value++){
            uint32_t out=UINT32_MAX;unsigned ok=pmsp_response_value(resource,value|(flag?UINT32_C(0x80000000):0),&out);
            CHECK(ok==(!flag||resource>=3));if(ok)CHECK(out==value);else CHECK(out==UINT32_MAX);
        }
        for(unsigned bit=bits;bit<31;bit++){
            uint32_t out=UINT32_MAX;CHECK(!pmsp_response_value(resource,(1u<<bit)|UINT32_C(0x80000000),&out));CHECK(out==UINT32_MAX);
        }
    }
    uint32_t out;CHECK(!pmsp_response_value(19,0,&out));CHECK(!pmsp_response_value(3,0,0));
    /* Full raise -> HELD verification -> stop -> restore, varying only raw
     * metadata. Pattern2 uses the observed all-zero VRM logical baseline. */
    for(pattern=0;pattern<4;pattern++){
        supply_fixture();read_responses=raw_metadata=0;inject_resource=UINT32_MAX;
        if(pattern==2){votes[0]=6;votes[1]=3;votes[2]=0;for(unsigned n=3;n<19;n++)votes[n]=0;memcpy(before_votes,votes,sizeof(votes));}
        CHECK(response_run()==PMSP_HELD);CHECK(logical_writes==11&&supply.events==41);
        for(unsigned n=0;n<19;n++)CHECK(supply.saved[n]==before_votes[n]&&!(supply.target[n]&UINT32_C(0x80000000)));
        make_stopped_clocks();CHECK(pmsp_release(&supply,&clocks,++tick)==PMSP_WAIT);CHECK(response_run()==PMSP_RESTORED);
        CHECK(logical_writes==22&&supply.events==101&&!memcmp(votes,before_votes,sizeof(votes)));
        CHECK(read_responses==79);CHECK((raw_metadata!=0)==(pattern!=0));scenarios++;
    }
    /* Unknown/reserved bits cannot be hidden by masking. These all refuse
     * while still sampling, before any voltage/enable command. */
    pattern=1;
    for(inject_resource=0;inject_resource<19;inject_resource++){
        unsigned bits=inject_resource<3?4:(inject_resource-3)%4==0?13:(inject_resource-3)%4==1?1:(inject_resource-3)%4==2?3:9;
        for(inject_bit=bits;inject_bit<(inject_resource<3?32u:31u);inject_bit++){
            supply_fixture();CHECK(response_run()==PMSP_FAILED&&supply.error==PMSP_VALUE&&supply.unknown&&!logical_writes);
            unsigned before=actions;CHECK(response_run()==PMSP_FAILED&&actions==before);scenarios++;
        }
    }
    inject_resource=UINT32_MAX;
    /* Logical drift during HELD still refuses restoration despite flags. */
    for(unsigned n=0;n<19;n++){
        supply_fixture();CHECK(response_run()==PMSP_HELD);make_stopped_clocks();CHECK(pmsp_release(&supply,&clocks,++tick)==PMSP_WAIT);votes[n]^=1;
        CHECK(response_run()==PMSP_FAILED&&supply.error==PMSP_VALUE&&logical_writes==11);scenarios++;
    }
    printf("PASS %u VRM response metadata scenarios / %u checks; SOFTWARE only\n",scenarios,checks);return 0;
}
