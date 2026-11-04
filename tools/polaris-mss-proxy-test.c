/* Software composition of real supplies, XO request, PRNG native leaves,
 * active clocks and stop/reset producers. No phone or privileged execution. */
#define main legacy_supplies_test
#include "polaris-mss-supplies-test.c"
#undef main
#define EFI_XNU_MSS_NATIVE_IO_AVAILABLE 1
#define EFI_XNU_MSS_RAIL_IO_AVAILABLE 1
#define EFI_XNU_MSS_PROXY_IO_AVAILABLE 1
#define POLARIS_MSS_NATIVE_SOFTWARE_PEER 1
#include "../shim/polaris/uefi-mss-mmio-native.h"
static struct pmpx_lifecycle proxy,proxy_held;
static struct pmni_arch px_opening;
static struct pmni_result px_native;
static unsigned proxy_cases,px_fault,px_raw,prng_writes,stuck;
static uint32_t prng_initial;
static int pmni_arch_read(struct pmni_arch*a)
{*a=px_opening;a->ticks=++tick;if(px_fault==1)a->daif=0;return 1;}
static int pmni_translate(struct pmni_translation*t)
{
    t->saved=t->restored=0x1234;t->read_par=t->write_par=t->page|0x200;
    t->read_issued=t->read_returned=t->write_issued=t->write_returned=t->restore_issued=t->restore_returned=1;
    if(px_fault==2)t->write_par^=4096;return 1;
}
static int pmni_raw(const struct pmni_command*c,uint32_t*v)
{
    px_raw++;if(px_fault==3)return 0;
    if(c->kind==PMNI_FULL_ORDER){CHECK(!c->address&&!c->value);return 1;}
    if(c->kind==PMNI_WRITE){CHECK(c->address==0x152004);CHECK((c->value^regs[2])==0x2000);regs[2]=c->value;prng_writes++;}
    else if(c->address==0x152004)*v=regs[2];
    else{CHECK(c->kind==PMNI_READ&&c->address==0x134004);*v=stuck?0x80000000:0;}
    return 1;
}
static void proxy_fixture(unsigned borrowed)
{
    supply_fixture();votes[19]=2;before_votes[19]=2;CHECK(supply_run(-1,0)==PMSP_HELD);
    memset(&proxy,0,sizeof(proxy));px_raw=px_fault=prng_writes=stuck=0;
    prng_initial=regs[2]=0x10000000|(borrowed?0x2000:0);proxy_cases++;
    CHECK(pmpx_begin(&proxy,&supply,++tick)==PMPX_WAIT);
}
static int proxy_run(int fail_event,unsigned failure)
{
    for(unsigned n=0;n<1200;n++){
        struct pmpx_command c;int result=pmpx_next(&proxy,++tick,&c);
        if(result==PMPX_WAIT){CHECK(tick<proxy.not_before);tick=proxy.not_before;continue;}
        if(result!=PMPX_IO)return result;
        int bad=(int)proxy.events-1==fail_event;uint32_t value=0;int returned=1;const struct pmrv_request*request=NULL;
        if(c.kind==PMPX_RAIL){
            memset(&q,0,sizeof(q));actions=edges=acks=pending=0;fail_at=mode=0;
            CHECK(pmrv_begin(&io,&q,1,1u<<slot,slot,19,c.write,c.value));
            int done=0;while(!done)done=pmrv_step(&io,&q);CHECK(done==1);request=&q;
            if(bad&&failure==2)q.epoch++;
        }else{
            memset(&px_native,0,sizeof(px_native));
            px_opening=(struct pmni_arch){.el=4,.mpidr=0x81000000,.ttbr0=0x10004000,.tcr=0x80803520,.sctlr=5,
                .mair=0xffbb4400,.daif=0xc0,.sre=7,.cpacr=0x300000,.frequency=19200000,.ticks=tick};
            px_fault=bad&&failure>=3?failure-2:0;
            returned=pmni_proxy(&proxy,&c,&px_opening,&px_native);value=px_native.value;
        }
        if(bad&&failure==1)returned=0;
        result=pmpx_complete(&proxy,&c,++tick,returned,value,request);
        if(result!=PMPX_WAIT)return result;
    }
    CHECK(0);return -1;
}
static void proxy_stop(void)
{
    make_stopped_clocks();CHECK(pmpx_release(&proxy,&supply,&clocks,++tick)==PMPX_WAIT);
}
int main(void)
{
    unsigned total[2];
    for(unsigned borrowed=0;borrowed<2;borrowed++){
        proxy_fixture(borrowed);CHECK(proxy_run(-1,0)==PMPX_HELD);CHECK(votes[19]==3&&(regs[2]&0x2000));
        proxy_held=proxy;struct pmpx_command c;unsigned count=proxy.events;
        tick+=19200000*3;CHECK(pmpx_next(&proxy,tick,&c)==PMPX_HELD&&proxy.events==count);
        proxy_stop();CHECK(proxy_run(-1,0)==PMPX_RESTORED);
        CHECK(votes[19]==2&&regs[2]==prng_initial&&prng_writes==(borrowed?0u:2u));total[borrowed]=proxy.events;
        CHECK(pmsp_release(&supply,&clocks,++tick)==PMSP_WAIT);CHECK(supply_run(-1,0)==PMSP_RESTORED);
        CHECK(pmsr_equal(votes,before_votes,sizeof(votes)));
    }
    for(unsigned borrowed=0;borrowed<2;borrowed++)for(unsigned event=0;event<total[borrowed];event++){
        proxy_fixture(borrowed);int result=proxy_run(event,1);
        if(result==PMPX_HELD){proxy_stop();result=proxy_run(event,1);}
        CHECK(result==PMPX_FAILED&&proxy.unknown&&!proxy.restored);
        struct pmpx_command c;unsigned raw=px_raw;CHECK(pmpx_next(&proxy,++tick,&c)==PMPX_FAILED&&raw==px_raw);
    }
    for(unsigned failure=3;failure<=5;failure++){
        proxy_fixture(0);CHECK(proxy_run(3,failure)==PMPX_FAILED&&proxy.unknown);
    }
    proxy_fixture(0);CHECK(proxy_run(0,2)==PMPX_FAILED&&proxy.unknown);
    proxy_fixture(0);votes[19]=4;CHECK(proxy_run(-1,0)==PMPX_FAILED&&!prng_writes);
    proxy_fixture(0);stuck=1;CHECK(proxy_run(-1,0)==PMPX_FAILED&&proxy.polls==500);
    proxy_fixture(0);CHECK(proxy_run(-1,0)==PMPX_HELD);proxy_stop();regs[2]^=1;
    CHECK(proxy_run(-1,0)==PMPX_FAILED&&prng_writes==1);
    proxy_fixture(0);CHECK(proxy_run(-1,0)==PMPX_HELD);proxy_stop();votes[19]=1;
    CHECK(proxy_run(-1,0)==PMPX_FAILED&&!proxy.restored);
    for(unsigned fault=0;fault<8;fault++){
        proxy_fixture(0);CHECK(proxy_run(-1,0)==PMPX_HELD);make_stopped_clocks();
        if(fault==0)supply.phase=7;if(fault==1)supply.unknown=1;if(fault==2)clocks.epoch++;
        if(fault==3)clocks.phase=2;if(fault==4)clocks.restored=0;if(fault==5)clocks.reset_at=proxy.held_at-1;
        if(fault==6)clocks.opening=proxy.held_at-1;if(fault==7)clocks.unknown=1;
        CHECK(pmpx_release(&proxy,&supply,&clocks,++tick)==PMPX_FAILED);
    }
    printf("MSS XO/PRNG proxy: %u scenarios / %u checks plus %u clock/stop checks PASS; no hardware\n",proxy_cases,checks,clock_checks);
    return 0;
}
