/* Native QMP adapter against a separate mailbox peer. Power/stop/proxy
 * records used for OFF are produced by their actual software engines. */
#define main legacy_supplies_test
#include "polaris-mss-supplies-test.c"
#undef main
#define EFI_XNU_MSS_NATIVE_IO_AVAILABLE 1
#define EFI_XNU_MSS_AOP_IO_AVAILABLE 1
#define POLARIS_MSS_NATIVE_SOFTWARE_PEER 1
#include "../shim/polaris/uefi-mss-mmio-native.h"
static struct pmaq_notify aq,on_record;
static struct pmpx_lifecycle xp;
static struct pmni_arch aq_opening;
static struct pmni_result aq_native;
static uint32_t ram[PMAQ_BYTES/4],payload_before[24];
static unsigned aq_cases,aq_fault,aq_target,aq_calls,aq_writes,aq_irq,aq_orders,aq_waiting;
static int pmni_arch_read(struct pmni_arch*a)
{*a=aq_opening;a->ticks=++tick;if(aq_fault==2&&aq.events==aq_target)a->daif=0;return 1;}
static int pmni_translate(struct pmni_translation*t)
{
    t->saved=t->restored=0x1234;t->read_par=t->write_par=t->page|0x200;
    t->read_issued=t->read_returned=t->write_issued=t->write_returned=t->restore_issued=t->restore_returned=1;
    if(aq_fault==3&&aq.events==aq_target)t->write_par^=4096;return 1;
}
static int pmni_raw(const struct pmni_command*c,uint32_t*v)
{
    aq_calls++;
    if(aq_fault==1&&aq.events==aq_target)return 0;
    if(c->kind==PMNI_FULL_ORDER){CHECK(!c->address&&!c->value);aq_orders++;return 1;}
    if(c->address==0x1799000c){
        CHECK(c->kind==PMNI_WRITE&&c->value==1&&aq_orders==1&&aq_irq==0);
        CHECK(ram[0x1000/4]==96);
        char expected[96]={0};snprintf(expected,sizeof(expected),"{class: image, res: load_state, name: modem, val: %s}",aq.on?"on":"off");
        CHECK(!memcmp((char*)ram+0x1004,expected,96));aq_irq++;aq_waiting=1;return 1;
    }
    CHECK(c->address>=PMAQ_BASE&&c->address<PMAQ_BASE+PMAQ_BYTES&&!(c->address&3));
    unsigned at=(unsigned)(c->address-PMAQ_BASE);
    if(c->kind==PMNI_WRITE){
        CHECK(at>=0x1000&&at<=0x1060);aq_writes++;
        if(at==0x1000){CHECK(c->value==96&&aq.step==PMAQ_LENGTH&&ram[at/4]==0);}
        else CHECK(!ram[0x1000/4]);
        ram[at/4]=c->value;
    }else{
        CHECK(c->kind==PMNI_READ);
        if(at==0x1000&&aq_waiting&&aq_fault!=4){ram[at/4]=0;aq_waiting=0;}
        *v=ram[at/4];
        if(aq_fault==5&&aq.step==PMAQ_CONFIRM&&aq.index==8)*v^=4;
        if(aq_fault==6&&aq.step==PMAQ_PRE_DESC&&aq.index==11)*v=0xffff0000;
        if(aq_fault==7&&aq.step==PMAQ_READBACK&&aq.index==0)*v^=1;
        if(aq_fault==8&&aq.step==PMAQ_RESTORE_READ&&aq.index==0)*v^=1;
    }
    return 1;
}
static void aq_fixture(void)
{
    memset(&aq,0,sizeof(aq));memset(ram,0,sizeof(ram));aq_cases++;
    aq_calls=aq_writes=aq_irq=aq_orders=aq_waiting=aq_fault=aq_target=0;tick=1000;
    uint32_t desc[16]={0x4d41494c,1,0,0xffff,0xffff,0xffff,0xffff,256,0x2000,
        0xffff,0xffff,0xffff,0xffff,256,0x1000,0};memcpy(ram,desc,64);
    for(unsigned k=0;k<24;k++)ram[0x1004/4+k]=payload_before[k]=0xa5000000+k;
    CHECK(pmaq_on(&aq,1,tick)==PMAQ_WAIT);
}
static int aq_run(void)
{
    for(unsigned n=0;n<2200;n++){
        struct pmaq_command c;int result=pmaq_next(&aq,++tick,&c);
        if(result==PMAQ_WAIT){CHECK(tick<aq.not_before);tick=aq.not_before;continue;}
        if(result!=PMAQ_IO)return result;
        memset(&aq_native,0,sizeof(aq_native));aq_opening=(struct pmni_arch){.el=4,.mpidr=0x81000000,
            .ttbr0=0x10004000,.tcr=0x80803520,.sctlr=5,.mair=0xffbb4400,.daif=0xc0,.sre=7,.cpacr=0x300000,.frequency=19200000,.ticks=tick};
        int returned=pmni_aop(&aq,&c,&aq_opening,&aq_native);
        result=pmaq_complete(&aq,&c,++tick,returned,aq_native.value);
        if(result!=PMAQ_WAIT)return result;
    }
    CHECK(0);return -1;
}
static int xp_run(void)
{
    for(unsigned n=0;n<50;n++){
        struct pmpx_command c;int result=pmpx_next(&xp,++tick,&c);uint32_t value=0;const struct pmrv_request*r=NULL;
        if(result==PMPX_WAIT){tick=xp.not_before;continue;}if(result!=PMPX_IO)return result;
        if(c.kind==PMPX_RAIL){
            memset(&q,0,sizeof(q));edges=acks=pending=actions=fail_at=mode=0;
            CHECK(pmrv_begin(&io,&q,1,1u<<slot,slot,19,c.write,c.value));int ready=0;while(!ready)ready=pmrv_step(&io,&q);CHECK(ready==1);r=&q;
        }else if(c.kind==PMPX_WRITE){CHECK(c.address==0x152004);regs[2]=c.value;}
        else if(c.kind==PMPX_READ)value=c.address==0x152004?regs[2]:0;
        result=pmpx_complete(&xp,&c,++tick,1,value,r);if(result!=PMPX_WAIT)return result;
    }
    CHECK(0);return -1;
}
static void power_cycle(void)
{
    supply_start=aq.last+100;supply_fixture();votes[19]=2;CHECK(supply_run(-1,0)==PMSP_HELD);
    memset(&xp,0,sizeof(xp));regs[2]=0x10000000;CHECK(pmpx_begin(&xp,&supply,++tick)==PMPX_WAIT);CHECK(xp_run()==PMPX_HELD);
    make_stopped_clocks();CHECK(pmpx_release(&xp,&supply,&clocks,++tick)==PMPX_WAIT);CHECK(xp_run()==PMPX_RESTORED);
    CHECK(pmsp_release(&supply,&clocks,++tick)==PMSP_WAIT);CHECK(supply_run(-1,0)==PMSP_RESTORED);
}
int main(void)
{
    aq_fixture();CHECK(aq_run()==PMAQ_CONSUMED);CHECK(aq.complete&&aq_irq==1&&aq_writes==49);
    CHECK(!memcmp(ram+0x1004/4,payload_before,96)&&ram[0x1000/4]==0);unsigned events=aq.events;on_record=aq;
    power_cycle();memset(&aq,0,sizeof(aq));aq_irq=aq_orders=aq_writes=aq_waiting=0;
    CHECK(pmaq_off(&aq,&on_record,&xp,&supply,++tick)==PMAQ_WAIT);CHECK(aq_run()==PMAQ_CONSUMED);
    CHECK(aq.on==0&&aq_irq==1&&aq_writes==49&&!memcmp(ram+0x1004/4,payload_before,96));
    for(unsigned event=1;event<=events;event++){
        aq_fixture();aq_fault=1;aq_target=event;CHECK(aq_run()==PMAQ_FAILED&&aq.unknown&&!aq.complete);
        unsigned calls=aq_calls;struct pmaq_command c;CHECK(pmaq_next(&aq,++tick,&c)==PMAQ_FAILED&&aq_calls==calls);
    }
    for(unsigned fault=2;fault<=8;fault++){
        aq_fixture();aq_fault=fault;aq_target=60;CHECK(aq_run()==PMAQ_FAILED&&aq.unknown&&!aq.complete);
    }
    for(unsigned fault=0;fault<7;fault++){
        aq_fixture();
        if(fault==0)ram[0]^=1;if(fault==1)ram[1]=2;if(fault==2)ram[9]=0xffff0000;
        if(fault==3)ram[14]=0x2000;if(fault==4)ram[13]=96;if(fault==5)ram[0x1000/4]=96;if(fault==6)ram[0x2000/4]=4;
        CHECK(aq_run()==PMAQ_FAILED&&!aq_writes&&!aq_irq);
    }
    for(unsigned fault=0;fault<5;fault++){
        memset(&aq,0,sizeof(aq));struct pmaq_notify saved_on=on_record;
        struct pmpx_lifecycle saved_x=xp;struct pmsp_lifecycle saved_s=supply;
        if(fault==0)saved_on.complete=0;if(fault==1)saved_x.restored=0;if(fault==2)saved_s.restored=0;
        if(fault==3)saved_s.epoch++;if(fault==4)saved_s.release_at=saved_x.last-1;
        CHECK(pmaq_off(&aq,&saved_on,&saved_x,&saved_s,supply.last+1)==PMAQ_FAILED);
    }
    printf("MSS AOP QMP: %u scenarios / %u checks plus %u clock/stop checks PASS; software native leaves\n",aq_cases,checks,clock_checks);
    return 0;
}
