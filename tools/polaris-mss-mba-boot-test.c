/* Hardware addresses remain data; real protocol producers feed MBA begin. */
#pragma push_macro("main")
#undef main
#define main unused_clock_suite
#include "polaris-mss-clocks-test.c"
#pragma pop_macro("main")
#include "polaris-mss-mba-boot.h"
static struct pmba_boot mba;
static struct pwmt_transaction mba_assignment;
static struct pwma_page mba_descriptor;
static const uint64_t mba_addresses[16]={0x4080018,0x4080018,0x4180000,0,0x4180014,0x4180018,0,
    0x408003c,0x408003c,0x408003c,0x4080400,0,0x4080404,0x4180040,0x4180004,0x418000c};
static uint64_t mba_inputs(void)
{
    uint64_t now=clock_fixture(0,0);now=run_transition(now,-1,0);
    memset(&mba,0,sizeof(mba));memset(&mba_assignment,0,sizeof(mba_assignment));memset(&mba_descriptor,0,sizeof(mba_descriptor));
    struct pwma_spec spec={.descriptor_pa=(uintptr_t)&mba_descriptor,.region_pa=0x90000000,.region_bytes=0x100000,
        .sources=1,.source={PWMA_HLOS},.destinations=1,.destination={{PWMA_MSS_MSA,PWMA_RW}}};
    CHECK(pwmt_begin(&mba_assignment,&mba_descriptor,&spec,++now,19200000)==PWMT_WAIT);
    for(unsigned step=PWMT_CLEAN;step<=PWMT_INVALIDATE;step++){
        struct pwmt_command c;CHECK(pwmt_next(&mba_assignment,++now,&c)==PWMT_IO&&c.operation==step);
        struct pwmk_record cache={.address=(uintptr_t)&mba_descriptor,.ctr_before=4u<<16,.ctr_after=4u<<16,.el=4,.sctlr=5,
            .operation=step==PWMT_CLEAN?PWMK_CLEAN_INVALIDATE:PWMK_INVALIDATE,.line_bytes=64,.lines_issued=64,
            .lines_returned=64,.attempted=1,.barrier_issued=1,.barrier_returned=1,.complete=1};
        struct pwma_registers zero={0};CHECK(pwmt_complete(&mba_assignment,&c,++now,1,step==PWMT_SMC?&zero:NULL,
            step==PWMT_SMC?NULL:&cache)==(step==PWMT_INVALIDATE?PWMT_ZERO:PWMT_WAIT));
    }
    return now+1;
}
static uint64_t mba_start(void)
{
    uint64_t now=mba_inputs();CHECK(pmba_begin(&mba,&clocks,&mba_assignment,238304,now)==PMBA_WAIT);return now+1;
}
static uint32_t mba_value(const struct pmba_command*c,unsigned ready,unsigned delayed)
{
    if(c->phase==2){
        CHECK(c->reset.step<14&&c->reset.address==expected_address[c->reset.step]&&c->reset.kind==expected_kind[c->reset.step]);
        CHECK(c->reset.value==expected_value[c->reset.step]);
        return c->reset.step==PMSR_PDC_READ_ON?0xa5000001:c->reset.step==PMSR_PDC_READ_OFF?0x5a000280:0;
    }
    CHECK(c->step<16&&c->address==mba_addresses[c->step]);
    unsigned kind=(c->step==0||c->step==7||c->step==9||c->step>=13)?PMSR_READ:
        (c->step==3||c->step==6||c->step==11)?PMSR_FULL_ORDER:PMSR_WRITE;
    CHECK(c->kind==kind);
    const uint32_t values[16]={0,0xabcd1234,0x90000000,0,0,0,0,0,0x80000021,0,1,0,1,0,0,0};
    CHECK(c->value==values[c->step]);
    switch(c->step){
    case PMBA_DEBUG_READ:return 0xabcd1234;case PMBA_SLEEP_READ:return 0x80000020;
    case PMBA_SLEEP_POLL:return delayed?0x80000021:0x21;
    case PMBA_BOOT_POLL:case PMBA_PBL_POLL:return delayed?0:1;
    case PMBA_MBA_POLL:return delayed?0:ready;
    default:return 0;
    }
}
static void mba_run(unsigned ready,int failed,unsigned fault,unsigned delayed_step,unsigned delay_count)
{
    uint64_t now=mba_start();unsigned event=0,loops=0;
    for(;;){
        struct pmba_command c;int result=pmba_next(&mba,now,&c);
        if(result==PMBA_READY){CHECK(failed<0&&ready<=2);break;}
        if(result==PMBA_WAIT){
            uint64_t wake=mba.phase==2?mba.reset.not_before:mba.next_poll;
            if(wake>now){unsigned n=mba.events;CHECK(pmba_next(&mba,wake-1,&c)==PMBA_WAIT&&mba.events==n);now=wake;}
            else now++;
            continue;
        }
        CHECK(result==PMBA_IO);now++;
        if((int)event==failed){
            if(fault==1)CHECK(pmba_complete(&mba,&c,now,0,0)==PMBA_FAILED);
            else if(fault==2){c.address^=4;CHECK(pmba_complete(&mba,&c,now,1,0)==PMBA_FAILED);}
            else if(fault==3)CHECK(pmba_next(&mba,now,&c)==PMBA_FAILED);
            else if(fault==4)CHECK(pmba_complete(&mba,&c,now-2,1,0)==PMBA_FAILED);
            CHECK(mba.unknown&&!mba.ready&&clocks.phase==2&&clocks.held==63);
            CHECK(pmba_next(&mba,now,&c)==PMBA_FAILED);return;
        }
        unsigned delayed=c.phase==3&&c.step==delayed_step&&mba.polls<=delay_count;
        uint32_t value=mba_value(&c,ready,delayed);
        result=pmba_complete(&mba,&c,now++,1,value);CHECK(result>=0);event++;CHECK(++loops<1700);
    }
    CHECK(mba.ready==1&&!mba.unknown&&mba.phase==4&&mba.debug==0xabcd1234&&mba.sleep==0x80000020);
    CHECK(mba.image_issued==1&&mba.boot_issued==1&&mba.reset.complete==1&&mba.mba==0x90000000);
    CHECK(event==30+delay_count&&clocks.phase==2&&clocks.held==63);
}
static void mba_poll_faults(void)
{
    const unsigned targets[]={PMBA_SLEEP_POLL,PMBA_BOOT_POLL,PMBA_PBL_POLL,PMBA_MBA_POLL};
    for(unsigned n=0;n<4;n++)for(unsigned mode=0;mode<2;mode++){
        uint64_t now=mba_start();unsigned loops=0;
        for(;;){
            struct pmba_command c;int result=pmba_next(&mba,now,&c);
            if(result<0)break;
            if(result==PMBA_WAIT){uint64_t wake=mba.phase==2?mba.reset.not_before:mba.next_poll;now=wake>now?wake:now+1;continue;}
            CHECK(result==PMBA_IO);now++;
            uint32_t value=mba_value(&c,1,c.phase==3&&c.step==targets[n]);
            if(c.phase==3&&c.step==targets[n]&&mode){
                if(n==0)value=0;else if(n==1)now=mba.window+192001;else value=0xffffffff;
            }
            result=pmba_complete(&mba,&c,now++,1,value);if(result<0)break;CHECK(++loops<1700);
        }
        CHECK(mba.unknown&&!mba.ready&&clocks.phase==2);
    }
}
static void mba_bad_inputs(void)
{
    for(unsigned fault=0;fault<17;fault++){
        uint64_t now=mba_inputs(),bytes=238304;
        switch(fault){
        case 0:clocks.phase=1;break;case 1:clocks.held=31;break;case 2:clocks.unknown=1;break;
        case 3:clocks.pending=1;break;case 4:clocks.epoch=0;break;
        case 5:mba_assignment.complete=0;break;case 6:mba_assignment.unknown=1;break;
        case 7:mba_assignment.pending=1;break;case 8:mba_assignment.spec.region_pa++;break;
        case 9:mba_assignment.spec.region_bytes=0x200000;break;
        case 10:mba_assignment.spec.source[0]=15;break;case 11:mba_assignment.spec.destination[0].vmid=24;break;
        case 12:mba_assignment.spec.destinations=2;break;case 13:bytes=0;break;
        case 14:bytes=0x100001;break;case 15:now=mba_assignment.last-1;break;
        case 16:now=UINT64_MAX;break;
        }
        CHECK(pmba_begin(&mba,&clocks,&mba_assignment,bytes,now)==PMBA_FAILED&&!mba.events&&!mba.image_issued&&!mba.boot_issued);
    }
}
int main(void)
{
    mba_run(1,-1,0,0,0);mba_run(2,-1,0,0,0);
    for(int event=0;event<30;event++)for(unsigned fault=1;fault<=4;fault++)mba_run(1,event,fault,0,0);
    mba_run(1,-1,0,PMBA_SLEEP_POLL,3);mba_run(1,-1,0,PMBA_BOOT_POLL,3);
    mba_run(1,-1,0,PMBA_PBL_POLL,3);mba_run(2,-1,0,PMBA_MBA_POLL,3);
    mba_poll_faults();mba_bad_inputs();printf("PASS %u MBA startup checks (software only)\n",checks);return 0;
}
