/* Native leaf control flow, software architecture/AT/MMIO peers only. */
#define main legacy_clock_test
#include "polaris-mss-clocks-test.c"
#undef main
#define EFI_XNU_MSS_NATIVE_IO_AVAILABLE 1
#define POLARIS_MSS_NATIVE_SOFTWARE_PEER 1
#include "../shim/polaris/uefi-mss-mmio-native.h"
static struct pmni_arch native_opening;
static struct pmni_result native_result;
static struct pmck_command native_clock_command;
static uint64_t native_ticks;
static unsigned native_fault,arch_calls,at_calls,raw_calls,native_clock_mode;
static uint32_t native_pdc,native_halt_req[3];
static int pmni_arch_read(struct pmni_arch*a)
{
    *a=native_opening;a->ticks=++native_ticks;arch_calls++;
    unsigned at=native_fault/100,what=native_fault%100;
    if(at>=1&&at<=3&&at==arch_calls){
        switch(what){
        case 1:return 0;case 2:a->el=8;break;case 3:a->mpidr|=0x100;break;
        case 4:a->mpidr|=UINT64_C(1)<<32;break;case 5:a->ttbr0^=4096;break;
        case 6:a->ttbr1^=4096;break;case 7:a->tcr^=1;break;case 8:a->sctlr^=4;break;
        case 9:a->mair^=1;break;case 10:a->daif=0;break;case 11:a->sre=0;break;
        case 12:a->group1=1;break;case 13:a->cpacr=0;break;case 14:a->frequency++;break;
        case 15:a->ticks=native_opening.ticks-1;break;case 16:a->ticks=native_opening.ticks+PMCK_LIMIT+1;break;
        }
    }return 1;
}
static int pmni_translate(struct pmni_translation*t)
{
    at_calls++;t->saved=t->restored=0x123456789abcdef0;t->read_par=t->write_par=t->page|0x200;
    t->read_issued=t->read_returned=t->write_issued=t->write_returned=t->restore_issued=t->restore_returned=1;
    switch(native_fault){
    case 401:return 0;case 402:t->page^=4096;break;case 403:t->read_issued=0;break;
    case 404:t->read_returned=0;break;case 405:t->write_issued=0;break;case 406:t->write_returned=0;break;
    case 407:t->restore_issued=0;break;case 408:t->restore_returned=0;break;case 409:t->restored++;break;
    case 410:t->write_par^=4096;break;case 411:t->read_par=t->write_par|=1;break;
    case 412:t->read_par=t->write_par&=~UINT64_C(0x200);break;
    case 413:t->read_par=t->write_par|=UINT64_C(0xff)<<56;break;
    case 414:t->read_par=t->write_par^=4096;break;
    case 415:native_opening.tcr^=1;break;
    case 416:t->read_par=t->write_par|=UINT64_C(4)<<56;break; /* valid Device-nGnRE */
    }return 1;
}
static int pmni_raw(const struct pmni_command*c,uint32_t*value)
{
    raw_calls++;
    if(native_fault==501)return 0;
    if(native_fault==502)native_opening.tcr^=1;
    if(native_clock_mode==1)*value=clock_peer(&native_clock_command,0);
    else if(native_clock_mode==2){
        if(c->address==PMSR_PDC){if(c->kind==PMNI_READ)*value=native_pdc;else native_pdc=c->value;}
        for(unsigned n=0;n<3;n++){
            if(c->address==pmh_base(n)){if(c->kind==PMNI_READ)*value=native_halt_req[n];else native_halt_req[n]=c->value;}
            if(c->address==pmh_base(n)+4||c->address==pmh_base(n)+8)*value=1;
        }
    }else if(c->kind==PMNI_READ)*value=0x12345678;
    return 1;
}
static void native_fixture(void)
{
    memset(&native_result,0,sizeof(native_result));native_fault=arch_calls=at_calls=raw_calls=native_clock_mode=0;
    native_ticks=100;
    native_opening=(struct pmni_arch){.el=4,.mpidr=0x81000000,.ttbr0=0x10004000,.ttbr1=0,
        .tcr=0x80803520,.sctlr=5,.mair=0xffbb4400,.daif=0xc0,.sre=7,.group1=0,
        .cpacr=0x300000,.frequency=19200000,.ticks=100};
}
static void native_faults(void)
{
    struct pmni_command command={.address=0x18a000,.kind=PMNI_READ};
    native_fixture();CHECK(pmni_access(&native_opening,&command,&native_result)==1);
    CHECK(native_result.complete&&!native_result.unknown&&native_result.value==0x12345678&&raw_calls==1&&at_calls==1&&arch_calls==3);
    CHECK(!pmni_access(&native_opening,&command,&native_result)&&raw_calls==1);
    for(unsigned at=1;at<=3;at++)for(unsigned what=1;what<=16;what++){
        native_fixture();native_fault=100*at+what;
        CHECK(!pmni_access(&native_opening,&command,&native_result));
        CHECK(native_result.unknown&&!native_result.complete&&raw_calls==(at==3));
    }
    for(unsigned fault=401;fault<=415;fault++){
        native_fixture();native_fault=fault;CHECK(!pmni_access(&native_opening,&command,&native_result));
        CHECK(native_result.unknown&&!native_result.issued&&!raw_calls);
    }
    native_fixture();native_fault=416;CHECK(pmni_access(&native_opening,&command,&native_result));
    for(unsigned fault=501;fault<=502;fault++){
        native_fixture();native_fault=fault;CHECK(!pmni_access(&native_opening,&command,&native_result));
        CHECK(native_result.unknown&&native_result.issued&&!native_result.complete);
    }
    for(unsigned kind=PMNI_STORE_ORDER;kind<=PMNI_FULL_ORDER;kind++){
        command=(struct pmni_command){.kind=kind};native_fixture();
        CHECK(pmni_access(&native_opening,&command,&native_result)&&!at_calls&&raw_calls==1);
    }
    const struct pmni_command invalid[]={
        {0x4180044,PMNI_READ,0},{0xc2b0000,PMNI_READ,0},{0x1f63004,PMNI_WRITE,1},
        {0x1f63008,PMNI_WRITE,1},{0x1f63000,PMNI_WRITE,0},{0x1799000c,PMNI_WRITE,1},
        {0x1799000c,PMNI_READ,0},{0x138004,PMNI_WRITE,1},{0x18a001,PMNI_READ,0},
        {0x18a000,PMNI_READ,1},{0,PMNI_READ,0},{0x18a000,PMNI_FULL_ORDER,0},
        {0,PMNI_STORE_ORDER,1},{0,5,0},{0x86004000,PMNI_READ,0}
    };
    for(unsigned n=0;n<sizeof(invalid)/sizeof(*invalid);n++){
        native_fixture();CHECK(!pmni_access(&native_opening,&invalid[n],&native_result));CHECK(!raw_calls&&!at_calls);
    }
}
static void native_clock_transition(void)
{
    for(;;){
        int next=pmck_next(&clocks,native_ticks,&native_clock_command);
        if(next==PMCK_HELD||next==PMCK_RESTORED)return;
        if(next==PMCK_WAIT){native_ticks=clocks.not_before;continue;}
        CHECK(next==PMCK_IO);memset(&native_result,0,sizeof(native_result));
        CHECK(pmni_clock(&clocks,&native_clock_command,&native_opening,&native_result));
        CHECK(native_result.complete&&!native_result.unknown&&native_result.issued&&native_result.returned);
        CHECK(pmck_complete(&clocks,&native_clock_command,native_result.after.ticks,1,native_result.value)>=0);
    }
}
static void native_clock_lifecycles(void)
{
    for(unsigned enabled=0;enabled<64;enabled++){
        clock_fixture(enabled,0);native_fixture();native_clock_mode=1;native_clock_transition();
        CHECK(clocks.phase==2&&writes[0]==(enabled^63));
        uint64_t now=stopped(native_ticks);CHECK(pmck_release(&clocks,&shutdown_state,now)==PMCK_WAIT);
        native_ticks=native_opening.ticks=now;native_clock_transition();
        CHECK(clocks.phase==4&&pmsr_equal(regs,initial,sizeof(regs))&&writes[1]==writes[0]);
    }
}
static void native_shutdown(void)
{
    /* Exercise actual nested pending-command adapters, with all26 stop/AXI
     * and14 reset operations. Stop RAM/doorbell are still software inputs. */
    for(int failure=-1;failure<32;failure++){
        shutdown_start=100;shutdown_begin();native_fixture();native_clock_mode=2;
        native_pdc=0xa5000001;memset(native_halt_req,0,sizeof(native_halt_req));unsigned event=0;
        for(;;){
            struct pmsd_command c={0};int result=pmsd_next(&shutdown_state,native_ticks,&c);
            if(result==PMSD_RESET_PULSED){CHECK(failure==-1);break;}
            if(result==PMSD_WAIT){CHECK(shutdown_state.phase==2);native_ticks=shutdown_state.reset.not_before;continue;}
            CHECK(result==PMSD_IO);const struct pms_sample*data=NULL;uint32_t value=0;
            if(c.phase==1&&c.command.stop.phase==1){
                unsigned step=c.command.stop.command.stop.step;
                if(step==PMS_INITIAL)data=&sample;
                if(step==PMS_SET_STOP)put(sample.out+96,0xa1);
                if(step==PMS_READBACK)value=0xa1;
                if(step==PMS_POLL){put(sample.in+96,8);data=&sample;}
                native_ticks++;
            }else{
                memset(&native_result,0,sizeof(native_result));native_fault=(int)event==failure?501:0;
                result=c.phase==2?pmni_reset(&shutdown_state,&c,&native_opening,&native_result):
                    pmni_halt(&shutdown_state,&c,&native_opening,&native_result);
                if((int)event==failure){
                    CHECK(!result&&native_result.unknown&&native_result.issued&&!native_result.complete);
                    CHECK(pmsd_complete(&shutdown_state,&c,native_ticks,0,0,NULL)==PMSD_FAILED);
                    CHECK(shutdown_state.unknown&&!shutdown_state.complete);break;
                }
                CHECK(result&&native_result.complete&&!native_result.unknown);value=native_result.value;event++;
            }
            CHECK(pmsd_complete(&shutdown_state,&c,native_ticks,1,value,data)==PMSD_WAIT);
        }
        if(failure==-1)CHECK(shutdown_state.complete&&native_pdc==0xa5000001&&event==32&&
            native_halt_req[0]==1&&native_halt_req[1]==1&&native_halt_req[2]==1);
    }
}
int main(void)
{
    legacy_clock_test();unsigned before=checks;native_faults();native_clock_lifecycles();native_shutdown();
    printf("PASS %u native MMIO caller checks, %u total (software leaves only)\n",checks-before,checks);return 0;
}
