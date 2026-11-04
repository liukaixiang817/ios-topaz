/* Real software producers feed the metadata/native adapter. No hardware. */
#pragma push_macro("main")
#undef main
#define main unused_mba_suite
#include "polaris-mss-mba-boot-test.c"
#pragma pop_macro("main")
#define EFI_XNU_MSS_NATIVE_IO_AVAILABLE 1
#define POLARIS_MSS_NATIVE_SOFTWARE_PEER 1
#include "../shim/polaris/uefi-mss-mmio-native.h"
static struct pmmd_metadata metadata;
static struct pwmt_transaction metadata_tx[2];
static struct pwma_page metadata_page[2];
static struct pmni_result metadata_io;
static struct pmni_arch metadata_arch;
static uint64_t metadata_counter;
static unsigned raw_failure,raw_count,status_value;
static int pmni_arch_read(struct pmni_arch*a)
{*a=metadata_arch;a->ticks=++metadata_counter;return 1;}
static int pmni_translate(struct pmni_translation*t)
{
    t->saved=t->restored=0x1234;t->read_par=t->write_par=t->page|0x200;
    t->read_issued=t->read_returned=t->write_issued=t->write_returned=t->restore_issued=t->restore_returned=1;return 1;
}
static int pmni_raw(const struct pmni_command*c,uint32_t*value)
{
#if defined(PMIM_TEST_ROUTER)
    if(modem_testing)return modem_raw(c,value);
#endif
    raw_count++;if(raw_failure)return 0;
    const uint64_t addresses[5]={0x4180018,0x4180010,0x4180008,0,0x418000c};
    const unsigned kinds[5]={2,2,2,4,1},values[5]={0,0x90200000,1,0,0};
    CHECK(metadata.step<5&&c->address==addresses[metadata.step]&&c->kind==kinds[metadata.step]&&c->value==values[metadata.step]);
    if(c->kind==PMNI_READ)*value=status_value;return 1;
}
static uint64_t metadata_assign(unsigned slot,uint64_t now)
{
    struct pwmt_transaction*t=&metadata_tx[slot];struct pwma_page*p=&metadata_page[slot];
    memset(t,0,sizeof(*t));memset(p,0,sizeof(*p));
    struct pwma_spec spec={.descriptor_pa=(uintptr_t)p,.region_pa=0x90200000,.region_bytes=0x3000,
        .sources=1,.source={slot?PWMA_MSS_MSA:PWMA_HLOS},.destinations=1,
        .destination={{slot?PWMA_HLOS:PWMA_MSS_MSA,slot?PWMA_RWX:PWMA_RW}}};
    CHECK(pwmt_begin(t,p,&spec,++now,19200000)==PWMT_WAIT);
    for(unsigned step=PWMT_CLEAN;step<=PWMT_INVALIDATE;step++){
        struct pwmt_command c;CHECK(pwmt_next(t,++now,&c)==PWMT_IO&&c.operation==step);
        struct pwmk_record cache={.address=(uintptr_t)p,.ctr_before=4u<<16,.ctr_after=4u<<16,.el=4,.sctlr=5,
            .operation=step==PWMT_CLEAN?PWMK_CLEAN_INVALIDATE:PWMK_INVALIDATE,.line_bytes=64,.lines_issued=64,
            .lines_returned=64,.attempted=1,.barrier_issued=1,.barrier_returned=1,.complete=1};
        struct pwma_registers zero={0};CHECK(pwmt_complete(t,&c,++now,1,step==PWMT_SMC?&zero:NULL,
            step==PWMT_SMC?NULL:&cache)==(step==PWMT_INVALIDATE?PWMT_ZERO:PWMT_WAIT));
    }return now+1;
}
static uint64_t metadata_inputs(void)
{
    mba_run(1,-1,0,0,0);memset(&metadata,0,sizeof(metadata));
    metadata_counter=metadata_assign(0,mba.last+1);raw_count=raw_failure=0;status_value=3;
    metadata_arch=(struct pmni_arch){.el=4,.mpidr=0x81000000,.ttbr0=0x10004000,.tcr=0x80803520,.sctlr=5,
        .mair=0xffbb4400,.daif=0xc0,.sre=7,.cpacr=0x300000,.frequency=19200000,.ticks=metadata_counter};
    return metadata_counter;
}
static void metadata_start(void)
{
    uint64_t now=metadata_inputs();CHECK(pmmd_begin(&metadata,&mba,&clocks,&metadata_tx[0],8412,now)==PMMD_WAIT);
    CHECK(metadata.allocation_bytes==0x3000&&metadata.bytes==8412&&metadata.mba_ready_at==mba.last);
}
static void metadata_run(int failed,unsigned fault,unsigned delay)
{
    metadata_start();unsigned event=0;
    for(;;){
        struct pmmd_command c;int result=pmmd_next(&metadata,metadata_counter,&c);
        if(result==PMMD_AUTHENTICATED){CHECK(failed<0&&event==5+delay);return;}
        if(result==PMMD_WAIT){
            unsigned events=metadata.events;CHECK(pmmd_next(&metadata,metadata.next_poll-1,&c)==PMMD_WAIT&&metadata.events==events);
            metadata_counter=metadata.next_poll;continue;
        }
        CHECK(result==PMMD_IO);memset(&metadata_io,0,sizeof(metadata_io));
        struct pmni_arch opening;CHECK(pmni_arch_read(&opening));
        if((int)event==failed){
            if(fault==1)raw_failure=1;
            else if(fault==2){c.address^=4;unsigned before=raw_count;CHECK(!pmni_metadata(&metadata,&c,&opening,&metadata_io)&&raw_count==before);return;}
            else if(fault==3){CHECK(pmmd_next(&metadata,metadata_counter,&c)==PMMD_FAILED);return;}
            else if(fault==4){CHECK(pmmd_complete(&metadata,&c,metadata.opening+PMMD_TIMEOUT+19200001,1,0)==PMMD_FAILED);return;}
        }
        status_value=c.step==PMMD_STATUS&&metadata.polls<=delay?(metadata.polls-1)%3:3;
        result=pmni_metadata(&metadata,&c,&opening,&metadata_io);
        if((int)event==failed){
            CHECK(!result&&metadata_io.unknown&&metadata_io.issued&&!metadata_io.complete);
            CHECK(pmmd_complete(&metadata,&c,metadata_counter,0,0)==PMMD_FAILED);
            CHECK(metadata.unknown&&clocks.phase==2&&mba.ready);return;
        }
        CHECK(result&&metadata_io.complete&&!metadata_io.unknown);
        CHECK(pmmd_complete(&metadata,&c,metadata_io.after.ticks,1,metadata_io.value)>=0);event++;
    }
}
static void return_cases(void)
{
    for(unsigned fault=0;fault<12;fault++){
        metadata_run(-1,0,0);metadata_assign(1,metadata.authenticated_at+1);
        struct pwmt_transaction*t=&metadata_tx[1];
        switch(fault){
        case 1:t->unknown=1;break;case 2:t->complete=0;break;case 3:t->pending=1;break;
        case 4:t->opening=metadata.authenticated_at-1;break;case 5:t->page=metadata.assignment_page;break;
        case 6:t->spec.region_pa+=4096;break;case 7:t->spec.region_bytes=4096;break;
        case 8:t->spec.source[0]=PWMA_HLOS;break;case 9:t->spec.destination[0].vmid=PWMA_MSS_MSA;break;
        case 10:t->spec.destination[0].permissions=PWMA_RW;break;case 11:metadata.phase=1;break;
        }
        CHECK(pmmd_return(&metadata,t)==(fault?PMMD_FAILED:PMMD_RETURNED_ZERO));
        if(fault)CHECK(metadata.unknown&&!metadata.returned_at);
        else{struct pmmd_command c;CHECK(pmmd_next(&metadata,t->last,&c)==PMMD_RETURNED_ZERO&&metadata.returned_at==t->last);}
    }
}
static void status_failures(void)
{
    for(unsigned failure=0;failure<3;failure++){
        metadata_start();unsigned iterations=0;
        for(;;){
            struct pmmd_command c;int result=pmmd_next(&metadata,metadata_counter,&c);
            if(result<0)break;
            if(!result){metadata_counter=metadata.next_poll;continue;}
            CHECK(result==PMMD_IO);memset(&metadata_io,0,sizeof(metadata_io));
            status_value=failure==0?0:failure==1?0xffffffff:4;
            struct pmni_arch opening;CHECK(pmni_arch_read(&opening));
            CHECK(pmni_metadata(&metadata,&c,&opening,&metadata_io));
            result=pmmd_complete(&metadata,&c,metadata_io.after.ticks,1,metadata_io.value);
            if(result<0)break;CHECK(++iterations<510);
        }
        CHECK(metadata.unknown&&!metadata.authenticated_at&&!metadata.returned_at);
    }
}
static void input_failures(void)
{
    for(unsigned fault=0;fault<13;fault++){
        uint64_t now=metadata_inputs(),bytes=8412;
        switch(fault){
        case 0:mba.ready=0;break;case 1:mba.unknown=1;break;case 2:clocks.phase=4;break;
        case 3:clocks.epoch++;break;case 4:metadata_tx[0].opening=mba.last-1;break;
        case 5:metadata_tx[0].unknown=1;break;case 6:metadata_tx[0].spec.region_pa=mba.mba;break;
        case 7:metadata_tx[0].spec.region_bytes=4096;break;case 8:metadata_tx[0].spec.destination[0].vmid=24;break;
        case 9:metadata_tx[0].spec.source[0]=15;break;case 10:bytes=0;break;
        case 11:bytes=65537;break;case 12:now=UINT64_MAX;break;
        }
        CHECK(pmmd_begin(&metadata,&mba,&clocks,&metadata_tx[0],bytes,now)==PMMD_FAILED&&!metadata.events&&!metadata.published);
    }
}
int main(void)
{
    metadata_run(-1,0,3);
    for(int event=0;event<5;event++)for(unsigned fault=1;fault<=4;fault++)metadata_run(event,fault,0);
    return_cases();status_failures();input_failures();
    printf("PASS %u metadata/native/secure-return checks (software only)\n",checks);return 0;
}
