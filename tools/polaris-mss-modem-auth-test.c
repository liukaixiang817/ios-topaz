/* Actual metadata/assignment producers, software RMB peer. No segment-copy
 * or Qualcomm execution claim: publication is an explicit parent boundary. */
#include <stdint.h>
struct pmni_command;
static unsigned modem_testing;
static int modem_raw(const struct pmni_command*,uint32_t*);
#define PMIM_TEST_ROUTER 1
#define EFI_XNU_MSS_MODEM_IO_AVAILABLE 1
#define main unused_metadata_suite
#include "polaris-mss-metadata-test.c"
#undef main
#include "uefi-mss-firmware-binding.h"
static struct pmim_auth modem;
static struct pwmt_transaction modem_tx[2];
static struct pwma_page modem_page[2];
static struct pmni_result modem_io;
static unsigned modem_reads,modem_raw_calls,modem_failure,modem_fault,modem_delay;
static unsigned exclusive_fault;
static int modem_raw(const struct pmni_command*c,uint32_t*value)
{
    modem_raw_calls++;if(modem_failure&&modem_raw_calls==modem_failure)return 0;
    CHECK(modem.pending==modem.events&&modem.events<=PMIM_EVENTS);
    const struct pmim_command*pending=&modem.event[modem.events-1].command;
    CHECK(c->address==pending->address&&c->kind==pending->kind&&c->value==pending->value);
    if(c->kind==PMNI_READ){
        modem_reads++;
        if(modem.step==PMIM_LENGTH_READ)*value=modem.length+(modem_fault==1);
        else *value=modem_fault==2?0xffffffff:modem_fault==3?5:
            modem.step==PMIM_FINAL&&modem.polls>modem_delay?4:3;
    }return 1;
}
static uint64_t modem_assign(unsigned exclusive,uint64_t now)
{
    struct pwmt_transaction*t=&modem_tx[exclusive];struct pwma_page*p=&modem_page[exclusive];
    memset(t,0,sizeof(*t));memset(p,0,sizeof(*p));
    struct pwma_spec spec={.descriptor_pa=(uintptr_t)p,.region_pa=0xf8300000,.region_bytes=0x7800000,
        .sources=1,.source={PWMA_HLOS},.destinations=2,
        .destination={{PWMA_HLOS,PWMA_RW},{PWMA_MSS_MSA,PWMA_RW}}};
    if(exclusive){spec.sources=2;spec.source[1]=PWMA_MSS_MSA;spec.destinations=1;
        spec.destination[0]=(struct pwma_destination){PWMA_MSS_MSA,PWMA_RW};spec.destination[1]=(struct pwma_destination){0};}
    CHECK(pwmt_begin_modem(t,p,&spec,++now,19200000)==PWMT_WAIT);
    for(unsigned step=PWMT_CLEAN;step<=PWMT_INVALIDATE;step++){
        struct pwmt_command c;CHECK(pwmt_next(t,++now,&c)==PWMT_IO&&c.operation==step);
        struct pwmk_record cache={.address=(uintptr_t)p,.ctr_before=4u<<16,.ctr_after=4u<<16,.el=4,.sctlr=5,
            .operation=step==PWMT_CLEAN?PWMK_CLEAN_INVALIDATE:PWMK_INVALIDATE,.line_bytes=64,.lines_issued=64,
            .lines_returned=64,.attempted=1,.barrier_issued=1,.barrier_returned=1,.complete=1};
        struct pwma_registers zero={0};CHECK(pwmt_complete(t,&c,++now,1,step==PWMT_SMC?&zero:NULL,
            step==PWMT_SMC?NULL:&cache)==(step==PWMT_INVALIDATE?PWMT_ZERO:PWMT_WAIT));
    }return now+1;
}
static void modem_start(void)
{
    modem_testing=0;metadata_run(-1,0,0);uint64_t now=metadata_assign(1,metadata.last+1);
    CHECK(pmmd_return(&metadata,&metadata_tx[1])==PMMD_RETURNED_ZERO);
    now=modem_assign(0,now);memset(&modem,0,sizeof(modem));
    CHECK(pmim_begin(&modem,&metadata,&clocks,&modem_tx[0],pmsf_segments,now)==PMIM_NEED_SEGMENT);
    metadata_counter=now;modem_reads=modem_raw_calls=0;modem_testing=1;
}
static void modem_run(unsigned failure,unsigned fault,unsigned delay)
{
    modem_failure=failure;modem_fault=fault;modem_delay=delay;modem_start();unsigned starts=0,commands=0;
    for(unsigned iteration=0;iteration<1500;iteration++){
        struct pmim_command c;int result=pmim_next(&modem,++metadata_counter,&c);
        if(result==PMIM_NEED_SEGMENT){CHECK(pmim_publish(&modem,modem.segment,++metadata_counter)==PMIM_WAIT);continue;}
        if(result==PMIM_NEED_EXCLUSIVE){metadata_counter=modem_assign(1,metadata_counter);
            struct pwmt_transaction*t=&modem_tx[1];
            switch(exclusive_fault){
            case 1:t->unknown=1;break;case 2:t->complete=0;break;case 3:t->spec.region_pa+=0x100000;break;
            case 4:t->spec.region_bytes-=4096;break;case 5:t->spec.sources=1;break;
            case 6:t->spec.destination[0].vmid=PWMA_HLOS;break;case 7:t->opening=modem.last-1;break;
            case 8:t->page=modem.shared_page;break;
            }
            if(exclusive_fault){CHECK(pmim_exclusive(&modem,t,metadata_counter)==PMIM_FAILED&&modem.unknown&&!modem.exclusive_at);return;}
            CHECK(pmim_exclusive(&modem,&modem_tx[1],metadata_counter)==PMIM_WAIT);continue;}
        if(result==PMIM_WAIT){metadata_counter=modem.next_poll;continue;}
        if(result==PMIM_FAILED){CHECK(delay>=501&&modem.unknown&&!modem.authenticated_at);return;}
        if(result==PMIM_AUTHENTICATED){
            CHECK(!failure&&!fault&&modem.segment==28&&modem.submitted==28&&starts==1&&commands==1);
            CHECK(modem.length==124977057&&modem.exclusive_at&&modem.events==115+delay&&modem.polls==1+delay);return;
        }
        CHECK(result==PMIM_IO);starts+=c.step==PMIM_START;commands+=c.step==PMIM_COMMAND;
        struct pmni_arch opening;CHECK(pmni_arch_read(&opening));memset(&modem_io,0,sizeof(modem_io));
        int returned=pmni_modem(&modem,&c,&opening,&modem_io);
        if(failure&&modem_raw_calls==failure){CHECK(!returned&&modem_io.unknown&&modem_io.issued);}
        else CHECK(returned&&modem_io.complete&&!modem_io.unknown);
        result=pmim_complete(&modem,&c,metadata_counter,returned,modem_io.value);
        if(result<0){CHECK((failure||fault)&&modem.unknown&&!modem.authenticated_at);return;}
    }CHECK(0);
}
int main(void)
{
    modem_run(0,0,0);modem_run(0,0,4);
    for(unsigned event=1;event<=115;event++)modem_run(event,0,0);
    for(unsigned fault=1;fault<=3;fault++)modem_run(0,fault,0);
    modem_run(0,0,501);
    for(exclusive_fault=1;exclusive_fault<=8;exclusive_fault++)modem_run(0,0,0);
    exclusive_fault=0;
    for(unsigned fault=0;fault<20;fault++){
        modem_start();struct pmsf_segment segments[28];memcpy(segments,pmsf_segments,sizeof(segments));
        switch(fault){
        case 0:metadata.phase=2;break;case 1:metadata.returned_at=0;break;case 2:metadata.unknown=1;break;
        case 3:clocks.held=0;break;case 4:clocks.epoch++;break;case 5:modem_tx[0].unknown=1;break;
        case 6:modem_tx[0].spec.destination[1].vmid=PWMA_WLAN;break;
        case 7:modem_tx[0].opening=metadata.returned_at-1;break;
        case 8:segments[0].index=3;break;case 9:segments[0].target_offset=4096;break;
        case 10:segments[27].memsz--;break;case 11:segments[3].filesz=segments[3].memsz+1;break;
        case 12:segments[1].target_offset=0;break;case 13:segments[2].alignment=8192;break;
        case 14:segments[4].flags=0;break;case 15:segments[3].asset=UINT32_MAX;break;
        case 16:segments[12].asset=2;break;case 17:segments[4].asset=27;break;
        case 18:modem_tx[0].spec.region_pa+=4096;break;case 19:modem_tx[0].spec.region_pa=0xf8900000;break;
        }
        memset(&modem,0,sizeof(modem));CHECK(pmim_begin(&modem,&metadata,&clocks,&modem_tx[0],segments,metadata_counter)==PMIM_FAILED);
        CHECK(!modem.events&&!modem.submitted&&!modem.authenticated_at);
    }
    for(unsigned fault=0;fault<8;fault++){
        modem_failure=modem_fault=modem_delay=0;modem_start();
        if(fault<4){
            if(fault==0)CHECK(pmim_publish(&modem,1,++metadata_counter)==PMIM_FAILED);
            if(fault==1)CHECK(pmim_publish(&modem,0,modem.opening+PMIM_TOTAL+1)==PMIM_FAILED);
            if(fault==2)CHECK(pmim_exclusive(&modem,&modem_tx[0],++metadata_counter)==PMIM_FAILED);
            if(fault==3){CHECK(pmim_publish(&modem,0,++metadata_counter)==PMIM_WAIT);CHECK(pmim_publish(&modem,0,++metadata_counter)==PMIM_FAILED);}
        }else{
            CHECK(pmim_publish(&modem,0,++metadata_counter)==PMIM_WAIT);struct pmim_command c;
            CHECK(pmim_next(&modem,++metadata_counter,&c)==PMIM_IO);struct pmni_arch opening;CHECK(pmni_arch_read(&opening));
            if(fault==4)c.address+=4;if(fault==5)c.sequence++;if(fault==6)c.value++;if(fault==7)c.segment++;
            memset(&modem_io,0,sizeof(modem_io));CHECK(!pmni_modem(&modem,&c,&opening,&modem_io)&&!modem_raw_calls);
        }
    }
    printf("PASS %u modem RMB authentication checks; software only, no copy/ownership claim\n",checks);return 0;
}
