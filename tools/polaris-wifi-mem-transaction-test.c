/* Software protocol peers only: no privileged instruction or firmware call. */
#include "polaris-wifi-mem-transaction.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
static struct pwmt_transaction transaction;
static struct pwma_page*page;
static unsigned checks;
#define CHECK(x) do{assert(x);checks++;}while(0)
static struct pwma_spec input(void)
{
    struct pwma_spec s={.descriptor_pa=UINT64_C(0x17e000000),
        .region_pa=0x90001000,.region_bytes=0x200000,.sources=1,.destinations=2,
        .source={PWMA_HLOS},.destination={{PWMA_HLOS,PWMA_RW},{PWMA_MSS_MSA,PWMA_RW}}};
#if defined(PWMT_TEST_MODEM)
    s.region_pa=0xf8300000;s.region_bytes=0x7800000;
    if(modem_exclusive){
        s.sources=2;s.source[1]=PWMA_MSS_MSA;s.destinations=1;
        s.destination[0]=(struct pwma_destination){PWMA_MSS_MSA,PWMA_RW};
        s.destination[1]=(struct pwma_destination){0};
    }
#endif
#if defined(PWMT_TEST_MODEM_RETURN)
    s.region_pa=0xf8300000;s.region_bytes=0x7800000;s.source[0]=PWMA_MSS_MSA;s.destinations=1;
    s.destination[0]=(struct pwma_destination){PWMA_HLOS,PWMA_RWX};s.destination[1]=(struct pwma_destination){0};
#endif
    return s;
}
static void begin(void)
{
    memset(&transaction,0,sizeof(transaction));memset(page,0,sizeof(*page));
    struct pwma_spec spec=input();
    CHECK(pwmt_begin(&transaction,page,&spec,100,19200000)==PWMT_WAIT);
}
static struct pwmk_record cache_record(unsigned operation,unsigned shift)
{
    return (struct pwmk_record){.address=(uintptr_t)page,.ctr_before=(uint64_t)shift<<16,
        .ctr_after=(uint64_t)shift<<16,.el=4,.sctlr=5,.operation=operation,
        .line_bytes=4u<<shift,.lines_issued=4096/(4u<<shift),.lines_returned=4096/(4u<<shift),
        .attempted=1,.barrier_issued=1,.barrier_returned=1,.complete=1};
}
static struct pwmt_command next(uint64_t now,unsigned operation)
{
    struct pwmt_command command={0};CHECK(pwmt_next(&transaction,now,&command)==PWMT_IO);
    CHECK(command.operation==operation&&command.page==(uintptr_t)page);return command;
}
static void clean(void)
{
    struct pwmt_command command=next(101,PWMT_CLEAN);
    struct pwmk_record cache=cache_record(PWMK_CLEAN_INVALIDATE,4);
    CHECK(pwmt_complete(&transaction,&command,102,1,NULL,&cache)==PWMT_WAIT);
}
static void success(unsigned rounds)
{
    begin();clean();struct pwma_registers previous=transaction.initial;
    CHECK(!mprotect(page,4096,PROT_NONE));
    /* First SMC requires the pre-cache byte check, so admit its page only for
     * that issue; every pending/continuation/post-SMC step stays inaccessible. */
    for(unsigned n=0;n<rounds;n++){
        if(!n)CHECK(!mprotect(page,4096,PROT_READ));
        struct pwmt_command command=next(103+n*2,PWMT_SMC);
        CHECK(!memcmp(&command.registers,&previous,sizeof(previous)));
        if(!n)CHECK(!mprotect(page,4096,PROT_NONE));
        struct pwma_registers response={{n+1==rounds?0:1,n+1==rounds?0:0x1117,
            0x11223344+n,0x55667788+n,0x99887766+n,0x22334455+n,0xabcdef00+n}};
        CHECK(pwmt_complete(&transaction,&command,104+n*2,1,&response,NULL)==PWMT_WAIT);
        CHECK(!memcmp(&transaction.event[n+1].response,&response,sizeof(response)));
        previous=response;
    }
    struct pwmt_command command=next(120,PWMT_INVALIDATE);
    CHECK(!transaction.complete&&transaction.rounds==rounds);
    CHECK(!mprotect(page,4096,PROT_READ|PROT_WRITE));
    struct pwmk_record cache=cache_record(PWMK_INVALIDATE,4);
    CHECK(pwmt_complete(&transaction,&command,121,1,NULL,&cache)==PWMT_ZERO);
    CHECK(transaction.complete==1&&!transaction.unknown&&transaction.events==rounds+2);
    CHECK(pwmt_next(&transaction,122,&command)==PWMT_ZERO);
    CHECK(pwmt_complete(&transaction,&command,123,1,NULL,&cache)==PWMT_FAILED);
    CHECK(transaction.unknown&&transaction.error==PWMT_REENTRY);
}
static void cache_failures(void)
{
    for(unsigned kind=0;kind<15;kind++){
        begin();struct pwmt_command command=next(101,PWMT_CLEAN);
        struct pwmk_record cache=cache_record(PWMK_CLEAN_INVALIDATE,4);
        switch(kind){
        case 0:cache.address+=4096;break;case 1:cache.operation=PWMK_INVALIDATE;break;
        case 2:cache.ctr_after++;break;case 3:cache.el=8;break;case 4:cache.sctlr=1;break;
        case 5:cache.line_bytes*=2;break;case 6:cache.lines_issued--;break;
        case 7:cache.lines_returned--;break;case 8:cache.attempted=0;break;
        case 9:cache.barrier_issued=0;break;case 10:cache.barrier_returned=0;break;
        case 11:cache.complete=0;break;case 12:cache.error=1;break;
        case 13:cache.reserved=1;break;case 14:cache.ctr_before=cache.ctr_after=0;break;
        }
        CHECK(pwmt_complete(&transaction,&command,102,1,NULL,&cache)==PWMT_FAILED);
        CHECK(transaction.error==PWMT_CACHE&&transaction.unknown&&!transaction.rounds);
        CHECK(pwmt_next(&transaction,103,&command)==PWMT_FAILED);
    }
    for(unsigned shift=0;shift<16;shift++){
        struct pwmk_record cache=cache_record(PWMK_CLEAN_INVALIDATE,shift);
        CHECK(pwmk_record_valid(&cache,(uintptr_t)page,PWMK_CLEAN_INVALIDATE)==(shift>=2&&shift<=10));
    }
}
static void changed_pages(void)
{
    /* First and last descriptors and unused tail are equally immutable. */
    const unsigned offsets[]={0,64,128,256,312,4095};
    for(unsigned phase=0;phase<3;phase++)for(unsigned i=0;i<sizeof(offsets)/sizeof(*offsets);i++){
        begin();struct pwmt_command command;
        if(phase)clean();
        if(phase==2){
            command=next(103,PWMT_SMC);struct pwma_registers response={{0}};
            CHECK(pwmt_complete(&transaction,&command,104,1,&response,NULL)==PWMT_WAIT);
            command=next(105,PWMT_INVALIDATE);
        }
        page->data[offsets[i]]^=1;
        if(phase<2)CHECK(pwmt_next(&transaction,105,&command)==PWMT_FAILED);
        else{
            struct pwmk_record cache=cache_record(PWMK_INVALIDATE,4);
            CHECK(pwmt_complete(&transaction,&command,106,1,NULL,&cache)==PWMT_FAILED);
        }
        CHECK(transaction.error==PWMT_CHANGED_PAGE&&transaction.unknown&&!transaction.complete);
    }
}
static void smc_failures(void)
{
    const uint64_t values[][2]={{UINT64_MAX,0},{UINT64_MAX-11,0},{0,1},{2,0}};
    for(unsigned i=0;i<sizeof(values)/sizeof(*values);i++){
        begin();clean();struct pwmt_command command=next(103,PWMT_SMC);
        struct pwma_registers response={{values[i][0],values[i][1],2,3,4,5,6}};
        CHECK(pwmt_complete(&transaction,&command,104,1,&response,NULL)==PWMT_FAILED);
        CHECK(transaction.rounds==1&&transaction.unknown&&transaction.error==PWMT_TRANSPORT);
        CHECK(!memcmp(&response,&transaction.event[1].response,sizeof(response)));
        CHECK(pwmt_next(&transaction,105,&command)==PWMT_FAILED);
    }
    begin();clean();
    for(unsigned i=0;i<PWMT_ROUNDS;i++){
        struct pwmt_command command=next(103+i*2,PWMT_SMC);
        struct pwma_registers response={{1,11,22,33,44,55,66+i}};
        CHECK(pwmt_complete(&transaction,&command,104+i*2,1,&response,NULL)==
            (i+1==PWMT_ROUNDS?PWMT_FAILED:PWMT_WAIT));
    }
    CHECK(transaction.error==PWMT_LIMIT&&transaction.unknown&&transaction.rounds==PWMT_ROUNDS);
}
static void control_failures(void)
{
    begin();struct pwmt_command command=next(101,PWMT_CLEAN),other;
    CHECK(pwmt_next(&transaction,102,&other)==PWMT_FAILED&&transaction.error==PWMT_REENTRY);
    for(unsigned kind=0;kind<8;kind++){
        begin();command=next(101,PWMT_CLEAN);struct pwmk_record cache=cache_record(PWMK_CLEAN_INVALIDATE,4);
        switch(kind){case 0:command.sequence++;break;case 1:command.page+=4096;break;
        case 2:command.operation=PWMT_SMC;break;case 3:command.registers.x[6]=1;break;
        case 4:transaction.step=PWMT_SMC;break;case 5:transaction.pending++;break;
        case 6:transaction.events=PWMT_EVENTS+1;break;case 7:transaction.event[0].issued=0;break;}
        CHECK(pwmt_complete(&transaction,&command,102,1,NULL,&cache)==PWMT_FAILED);
        CHECK(transaction.unknown&&transaction.error==PWMT_REENTRY);
    }
    for(unsigned kind=0;kind<6;kind++){
        begin();command=next(101,PWMT_CLEAN);struct pwmk_record cache=cache_record(PWMK_CLEAN_INVALIDATE,4);
        uint64_t now=kind==0?100:kind==1?101+PWMT_TICKS:102;
        int returned=kind==2?0:kind==3?2:1;struct pwma_registers response={{0}};
        CHECK(pwmt_complete(&transaction,&command,now,returned,kind==4?&response:NULL,kind==5?NULL:&cache)==PWMT_FAILED);
        CHECK(transaction.unknown&&!transaction.complete);
        if(kind==2||kind==3){
            CHECK(transaction.event[0].return_raw==returned);
            CHECK(!memcmp(&transaction.event[0].cache,&cache,sizeof(cache)));
        }
    }
    begin();CHECK(pwmt_next(&transaction,101,(void*)&transaction)==PWMT_FAILED);
    begin();CHECK(pwmt_next(&transaction,101,(void*)page)==PWMT_FAILED);
    begin();CHECK(pwmt_next(&transaction,99,&command)==PWMT_FAILED);
    begin();CHECK(pwmt_next(&transaction,101+PWMT_TICKS,&command)==PWMT_FAILED);
    begin();command=next(101,PWMT_CLEAN);
    CHECK(pwmt_complete(&transaction,&command,102,1,NULL,(void*)page)==PWMT_FAILED);
    begin();command=next(101,PWMT_CLEAN);
    CHECK(pwmt_complete(&transaction,&command,102,1,NULL,(void*)&transaction)==PWMT_FAILED);
    begin();struct pwma_spec spec=input();
    CHECK(pwmt_begin(&transaction,page,&spec,100,19200000)==PWMT_FAILED);
    CHECK(pwmt_begin(NULL,page,&spec,100,19200000)==PWMT_FAILED);
    CHECK(pwmt_begin(&transaction,NULL,&spec,100,19200000)==PWMT_FAILED);
    CHECK(pwmt_begin(&transaction,page,NULL,100,19200000)==PWMT_FAILED);
    memset(&transaction,0,sizeof(transaction));memset(page,0,sizeof(*page));
    CHECK(pwmt_begin(&transaction,page,&spec,100,24000000)==PWMT_FAILED);
    CHECK(pwmt_begin(&transaction,page,&spec,0,19200000)==PWMT_FAILED);
    CHECK(pwmt_begin(&transaction,page,(void*)page,100,19200000)==PWMT_FAILED);
    CHECK(pwmt_begin(&transaction,(void*)&transaction,&spec,100,19200000)==PWMT_FAILED);
}
static void auth_budget(void)
{
    struct pwmt_command c;struct pwmk_record clean_record=cache_record(PWMK_CLEAN_INVALIDATE,4);
    struct pwmk_record invalidate_record=cache_record(PWMK_INVALIDATE,4);struct pwma_registers response={{0}};
    /* Exact1s end allowed, all three issued steps each no more than100ms. */
    begin();CHECK(pwmt_auth_next(&transaction,100,&c)==PWMT_IO);
    CHECK(pwmt_auth_complete(&transaction,&c,100+PWMT_TICKS,1,NULL,&clean_record)==PWMT_WAIT);
    CHECK(pwmt_auth_next(&transaction,100+3*PWMT_TICKS,&c)==PWMT_IO);
    CHECK(!mprotect(page,4096,PROT_NONE));
    CHECK(pwmt_auth_complete(&transaction,&c,100+4*PWMT_TICKS,1,&response,NULL)==PWMT_WAIT);
    CHECK(pwmt_auth_next(&transaction,100+9*PWMT_TICKS,&c)==PWMT_IO);
    CHECK(!mprotect(page,4096,PROT_READ|PROT_WRITE));
    CHECK(pwmt_auth_complete(&transaction,&c,100+PWMT_AUTH_TICKS,1,NULL,&invalidate_record)==PWMT_ZERO);
    for(unsigned kind=0;kind<4;kind++){
        begin();uint64_t issue=kind==3?100+PWMT_AUTH_TICKS:100;
        CHECK(pwmt_auth_next(&transaction,issue,&c)==PWMT_IO);
        uint64_t done=kind==0?99:kind==1?100+PWMT_TICKS+1:kind==2?100+PWMT_AUTH_TICKS+1:issue+1;
        CHECK(pwmt_auth_complete(&transaction,&c,done,1,NULL,&clean_record)==PWMT_FAILED);
        CHECK(transaction.error==PWMT_TIME&&transaction.unknown&&!transaction.complete);
    }
    begin();CHECK(pwmt_auth_next(&transaction,101+PWMT_AUTH_TICKS,&c)==PWMT_FAILED);
    CHECK(transaction.events==0&&transaction.error==PWMT_TIME);
    /* A delayed SMC must still fail after its saved raw response is captured. */
    begin();clean();CHECK(pwmt_auth_next(&transaction,103,&c)==PWMT_IO);
    CHECK(!mprotect(page,4096,PROT_NONE));
    CHECK(pwmt_auth_complete(&transaction,&c,104+PWMT_TICKS,1,&response,NULL)==PWMT_FAILED);
    CHECK(transaction.error==PWMT_TIME&&transaction.pending==2&&transaction.event[1].returned);
    CHECK(!mprotect(page,4096,PROT_READ|PROT_WRITE));
}
int main(void)
{
    page=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    assert(page!=MAP_FAILED);
    for(unsigned rounds=1;rounds<=PWMT_ROUNDS;rounds++)success(rounds);
    cache_failures();changed_pages();smc_failures();control_failures();auth_budget();
    CHECK(!munmap(page,4096));printf("PASS %u secure memory transaction checks (software only)\n",checks);return 0;
}
