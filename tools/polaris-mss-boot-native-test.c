/* Actual allocation/staging/assignment -> current resources -> AOP/power/
 * clocks -> native MBA startup. CPU/SMC/register leaves are software peers;
 * the assigned MBA host shadow stays inaccessible throughout this startup. */
struct pmni_arch;struct pmni_translation;struct pmni_command;
static void boot_arch_hook(struct pmni_arch*);
static void boot_at_hook(struct pmni_translation*);
static int boot_raw_hook(const struct pmni_command*,unsigned*);
#define PMAN_TEST_ARCH_HOOK boot_arch_hook
#define PMAN_TEST_AT_HOOK boot_at_hook
#define PMAN_TEST_RAW_HOOK boot_raw_hook
#define PMAN_TEST_ENTRY unused_aop_native_suite
#define EFI_XNU_MSS_BOOT_NATIVE_AVAILABLE 1
/* Fast-response SOFTWARE time model, not a physical performance claim. A
 * separate slow-delivery case must still exceed/refuse the own200us window. */
#define PGCD_TEST_ARCH_TICK_STEP 1u
#include "polaris-mss-aop-native-test.c"
#include "uefi-mss-boot-native.h"
static struct pmbn_state*boot_owner;
static struct pmbn_delivery*boot_records;
static unsigned boot_fault,boot_trigger,boot_calls,boot_scenarios,boot_status,boot_bad_status,boot_raw_delay;
static uint32_t boot_debug,boot_sleep,boot_pdc,boot_alt,boot_restart,boot_image,boot_core,boot_command;
static unsigned sleep_reads,fsm_reads,pbl_reads,mba_reads;
static int boot_selected(void){return boot_owner&&boot_owner->pending&&boot_owner->pending==boot_trigger;}
static void boot_arch_hook(struct pmni_arch*a){
#ifdef PMBN_TEST_ARCH_HOOK
    PMBN_TEST_ARCH_HOOK(a);
#endif
    if(boot_selected()&&boot_fault==3)a->ttbr0^=4096;
}
static void boot_at_hook(struct pmni_translation*t){
#ifdef PMBN_TEST_AT_HOOK
    PMBN_TEST_AT_HOOK(t);
#endif
    if(boot_selected()&&boot_fault==2)t->restored++;
}
static int boot_raw_hook(const struct pmni_command*c,unsigned*v)
{
#ifdef PMBN_TEST_RAW_HOOK
    int handled=PMBN_TEST_RAW_HOOK(c,v);if(handled>=0)return handled;
#endif
    if(!boot_owner||!boot_owner->pending)return -1;
    CHECK(!aop_owner->pending&&!clock_owner->pending&&!power->pending&&target_protected);boot_calls++;
    owner_delay+=boot_raw_delay;
    if(boot_selected()){
        if(boot_fault==1)return 0;
        if(boot_fault==4)owner_delay+=PMSC_TOTAL+1;
        if(boot_fault==5)put(image_heap+0x3030,0,8);
        if(boot_fault==6)boot_owner->mba.command.value^=4;
    }
    if(c->kind==PMNI_STORE_ORDER||c->kind==PMNI_FULL_ORDER){CHECK(!c->address&&!c->value);return 1;}
    if(c->kind==PMNI_READ){
        switch(c->address){
        case 0x4080018:*v=boot_debug;break;
        case 0xb2e0100:*v=boot_pdc;break;
        case 0x408003c:
            if(boot_sleep&1){if(++sleep_reads==2)boot_sleep&=0x7fffffff;}
            *v=boot_bad_status==1&&(boot_sleep&1)?0:boot_sleep;break;
        case 0x4180040:CHECK(boot_command&&boot_core&&boot_image);*v=++fsm_reads>1;break;
        case 0x4180004:CHECK(fsm_reads>1);*v=++pbl_reads>1?(boot_bad_status==2?2:1):0;break;
        case 0x418000c:CHECK(pbl_reads>1);*v=++mba_reads>1?(boot_bad_status==3?UINT32_MAX:boot_status):0;break;
        default:CHECK(0);
        }return 1;
    }
    CHECK(c->kind==PMNI_WRITE&&(owner->effects&PMSC_REMOTE));
    switch(c->address){
    case 0xb2e0100:CHECK(((boot_pdc^c->value)&~0x200u)==0);boot_pdc=c->value;break;
    case 0x4180044:CHECK(boot_pdc&0x200);CHECK(c->value<=1&&c->value!=boot_alt);boot_alt=c->value;break;
    case 0xc2b0000:CHECK(boot_alt&&c->value<=1&&c->value!=boot_restart);boot_restart=c->value;break;
    case 0x4080018:CHECK(!(boot_pdc&0x200)&&!boot_alt&&!boot_restart&&c->value==boot_debug);break;
    case 0x4180000:CHECK(c->value==mss->memory.claim[1].requested);boot_image=c->value;break;
    case 0x4180014:case 0x4180018:CHECK(boot_image&&!c->value);break;
    case 0x408003c:CHECK(c->value==(boot_sleep|1));boot_sleep=c->value;break;
    case 0x4080400:CHECK(boot_sleep==0x21&&c->value==1);boot_core=1;break;
    case 0x4080404:CHECK(boot_core&&c->value==1);boot_command=1;break;
    default:CHECK(0);
    }return 1;
}
static void boot_setup(void)
{
    boot_owner=0;boot_fault=boot_trigger=boot_calls=boot_bad_status=boot_raw_delay=0;boot_status=2;boot_scenarios++;
    boot_debug=0xabcd1234;boot_sleep=0x80000020;boot_pdc=0xa5000001;boot_alt=boot_restart=boot_image=boot_core=boot_command=0;
    sleep_reads=fsm_reads=pbl_reads=mba_reads=0;
    aop_setup();CHECK(aop_drive());uint32_t minimum[3];for(unsigned n=0;n<3;n++)minimum[n]=database_state->pass[1].resource[n].minimum;
    CHECK(pmsp_begin(supplies,owner->opening,minimum,power_now(),19200000)==PMSP_WAIT);
    CHECK(supply_drive(110)==PMSP_HELD&&pmpn_proxy_begin(power,proxy)&&native_proxy_drive()==PMPX_HELD);
    CHECK(pmcn_clock_begin(clock_owner,active_clocks)&&native_clock_drive()==PMCK_HELD);
    boot_owner=(void*)(arena+0x3c80000);boot_records=(void*)(arena+0x3d00000);
    CHECK(0x3700000+sizeof(*aop_records)*PMAN_RECORDS<0x3c80000&&0x3c80000+sizeof(*boot_owner)<0x3d00000);
    CHECK(0x3d00000+sizeof(*boot_records)*PMBN_RECORDS<PMMN_TEST_IMAGE_BYTES);
    memset(boot_owner,0,sizeof(*boot_owner));memset(boot_records,0,sizeof(*boot_records)*PMBN_RECORDS);
}
static int boot_drive(void)
{
    for(unsigned n=0;n<2*PMBN_RECORDS;n++){
        int result=pmbn_step(boot_owner);if(result==PMBA_READY)return 1;if(result<0)return 0;
        CHECK(result==PMBA_WAIT);struct pmba_boot*b=&boot_owner->mba;
        uint64_t at=b->phase==2?b->reset.not_before:b->next_poll;advance_to(at);
    }CHECK(0);return 0;
}
#ifndef PMBN_TEST_ENTRY
#define PMBN_TEST_ENTRY main
#endif
int PMBN_TEST_ENTRY(int argc,char**argv)
{
    aop_test_open(argc,argv);boot_setup();CHECK(pmbn_begin(boot_owner,boot_records,aop_owner));
    int ready=boot_drive();if(!ready)fprintf(stderr,"boot refusal: error=%u phase=%u step=%u child_error=%u deliveries=%u raw=%u power=%u owner=%u\n",
        boot_owner->error,boot_owner->mba.phase,boot_owner->mba.step,boot_owner->mba.error,boot_owner->deliveries,boot_calls,power->error,owner->error);
    if(!ready)fprintf(stderr,"boot time: since_window=%llu ticks; last native=%llu ticks; polls=%u\n",
        (unsigned long long)(boot_owner->mba.last-boot_owner->mba.window),
        (unsigned long long)(boot_records[boot_owner->deliveries-1].native.after.ticks-boot_records[boot_owner->deliveries-1].opening.ticks),boot_owner->mba.polls);
    CHECK(ready&&pmbn_current(boot_owner));
    CHECK(boot_owner->mba.ready==1&&boot_owner->mba.image_bytes==238304&&boot_owner->mba.mba==mss->memory.claim[1].requested&&target_protected);
    CHECK(boot_pdc==0xa5000001&&!boot_alt&&!boot_restart&&boot_debug==0xabcd1234&&active_clocks->held==63&&owner->held);
    CHECK(!pman_off(aop_owner)&&!pmsc_close_unused(owner));unsigned total=boot_owner->deliveries;
    unsigned locations[8]={1,3,5,0,0,0,0,total};
    for(unsigned n=0;n<total;n++){
        const struct pmbn_delivery*r=&boot_records[n];
        if(r->native.command.address==0x4180000&&!locations[3])locations[3]=n+1;
        if(r->native.command.address==0x408003c&&r->native.command.kind==PMNI_WRITE&&!locations[4])locations[4]=n+1;
        if(r->native.command.address==0x4080404&&!locations[5])locations[5]=n+1;
        if(r->native.command.address==0x418000c&&!locations[6])locations[6]=n+1;
    }
    boot_records[0].native.value^=1;CHECK(!pmbn_current(boot_owner));boot_records[0].native.value^=1;CHECK(pmbn_current(boot_owner));
    fprintf(stderr,"owned native MBA startup PASS (%u deliveries); checking status and failures\n",total);
    boot_setup();boot_status=1;CHECK(pmbn_begin(boot_owner,boot_records,aop_owner)&&boot_drive()&&pmbn_current(boot_owner));
    for(unsigned n=0;n<8;n++){
        CHECK(locations[n]);boot_setup();CHECK(pmbn_begin(boot_owner,boot_records,aop_owner));boot_fault=1;boot_trigger=locations[n];
        CHECK(!boot_drive()&&boot_owner->unknown&&power->unknown&&boot_owner->pending==boot_trigger&&!boot_owner->complete&&target_protected);
        unsigned prior=boot_calls;CHECK(pmbn_step(boot_owner)==PMBA_FAILED&&boot_calls==prior&&owner->held);
    }
    for(unsigned fault=2;fault<=6;fault++){
        boot_setup();CHECK(pmbn_begin(boot_owner,boot_records,aop_owner));boot_fault=fault;boot_trigger=locations[3];
        CHECK(!boot_drive()&&boot_owner->unknown&&power->unknown&&!boot_owner->complete&&target_protected);
    }
    for(unsigned status=1;status<=3;status++){
        boot_setup();CHECK(pmbn_begin(boot_owner,boot_records,aop_owner));boot_bad_status=status;
        CHECK(!boot_drive()&&boot_owner->unknown&&boot_owner->mba.unknown&&!boot_owner->complete&&target_protected);
    }
    boot_setup();CHECK(pmbn_begin(boot_owner,boot_records,aop_owner));boot_raw_delay=2000;
    CHECK(!boot_drive()&&boot_owner->unknown&&boot_owner->mba.error==PMBA_TIME&&boot_owner->mba.step==PMBA_SLEEP_POLL&&target_protected);
    boot_setup();active_clocks->held=31;CHECK(!pmbn_begin(boot_owner,boot_records,aop_owner)&&!boot_calls);
    boot_setup();stage->copied_hash[0][0]^=1;CHECK(!pmbn_begin(boot_owner,boot_records,aop_owner)&&!boot_calls);
    aop_test_close();printf("PASS %u owned native MBA checks, %u scenarios; no hardware/provider/USB or modem/WLAN claim\n",checks,boot_scenarios);return 0;
}
