/* Actual power/native clock composition, with an independent register peer.
 * STOP/halt/reset is an actual software protocol producer in the peer TU;
 * no claim that its leaves or this test touch physical hardware. */
struct pmni_arch;struct pmni_translation;struct pmni_command;
static void clock_arch_hook(struct pmni_arch*);
static int clock_at_hook(struct pmni_translation*);
static int clock_raw_hook(const struct pmni_command*,unsigned*);
#define PMPN_TEST_ARCH_HOOK clock_arch_hook
#define PMPN_TEST_AT_HOOK clock_at_hook
#define PMPN_TEST_RAW_HOOK clock_raw_hook
#define PMPN_TEST_ENTRY unused_power_suite
#define EFI_XNU_MSS_PROXY_IO_AVAILABLE 1
#define EFI_XNU_MSS_CLOCK_NATIVE_AVAILABLE 1
#include "polaris-mss-power-native-test.c"
#include "uefi-mss-clock-native.h"
uint64_t pmpn_test_stop(struct pmsd_shutdown*,uint64_t,uint64_t,unsigned*);
static struct pmcn_state*clock_owner;
static struct pmcn_delivery*clock_records;
static struct pmck_lifecycle*active_clocks;
static struct pmsd_shutdown*stop_record;
static uint32_t clock_regs[7],clock_original[7];
static const uint64_t clock_addresses[]={0x18a000,0x18a154,0x152004,0x138004,0x18a150,0x18a004,0x134004};
static unsigned clock_fault,clock_trigger,clock_reads,clock_writes,clock_orders,clock_scenarios;
static int clock_selected(void){return clock_owner&&clock_owner->pending&&clock_owner->pending==clock_trigger;}
static void clock_arch_hook(struct pmni_arch*a)
{if(clock_selected()&&clock_fault==3)a->ttbr0^=4096;}
static int clock_at_hook(struct pmni_translation*t)
{if(clock_selected()&&clock_fault==2)t->restored++;return 1;}
static int clock_raw_hook(const struct pmni_command*c,unsigned*v)
{
    CHECK(clock_owner&&clock_owner->pending&&power->pending==0);
    if(c->kind==PMNI_WRITE)clock_writes++;else if(c->kind==PMNI_READ)clock_reads++;else clock_orders++;
    if(clock_selected()){
        if(clock_fault==1)return 0;
        if(clock_fault==4)owner_delay+=PMCK_LIMIT+1;
        if(clock_fault==5)put(image_heap+0x3030,0,8);
        if(clock_fault==6){
            if(clock_records[clock_owner->pending-1].kind==1)proxy->event[proxy->events-1].command.value^=4;
            else active_clocks->event[active_clocks->events-1].command.value^=4;
        }
    }
    if(c->kind==PMNI_FULL_ORDER){CHECK(!c->address&&!c->value);return 1;}
    unsigned n=0;while(n<7&&clock_addresses[n]!=c->address)n++;CHECK(n<7);
    if(c->kind==PMNI_WRITE){
        CHECK(owner->effects&PMSC_POWER);CHECK(n!=3&&n!=6);
        clock_regs[n]=c->value&(n==2?UINT32_MAX:0x0fffffff);return 1;
    }
    CHECK(c->kind==PMNI_READ);uint32_t value=clock_regs[n];
    if(n==2){*v=value;return 1;}
    unsigned on=n==3?!!(clock_regs[2]&0x400):n==6?!!(clock_regs[2]&0x2000):!!(value&1);
    if(value&2)on=0;*v=(value&0x0fffffff)|(on?0:0x80000000);return 1;
}
static void native_clock_setup(unsigned enabled,unsigned hwcg,unsigned prng_on)
{
    clock_owner=0;clock_fault=clock_trigger=clock_reads=clock_writes=clock_orders=0;clock_scenarios++;
    memset(clock_regs,0,sizeof(clock_regs));clock_regs[2]=0x10000000|(prng_on?0x2000:0);
    clock_regs[0]=(hwcg&1)?2:0;clock_regs[3]=(hwcg&2)?2:0;clock_regs[5]=(hwcg&4)?2:0;
    const unsigned index[]={0,1,2,2,4,5};const uint32_t masks[]={1,1,0x400,0x20000,1,1};
    for(unsigned n=0;n<6;n++)if(enabled&(1u<<n))clock_regs[index[n]]|=masks[n];
    memcpy(clock_original,clock_regs,sizeof(clock_regs));power_setup();
    clock_owner=(void*)(arena+0x2800000);active_clocks=(void*)(arena+0x2900000);
    stop_record=(void*)(arena+0x2a00000);clock_records=(void*)(arena+0x2c00000);
    CHECK(0x1000000+sizeof(*requests)*PMPN_REQUESTS<0x2800000);
    CHECK(0x2900000+sizeof(*active_clocks)<0x2a00000&&0x2a00000+sizeof(*stop_record)<0x2c00000);
    CHECK(0x2c00000+sizeof(*clock_records)*PMCN_RECORDS<PMMN_TEST_IMAGE_BYTES);
    memset(clock_owner,0,sizeof(*clock_owner));memset(active_clocks,0,sizeof(*active_clocks));memset(stop_record,0,sizeof(*stop_record));
    memset(clock_records,0,sizeof(*clock_records)*PMCN_RECORDS);CHECK(pmcn_begin(clock_owner,clock_records,power));
}
static int native_proxy_drive(void)
{
    for(unsigned n=0;n<PMPX_EVENTS;n++){
        struct pmpx_command c;int result=pmpx_next(proxy,power_now(),&c);
        if(result==PMPX_HELD||result==PMPX_RESTORED)return result;
        if(result==PMPX_WAIT){advance_to(proxy->not_before);continue;}
        if(result!=PMPX_IO)return -1;
        if(c.kind==PMPX_RAIL){if(!pmpn_proxy(power,proxy,&c))return -1;}
        else if(!pmcn_proxy(clock_owner,proxy,&c))return -1;
    }CHECK(0);return -1;
}
static int native_clock_drive(void)
{
    for(unsigned n=0;n<PMCK_EVENTS;n++){
        struct pmck_command c;int result=pmck_next(active_clocks,power_now(),&c);
        if(result==PMCK_HELD||result==PMCK_RESTORED)return result;
        if(result==PMCK_WAIT){advance_to(active_clocks->not_before);continue;}
        if(result!=PMCK_IO||!pmcn_clock(clock_owner,active_clocks,&c))return -1;
    }CHECK(0);return -1;
}
static int native_cycle(void)
{
    CHECK(supply_drive(110)==PMSP_HELD&&pmpn_proxy_begin(power,proxy));
    if(native_proxy_drive()!=PMPX_HELD)return 0;
    CHECK(pmcn_clock_begin(clock_owner,active_clocks));
    if(native_clock_drive()!=PMCK_HELD)return 0;
    CHECK(active_clocks->held==63&&owner->held&&!pmsc_close_unused(owner));advance_to(power_now()+19200000);
    uint64_t now=pmpn_test_stop(stop_record,owner->opening,power_now(),&retirement_checks);advance_to(now);
    CHECK(pmcn_clock_release(clock_owner,active_clocks,stop_record));
    if(native_clock_drive()!=PMCK_RESTORED)return 0;
    CHECK(pmpn_proxy_release(power,proxy,active_clocks));if(native_proxy_drive()!=PMPX_RESTORED)return 0;
    CHECK(pmsp_release(supplies,active_clocks,power_now())==PMSP_WAIT&&supply_drive(110)==PMSP_RESTORED);
    CHECK(pmpn_finish(power)&&pmcn_finish(clock_owner));
    CHECK(!memcmp(clock_regs,clock_original,sizeof(clock_regs))&&!memcmp(votes,original_votes,sizeof(votes)));
    CHECK(owner->held&&!pmsc_close_unused(owner)&&clock_orders&&clock_reads&&clock_owner->deliveries==clock_owner->proxy_calls+clock_owner->clock_calls);
    return 1;
}
int main(int argc,char**argv)
{
    CHECK(argc==5);CHECK(!posix_memalign((void**)&arena,0x4000,PMMN_TEST_ARENA_BYTES));
    original=malloc(PGCI_IMAGE_BYTES);rp_original=malloc(PWRPI_IMAGE_BYTES);cd_original=malloc(PWCDI_IMAGE_BYTES);
    database=malloc(PMDC_BYTES);db_original=malloc(PMDC_BYTES);CHECK(original&&rp_original&&cd_original&&database&&db_original);
    uint8_t*dst[]={original,rp_original,cd_original,db_original};const size_t bytes[]={PGCI_IMAGE_BYTES,PWRPI_IMAGE_BYTES,PWCDI_IMAGE_BYTES,PMDC_BYTES};
    for(unsigned n=0;n<4;n++){FILE*f=fopen(argv[n+1],"rb");CHECK(f&&fread(dst[n],1,bytes[n],f)==bytes[n]&&!fclose(f));}
    host_page=(size_t)sysconf(_SC_PAGESIZE);CHECK(host_page&&host_page<=0x4000&&!(host_page&(host_page-1)));
    shadow_mapping=mmap(0,0x104000+2*host_page,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(shadow_mapping!=MAP_FAILED);
    shadow=shadow_mapping+host_page;CHECK(!mprotect(shadow,0x104000,PROT_READ|PROT_WRITE));
    heap_mapping=mmap(0,0x100000+2*host_page,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(heap_mapping!=MAP_FAILED);
    image_heap=heap_mapping+host_page;CHECK(!mprotect(image_heap,0x100000,PROT_READ|PROT_WRITE));db_map_attr=8;
    native_clock_setup(0,0,0);CHECK(native_cycle());unsigned total=clock_owner->deliveries;
    unsigned locations[8]={1,2,0,0,0,0,0,total};
    for(unsigned n=0;n<total;n++){
        const struct pmcn_delivery*r=&clock_records[n];
        if(r->kind==2&&r->command.clock.phase==1&&!locations[2])locations[2]=n+1;
        if(r->kind==2&&r->command.clock.phase==1&&r->native.command.kind==PMNI_WRITE&&!locations[3])locations[3]=n+1;
        if(r->kind==2&&r->command.clock.phase==3&&!locations[4])locations[4]=n+1;
        if(r->kind==2&&r->command.clock.phase==3&&r->native.command.kind==PMNI_WRITE&&!locations[5])locations[5]=n+1;
        if(r->kind==1&&r->command.proxy.step==PMPX_PRNG_RETURN&&!locations[6])locations[6]=n+1;
    }
    fprintf(stderr,"native PRNG/six-clock complete cycle PASS (%u deliveries); checking borrowed votes and failures\n",total);
    native_clock_setup(63,7,1);CHECK(native_cycle()&&!clock_writes);
    native_clock_setup(0x15,5,1);CHECK(native_cycle());
    for(unsigned n=0;n<8;n++){
        CHECK(locations[n]);native_clock_setup(0,0,0);clock_fault=1;clock_trigger=locations[n];CHECK(!native_cycle());
        CHECK(clock_owner->unknown&&power->unknown&&clock_owner->pending==clock_trigger&&!clock_owner->restored&&owner->held);
        unsigned prior=clock_reads+clock_writes+clock_orders;CHECK(!pmcn_live(clock_owner)&&!pmpn_live(power)&&prior==clock_reads+clock_writes+clock_orders);
    }
    for(unsigned fault=2;fault<=6;fault++){
        native_clock_setup(0,0,0);clock_fault=fault;clock_trigger=locations[3];CHECK(!native_cycle());
        CHECK(clock_owner->unknown&&power->unknown&&!clock_owner->restored&&owner->held);
    }
    CHECK(!munmap(heap_mapping,0x100000+2*host_page)&&!munmap(shadow_mapping,0x104000+2*host_page));
    free(original);free(rp_original);free(cd_original);free(database);free(db_original);free(arena);
    printf("PASS %u owned native clock checks, %u complete/fault scenarios, %u software stop checks; no hardware/provider/USB\n",checks,clock_scenarios,retirement_checks);return 0;
}
