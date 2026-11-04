/* Composed native AOP/power/PRNG/clock path against independent memory and
 * register peers. Secure/MSS/WLAN and physical execution are not simulated
 * into success; STOP remains the explicitly named software producer. */
struct pmni_arch;struct pmni_translation;struct pmni_command;
static void aop_arch_hook(struct pmni_arch*);
static void aop_at_hook(struct pmni_translation*);
static int aop_raw_hook(const struct pmni_command*,unsigned*);
#define PMCN_TEST_ARCH_HOOK aop_arch_hook
#define PMCN_TEST_AT_HOOK aop_at_hook
#define PMCN_TEST_RAW_HOOK aop_raw_hook
#define PMCN_TEST_ENTRY unused_native_clock_suite
#define PMPN_TEST_DEFER_SUPPLY 1
#define EFI_XNU_MSS_AOP_IO_AVAILABLE 1
#define EFI_XNU_MSS_AOP_NATIVE_AVAILABLE 1
#include "polaris-mss-clock-native-test.c"
#include "uefi-mss-aop-native.h"
static struct pman_state*aop_owner;
static struct pman_delivery*aop_records;
static uint8_t*aop_memory,*aop_original;
static unsigned aop_fault,aop_trigger,aop_reads,aop_writes,aop_orders,aop_doorbells,aop_pending,aop_remote_reads,aop_scenarios;
static int aop_selected(void){return aop_owner&&aop_owner->pending&&aop_owner->pending==aop_trigger;}
static void aop_arch_hook(struct pmni_arch*a){if(aop_selected()&&aop_fault==3)a->ttbr0^=4096;}
static void aop_at_hook(struct pmni_translation*t){if(aop_selected()&&aop_fault==2)t->restored++;}
static int aop_raw_hook(const struct pmni_command*c,unsigned*v)
{
    if(!aop_owner||!aop_owner->pending)return -1;
    CHECK(!clock_owner->pending&&!power->pending);
    if(c->kind==PMNI_READ)aop_reads++;else if(c->kind==PMNI_WRITE)aop_writes++;else aop_orders++;
    if(aop_selected()){
        if(aop_fault==1)return 0;
        if(aop_fault==4)owner_delay+=PMSC_TOTAL+1;
        if(aop_fault==5)put(image_heap+0x3030,0,8);
        if(aop_fault==6){struct pmaq_notify*q=&aop_owner->notify[aop_owner->phase-1];q->event[q->events-1].command.value^=4;}
    }
    if(c->kind==PMNI_FULL_ORDER){CHECK(!c->address&&!c->value);return 1;}
    if(c->address==0x1799000c){
        CHECK(c->kind==PMNI_WRITE&&c->value==1&&(owner->effects&PMSC_REMOTE)&&!aop_pending&&aop_doorbells<2);
        static const char messages[2][96]={"{class: image, res: load_state, name: modem, val: on}","{class: image, res: load_state, name: modem, val: off}"};
        CHECK(pwfi_le(aop_memory+0x2000,4)==96&&!memcmp(aop_memory+0x2004,messages[aop_doorbells],96));
        aop_doorbells++;aop_pending=1;aop_remote_reads=0;return 1;
    }
    CHECK(c->address>=0xc300000&&c->address<0xc400000&&!(c->address&3));unsigned off=(unsigned)(c->address-0xc300000);
    if(c->kind==PMNI_READ){
        if(off==0x2000&&aop_pending&&++aop_remote_reads==3){put(aop_memory+off,0,4);aop_pending=0;}
        *v=(uint32_t)pwfi_le(aop_memory+off,4);return 1;
    }
    CHECK(c->kind==PMNI_WRITE&&(owner->effects&PMSC_REMOTE)&&off>=0x2000&&off<0x2064);
    if(off==0x2000)CHECK(c->value==96&&!aop_pending);
    put(aop_memory+off,c->value,4);return 1;
}
static void aop_setup(void)
{
    aop_owner=0;aop_fault=aop_trigger=aop_reads=aop_writes=aop_orders=aop_doorbells=aop_pending=aop_remote_reads=0;aop_scenarios++;
    native_clock_setup(0,0,0);memset(aop_memory,0,0x100000);
    const unsigned state[]={3,4,5,6,9,10,11,12};put(aop_memory,0x4d41494c,4);put(aop_memory+4,1,4);
    for(unsigned n=0;n<8;n++)put(aop_memory+4*state[n],0xffff,4);
    put(aop_memory+28,0x100,4);put(aop_memory+32,0x1000,4);put(aop_memory+52,0x100,4);put(aop_memory+56,0x2000,4);
    for(unsigned n=0;n<96;n++)aop_memory[0x2004+n]=(uint8_t)(n*7+19);
    memcpy(aop_original,aop_memory,0x100000);
    aop_owner=(void*)(arena+0x3600000);aop_records=(void*)(arena+0x3700000);
    CHECK(0x2c00000+sizeof(*clock_records)*PMCN_RECORDS<0x3600000&&0x3600000+sizeof(*aop_owner)<0x3700000);
    CHECK(0x3700000+sizeof(*aop_records)*PMAN_RECORDS<PMMN_TEST_IMAGE_BYTES);
    memset(aop_owner,0,sizeof(*aop_owner));memset(aop_records,0,sizeof(*aop_records)*PMAN_RECORDS);
    CHECK(pman_begin(aop_owner,aop_records,clock_owner));
}
static int aop_drive(void)
{
    for(unsigned n=0;n<2*PMAQ_EVENTS;n++){
        int result=pman_step(aop_owner);if(result==PMAQ_CONSUMED)return 1;if(result<0)return 0;
        CHECK(result==PMAQ_WAIT);struct pmaq_notify*q=&aop_owner->notify[aop_owner->phase-1];advance_to(q->not_before);
    }CHECK(0);return 0;
}
static int aop_cycle(void)
{
    if(!aop_drive())return 0;
    CHECK(aop_doorbells==1&&!aop_pending&&!memcmp(aop_memory,aop_original,0x100000));
    CHECK(!pman_off(aop_owner)); /* power/clock lifetime has not run yet */
    uint32_t minimum[3];for(unsigned n=0;n<3;n++)minimum[n]=database_state->pass[1].resource[n].minimum;
    CHECK(pmsp_begin(supplies,owner->opening,minimum,power_now(),19200000)==PMSP_WAIT&&native_cycle());
    CHECK(pman_off(aop_owner));if(!aop_drive())return 0;
    CHECK(pman_finish(aop_owner)&&aop_doorbells==2&&!aop_pending&&!memcmp(aop_memory,aop_original,0x100000));
    CHECK(owner->held&&(owner->effects&PMSC_REMOTE)&&(owner->effects&PMSC_POWER)&&!pmsc_close_unused(owner));return 1;
}
int main(int argc,char**argv)
{
    CHECK(argc==5);CHECK(!posix_memalign((void**)&arena,0x4000,PMMN_TEST_ARENA_BYTES));
    original=malloc(PGCI_IMAGE_BYTES);rp_original=malloc(PWRPI_IMAGE_BYTES);cd_original=malloc(PWCDI_IMAGE_BYTES);
    database=malloc(PMDC_BYTES);db_original=malloc(PMDC_BYTES);aop_memory=malloc(0x100000);aop_original=malloc(0x100000);
    CHECK(original&&rp_original&&cd_original&&database&&db_original&&aop_memory&&aop_original);
    uint8_t*dst[]={original,rp_original,cd_original,db_original};const size_t bytes[]={PGCI_IMAGE_BYTES,PWRPI_IMAGE_BYTES,PWCDI_IMAGE_BYTES,PMDC_BYTES};
    for(unsigned n=0;n<4;n++){FILE*f=fopen(argv[n+1],"rb");CHECK(f&&fread(dst[n],1,bytes[n],f)==bytes[n]&&!fclose(f));}
    host_page=(size_t)sysconf(_SC_PAGESIZE);CHECK(host_page&&host_page<=0x4000&&!(host_page&(host_page-1)));
    shadow_mapping=mmap(0,0x104000+2*host_page,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(shadow_mapping!=MAP_FAILED);
    shadow=shadow_mapping+host_page;CHECK(!mprotect(shadow,0x104000,PROT_READ|PROT_WRITE));
    heap_mapping=mmap(0,0x100000+2*host_page,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(heap_mapping!=MAP_FAILED);
    image_heap=heap_mapping+host_page;CHECK(!mprotect(image_heap,0x100000,PROT_READ|PROT_WRITE));db_map_attr=8;
    aop_setup();CHECK(aop_cycle());unsigned total=aop_owner->deliveries,on=aop_owner->completed[0];
    unsigned locations[8]={1,0,0,0,0,0,on,total};
    for(unsigned n=0;n<on;n++){
        const struct pman_delivery*r=&aop_records[n];
        if(r->command.step==PMAQ_WRITE&&!locations[1])locations[1]=n+1;
        if(r->command.step==PMAQ_LENGTH&&!locations[2])locations[2]=n+1;
        if(r->command.step==PMAQ_DOORBELL&&!locations[3])locations[3]=n+1;
        if(r->command.step==PMAQ_POLL_TX&&!locations[4])locations[4]=n+1;
        if(r->command.step==PMAQ_RESTORE&&!locations[5])locations[5]=n+1;
    }
    fprintf(stderr,"native AOP/power/PRNG/six-clock on/off PASS (%u AOP deliveries); checking failures\n",total);
    for(unsigned n=0;n<8;n++){
        CHECK(locations[n]);aop_setup();aop_fault=1;aop_trigger=locations[n];CHECK(!aop_cycle());
        CHECK(aop_owner->unknown&&power->unknown&&aop_owner->pending==aop_trigger&&!aop_owner->restored&&owner->held);
        unsigned prior=aop_reads+aop_writes+aop_orders;CHECK(pman_step(aop_owner)==PMAQ_FAILED&&prior==aop_reads+aop_writes+aop_orders);
    }
    for(unsigned fault=2;fault<=6;fault++){
        aop_setup();aop_fault=fault;aop_trigger=locations[1];CHECK(!aop_cycle());
        CHECK(aop_owner->unknown&&power->unknown&&!aop_owner->restored&&owner->held);
    }
    for(unsigned malformed=0;malformed<3;malformed++){
        aop_setup();put(aop_memory+(malformed==0?0:malformed==1?0x1000:0x2000),4,4);
        CHECK(!aop_drive()&&aop_owner->unknown&&!aop_writes&&!aop_doorbells&&!owner->effects);
    }
    CHECK(!munmap(heap_mapping,0x100000+2*host_page)&&!munmap(shadow_mapping,0x104000+2*host_page));
    free(original);free(rp_original);free(cd_original);free(database);free(db_original);free(aop_memory);free(aop_original);free(arena);
    printf("PASS %u owned native AOP checks, %u scenarios, %u software stop checks; no hardware/provider/USB\n",checks,aop_scenarios,retirement_checks);return 0;
}
