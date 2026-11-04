/* Actual source/reader/SFPB/allocator composition. Privileged operations are
 * software leaves; compare the entire SMEM shadow against independent bytes. */
struct pmni_translation;struct pmni_command;
static int alloc_translate(struct pmni_translation*);
static int alloc_lock_read(const struct pmni_command*,unsigned*);
#define PMSL_TEST_TRANSLATE alloc_translate
#define PMSL_TEST_RAW_GUARD alloc_lock_read
#define PMSL_TEST_ENTRY unused_lock_suite
#define POLARIS_MSS_SMEM_ALLOCATE_SOFTWARE_PEER 1
#include "polaris-mss-smem-lock-test.c"
#include "uefi-mss-smem-allocate.h"
static struct pmsa_state*allocation;
static uint8_t*expected;
static unsigned alloc_stores,alloc_fault,alloc_trigger,alloc_ats,alloc_lock_reads,alloc_scenarios,alloc_start;
static int alloc_translate(struct pmni_translation*t)
{
    if(t->page<PMSQ_BASE||t->page>=PMSQ_BASE+PMSQ_BYTES)return -1;
    CHECK(allocation&&allocation->pending);alloc_ats++;
    t->saved=t->restored=0x123;t->read_par=t->write_par=UINT64_C(0x4400000000000b00)|t->page;
    t->read_issued=t->read_returned=t->write_issued=t->write_returned=t->restore_issued=t->restore_returned=1;
    if(alloc_fault==3)t->write_par|=1;return 1;
}
static int alloc_lock_read(const struct pmni_command*c,unsigned*out)
{
    if(!allocation||!allocation->pending||lock->pending)return -1;
    CHECK(c->kind==PMNI_READ&&c->address==PMSL_ADDRESS&&lock->held);alloc_lock_reads++;*out=lock_value;return 1;
}
static int pmsa_store(uint64_t at,uint32_t value,uint32_t*readback)
{
    CHECK(allocation&&allocation->pending&&lock->held&&(owner->effects&PMSC_REMOTE));
    CHECK(at>=PMSQ_BASE+0xb9000&&at<PMSQ_BASE+0x135000&&!(at&3));alloc_stores++;
    put(sm_shadow+at-PMSQ_BASE,value,4);*readback=value;
    if(alloc_stores==alloc_trigger){
        if(alloc_fault==1)return 0;
        if(alloc_fault==2)*readback^=1;
        if(alloc_fault==4)lock_value=2;
        if(alloc_fault==5)sm_image[PWFC_CACHE_RVA+112]^=8;
        if(alloc_fault==6)owner_delay=PMSC_TOTAL+1;
    }return 1;
}
static void alloc_partition(unsigned index,unsigned offset,unsigned bytes,unsigned hosts)
{
    uint8_t*t=sm_shadow+PMSQ_BYTES-4096+32+48*index,*h=sm_shadow+offset;
    put(t,offset,4);put(t+4,bytes,4);put(t+12,hosts,4);put(t+16,32,4);
    put(h,0x54525024,4);put(h+4,hosts,4);put(h+8,bytes,4);put(h+12,32,4);put(h+16,bytes,4);
}
static void alloc_setup(unsigned start)
{
    allocation=0;lock_setup();CHECK(pmsl_acquire(lock,sm));
    allocation=(void*)(arena+0x600000);CHECK(0x600000+sizeof(*allocation)<PMMN_TEST_IMAGE_BYTES);memset(allocation,0,sizeof(*allocation));
    alloc_stores=alloc_fault=alloc_trigger=alloc_ats=alloc_lock_reads=0;alloc_start=start;alloc_scenarios++;
    memset(sm_shadow,0,PMSQ_BYTES);put(sm_shadow+92,0xc0000,4);put(sm_shadow+192,1,4);
    uint8_t*t=sm_shadow+PMSQ_BYTES-4096;put(t,0x434f5424,4);put(t+4,1,4);put(t+8,2,4);
    alloc_partition(0,0x1000,0x88000,0xfffefffe);alloc_partition(1,0xb9000,0x7c000,0x10000);
    memset(sm_shadow+0xb9020,0xa7,0x7c000-32);
    if(start>32){
        uint8_t*h=sm_shadow+0xb9020;put(h,0xa5a5|(480u<<16),4);put(h+4,start-48,4);put(h+8,0,4);put(h+12,0,4);
    }
    put(sm_shadow+0xb900c,start,4);memcpy(expected,sm_shadow,PMSQ_BYTES);
}
static void alloc_success(void)
{
    int prepared=pmsa_prepare(allocation,lock),published=prepared?pmsa_publish(allocation):0;
    if(!published)fprintf(stderr,"allocation refusal prepared=%d error=%u events=%u stores=%u lock=%u source=%u owner=%u inventory=%u\n",
        prepared,allocation->error,allocation->events,alloc_stores,lock->error,sm->error,owner->error,allocation->inventory.inventory.count);
    CHECK(prepared&&published&&allocation->complete&&!allocation->unknown&&alloc_stores==4203);
    CHECK(alloc_lock_reads==2*allocation->events&&alloc_ats==2*allocation->events&&lock_value==1);
    unsigned cursor=0xb9000+alloc_start;
    const unsigned ids[]={428,478,479},sizes[]={340,32,16384};
    for(unsigned n=0;n<3;n++){
        unsigned rounded=(sizes[n]+7)&~7u;memset(expected+cursor,0,16+rounded);
        put(expected+cursor,0xa5a5|(ids[n]<<16),4);put(expected+cursor+4,rounded,4);put(expected+cursor+8,rounded-sizes[n],4);
        CHECK(allocation->item[n].id==ids[n]&&allocation->item[n].bytes==sizes[n]&&allocation->item[n].data==cursor+16);
        cursor+=16+rounded;
    }
    put(expected+0xb900c,cursor-0xb9000,4);CHECK(!memcmp(sm_shadow,expected,PMSQ_BYTES));
    CHECK(!pmsa_current(allocation)&&pmsl_release(lock)&&pmsa_current(allocation)&&!lock_value);
    unsigned stores=alloc_stores;CHECK(!pmsa_publish(allocation)&&stores==alloc_stores);
}
int main(int argc,char**argv)
{
    smem_test_open(argc,argv);expected=malloc(PMSQ_BYTES);CHECK(expected);
    alloc_setup(32);alloc_success();alloc_setup(4088);alloc_success();
    for(unsigned id=0;id<3;id++){
        alloc_setup(80);put(sm_shadow+0xb9020,0xa5a5|((id==0?428u:id==1?478u:479u)<<16),4);
        CHECK(!pmsa_prepare(allocation,lock)&&!alloc_stores&&pmsl_release(lock));
    }
    alloc_setup(0x7c000-32);CHECK(!pmsa_prepare(allocation,lock)&&!alloc_stores&&pmsl_release(lock));
    alloc_setup(32);CHECK(pmsa_prepare(allocation,lock));put(sm_shadow+0xb900c,40,4);
    CHECK(!pmsa_publish(allocation)&&!alloc_stores&&pmsl_release(lock));
    alloc_setup(32);CHECK(pmsa_prepare(allocation,lock));allocation->item[0].data+=8;
    CHECK(!pmsa_publish(allocation)&&!alloc_stores);
    const unsigned triggers[]={1,2048,4191,4203};
    for(unsigned n=0;n<4;n++){
        alloc_setup(32);CHECK(pmsa_prepare(allocation,lock));alloc_fault=1;alloc_trigger=triggers[n];
        CHECK(!pmsa_publish(allocation)&&allocation->unknown&&lock->unknown&&!allocation->complete&&alloc_stores==triggers[n]);
        unsigned stores=alloc_stores;CHECK(!pmsl_release(lock)&&!pmsa_publish(allocation)&&stores==alloc_stores);
    }
    for(unsigned fault=2;fault<=6;fault++){
        alloc_setup(32);CHECK(pmsa_prepare(allocation,lock));alloc_fault=fault;alloc_trigger=1;
        CHECK(!pmsa_publish(allocation)&&allocation->unknown&&!allocation->complete);
        if(fault==3)CHECK(!alloc_stores&&pmsl_release(lock));else CHECK(lock->unknown&&!pmsl_release(lock));
    }
    free(expected);smem_test_close();printf("PASS %u native SMEM allocation checks, %u scenarios; software privileged leaves only\n",checks,alloc_scenarios);return 0;
}
