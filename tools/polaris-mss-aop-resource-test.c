/* Own DT resource against actual retained CPU/GCD producers and AOP caller.
 * Namespace/translation/remote are software peers; no hardware permission. */
struct pwea_map;struct pmni_translation;
static void aop_dt_at(struct pmni_translation*);
#define PMAN_TEST_AT_HOOK aop_dt_at
static void aop_dt_prepare(void);
static void aop_dt_map(struct pwea_map*);
#define PMDC_TEST_PREPARE aop_dt_prepare
#define PMDC_TEST_EXTRA_MAP aop_dt_map
#define PMAN_TEST_ENTRY unused_aop_suite
#include "polaris-mss-aop-native-test.c"
static unsigned dt_fault;
static void aop_dt_at(struct pmni_translation*t)
{if(dt_fault==9&&t->page>=PMAQ_BASE&&t->page<PMAQ_BASE+PMAQ_BYTES)t->read_par=t->write_par=t->page|UINT64_C(0xff00000000000b80);}
static void aop_dt_prepare(void)
{
    uint64_t last=PMAQ_BASE+PMAQ_BYTES-1-(dt_fault==8?4096:0);
    uint8_t*first=image_heap+0x3000,*middle=image_heap+0x18000,*tail=image_heap+0x19000;
    put(first+8,(uintptr_t)middle+8,8);put(first+32,PMAQ_BASE-1,8);
    put(middle,0x6d646367,8);put(middle+8,(uintptr_t)tail+8,8);put(middle+16,(uintptr_t)first+8,8);
    put(middle+24,PMAQ_BASE,8);put(middle+32,last,8);
    put(middle+40,dt_fault==2?8:dt_fault==3?1:0,8);put(middle+48,dt_fault==2?8:dt_fault==4?1:0,8);
    put(middle+56,dt_fault==1?1:dt_fault==2?2:0,4);put(middle+64,dt_fault==5?1:0,8);
    put(tail,0x6d646367,8);put(tail+8,(uintptr_t)image_heap+0x4008,8);put(tail+16,(uintptr_t)middle+8,8);
    put(tail+24,last+1,8);put(tail+32,0x179dffff,8);put(tail+40,1,8);put(tail+48,1,8);put(tail+56,3,4);
    put(image_heap+0x4010,(uintptr_t)tail+8,8);
}
static void aop_dt_map(struct pwea_map*m)
{
    if(dt_fault!=6&&dt_fault!=7)return;
    struct efi_memory*d=(void*)(m->data+m->map.bytes);
    emit_descriptor((void*)d,dt_fault==6?4:11,PMAQ_BASE,4096);d->attributes=dt_fault==6?8:1;m->map.bytes+=40;
}
int main(int argc,char**argv)
{
    aop_test_open(argc,argv);aop_setup();
    struct pmrg_target t={0};CHECK(!pmpn_target(power,PMAQ_BASE,&t));
    memset(&t,0,sizeof(t));CHECK(!pman_target(power,PMAQ_BASE-4096,&t));
    memset(&t,0,sizeof(t));CHECK(!pman_target(power,PMAQ_BASE+PMAQ_BYTES,&t));
    memset(&t,0,sizeof(t));CHECK(!pman_target(power,PMAQ_BASE+4,&t));
    CHECK(aop_cycle());
    for(unsigned n=0;n<aop_owner->deliveries;n++){
        const struct pman_delivery*d=&aop_records[n];
        if(d->command.kind==PMAQ_FULL_ORDER)continue;
        for(unsigned k=0;k<2;k++)CHECK(d->target[k].complete&&
            d->target[k].descriptor.type==(d->command.address==PMAQ_IRQ?3:0));
        CHECK(!d->native.AT.read_par||!(d->native.AT.read_par&1));
    }
    for(dt_fault=1;dt_fault<=8;dt_fault++){
        aop_setup();CHECK(!aop_drive());CHECK(aop_owner->error==4&&aop_records[0].reserved==1);
        CHECK(!aop_reads&&!aop_writes&&!aop_orders&&!aop_doorbells&&!owner->effects);
    }
    dt_fault=0;aop_setup();put(image_heap+0x18030,1,8);
    CHECK(!aop_drive()&&resource_map->error==5&&aop_records[0].reserved==1&&!aop_reads&&!aop_writes);
    aop_setup();aop_fault=2;aop_trigger=1;
    CHECK(!aop_drive()&&aop_records[0].reserved==5&&aop_records[0].native.error==3&&!aop_reads&&!aop_writes);
    dt_fault=9;aop_setup();
    CHECK(!aop_drive()&&aop_records[0].reserved==5&&aop_records[0].native.error==3&&!aop_reads&&!aop_writes);
    aop_test_close();printf("PASS %u AOP DT resource checks, %u scenarios; SOFTWARE namespace/AT/radio only\n",checks,aop_scenarios);return 0;
}
