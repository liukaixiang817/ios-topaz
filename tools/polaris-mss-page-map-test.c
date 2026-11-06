/* Real composed owner, allocation/ledger/namespace and MBA state machine.
 * Only CPU translation and publication instructions are software peers. */
#include <stdint.h>
static uintptr_t table_base;
static uint64_t table_tcr;
#define PGCD_TEST_TTBR0 (table_base|1)
#define PGCD_TEST_TCR table_tcr
#define EFI_XNU_MSS_PAGE_MAP_AVAILABLE 1
#define POLARIS_MSS_PAGE_MAP_SOFTWARE_PEER 1
struct pmni_translation;
static void map_at(struct pmni_translation*);
#define PMBN_TEST_AT_HOOK map_at
#define PMBN_TEST_ENTRY unused_boot_suite
#define PMRG_TEST_UNREGISTERED_MSS 1
#define PMRG_TEST_UNREGISTERED_PDC 1
#include "polaris-mss-boot-native-test.c"
static unsigned map_fault,publishes,map_group;
static void map_at(struct pmni_translation*t)
{
    if(t->page!=0x4080000&&t->page!=0x4180000&&t->page!=0xb2e0000)return;
    if((map_group==0&&t->page==0xb2e0000)||(map_group==1&&t->page!=0xb2e0000))return;
    struct pmbm_state*m=t->page==0xb2e0000?&boot_owner->pdc_mapping:&boot_owner->mapping;
    if(!m->installed){
        if(map_fault==7||(map_fault==8&&t->page==0x4180000))return;
        t->read_par=t->write_par=0xb80;
        if(map_fault==11)t->restored++;
        if(map_fault==12)t->read_returned=0;
        if((map_fault==13||map_fault==17)&&t->page==(map_group?0xb2e0000u:0x4180000u)){
            image_fault=9;image_trigger=image_ats+(map_fault==13?1:7);
        }
    }else if(map_fault==6)t->write_par^=4096;
}
static int pmbm_publish(struct pmbm_state*m)
{
    publishes++;CHECK(pmbn_live(boot_owner)&&!boot_calls&&owner->held&&owner->effects);
    for(unsigned n=0;n<512;n++)CHECK(((uint64_t*)(uintptr_t)m->table)[n]==pmbm_leaf(m->base,n));
    if(map_fault==5)put((void*)(uintptr_t)m->entry,0x123,8);
    m->issued=m->returned=1;
    if(*(uint64_t*)(uintptr_t)m->entry)return 0;
    put((void*)(uintptr_t)m->entry,m->value,8);m->installed=1;if(map_fault==18)put((void*)table_base,0,8);return 1;
}
static void map_setup(unsigned f,unsigned group)
{
    table_tcr=UINT64_C(0x280803510)+(f==15?9:f==16?8:0);
    table_base=(uintptr_t)image_heap+(f==14?0x80000:0x60000);map_fault=f;map_group=group;publishes=0;boot_setup();
    put((void*)table_base,table_base+4096+3,8);put((void*)(table_base+4096),table_base+8192+3,8);
    put((void*)(table_base+8192+0x100),0,8);put((void*)(table_base+8192+0x2c8),0,8);
    uintptr_t entry=table_base+8192+(group?0x2c8:0x100);
    if(f==1)put((void*)entry,group?0xb200601:0x4000601,8);
    if(f==2)put((void*)(table_base+4096),table_base+3,8);
    if(f==3)put((void*)entry,2,8);
    if(f==4)put((void*)table_base,(table_base+4096+3)|(UINT64_C(1)<<59),8);
}
int main(int argc,char**argv)
{
    aop_test_open(argc,argv);unsigned cases=0;
    for(unsigned group=0;group<2;group++)for(unsigned f=0;f<19;f++){
        if(group&&f==8)continue; /* Mixed pair is impossible for a one-page group. */
        map_setup(f,group);
        int ok=pmbn_begin(boot_owner,boot_records,aop_owner);
        struct pmbm_state*m=group?&boot_owner->pdc_mapping:&boot_owner->mapping;
        if(f==0||f==7||f==9||f==10||f==16){
            if(!ok)fprintf(stderr,"group=%u case=%u map_error=%u walk=%u/%u/%u source=%u\n",group,f,m->error,m->walk.error,m->walk.levels,m->walk.stable,m->read_error);
            CHECK(ok&&m->complete&&!m->error&&pmbm_current(m)&&publishes==(f!=7));
            if(f==9){((uint64_t*)(uintptr_t)m->table)[group?225:129]=pmbm_leaf(m->base,group?224:128);CHECK(!pmbm_current(m)&&!pmbn_live(boot_owner)&&!boot_drive()&&!boot_calls);}
            else if(f==10){put((void*)(table_base+4096),0,8);CHECK(!pmbm_current(m)&&!boot_drive()&&!boot_calls);}
            else {CHECK(boot_drive()&&boot_owner->complete&&boot_calls);CHECK(m->installed==(f!=7));}
        }else {
            CHECK(!ok&&boot_owner->error==4&&!boot_calls&&!m->complete);
            CHECK(publishes==(f==5||f==6||f==18));CHECK(m->installed==(f==6||f==18));
            CHECK(!pmbn_begin(boot_owner,boot_records,aop_owner)&&!boot_drive()&&!boot_calls);
        }
        cases++;
    }
    map_setup(0,2);CHECK(pmbn_begin(boot_owner,boot_records,aop_owner));
    CHECK(publishes==2&&boot_owner->mapping.installed&&boot_owner->pdc_mapping.installed);
    CHECK(boot_owner->mapping.table!=boot_owner->pdc_mapping.table&&boot_drive()&&pmbn_current(boot_owner));cases++;
    CHECK(!pmbm_pages(0xb2e1000)&&!pmbm_pages(0x4081000)&&!pmbm_leaf(0xb2e1000,224));
    aop_test_close();printf("PASS %u MSS/PDC page mapping scenarios / %u checks; SOFTWARE only\n",cases,checks);return 0;
}
