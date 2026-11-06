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
#include "polaris-mss-boot-native-test.c"
static unsigned map_fault,publishes;
static void map_at(struct pmni_translation*t)
{
    if(t->page!=0x4080000&&t->page!=0x4180000)return;
    if(!boot_owner->mapping.installed){
        if(map_fault==7||(map_fault==8&&t->page==0x4180000))return;
        t->read_par=t->write_par=0xb80;
        if(map_fault==11)t->restored++;
        if(map_fault==12)t->read_returned=0;
        if((map_fault==13||map_fault==17)&&t->page==0x4180000){image_fault=9;image_trigger=image_ats+(map_fault==13?1:7);}
    }else if(map_fault==6)t->write_par^=4096;
}
static int pmbm_publish(struct pmbm_state*m)
{
    publishes++;CHECK(pmbn_live(boot_owner)&&!boot_calls&&owner->held&&owner->effects);
    for(unsigned n=0;n<512;n++)CHECK(((uint64_t*)(uintptr_t)m->table)[n]==pmbm_leaf(n));
    if(map_fault==5)put((void*)(uintptr_t)m->entry,0x123,8);
    m->issued=m->returned=1;
    if(*(uint64_t*)(uintptr_t)m->entry)return 0;
    put((void*)(uintptr_t)m->entry,m->value,8);m->installed=1;if(map_fault==18)put((void*)table_base,0,8);return 1;
}
int main(int argc,char**argv)
{
    aop_test_open(argc,argv);unsigned cases=0;
    for(unsigned f=0;f<19;f++){
        table_tcr=UINT64_C(0x280803510)+(f==15?9:f==16?8:0);table_base=(uintptr_t)image_heap+(f==14?0x80000:0x60000);map_fault=f;publishes=0;boot_setup();
        put((void*)table_base,table_base+4096+3,8);put((void*)(table_base+4096),table_base+8192+3,8);
        put((void*)(table_base+8192+0x100),0,8);
        if(f==1)put((void*)(table_base+8192+0x100),0x4000601,8);
        if(f==2)put((void*)(table_base+4096),table_base+3,8);
        if(f==3)put((void*)(table_base+8192+0x100),2,8);
        if(f==4)put((void*)table_base,(table_base+4096+3)|(UINT64_C(1)<<59),8);
        int ok=pmbn_begin(boot_owner,boot_records,aop_owner);struct pmbm_state*m=&boot_owner->mapping;
        if(f==0||f==7||f==9||f==10||f==16){
            if(!ok)fprintf(stderr,"case=%u map_error=%u walk=%u/%u/%u source=%u table=%llx tcr=%llx target=%u/%u arch=%llx live=%d\n",f,m->error,m->walk.error,m->walk.levels,m->walk.stable,m->read_error,(unsigned long long)m->table,(unsigned long long)m->walk.tcr,m->target[0].complete,m->target[1].complete,(unsigned long long)m->architecture.tcr,pmbn_live(boot_owner));
            CHECK(ok&&m->complete&&!m->error&&pmbm_current(m)&&publishes==(f!=7));
            if(f==9){((uint64_t*)(uintptr_t)m->table)[129]=pmbm_leaf(128);CHECK(!pmbm_current(m)&&!pmbn_live(boot_owner)&&!boot_drive()&&!boot_calls);}
            else if(f==10){put((void*)(table_base+4096),0,8);CHECK(!pmbm_current(m)&&!boot_drive()&&!boot_calls);}
            else {CHECK(boot_drive()&&boot_owner->complete&&boot_calls);CHECK(m->installed==(f!=7));}
        }else {
            CHECK(!ok&&boot_owner->error==4&&!boot_calls&&!m->complete);
            CHECK(publishes==(f==5||f==6||f==18));CHECK(m->installed==(f==6||f==18));
            CHECK(!pmbn_begin(boot_owner,boot_records,aop_owner)&&!boot_drive()&&!boot_calls);
        }
        cases++;
    }
    aop_test_close();printf("PASS %u MSS two-page mapping scenarios / %u checks; SOFTWARE only\n",cases,checks);return 0;
}
