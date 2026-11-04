/* Actual current source/read/lock callers; software register/AT/CPU leaves. */
#define EFI_XNU_MSS_NATIVE_IO_AVAILABLE 1
#define EFI_XNU_MSS_SFPB_IO_AVAILABLE 1
#define POLARIS_MSS_NATIVE_SOFTWARE_PEER 1
#define PMSQ_TEST_ENTRY unused_smem_suite
#include "polaris-mss-smem-native-test.c"
#include "uefi-mss-smem-lock.h"
static struct pmsl_lock*lock;
static unsigned lock_value,lock_writes,lock_reads,lock_calls,lock_fault,lock_trigger,lock_race,lock_scenarios;
static int lock_selected(void){return lock&&lock->pending==lock_trigger;}
static int pmni_arch_read(struct pmni_arch*a)
{
    struct pgcd_arch arch;CHECK(owner_arch(0,&arch));const struct pwfc_arch*b=&arch.cpu;
    *a=(struct pmni_arch){b->el,b->mpidr,b->ttbr0,b->ttbr1,b->tcr,b->sctlr,b->mair,b->daif,b->sre,b->group1,arch.cpacr,b->frequency,b->ticks};
    if(lock_selected()&&lock_fault==3)a->ttbr0^=4096;return 1;
}
static int pmni_translate(struct pmni_translation*t)
{
#ifdef PMSL_TEST_TRANSLATE
    int result=PMSL_TEST_TRANSLATE(t);if(result>=0)return result;
#endif
    CHECK(t->page==PMSL_ADDRESS);t->saved=t->restored=0x123;
    t->read_par=t->write_par=t->page|0xb00;
    t->read_issued=t->read_returned=t->write_issued=t->write_returned=t->restore_issued=t->restore_returned=1;
    if(lock_selected()&&lock_fault==2)t->restored++;return 1;
}
static int pmni_raw(const struct pmni_command*c,uint32_t*out)
{
#ifdef PMSL_TEST_RAW_GUARD
    int handled=PMSL_TEST_RAW_GUARD(c,out);if(handled>=0)return handled;
#endif
    CHECK(lock&&lock->pending&&owner->held&&local_mask);lock_calls++;
    if(lock_selected()){
        if(lock_fault==1)return 0;
        if(lock_fault==4)lock->held^=1;
        if(lock_fault==5)owner->fp.q8_q15[0]^=1;
        if(lock_fault==6)put(image_heap+0x3030,0,8);
        if(lock_fault==7)sm_image[PWFC_CACHE_RVA+112]^=8;
        if(lock_fault==8)owner_delay=PMSC_TOTAL+1;
    }
    if(c->kind==PMNI_FULL_ORDER){CHECK(!c->address&&!c->value);return 1;}
    CHECK(c->address==PMSL_ADDRESS);
    if(c->kind==PMNI_READ){lock_reads++;*out=lock_value;return 1;}
    CHECK(c->kind==PMNI_WRITE&&c->value<=1&&(owner->effects&PMSC_REMOTE));lock_writes++;
    if(c->value){CHECK(lock->events==2);if(!lock_value)lock_value=lock_race?2:1;}
    else{CHECK(lock->events==6&&lock_value==1);lock_value=0;}return 1;
}
static void lock_setup(void)
{
    lock=0;smem_setup();lock=(void*)(arena+0x500000);CHECK(0x500000+sizeof(*lock)<PMMN_TEST_IMAGE_BYTES);
    memset(lock,0,sizeof(*lock));lock_value=lock_writes=lock_reads=lock_calls=lock_fault=lock_trigger=lock_race=0;lock_scenarios++;
}
#ifndef PMSL_TEST_ENTRY
#define PMSL_TEST_ENTRY main
#endif
int PMSL_TEST_ENTRY(int argc,char**argv)
{
    smem_test_open(argc,argv);lock_setup();CHECK(pmsl_acquire(lock,sm)&&pmsl_held(lock));
    CHECK(lock_value==1&&lock_writes==1&&lock->events==4&&pmsq_read(sm,0,32));
    CHECK(pmsl_release(lock)&&lock->released&&!lock->held&&lock->events==8&&lock_value==0&&lock_writes==2&&lock_calls==8);
    CHECK(!pmsl_release(lock)&&!pmsc_close_unused(owner));
    for(unsigned busy=1;busy<=2;busy++){
        lock_setup();lock_value=busy;CHECK(!pmsl_acquire(lock,sm)&&lock->busy&&!lock->unknown&&!lock_writes&&lock_reads==1);
        CHECK(!pmsl_release(lock)&&lock_value==busy&&!lock_writes);
    }
    lock_setup();lock_race=1;CHECK(!pmsl_acquire(lock,sm)&&lock->unknown&&lock_value==2&&lock_writes==1);
    CHECK(!pmsl_release(lock)&&lock_value==2&&lock_writes==1);
    for(unsigned at=1;at<=8;at++){
        lock_setup();lock_fault=1;lock_trigger=at;
        if(at<=4)CHECK(!pmsl_acquire(lock,sm));else{CHECK(pmsl_acquire(lock,sm));CHECK(!pmsl_release(lock));}
        CHECK(lock->unknown&&lock->pending&&!lock->released&&lock_calls==at);
        unsigned calls=lock_calls;CHECK(!pmsl_release(lock)&&lock_calls==calls);
    }
    for(unsigned fault=2;fault<=8;fault++){
        lock_setup();lock_fault=fault;lock_trigger=2;CHECK(!pmsl_acquire(lock,sm)&&lock->unknown&&!lock->released);
        unsigned calls=lock_calls;CHECK(!pmsl_release(lock)&&lock_calls==calls);
    }
    lock_setup();CHECK(pmsl_acquire(lock,sm));lock_value=2;CHECK(!pmsl_release(lock)&&lock->unknown&&lock_writes==1&&lock_value==2);
    lock_setup();CHECK(pmsl_acquire(lock,sm));lock->record[0].native.value^=1;CHECK(!pmsl_held(lock)&&!pmsl_release(lock)&&lock_writes==1);
    smem_test_close();printf("PASS %u native SMEM lock checks, %u scenarios; software privileged leaves only\n",checks,lock_scenarios);return 0;
}
