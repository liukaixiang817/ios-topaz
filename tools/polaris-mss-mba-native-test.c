/* Actual MBA native adapter control flow; architecture/AT/MMIO are software. */
#define main legacy_mba_suite
#include "polaris-mss-mba-boot-test.c"
#undef main
#define EFI_XNU_MSS_NATIVE_IO_AVAILABLE 1
#define POLARIS_MSS_NATIVE_SOFTWARE_PEER 1
#include "../shim/polaris/uefi-mss-mmio-native.h"
static struct pmni_arch mba_arch;
static struct pmni_result mba_io;
static struct pmba_command mba_io_command;
static uint64_t mba_counter;
static unsigned mba_raw_failure,mba_raw_calls,mba_at_calls;
static int pmni_arch_read(struct pmni_arch*a)
{*a=mba_arch;a->ticks=++mba_counter;return 1;}
static int pmni_translate(struct pmni_translation*t)
{
    mba_at_calls++;t->saved=t->restored=0x1234;t->read_par=t->write_par=t->page|0x200;
    t->read_issued=t->read_returned=t->write_issued=t->write_returned=t->restore_issued=t->restore_returned=1;return 1;
}
static int pmni_raw(const struct pmni_command*c,uint32_t*value)
{
    mba_raw_calls++;const struct pmba_command*q=&mba_io_command;
    uint64_t address=q->phase==2?q->reset.address:q->address;
    uint32_t kind=q->phase==2?q->reset.kind:q->kind,v=q->phase==2?q->reset.value:q->value;
    CHECK(c->address==address&&c->kind==kind&&c->value==v);
    if(mba_raw_failure)return 0;*value=mba_value(q,2,0);return 1;
}
static void native_mba_case(int failed,unsigned altered)
{
    mba_counter=mba_start();mba_raw_failure=mba_raw_calls=mba_at_calls=0;
    mba_arch=(struct pmni_arch){.el=4,.mpidr=0x81000000,.ttbr0=0x10004000,.tcr=0x80803520,.sctlr=5,
        .mair=0xffbb4400,.daif=0xc0,.sre=7,.cpacr=0x300000,.frequency=19200000,.ticks=mba_counter};
    unsigned event=0;
    for(;;){
        int next=pmba_next(&mba,mba_counter,&mba_io_command);
        if(next==PMBA_READY){CHECK(failed<0&&event==30&&mba_raw_calls==30);return;}
        if(next==PMBA_WAIT){
            uint64_t wake=mba.phase==2?mba.reset.not_before:mba.next_poll;
            mba_counter=wake>mba_counter?wake:mba_counter+1;continue;
        }
        CHECK(next==PMBA_IO);memset(&mba_io,0,sizeof(mba_io));
        unsigned before=mba_raw_calls;
        if((int)event==failed&&altered)mba_io_command.address^=4;
        mba_raw_failure=(int)event==failed&&!altered;
        int result=pmni_mba(&mba,&mba_io_command,&mba_arch,&mba_io);
        if((int)event==failed){
            CHECK(!result&&!mba_io.complete);
            CHECK(mba_raw_calls==before+!altered);
            if(!altered){CHECK(mba_io.unknown&&mba_io.issued&&!mba_io.returned);
                CHECK(pmba_complete(&mba,&mba_io_command,mba_counter,0,0)==PMBA_FAILED);CHECK(mba.unknown);}
            CHECK(clocks.phase==2&&clocks.held==63&&!mba.ready);return;
        }
        CHECK(result&&mba_io.complete&&!mba_io.unknown&&mba_io.issued&&mba_io.returned);
        CHECK(pmba_complete(&mba,&mba_io_command,mba_io.after.ticks,1,mba_io.value)>=0);event++;
    }
}
int main(void)
{
    legacy_mba_suite();unsigned before=checks;native_mba_case(-1,0);
    for(int failed=0;failed<30;failed++){native_mba_case(failed,0);native_mba_case(failed,1);}
    printf("PASS %u native MBA adapter checks, %u total (software only)\n",checks-before,checks);return 0;
}
