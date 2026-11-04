/* Full early -> retained -> actual secure caller, SOFTWARE leaves only. */
#define PWEH_TEST_ENTRY original_retained_test
#include "polaris-wifi-retained-memory-test.c"
#include <sys/mman.h>
#include <unistd.h>
static unsigned local_mask,s_fault,s_trigger,peer_calls,zero_calls,cache_calls,smc_calls,interrupts;
static int share_arch(void*,struct pgcd_arch*);
#undef pgcd_actual_arch
#define pgcd_actual_arch share_arch
#define EFI_XNU_WIFI_MEM_ASSIGN_AVAILABLE 1
#define EFI_XNU_WIFI_RMTFS_SHARE_AVAILABLE 1
#define POLARIS_WIFI_RMTFS_SHARE_SOFTWARE_PEER 1
#include "../shim/polaris/uefi-wifi-rmtfs-share.h"
static struct pwsr_result*share;
static uint8_t*target_shadow,*target_allocation;
static unsigned page_protected;
static size_t host_page_bytes;
_Static_assert(sizeof(struct pwsr_result)<0x40000,"fixture resident share range");
static int share_arch(void*p,struct pgcd_arch*a)
{
    int ok=early_arch(p,a);a->cpu.daif=local_mask?0xc0:0;a->cpu.group1=local_mask?0:1;
    if(s_fault==1&&zero_calls==s_trigger)a->cpu.ttbr0^=4096;
    if(s_fault==2&&zero_calls==s_trigger)a->cpu.ticks+=PGCD_FRESH_TICKS;
    return ok;
}
static struct pwmk_record scache(uint64_t address,unsigned op)
{return (struct pwmk_record){.address=address,.ctr_before=4u<<16,.ctr_after=4u<<16,.el=4,.sctlr=5,
    .operation=op,.line_bytes=64,.lines_issued=64,.lines_returned=64,.attempted=1,.barrier_issued=1,.barrier_returned=1,.complete=1};}
static int pwsr_zero_page(uint64_t at,struct pwsr_zero*z)
{
    CHECK(local_mask&&at==early->memory.claim[1].exposed+4096*zero_calls&&zero_calls<512&&!smc_calls);
    z->AT.page=at;CHECK(early_translate(&z->AT));zero_calls++;
    if(s_fault==3&&zero_calls==s_trigger){z->words_issued=1;return 0;}
    CHECK(pwsr_zero_words((uintptr_t)(target_shadow+4096*(zero_calls-1)),z));
    z->cache=scache(at,PWMK_CLEAN_INVALIDATE);z->complete=1;
    if(s_fault==4&&zero_calls==s_trigger)z->cache.barrier_returned=0;
    return 1;
}
static int pwsr_affinity(uint64_t target,int64_t*raw)
{
    CHECK(local_mask&&target==0x100*(peer_calls%7+1));peer_calls++;*raw=1;
    if(s_fault==5&&peer_calls==s_trigger)*raw=0;
    if(s_fault==6&&peer_calls==s_trigger)share->fp.q8_q15[0]^=1;
    return s_fault==7&&peer_calls==s_trigger?0:1;
}
static int pwsr_mask(struct pwrpc_transition*t)
{
    CHECK(!local_mask&&t->target_daif==0xc0&&!t->target_group);
    t->group_before=1;t->daif_read=0xc0;t->daif_written=t->daif_observed=t->group_written=t->group_observed=1;
    local_mask=1;if(s_fault==8)t->group_read=1;return 1;
}
static int pwsr_restore(struct pwrpc_transition*t)
{
    CHECK(local_mask&&t->target_group==1&&!t->target_daif&&share->assignment_returned_zero);
    t->daif_before=0xc0;t->group_read=1;t->daif_written=t->daif_observed=t->group_written=t->group_observed=1;
    if(s_fault==9){t->group_read=0;return 0;}local_mask=0;return 1;
}
static int pwsr_cache(struct pwma_page*page,unsigned op,struct pwmk_record*r)
{
    CHECK(local_mask&&page==&share->page&&zero_calls==512);cache_calls++;
    CHECK((cache_calls==1&&op==PWMK_CLEAN_INVALIDATE)||(cache_calls==2&&op==PWMK_INVALIDATE));
    *r=scache((uintptr_t)page,op);
    if(s_fault==10&&cache_calls==s_trigger){r->lines_returned=1;return 0;}
    if(op==PWMK_INVALIDATE){CHECK(page_protected&&!mprotect(page,host_page_bytes,PROT_READ|PROT_WRITE));page_protected=0;}
    if(s_fault==11&&cache_calls==2)page->data[4095]^=1;
    return 1;
}
static int pwsr_round(struct pwma_registers*r)
{
    CHECK(local_mask&&zero_calls==512&&cache_calls==1&&peer_calls==7);smc_calls++;
    if(smc_calls==1){
        CHECK(r->x[0]==PWMA_FN&&r->x[1]==PWMA_ARGS);
        CHECK(pwfi_le(share->page.data+PWMA_REGION_OFFSET,8)==early->memory.claim[1].exposed);
        CHECK(pwfi_le(share->page.data+PWMA_REGION_OFFSET+8,8)==0x200000);
        for(unsigned n=0;n<0x200000;n++)assert(!target_shadow[n]);
    }else CHECK(r->x[0]==1&&r->x[1]==0x12340000+smc_calls-1);
    if(!page_protected){CHECK(!mprotect(&share->page,host_page_bytes,PROT_NONE));page_protected=1;}
    r->x[0]=smc_calls<=interrupts?1:0;r->x[1]=r->x[0]?0x12340000+smc_calls:0;
    if(s_fault==12)r->x[0]=UINT64_MAX;
    if(s_fault==13)share->fp.q8_q15[0]^=1;
    if(s_fault==14)held->payload_bytes++;
    return s_fault==15?0:1;
}
static void ssetup(unsigned fault_kind,unsigned position,unsigned continuations)
{
    if(page_protected){CHECK(!mprotect(&share->page,host_page_bytes,PROT_READ|PROT_WRITE));page_protected=0;}
    setup(0,0);early_sctlr_extra=4;self->bytes=0xc0000;CHECK(run());held=(void*)(arena+0x60000);
    uint8_t*digest=arena+0x7f040;pweh_digest(early,sizeof(*early),digest);
    hi=(struct pweh_input){.early=early,.digest=digest,.payload_slot=(void*)(arena+0x7f008),.log_slot=(void*)(arena+0x7f010),
        .state=(void*)(arena+0x7f018),.received=(void*)(arena+0x7f020),.count=(void*)(arena+0x7f028),.logical_bytes=5000,.log_bytes=16384};
    *(uint8_t**)(uintptr_t)hi.payload_slot=(void*)UINT64_C(0xd0000000);*(uint8_t**)(uintptr_t)hi.log_slot=(void*)UINT64_C(0xd1000000);
    *(uint32_t*)(uintptr_t)hi.state=2;*(uint64_t*)(uintptr_t)hi.received=*(uint64_t*)(uintptr_t)hi.count=hi.logical_bytes;
    at_calls=core_at_calls=0;h_fault=h_maps=0;CHECK(pweh_run(held,&hi));
    uintptr_t at=(uintptr_t)arena+0xb0000;
    at+=(-(at+offsetof(struct pwsr_result,page)))&(host_page_bytes-1);
    share=(void*)at;CHECK((uintptr_t)&share->page+host_page_bytes<=(uintptr_t)arena+0x100000);
    memset(target_allocation,0xa5,0x202000);
    local_mask=peer_calls=zero_calls=cache_calls=smc_calls=0;s_fault=fault_kind;s_trigger=position;interrupts=continuations;
}
int main(int argc,char**argv)
{
    assert(argc==2);CHECK(!posix_memalign((void**)&arena,4096,0x100000));original=malloc(PGCI_IMAGE_BYTES);
    host_page_bytes=(size_t)sysconf(_SC_PAGESIZE);CHECK(host_page_bytes>=4096&&!(host_page_bytes&(host_page_bytes-1)));
    CHECK(!posix_memalign((void**)&target_allocation,4096,0x202000));target_shadow=target_allocation+4096;assert(original);
    FILE*f=fopen(argv[1],"rb");assert(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));
    for(unsigned rounds=0;rounds<4;rounds++){
        ssetup(0,0,rounds);CHECK(pwsr_share(share,held));CHECK(share->complete&&!share->unknown&&!share->held&&!local_mask);
        CHECK(share->assignment_returned_zero&&!share->remote_publish_issued&&peer_calls==14&&zero_calls==512&&cache_calls==2&&smc_calls==rounds+1);
        CHECK(!pwsr_share(share,held)&&smc_calls==rounds+1);
        for(unsigned k=0;k<4096;k++)assert(target_allocation[k]==0xa5&&target_shadow[0x200000+k]==0xa5);
    }
    for(unsigned kind=1;kind<=15;kind++){
        unsigned limit=(kind>=5&&kind<=7)?14:(kind==3||kind==4)?512:kind==10?2:1;
        for(unsigned index=0;index<(limit>14?3:limit);index++){
            unsigned pos=limit>14?(unsigned[]){1,256,512}[index]:index+1;
            ssetup(kind,pos,0);CHECK(!pwsr_share(share,held)&&share->unknown&&!share->complete);
            CHECK(!pwsr_share(share,held));
        }
    }
    for(unsigned kind=33;kind<=34;kind++){
        ssetup(0,0,0);efault=kind;trigger=api_calls;
        CHECK(!pwsr_share(share,held)&&share->unknown&&!share->complete);
        CHECK(kind==33?(!local_mask&&!smc_calls):(local_mask&&share->assignment_returned_zero));
    }
    ssetup(0,0,4);CHECK(!pwsr_share(share,held)&&share->unknown&&smc_calls==4&&cache_calls==1&&local_mask);
    if(page_protected)CHECK(!mprotect(&share->page,host_page_bytes,PROT_READ|PROT_WRITE));
    free(target_allocation);free(original);free(arena);printf("PASS %u actual RMTFS share caller SOFTWARE checks\n",checks);return 0;
}
