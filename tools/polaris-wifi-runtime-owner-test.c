/* Actual CPU-owner source/clock gates with synthetic handoff records.
 * This does not exercise CPU_ON or claim a complete native handoff. */
#define EFI_XNU_WIFI_RUNTIME_HANDOFF_AVAILABLE 1
#define PMSC_TEST_ENTRY unused_owner_main
#include "polaris-mss-cpu-owner-test.c"
static void model_transition(void)
{
    struct pmsc_runtime*r=&owner->runtime;
    r->attempted=r->issued=r->returned=r->observed=r->complete=1;
    r->parent=1;r->copy=2;r->entry=3;r->context=4;r->started=owner->last;
    *native_flag=1;*(uint32_t*)(uintptr_t)held_input.state=4;owner->phase=4;
}
int main(int argc,char**argv)
{
    CHECK(argc==2);CHECK(!posix_memalign((void**)&arena,0x4000,0x200000));original=malloc(PGCI_IMAGE_BYTES);CHECK(original);
    FILE*f=fopen(argv[1],"rb");CHECK(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));
    host_page=(size_t)sysconf(_SC_PAGESIZE);CHECK(host_page&&host_page<=0x4000&&!(host_page&(host_page-1)));
    shadow_mapping=mmap(0,0x104000+2*host_page,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(shadow_mapping!=MAP_FAILED);
    shadow=shadow_mapping+host_page;CHECK(!mprotect(shadow,0x104000,PROT_READ|PROT_WRITE));
    owner_setup(0,0);CHECK(owner_begin());uint64_t epoch=owner->opening;
    CHECK(pmsc_count_available(owner,65535,65536)&&!pmsc_count_available(owner,65536,65536));
    CHECK(pmsc_count_valid(owner,65536,65536)&&!pmsc_count_valid(owner,65537,65536));
    model_transition();CHECK(pmsc_count_available(owner,UINT32_MAX,65536)&&pmsc_count_valid(owner,UINT32_MAX,65536));
    CHECK(!pmsc_count_available(owner,UINT64_MAX,65536));CHECK(pmsc_bound(owner)&&pmsc_live(owner));owner_delay=PMSC_TOTAL+19200000;
    CHECK(pmsc_live(owner)&&owner->opening==epoch&&owner->runtime.live_checks==2);
    CHECK(!pmsc_close_unused(owner)&&owner->held&&!owner->restore_issued);
    for(unsigned bad=0;bad<14;bad++){
        owner_setup(0,0);CHECK(owner_begin());model_transition();
        struct pmsc_runtime*r=&owner->runtime;
        if(bad==0)r->attempted=0;else if(bad==1)r->issued=0;else if(bad==2)r->returned=0;
        else if(bad==3)r->observed=0;else if(bad==4)r->complete=0;else if(bad==5)r->result=-1;
        else if(bad==6)r->unknown=1;else if(bad==7)r->parent=0;else if(bad==8)r->copy=0;
        else if(bad==9)r->context=0;else if(bad==10)r->entry=0;
        else if(bad==11)*native_flag=0;else if(bad==12)*(uint32_t*)(uintptr_t)held_input.state=2;
        else r->live_checks=UINT64_MAX;
        CHECK(!pmsc_live(owner)&&owner->held&&!owner->restore_issued);
    }
    owner_setup(0,0);CHECK(owner_begin());model_transition();owner->runtime.complete=0;owner_delay=PMSC_TOTAL+1;
    CHECK(!pmsc_arch(owner,&owner->current,1)&&owner->unknown);
    owner_setup(0,0);CHECK(owner_begin());owner_delay=PMSC_TOTAL+1;CHECK(!pmsc_live(owner)&&owner->unknown);
    owner_setup(0,0);CHECK(owner_begin());model_transition();put(core+0x1cdb0,held->map.map.key+1,8);
    CHECK(!pmsc_live(owner)&&owner->unknown);
    owner_setup(0,0);CHECK(owner_begin());model_transition();mss->early_digest[0]^=1;CHECK(!pmsc_bound(owner));
    if(descriptor_protected)CHECK(!mprotect(&share->page,host_page,PROT_READ|PROT_WRITE));
    CHECK(!munmap(shadow_mapping,0x104000+2*host_page));free(original);free(arena);
    printf("PASS %u runtime-owner checks (software transition records only)\n",checks);return 0;
}
