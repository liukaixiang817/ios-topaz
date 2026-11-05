/* Actual retained-source bindings at startup and running-kernel states.
 * Privileged leaves are the existing software fixture; binding state1/4 is
 * NOT a runtime owner grant, as the old owner rejection below demonstrates. */
#define PMSC_TEST_ENTRY unused_owner_main
#include "polaris-mss-cpu-owner-test.c"
int main(int argc,char**argv)
{
    CHECK(argc==2);CHECK(!posix_memalign((void**)&arena,0x4000,0x200000));original=malloc(PGCI_IMAGE_BYTES);CHECK(original);
    FILE*f=fopen(argv[1],"rb");CHECK(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));
    host_page=(size_t)sysconf(_SC_PAGESIZE);CHECK(host_page&&host_page<=0x4000&&!(host_page&(host_page-1)));
    shadow_mapping=mmap(0,0x104000+2*host_page,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(shadow_mapping!=MAP_FAILED);
    shadow=shadow_mapping+host_page;CHECK(!mprotect(shadow,0x104000,PROT_READ|PROT_WRITE));
    owner_setup(0,0);CHECK(owner_begin());
    CHECK(pmsb_binding(share)&&pmsb_binding_at(share,0,2)&&!pmsb_binding_at(share,1,4));
    *native_flag=1;*(uint32_t*)(uintptr_t)held_input.state=4;
    CHECK(!pwea_native_binding(early)&&!pweh_binding(held)&&!pmmn_binding(mss)&&!pmsi_binding(stage)&&!pmsb_binding(share));
    CHECK(pwea_native_binding_at(early,1)&&pweh_binding_at(held,1,4)&&pmmn_binding_at(mss,1)&&
          pmmn_retained_at(mss,allocation_digest,held,1,4)&&pmsi_binding_at(stage,1,4)&&pmsb_binding_at(share,1,4));
    CHECK(!pmsb_binding_at(share,1,2)&&!pmsb_binding_at(share,0,4)&&!pmsb_binding_at(share,2,4));
    for(unsigned state=0;state<7;state++){
        *(uint32_t*)(uintptr_t)held_input.state=state;
        CHECK(pmsb_binding_at(share,1,4)==(state==4));
    }
    *(uint32_t*)(uintptr_t)held_input.state=4;
    struct pwea_core*q=calloc(1,sizeof(*q));CHECK(q);
    CHECK(pwea_core_check_at(early,q,&held->map,1)&&q->complete);memset(q,0,sizeof(*q));
    CHECK(!pwea_core_check(early,q,&held->map));
    mss->early_digest[0]^=1;CHECK(!pmsb_binding_at(share,1,4));mss->early_digest[0]^=1;
    stage->asset[0].bytes^=1;CHECK(!pmsb_binding_at(share,1,4));stage->asset[0].bytes^=1;
    CHECK(pmsb_binding_at(share,1,4));
    CHECK(!pmsc_live(owner)&&owner->unknown&&owner->held&&!owner->restore_issued);
    free(q);
    if(descriptor_protected)CHECK(!mprotect(&share->page,host_page,PROT_READ|PROT_WRITE));
    CHECK(!munmap(shadow_mapping,0x104000+2*host_page));free(original);free(arena);
    printf("PASS %u retained-source checks including original fixture; startup authority remains closed after CPU_ON\n",checks);return 0;
}
