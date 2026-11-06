/* Real allocation/stage/MBA producers; all privileged leaves are software.
 * The MBA shadow stays PROT_NONE while the independent CPU interval runs. */
#define PMSB_TEST_ENTRY unused_share_suite
#include "polaris-mss-mba-share-test.c"
static int owner_arch(void*,struct pgcd_arch*);
#undef pgcd_actual_arch
#define pgcd_actual_arch owner_arch
#define EFI_XNU_MSS_CPU_OWNER_AVAILABLE 1
#define POLARIS_MSS_CPU_OWNER_SOFTWARE_PEER 1
#include "uefi-mss-cpu-owner.h"
static struct pmsc_owner*owner;
static unsigned owner_fault,owner_trigger,owner_peers,owner_arches;
static uint64_t owner_delay;
_Static_assert(sizeof(struct pmsc_owner)<0x20000,"owner fixture before MBA descriptor");
static int owner_arch(void*p,struct pgcd_arch*a)
{
    int ok=early_arch(p,a);a->cpu.daif=local_mask?0xc0:0;a->cpu.group1=local_mask?0:1;
    a->cpu.ticks+=owner_delay;owner_arches++;
    if(owner_arches==owner_trigger){
        if(owner_fault==1)a->cpu.ttbr0^=4096;
        if(owner_fault==2)a->cpu.daif^=0x80;
        if(owner_fault==3)a->cpu.group1^=1;
        if(owner_fault==4)a->cpacr=0;
    }return ok;
}
static int pmsc_affinity(uint64_t target,int64_t*raw)
{
    CHECK(local_mask&&target==(owner_peers%7+1)*0x100);owner_peers++;*raw=1;
    if(owner_peers==1&&owner_fault==11)owner_delay+=PMSC_ADMISSION_TICKS+1;
    if(owner_peers==owner_trigger){
        if(owner_fault==5)*raw=0;
        if(owner_fault==6)return 0;
        if(owner_fault==7)owner->fp.q8_q15[0]^=1;
    }return 1;
}
static int pmsc_mask(struct pwrpc_transition*t)
{
    CHECK(!local_mask&&t->target_daif==0xc0&&!t->target_group);
    t->group_before=1;t->daif_read=0xc0;t->daif_written=t->daif_observed=t->group_written=t->group_observed=1;
    local_mask=1;if(owner_fault==8)t->daif_read=0x80;
    if(owner_fault==10)put(core+0x1cdb0,held->map.map.key+1,8);return 1;
}
static int pmsc_restore(struct pwrpc_transition*t)
{
    CHECK(local_mask&&!owner->effects&&t->target_group==1&&!t->target_daif);
    t->daif_before=0xc0;t->group_read=1;t->daif_written=t->daif_observed=t->group_written=t->group_observed=1;
    if(owner_fault==9){t->group_read=0;return 0;}local_mask=0;return 1;
}
static void owner_setup(unsigned f,unsigned at)
{
    share_setup(0,0,0);CHECK(pmsb_share(share,stage));
    CHECK(target_protected&&!local_mask&&share->complete);
    owner=(void*)(arena+0x150000);memset(owner,0,sizeof(*owner));
    owner_fault=f;owner_trigger=at;owner_peers=owner_arches=0;owner_delay=0;
}
static int owner_begin(void){return pmsc_begin(owner,held,mss,allocation_digest,share);}
#ifndef PMSC_TEST_ENTRY
#define PMSC_TEST_ENTRY main
#endif
int PMSC_TEST_ENTRY(int argc,char**argv)
{
    CHECK(argc==2);CHECK(!posix_memalign((void**)&arena,0x4000,0x200000));original=malloc(PGCI_IMAGE_BYTES);CHECK(original);
    FILE*f=fopen(argv[1],"rb");CHECK(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));
    host_page=(size_t)sysconf(_SC_PAGESIZE);CHECK(host_page&&host_page<=0x4000&&!(host_page&(host_page-1)));
    shadow_mapping=mmap(0,0x104000+2*host_page,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(shadow_mapping!=MAP_FAILED);
    shadow=shadow_mapping+host_page;CHECK(!mprotect(shadow,0x104000,PROT_READ|PROT_WRITE));
    owner_setup(0,0);CHECK(owner_begin()&&owner->held&&local_mask&&owner->phase==2&&owner->checkpoints==2&&owner_peers==7);
    uint64_t opening=owner->opening;owner_delay=PGCD_FRESH_TICKS+1;
    CHECK(pmsc_live(owner)&&owner->opening==opening&&pmsc_checkpoint(owner));
    CHECK(pmsc_close_unused(owner)&&!local_mask&&!owner->held&&owner->complete&&owner_peers==14);
    CHECK(!owner_begin()&&!pmsc_live(owner)&&!pmsc_close_unused(owner));
    for(unsigned effect=1;effect<=8;effect*=2){
        owner_setup(0,0);CHECK(owner_begin());CHECK(pmsc_mark_effect(owner,effect));
        CHECK(!pmsc_close_unused(owner)&&owner->held&&local_mask&&!owner->restore_issued);
    }
    for(unsigned fault=5;fault<=7;fault++)for(unsigned peer=1;peer<=14;peer++){
        owner_setup(fault,peer);
        if(peer<=7)CHECK(!owner_begin());else{CHECK(owner_begin());CHECK(!pmsc_close_unused(owner));}
        CHECK(owner->unknown&&owner->held&&local_mask&&!owner->complete&&owner_peers==peer);
    }
    for(unsigned fault=1;fault<=4;fault++)for(unsigned at=1;at<=20;at++){
        owner_setup(fault,at);CHECK(!owner_begin()&&owner->unknown&&!owner->complete);
    }
    owner_setup(8,0);CHECK(!owner_begin()&&owner->unknown&&owner->held);
    owner_setup(10,0);CHECK(!owner_begin()&&owner->unknown&&owner->held&&!owner_peers);
    owner_setup(9,0);CHECK(owner_begin());CHECK(!pmsc_close_unused(owner)&&owner->unknown&&owner->held&&owner->restore_issued);
    for(unsigned fault=0;fault<7;fault++){
        owner_setup(0,0);CHECK(owner_begin());
        if(fault==0)owner_delay=PMSC_TOTAL+1;
        if(fault==1)*native_flag=1;
        if(fault==2)*(uint64_t*)(uintptr_t)held_input.received=0;
        if(fault==3)*(uint8_t**)(uintptr_t)held_input.payload_slot+=4096;
        if(fault<4)CHECK(!pmsc_live(owner)&&owner->unknown&&owner->held);
        else{
            if(fault==4)held->map.data[0]^=1;
            if(fault==5)mss->complete=0;
            if(fault==6)share->transaction.complete=0;
            CHECK(!pmsc_checkpoint(owner)&&owner->unknown&&owner->held);
        }
    }
    owner_setup(0,0);owner_delay=PGCD_FRESH_TICKS+1;CHECK(!owner_begin()&&!owner->mask_issued);
    /* A fully checked long MBA caller is a fresh predecessor even though
     * the pre-staging GetMap is now older than a single GCD-call budget. */
    owner_setup(0,0);share_setup(27,0,0);CHECK(pmsb_share(share,stage));
    owner_delay=share_clock_delay;CHECK(owner_begin()&&owner->phase==2&&owner->held);
    CHECK(owner->entry.cpu.ticks-held->final.cpu.ticks>PGCD_FRESH_TICKS);
    CHECK(owner->entry.cpu.ticks-share->restored.cpu.ticks<=PGCD_FRESH_TICKS);
    CHECK(pmsc_close_unused(owner));
    /* Once started, admission may exceed200ms but never renew its500ms bound. */
    owner_setup(0,0);CHECK(owner_begin());
    owner->phase=1;owner_delay=PGCD_FRESH_TICKS+1;CHECK(pmsc_arch(owner,&owner->current,1));
    owner_delay=PMSC_ADMISSION_TICKS+1;CHECK(!pmsc_arch(owner,&owner->current,1));
    owner_setup(11,0);CHECK(!owner_begin()&&owner->unknown&&owner->held&&owner_peers==1);
    for(unsigned changed=0;changed<8;changed++){
        owner_setup(0,0);CHECK(owner_begin());
        unsigned at=(unsigned[]){0x1cdb0,0x1cc08,0x1dc10,0x1b350,0x1bd58,0x1c208,0x1b098,0x1cb78}[changed];
        put(core+at,changed==0?held->map.map.key+1:changed==6?8:(changed<3||changed==7)?1:0,8);
        CHECK(!pmsc_live(owner)&&owner->unknown&&owner->held&&!owner->restore_issued);
    }
    owner_setup(0,0);CHECK(owner_begin());
    while(owner->checkpoints<PMSC_CHECKPOINTS)CHECK(pmsc_checkpoint(owner));
    CHECK(!pmsc_checkpoint(owner)&&owner->unknown&&owner->held&&!owner->restore_issued);
    if(descriptor_protected)CHECK(!mprotect(&share->page,host_page,PROT_READ|PROT_WRITE));
    CHECK(!munmap(shadow_mapping,0x104000+2*host_page));free(original);free(arena);
    printf("PASS %u continuous CPU interval checks; software only, no DRV2/DMA ownership claim\n",checks);return 0;
}
