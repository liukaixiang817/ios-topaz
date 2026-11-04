/* Real CPU/image/GCD/RPMh readers and native delivery control flow. All
 * Device/architectural leaves are software; firmware bytes stay inert. */
#define PMRD_TEST_ENTRY unused_rpmh_suite
#include "polaris-mss-rpmh-state-test.c"
#define EFI_XNU_MSS_NATIVE_IO_AVAILABLE 1
#define EFI_XNU_MSS_RAIL_IO_AVAILABLE 1
#define EFI_XNU_MSS_RSC_STATE_AVAILABLE 1
#define POLARIS_MSS_NATIVE_SOFTWARE_PEER 1
#include "uefi-mss-rsc-state.h"
static struct pmrs_state*device;
static unsigned device_ats,device_reads,device_fault,device_trigger,device_shape;
static int pmni_arch_read(struct pmni_arch*a)
{
    struct pgcd_arch q;if(!owner_arch(0,&q))return 0;const struct pwfc_arch*c=&q.cpu;
    *a=(struct pmni_arch){c->el,c->mpidr,c->ttbr0,c->ttbr1,c->tcr,c->sctlr,c->mair,c->daif,c->sre,c->group1,q.cpacr,c->frequency,c->ticks};
    if(device_fault==5&&device_ats==device_trigger)a->ttbr0^=4096;
    return 1;
}
static int pmni_translate(struct pmni_translation*t)
{
    device_ats++;t->saved=t->restored=0x12345;t->read_par=t->write_par=t->page|0x200;
    t->read_issued=t->read_returned=t->write_issued=t->write_returned=t->restore_issued=t->restore_returned=1;
    if(device_ats==device_trigger){
        if(device_fault==1)return 0;
        if(device_fault==2)t->read_par|=1;
        if(device_fault==3)t->write_par^=4096;
        if(device_fault==4)t->restored++;
    }
    return 1;
}
static int pmni_raw(const struct pmni_command*c,uint32_t*v)
{
    CHECK(c->kind==PMNI_READ&&!c->value&&pmrs_readable(c->address));device_reads++;
    if(device_ats==device_trigger){
        if(device_fault==6)return 0;
        if(device_fault==7)owner_delay=PMSC_TOTAL+1;
    }
    if(c->address==0x179e000c)*v=(8u<<12)|(16u<<27);
    else if(c->address==PWRSC_BASE)*v=15;
    else if(c->address==PWRSC_BASE+4)*v=0;
    else{
        unsigned n=(unsigned)(c->address-PWRSC_BASE)/PWRSC_STRIDE,off=(unsigned)(c->address-PWRSC_BASE)%PWRSC_STRIDE;
        *v=off==0x18?1:off==0x14&&!n?0x01010000:off==0x1c&&!n?1:0;
    }
    if(device_shape==1&&c->address==0x179e000c)*v^=1u<<12;
    if(device_shape==2&&c->address==0x179e000c)*v^=1u<<27;
    if(device_shape==3&&c->address==PWRSC_BASE)*v=0xf0;
    if(device_shape==4&&c->address==PWRSC_BASE+4)*v=1;
    if(device_shape==5&&c->address==PWRSC_BASE+0x18)*v=0;
    if(device_shape==6&&c->address==PWRSC_BASE+0x14)*v=0x01000000;
    if(device_shape==7&&c->address==PWRSC_BASE+0x1c)*v=2;
    if(device_shape==8&&c->address==PWRSC_BASE+PWRSC_STRIDE+0x1c)*v=1;
    if(device_shape==9&&device_reads>35&&c->address==0x179e000c)*v^=1;
    if(device_shape==10&&device_reads>35&&c->address==PWRSC_BASE)*v=7;
    if(device_shape==11&&device_reads>35&&c->address==PWRSC_BASE+7*PWRSC_STRIDE+0x10)*v=1;
    if(device_shape==12&&device_reads==70)image_heap[0x15004+0x3f]^=1;
    if(device_shape==13&&device_reads==70)rp_image[0x1000]^=1;
    if(device_shape==14&&device_reads==70)put(core+0x1cdb0,101,8);
    if(device_shape==15&&device_reads==1)put(image_heap+0x4030,0,8);
    return 1;
}
static void device_setup(void)
{
    device_ats=device_reads=device_fault=device_trigger=device_shape=0;rpmh_setup();CHECK(rpmh_run());
    device=(void*)(arena+0x500000);CHECK(0x500000+sizeof(*device)<PMMN_TEST_IMAGE_BYTES&&0x400000+sizeof(*state)<0x500000);
    memset(device,0,sizeof(*device));
}
static int device_run(void){return pmrs_capture(device,state,resource_map);}
int main(int argc,char**argv)
{
    CHECK(argc==3);CHECK(!posix_memalign((void**)&arena,0x4000,PMMN_TEST_ARENA_BYTES));
    original=malloc(PGCI_IMAGE_BYTES);rp_original=malloc(PWRPI_IMAGE_BYTES);CHECK(original&&rp_original);
    FILE*f=fopen(argv[1],"rb");CHECK(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));
    f=fopen(argv[2],"rb");CHECK(f&&fread(rp_original,1,PWRPI_IMAGE_BYTES,f)==PWRPI_IMAGE_BYTES&&!fclose(f));
    host_page=(size_t)sysconf(_SC_PAGESIZE);CHECK(host_page&&host_page<=0x4000&&!(host_page&(host_page-1)));
    shadow_mapping=mmap(0,0x104000+2*host_page,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(shadow_mapping!=MAP_FAILED);
    shadow=shadow_mapping+host_page;CHECK(!mprotect(shadow,0x104000,PROT_READ|PROT_WRITE));
    heap_mapping=mmap(0,0x100000+2*host_page,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(heap_mapping!=MAP_FAILED);
    image_heap=heap_mapping+host_page;CHECK(!mprotect(image_heap,0x100000,PROT_READ|PROT_WRITE));
    device_setup();int ok=device_run();
    if(!ok)fprintf(stderr,"DRV2 error%u events%u reads%u AT%u native%u CPU%u after%u\n",device->error,device->events,device_reads,device_ats,device->event[device->events?device->events-1:0].native.error,owner->error,device->after.error);
    CHECK(ok&&device->complete&&!device->unknown&&!device->pending&&device->events==70&&device_reads==70&&device_ats==70&&device->selected==0&&device->active_mask==15);
    CHECK(pmrs_current(device,state,resource_map));device->event[0].native.value^=1;
    CHECK(!pmrs_current(device,state,resource_map));device->event[0].native.value^=1;
    CHECK(!device_run());CHECK(pmsc_close_unused(owner)&&!pmrs_current(device,state,resource_map));
    fprintf(stderr,"normal DRV2 capture PASS; starting all70 delivery failure positions\n");
    for(unsigned fault=1;fault<=7;fault++){
        for(unsigned at=1;at<=70;at++){
            device_setup();device_fault=fault;device_trigger=at;CHECK(!device_run()&&device->unknown&&!device->complete&&device->pending==at&&device_ats==at);
            CHECK(device_reads==(fault<=5?at-1:at));
        }
        fprintf(stderr,"delivery failure class%u/7 PASS\n",fault);
    }
    for(unsigned shape=1;shape<=15;shape++){
        device_setup();device_shape=shape;ok=device_run();if(ok)fprintf(stderr,"accepted shape%u\n",shape);
        CHECK(!ok&&device->unknown&&!device->complete);
    }
    device_setup();state->pass[1].read[0].raw[0]^=1;CHECK(!device_run()&&!device_reads);
    device_setup();owner->effects=1;CHECK(!device_run()&&!device_reads);
    device_setup();put(image_heap+0x4038,2,4);CHECK(!device_run()&&!device_reads);
    struct pmni_command write_config={0x179e000c,PMNI_WRITE,1};CHECK(!pmni_allowed(&write_config));
    CHECK(!munmap(heap_mapping,0x100000+2*host_page));CHECK(!munmap(shadow_mapping,0x104000+2*host_page));free(original);free(rp_original);free(arena);
    printf("PASS %u current DRV2 checks, %u scenarios, 70 native reads/capture; no hardware/votes/IRQ writes\n",checks,scenarios);return 0;
}
