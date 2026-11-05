/* Actual handoff body + actual retained/MBA/CPU source gates. Only the
 * complete-radio READY predicate and privileged leaves are software peers.
 * No real CPU or radio is started; this is not the complete parent model. */
#include <stdint.h>
static uintptr_t test_payload_base;
#define PMMN_TEST_PAYLOAD_BASE test_payload_base
#define EFI_XNU_WIFI_RUNTIME_HANDOFF_AVAILABLE 1
#define PMMN_TEST_PAYLOAD_BYTES 0x8000
#define PMSC_TEST_ENTRY unused_owner_main
#include "polaris-mss-cpu-owner-test.c"
#define POLARIS_UEFI_WIFI_STARTUP_PARENT_H
#define EFI_XNU_WIFI_STARTUP_PARENT_AVAILABLE 1
#define POLARIS_WIFI_RUNTIME_SOFTWARE_PEER 1
#define PWNS_READY 45
struct pwns_parent {
    struct pmsc_owner owner;unsigned attempted,phase,unknown,error;
    struct {struct {unsigned phase;uint8_t mac[6];}client;}wmi;
    unsigned data,nonce;
};
static unsigned radio_ready=1,cpu_calls,cache_calls,cache_fail,cpu_fault;
#define pmwi_live(p) ((void)(p),radio_ready)
#define pmhd_live(p) ((void)(p),radio_ready)
#define pmnp_live(p) ((void)(p),radio_ready)
#include "uefi-wifi-runtime-handoff.h"
static struct pwns_parent*parent;
static struct polaris_efi_ap*boot_ap;
static struct pwks_image*copied;
static struct polaris_plan boot_plan;
static struct polaris_payload*boot_payload;
static uint8_t*kernel_shadow;
static int pwkr_cache(uint64_t at,uint64_t bytes,unsigned clean)
{
    CHECK(at&&bytes&&clean<=1);cache_calls++;return cache_calls!=cache_fail;
}
static int64_t pwkr_cpu_on(uint64_t entry,uint64_t context)
{
    cpu_calls++;CHECK(cpu_calls==1&&entry==(uintptr_t)arena+0x175000&&context==(uintptr_t)boot_ap);
    CHECK(*native_flag==1&&*held_input.state==4&&owner->phase==4&&owner->runtime.issued==1);
    CHECK(!pmsc_live(owner)&&owner->held&&!owner->restore_issued);
    CHECK(owner_peers==14&&cache_calls>=4);
    struct pwmb_identity id;CHECK(pwmb_bootstrap_parse(kernel_shadow+0x4000+PWMB_BOOTSTRAP_OFFSET,&id));
    CHECK(id.epoch==owner->opening&&id.mac[5]==7);
    if(cpu_fault==2)owner->fp.q8_q15[0]^=1;
    return cpu_fault==1?-1:0;
}
static void handoff_setup(void)
{
    owner_setup(0,0);CHECK(owner_begin());parent=(void*)owner;
    memset((uint8_t*)parent+sizeof(*owner),0,sizeof(*parent)-sizeof(*owner));
    parent->attempted=1;parent->phase=PWNS_READY;parent->wmi.client.phase=4;
    parent->wmi.client.mac[0]=2;parent->wmi.client.mac[5]=7;
    radio_ready=1;cpu_calls=cache_calls=cache_fail=cpu_fault=0;
    copied=(void*)(arena+0x170000);memset(copied,0,sizeof(*copied));
    boot_ap=(void*)(arena+0x174000);memset(boot_ap,0,sizeof(*boot_ap));
    memset(boot_payload,0,PMMN_TEST_PAYLOAD_BYTES);memset(kernel_shadow,0,0x10000);
    struct polaris_payload*p=boot_payload;memcpy(p->magic,"SWEETXNU",8);p->version=1;p->nsegs=2;
    p->virt_base=UINT64_C(0xfffffe0006000000);p->kernel_end=p->virt_base+0x8000;p->entry_va=p->virt_base;
    p->phys_base=(uintptr_t)kernel_shadow;p->mem_size=0x10000;p->adt_size=8;
    p->segs[0]=(struct polaris_segment){p->virt_base,0x4000,0x1000,64};
    p->segs[1]=(struct polaris_segment){p->virt_base+0x4000,0x4000,0x2000,0x4000};
    ((uint8_t*)p)[0x1000]=0xa5;((uint8_t*)p)[0x2000]=0x50;((uint8_t*)p)[0x2001]=0x57;
    CHECK(pwks_begin(copied,p,PMMN_TEST_PAYLOAD_BYTES));
    memcpy(kernel_shadow,(uint8_t*)p+0x1000,64);CHECK(pwks_verify(copied,0));
    memcpy(kernel_shadow+0x4000,(uint8_t*)p+0x2000,0x4000);CHECK(pwks_verify(copied,1));
    boot_plan=(struct polaris_plan){(uintptr_t)kernel_shadow+0x8000,(uintptr_t)kernel_shadow+0xc000,(uintptr_t)kernel_shadow+0x10000,(uintptr_t)kernel_shadow};
    *boot_ap=(struct polaris_efi_ap){.entry=boot_plan.entry_pa,.args=boot_plan.args_pa,.sctlr=owner->current.cpu.sctlr,
        .cpacr=owner->current.cpacr,.stack=(uintptr_t)arena+0x17a000};
}
static int launch(void)
{return pwkr_begin(parent,copied,boot_ap,(uintptr_t)arena+0x175000,(uintptr_t)arena+0x176000,0x4000,&boot_plan,boot_payload->virt_base+0x4000);}
#ifndef PWKR_TEST_ENTRY
#define PWKR_TEST_ENTRY main
#endif
int PWKR_TEST_ENTRY(int argc,char**argv)
{
    CHECK(argc==2);CHECK(!posix_memalign((void**)&arena,0x4000,0x200000));original=malloc(PGCI_IMAGE_BYTES);CHECK(original);
    FILE*f=fopen(argv[1],"rb");CHECK(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));
    host_page=(size_t)sysconf(_SC_PAGESIZE);CHECK(host_page&&host_page<=0x4000&&!(host_page&(host_page-1)));
    shadow_mapping=mmap(0,0x104000+2*host_page,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(shadow_mapping!=MAP_FAILED);
    shadow=shadow_mapping+host_page;CHECK(!mprotect(shadow,0x104000,PROT_READ|PROT_WRITE));
    boot_payload=mmap(0,PMMN_TEST_PAYLOAD_BYTES,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    CHECK(boot_payload!=MAP_FAILED);test_payload_base=(uintptr_t)boot_payload;
    kernel_shadow=mmap(0,0x10000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(kernel_shadow!=MAP_FAILED);
    handoff_setup();CHECK(launch()&&cpu_calls==1&&!pmsc_live(owner));CHECK(!launch()&&cpu_calls==1);
    CHECK(pwkr_poll(parent)==1);boot_ap->stage=1;boot_ap->mpidr=0x700;
    CHECK(pwkr_poll(parent)==2&&pmsc_live(owner));owner_delay=PMSC_TOTAL+19200000;
    CHECK(pwkr_poll(parent)==2&&pmsc_live(owner));CHECK(!pmsc_close_unused(owner));
    for(unsigned bad=0;bad<11;bad++){
        handoff_setup();
        if(bad==0)radio_ready=0;else if(bad==1)copied->complete=0;else if(bad==2)boot_ap->args+=0x4000;
        else if(bad==3)kernel_shadow[0x4002]=1;else if(bad==4)boot_payload->cmdline[0]=1;
        else if(bad==5)boot_ap->stack-=128;else if(bad==6)boot_plan.top-=1;
        else if(bad==7)parent->wmi.client.mac[0]=1;else {cache_fail=bad-7;}
        CHECK(!launch()&&!cpu_calls&&owner->held&&!owner->restore_issued);
    }
    for(unsigned fault=1;fault<=2;fault++){
        handoff_setup();cpu_fault=fault;CHECK(!launch()&&cpu_calls==1&&owner->unknown&&owner->runtime.unknown);
        CHECK(*native_flag==1&&*held_input.state==4&&!launch()&&cpu_calls==1);
    }
    handoff_setup();CHECK(launch());owner_delay=19200000*3+1;CHECK(!pwkr_poll(parent)&&owner->unknown);
    handoff_setup();CHECK(launch());boot_ap->stage=2;CHECK(!pwkr_poll(parent)&&owner->unknown);
    handoff_setup();CHECK(launch());boot_ap->stage=1;boot_ap->mpidr=0x600;CHECK(!pwkr_poll(parent)&&owner->unknown);
    handoff_setup();CHECK(launch());copied->image_digest[0]^=1;CHECK(!pwkr_poll(parent)&&owner->unknown);
    handoff_setup();CHECK(launch());kernel_shadow[0x4000+PWMB_BOOTSTRAP_OFFSET]^=1;CHECK(!pwkr_poll(parent)&&owner->unknown);
    CHECK(!munmap(boot_payload,PMMN_TEST_PAYLOAD_BYTES)&&!munmap(kernel_shadow,0x10000));
    if(descriptor_protected)CHECK(!mprotect(&share->page,host_page,PROT_READ|PROT_WRITE));
    CHECK(!munmap(shadow_mapping,0x104000+2*host_page));free(original);free(arena);
    printf("PASS %u actual handoff checks (software radio predicate/privileged leaves)\n",checks);return 0;
}
