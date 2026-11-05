/* Actual retained/CPU owner and kernel handoff; SOFTWARE architectural mask
 * and UI leaves. No PMIC, firmware or physical ownership is proved here. */
#define PWKR_TEST_ENTRY unused_handoff_main
#include "polaris-wifi-runtime-handoff-test.c"
#define POLARIS_WIFI_UI_SOFTWARE_PEER 1
static int ui_arch(void*,struct pgcd_arch*);
static int ui_owner_live(struct pmsc_owner*o);
#undef pgcd_actual_arch
#define pgcd_actual_arch ui_arch
#define pmsc_live ui_owner_live
#include "uefi-wifi-ui-window.h"
#undef pgcd_actual_arch
#undef pmsc_live
static struct pwnu_state*ui;
static uint64_t ui_mask;
static unsigned ui_fault,ui_masks,ui_services,ui_arches,ui_close_ready;
static int ui_owner_live(struct pmsc_owner*o)
{CHECK(ui_mask==0xc0);return pmsc_live(o);}
static int ui_arch(void*p,struct pgcd_arch*a)
{
    int ok=owner_arch(p,a);a->cpu.daif=ui_mask;ui_arches++;
    if(ui_fault==3&&ui_services)a->cpu.ttbr0^=4096;
    if(ui_fault==4&&ui_services)a->cpacr^=1;
    if(ui_fault==5&&ui_services)a->cpu.ticks=0;
    if(ui_fault==6&&ui_services)a->cpu.group1=1;
    return ok;
}
static int pwnu_change_mask(uint64_t before,uint64_t after)
{
    CHECK(ui_mask==before&&((before==0xc0&&after==0x3c0)||(before==0x3c0&&after==0xc0)));
    ui_masks++;if(ui_fault==1&&before==0xc0)return 0;
    if(ui_fault==2&&before==0x3c0)return 0;
    ui_mask=after;return 1;
}
static int pwnu_service(unsigned operation,uint64_t cookie,uint32_t sequence)
{
    CHECK(ui_mask==0x3c0&&owner->held&&!owner->restore_issued&&ui->active&&ui->unknown);
    CHECK(operation>=PWNU_PREPARE&&operation<=PWNU_SEAL);
    CHECK((operation==PWNU_SEAL)==!!(cookie&&sequence));ui_services++;
    if(ui_fault==7)owner->fp.q8_q15[0]^=1;
    if(ui_fault==8)return 0;
    if(ui_fault==9)return 2;
    return operation==PWNU_CLOSE&&ui_close_ready?2:1;
}
static void ui_setup(void)
{
    handoff_setup();ui=(void*)(arena+0x17c000);memset(ui,0,sizeof(*ui));
    ui_mask=0xc0;ui_fault=ui_masks=ui_services=ui_arches=ui_close_ready=0;
}
static void ui_launch(void)
{CHECK(launch());boot_ap->stage=1;boot_ap->mpidr=0x700;CHECK(pwkr_poll(parent)==2);}
int main(int argc,char**argv)
{
    CHECK(argc==2);CHECK(!posix_memalign((void**)&arena,0x4000,0x200000));original=malloc(PGCI_IMAGE_BYTES);CHECK(original);
    FILE*f=fopen(argv[1],"rb");CHECK(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));
    host_page=(size_t)sysconf(_SC_PAGESIZE);CHECK(host_page&&host_page<=0x4000&&!(host_page&(host_page-1)));
    shadow_mapping=mmap(0,0x104000+2*host_page,PROT_NONE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(shadow_mapping!=MAP_FAILED);
    shadow=shadow_mapping+host_page;CHECK(!mprotect(shadow,0x104000,PROT_READ|PROT_WRITE));
    boot_payload=mmap(0,PMMN_TEST_PAYLOAD_BYTES,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    CHECK(boot_payload!=MAP_FAILED);test_payload_base=(uintptr_t)boot_payload;
    kernel_shadow=mmap(0,0x10000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);CHECK(kernel_shadow!=MAP_FAILED);
    ui_setup();CHECK(!pwnu_run(ui,owner,PWNU_POLL,0,0)&&!ui_masks);
    CHECK(pwnu_run(ui,owner,PWNU_PREPARE,0,0)==1&&ui->ready&&ui_mask==0xc0&&ui_masks==2&&ui_services==1);
    CHECK(!pwnu_run(ui,owner,PWNU_PREPARE,0,0)&&ui_masks==2);
    CHECK(!pwnu_run(ui,owner,PWNU_POLL,0,0)&&ui_masks==2);ui_launch();
    CHECK(pwnu_run(ui,owner,PWNU_POLL,0,0)==1&&pmsc_persistent(owner));
    CHECK(!pwnu_run(ui,owner,PWNU_SEAL,7,1));
    CHECK(pwnu_run(ui,owner,PWNU_CLOSE,0,0)==1&&ui->closing);
    CHECK(!pwnu_run(ui,owner,PWNU_POLL,0,0));ui_close_ready=1;
    CHECK(pwnu_run(ui,owner,PWNU_CLOSE,0,0)==2);
    CHECK(!pwnu_run(ui,owner,PWNU_SEAL,7,0));CHECK(!pwnu_run(ui,owner,PWNU_SEAL,0,1));
    CHECK(pwnu_run(ui,owner,PWNU_SEAL,7,1)==1&&ui->sealed&&ui->cookie==7&&ui->sequence==1);
    CHECK(!pwnu_run(ui,owner,PWNU_SEAL,7,1)&&ui_mask==0xc0);
    for(unsigned fault=1;fault<=9;fault++){
        ui_setup();ui_fault=fault;CHECK(!pwnu_run(ui,owner,PWNU_PREPARE,0,0));
        CHECK(ui->unknown&&ui->error&&ui->active&&!ui->ready&&owner->held&&!owner->restore_issued);
        CHECK(ui_masks==(fault==2?2u:1u)&&ui_services==(fault==1?0u:1u));
        unsigned calls=ui_masks,services=ui_services;CHECK(!pwnu_run(ui,owner,PWNU_PREPARE,0,0));
        CHECK(ui_masks==calls&&ui_services==services);
    }
    ui_setup();CHECK(pwnu_run(ui,owner,PWNU_PREPARE,0,0));ui_launch();ui_fault=7;
    CHECK(!pwnu_run(ui,owner,PWNU_POLL,0,0)&&ui->unknown&&ui_mask==0x3c0&&!owner->restore_issued);
    printf("PASS %u UI mask-window checks; actual CPU owner/handoff, SOFTWARE architecture/UI leaves\n",checks);
    CHECK(!munmap(kernel_shadow,0x10000)&&!munmap(boot_payload,PMMN_TEST_PAYLOAD_BYTES));
    CHECK(!munmap(shadow_mapping,0x104000+2*host_page));free(original);free(arena);return 0;
}
