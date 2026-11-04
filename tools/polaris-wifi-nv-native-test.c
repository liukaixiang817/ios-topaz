/* Actual early producer -> independent allocation -> real NV collector.
 * Core/GPT metadata inert DATA; all UEFI/architectural leaves SOFTWARE. */
#define PWEA_TEST_ENTRY unused_early_suite
#include "polaris-wifi-early-native-test.c"
#define PNV_TEST_ENTRY unused_nv_collector_suite
#include "polaris-wifi-nv-inputs-test.c"
#define EFI_XNU_WIFI_NV_NATIVE_AVAILABLE 1
#define POLARIS_WIFI_NV_SOFTWARE_PEER 1
static int nv_actual_arch(void*,struct pgcd_arch*);
#undef pgcd_actual_arch
#define pgcd_actual_arch nv_actual_arch
#include "uefi-wifi-nv-native.h"
static struct pnnv_state*native_nv;
static struct pnv_plan*native_plan;
static unsigned nv_maps,nv_allocations,nv_fault,nv_scenarios;
static int nv_actual_arch(void*p,struct pgcd_arch*a)
{
    int ok=early_arch(p,a);if(nv_maps){if(nv_fault==9)a->cpu.ttbr0^=4096;if(nv_fault==10)a->cpu.ticks+=PNNV_TICKS+1;}return ok;
}
static efi_status pnnv_map(struct efi_system*system,struct pwea_map*m)
{
    CHECK(system==s&&nv_maps<3&&m==&native_nv->map[nv_maps]);nv_maps++;
    unsigned count=0;emit_descriptor(m->data+40*count++,3,(uintptr_t)arena,0x400000);
    emit_descriptor(m->data+40*count++,2,0x180000000,0x10000000);
    for(unsigned n=0;n<2;n++)emit_descriptor(m->data+40*count++,2,early->memory.claim[n].requested,early->memory.claim[n].bytes);
    emit_descriptor(m->data+40*count++,nv_allocations?2:7,(uintptr_t)memory,PNV_BYTES);
    m->map.bytes=40*count;m->map.stride=40;m->map.version=1;m->map.key=50+nv_maps;
    if(nv_fault==1&&nv_maps==2)((struct efi_memory*)(m->data+160))->type=7;
    if(nv_fault==2&&nv_maps==2)((struct efi_memory*)m->data)->attributes^=1;
    if(nv_fault==3&&nv_maps==3)((struct efi_memory*)(m->data+160))->type=7;
    if(nv_fault==4&&nv_maps==1)native_nv->plan.part[0].blocks++;
    if(nv_fault==5&&nv_maps==2)core[0x1010]^=1;
    return nv_fault==6&&nv_maps==1?EFI_ERROR|7:0;
}
static efi_status pnnv_allocate(struct efi_system*system,uint64_t*at)
{
    CHECK(system==s&&!nv_allocations&&at==&native_nv->allocation.address);nv_allocations++;
    *at=(uintptr_t)memory;if(nv_fault==7)*at+=4096;return nv_fault==8?EFI_ERROR|9:0;
}
static void nv_native_setup(unsigned fault)
{
    setup(0,0);self->bytes=0x300000;native_nv=(void*)(arena+0x100000);native_plan=(void*)(arena+0x300000);
    CHECK(sizeof(*native_nv)<0x100000);memset(native_nv,0,sizeof(*native_nv));*native_plan=polaris_nv_plan;
    result=&native_nv->inputs;nv_setup(0);
    s->boot->locate_buffer=boot.locate_buffer;s->boot->handle_protocol=boot.handle_protocol;s->boot->free_pool=boot.free_pool;
    CHECK(run());nv_maps=nv_allocations=0;nv_fault=fault;nv_scenarios++;
    if(fault==11){efault=37;trigger=at_calls+1;}
}
int main(int argc,char**argv)
{
    CHECK(argc==3);CHECK(!posix_memalign((void**)&arena,4096,0x400000));original=malloc(PGCI_IMAGE_BYTES);memory=aligned_alloc(4096,PNV_BYTES);CHECK(original&&memory);
    FILE*f=fopen(argv[1],"rb");CHECK(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));
    load(argv[2],"gpt0-primary.bin",headers[0][0],4096);load(argv[2],"gpt0-backup.bin",headers[0][1],4096);load(argv[2],"gpt0-table.bin",tables[0],polaris_nv_plan.disk[0].table_bytes);
    load(argv[2],"gpt1-primary.bin",headers[1][0],4096);load(argv[2],"gpt1-backup.bin",headers[1][1],4096);load(argv[2],"gpt1-table.bin",tables[1],polaris_nv_plan.disk[1].table_bytes);
    nv_native_setup(0);int ok=pnnv_run(native_nv,early,native_plan);
    if(!ok)fprintf(stderr,"native NV error=%u calls=%u pending=%u maps=%u alloc=%u translated=%u/%u collector=%u\n",native_nv->error,native_nv->calls,native_nv->pending,nv_maps,nv_allocations,native_nv->translated[0],native_nv->translated[1],native_nv->inputs.error);
    CHECK(ok&&native_nv->complete&&native_nv->allocated&&nv_maps==3&&nv_allocations==1&&native_nv->inputs.complete&&native_nv->inputs.passes==2);
    CHECK(native_nv->translated[0]==PNV_BYTES/4096&&native_nv->translated[1]==PNV_BYTES/4096&&!*native_flag);
    CHECK(!pnnv_run(native_nv,early,native_plan));
    for(unsigned fault=1;fault<=11;fault++){
        nv_native_setup(fault);CHECK(!pnnv_run(native_nv,early,native_plan)&&native_nv->unknown&&!native_nv->complete&&!*native_flag);
        unsigned calls=nv_maps+nv_allocations+reads;CHECK(!pnnv_run(native_nv,early,native_plan)&&calls==nv_maps+nv_allocations+reads);
    }
    nv_native_setup(0);mode=4;CHECK(!pnnv_run(native_nv,early,native_plan)&&native_nv->unknown&&native_nv->inputs.unknown&&native_nv->allocated);
    free(memory);free(original);free(arena);printf("PASS %u native NV checks, %u scenarios; software UEFI/AT/FP, no device\n",checks+nv_checks,nv_scenarios);return 0;
}
