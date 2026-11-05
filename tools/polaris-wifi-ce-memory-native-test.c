/* Complete early parent and actual CE allocation producer. Firmware Core is
 * inert DATA; allocation, map, FP and architectural leaves are SOFTWARE. */
#define PWEA_TEST_ENTRY unused_early_suite
#include "polaris-wifi-early-native-test.c"
#define EFI_XNU_WIFI_CE_MEMORY_AVAILABLE 1
#define POLARIS_WIFI_CE_MEMORY_SOFTWARE_PEER 1
static int ce_memory_arch(void*,struct pgcd_arch*);
#undef pgcd_actual_arch
#define pgcd_actual_arch ce_memory_arch
#include "uefi-wifi-ce-memory-native.h"
static struct pcdm_state*dma;
static unsigned dma_maps,dma_allocations,dma_fault,dma_scenarios;
#define DMA_AT UINT64_C(0xb0200000)
static int ce_memory_arch(void*p,struct pgcd_arch*a)
{
    int ok=early_arch(p,a);
    if(dma_maps&&dma_fault==8)a->cpu.ttbr0^=4096;
    if(dma_maps&&dma_fault==9)a->cpu.ticks+=PCDM_TICKS+1;
    return ok;
}
static efi_status pcdm_map(struct efi_system*system,struct pwea_map*m)
{
    CHECK(system==s&&dma_maps<2&&m==&dma->map[dma_maps]);dma_maps++;
    unsigned n=0;emit_descriptor(m->data+40*n++,3,(uintptr_t)arena,0x400000);
    emit_descriptor(m->data+40*n++,2,0x180000000,0x10000000);
    for(unsigned j=0;j<2;j++)emit_descriptor(m->data+40*n++,2,early->memory.claim[j].requested,early->memory.claim[j].bytes);
    if(!dma_allocations)emit_descriptor(m->data+40*n++,7,0xb0000000,0x1000000);
    else{
        emit_descriptor(m->data+40*n++,7,0xb0000000,0x200000);
        emit_descriptor(m->data+40*n++,dma_fault==1?7:2,DMA_AT,PWDM_BYTES);
        emit_descriptor(m->data+40*n++,7,DMA_AT+PWDM_BYTES,0xb1000000-DMA_AT-PWDM_BYTES);
    }
    m->map.bytes=40*n;m->map.stride=40;m->map.version=1;m->map.key=100+dma_maps;
    if(dma_maps==2&&dma_fault==2)((struct efi_memory*)m->data)->attributes^=1;
    if(dma_fault==3)dma->layout.used++;
    if(dma_maps==2&&dma_fault==4)core[0x1010]^=1;
    return dma_fault==5?EFI_ERROR|7:0;
}
static efi_status pcdm_allocate(struct efi_system*system,uint64_t*at)
{
    CHECK(system==s&&!dma_allocations&&at==&dma->allocation.address&&*at==PWDM_LIMIT-1);dma_allocations++;
    *at=DMA_AT;if(dma_fault==6)*at=PWDM_LIMIT-PWDM_BYTES+4096;
    if(dma_fault==7)*at+=1;
    return dma_fault==10?EFI_ERROR|9:0;
}
static void dma_setup(unsigned fault_kind)
{
    setup(0,0);self->bytes=0x300000;dma=(void*)(arena+0x100000);
    CHECK(sizeof(*dma)<0x100000);memset(dma,0,sizeof(*dma));CHECK(run());
    dma_maps=dma_allocations=0;dma_fault=fault_kind;dma_scenarios++;
    if(fault_kind==11){efault=37;trigger=at_calls+1;}
    if(fault_kind==12){efault=37;trigger=at_calls+PWDM_BYTES/4096+1;}
}
static void check_layout(const struct pwdm_layout*l)
{
    CHECK(l->allocation==DMA_AT&&l->bytes==PWDM_BYTES&&l->rri==4096&&l->used<=PWDM_USABLE+4096);
    uint32_t offsets[49]={l->rri},sizes[49]={4096};unsigned count=1;
    for(unsigned n=0;n<12;n++){
        const struct pwdm_pipe*p=&l->pipe[n];
        CHECK(p->sources==polaris_wcn3990_host[n].source_entries&&p->destinations==polaris_wcn3990_host[n].destination_entries);
        uint32_t at[]={p->source,p->destination,p->source_buffers,p->destination_buffers};
        uint32_t sz[]={16u*p->sources,16u*p->destinations,(uint32_t)p->sources*p->buffer_bytes,(uint32_t)p->destinations*p->buffer_bytes};
        for(unsigned j=0;j<4;j++){
            if(!sz[j]){CHECK(!at[j]);continue;}
            CHECK(at[j]>=4096&&!(at[j]&4095)&&at[j]+sz[j]<=PWDM_USABLE+4096);
            offsets[count]=at[j];sizes[count++]=sz[j];
        }
    }
    for(unsigned i=0;i<count;i++)for(unsigned j=i+1;j<count;j++)CHECK(offsets[i]+sizes[i]<=offsets[j]||offsets[j]+sizes[j]<=offsets[i]);
    CHECK(!l->pipe[6].source&&!l->pipe[6].destination&&l->pipe[4].sources==2048&&l->pipe[5].destinations==512);
}
int main(int argc,char**argv)
{
    CHECK(argc==2);CHECK(!posix_memalign((void**)&arena,4096,0x400000));original=malloc(PGCI_IMAGE_BYTES);CHECK(original);
    FILE*f=fopen(argv[1],"rb");CHECK(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));
    dma_setup(0);int ok=pcdm_run(dma,early);
    if(!ok)fprintf(stderr,"CE memory error=%u calls=%u maps=%u allocated=%u translated=%u/%u\n",dma->error,dma->calls,dma_maps,dma->allocated,dma->translated[0],dma->translated[1]);
    CHECK(ok&&dma->complete&&dma->allocated&&dma_maps==2&&dma_allocations==1&&!*native_flag);
    CHECK(dma->translated[0]==PWDM_BYTES/4096&&dma->translated[1]==PWDM_BYTES/4096);check_layout(&dma->layout);
    CHECK(!pcdm_run(dma,early));
    for(unsigned kind=1;kind<=12;kind++){
        dma_setup(kind);CHECK(!pcdm_run(dma,early)&&dma->unknown&&!dma->complete&&!*native_flag);
        unsigned calls=dma_maps+dma_allocations+at_calls;CHECK(!pcdm_run(dma,early)&&calls==dma_maps+dma_allocations+at_calls);
    }
    struct pwdm_layout edge={0};CHECK(pwdm_plan(&edge,PWDM_LIMIT-PWDM_BYTES));
    memset(&edge,0,sizeof(edge));CHECK(!pwdm_plan(&edge,PWDM_LIMIT-PWDM_BYTES+4096));
    printf("PASS %u native CE memory checks, %u scenarios; independent35-bit allocation/layout, SOFTWARE leaves, no DMA\n",checks,dma_scenarios);
    free(original);free(arena);return 0;
}
