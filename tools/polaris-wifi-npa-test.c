/* Software original-service peer + relocated real NpaDxe bytes as DATA only. */
#define main original_gcd_test_main
#include "polaris-uefi-gcd-test.c"
#undef main
#include "uefi-audio-i2c-cache.h"
#define EFI_XNU_WIFI_NPA_READONLY_AVAILABLE 1
#include "uefi-wifi-npa-readonly.h"
static struct pwnpa_result *nr;
static struct pwnpa_work *nw;
static struct paic_result *enumeration;
static uint8_t *npa,*npa_original,*links;
static unsigned bs_calls,npa_fault;
static uint64_t npa_status;
static int npa_core_map(void *p,struct efi_system *sys,struct pgcd_map *m,void *out)
{ int ok=map(p,sys,m,out);((struct efi_memory*)out)->pages=0x101000/4096;return ok; }
static int npa_arch(void *v,struct paic_arch *a)
{
    struct pgcd_arch g;
    if(!arch(v,&g))return 0;
    *a=(struct paic_arch){g.cpu.el,g.cpu.mpidr,g.cpu.ttbr0,g.cpu.ttbr1,g.cpu.tcr,g.cpu.sctlr,g.cpu.mair,
        g.cpu.daif,g.cpu.sre,g.cpu.group1,g.cpu.frequency,g.cpu.ticks};return 1;
}
static int locate_npa(void *ctx,struct efi_system *sys,const efi_guid *guid,void **table,uint64_t *status)
{
    (void)ctx;assert(sys==s);*status=0;assert(guid->a==0x79d6c870);bs_calls++;
    *table=npa+0x100b0;
    if(npa_fault==1)*status=0x800000000000000eULL;
    if(npa_fault==2&&bs_calls>2)*table=npa+0x100b8;
    if(npa_fault==3)put(core+0x1b098,8,8);
    if(npa_fault==4)fault=2;
    if(npa_fault==10)return 0;
    if(npa_fault==12)core[0x1bb18]^=1;
    return 1;
}
static int npa_map(void *ctx,struct efi_system *sys,uint8_t *buffer,struct paic_map_sample *m)
{
    (void)ctx;assert(sys==s);struct efi_memory *dest=(void*)buffer;
    bs_calls++;assert(m->bytes>=sizeof(*dest));
    *dest=(struct efi_memory){3,0,(uintptr_t)arena,0,0x101000/4096,8};
    m->bytes=sizeof(*dest);m->key=npa_fault==5&&bs_calls>3?2:1;m->stride=sizeof(*dest);m->version=1;
    if(npa_fault==6)dest->type=7;
    if(npa_fault==7&&bs_calls>3)links[0x201]^=1;
    if(npa_fault==8&&bs_calls>3)npa[0x1000]^=1;
    if(npa_fault==9)m->bytes=5000;
    m->status=npa_status;return npa_fault!=11;
}
static void npa_reset(unsigned f)
{
    reset(0);memset(r,0,sizeof(*r));self->bytes=0xa9000;assert(pgcd_bind(r,self));
    struct pgcd_config original_config=*cfg;
    cfg=(void*)(arena+0x100000);*cfg=original_config;s->tables=cfg;c->io.map=npa_core_map;
    npa_fault=f;npa_status=0;bs_calls=0;pwnpa_ticket.used=pwnpa_ticket.outstanding=0;
    nr=(void*)(arena+0x60000);nw=(void*)(arena+0x90000);enumeration=(void*)(arena+0xa0000);
    npa=arena+0xb0000;links=arena+0xd0000;
    assert(sizeof(*nr)<0x30000);
    memcpy(npa,npa_original,PWNPI_IMAGE_BYTES);
    for(unsigned i=0;i<PWNPI_RELOC_COUNT;i++)put(npa+pwnpi_relocs[i],pwfi_le(npa+pwnpi_relocs[i],8)+(uintptr_t)npa,8);
    put(npa+0x108b0,(uintptr_t)links,8);
    put(links,(uintptr_t)links+0x100,8);put(links+16,(uintptr_t)links+0x200,8);put(links+24,(uintptr_t)links+0x400,8);
    strcpy((char*)links+0x200,"/arc/client/rail_cx");
    put(links+0x100+16,(uintptr_t)links+0x280,8);strcpy((char*)links+0x280,"/arc/client/rail_mx");
    put(links+0x400,(uintptr_t)links+0x600,8);put(links+0x428,(uintptr_t)links+0x700,8);
    struct efi_loaded *owner=(void*)(arena+0xa8000);
    *owner=(struct efi_loaded){.revision=0x1000,.system=s,.base=npa,.bytes=PWNPI_IMAGE_BYTES,.code_type=3,.data_type=4};
    enumeration->owner_matches=enumeration->cache_consistent=enumeration->handle_count=1;
    enumeration->loaded_address[0]=(uintptr_t)owner;
    /* Actual core table is mutable. The original hash canonicalization excludes
     * these registered BootServices pointers, just as in the proven GCD peer. */
    /* Original core service pointers remain intact: callbacks model delivery. */
}
int main(int argc,char **argv)
{
    assert(argc==3);assert(!posix_memalign((void**)&arena,4096,0x101000));
    original=malloc(PGCI_IMAGE_BYTES);npa_original=malloc(PWNPI_IMAGE_BYTES);assert(original&&npa_original);
    FILE *f=fopen(argv[1],"rb");assert(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));
    f=fopen(argv[2],"rb");assert(f&&fread(npa_original,1,PWNPI_IMAGE_BYTES,f)==PWNPI_IMAGE_BYTES&&!fclose(f));
    struct pwnpa_io ops={{NULL,NULL,npa_arch,identity,order},locate_npa,npa_map};unsigned checks=0;
    npa_reset(0);ops.memory.system=s;
    int ok=pwnpa_collect(&ops,2,enumeration,c,nr,nw);
    if(!ok)fprintf(stderr,"baseline err=%u GCD=%u calls=%u maps=%u hash=%u/%u\n",nr->error,r->error,bs_calls,maps,nr->hash_count[0],nr->hash_failed[0]);
    assert(ok&&nr->stable&&nr->nodes[0]==2&&nr->walk_complete[1]&&nr->issued==4&&nr->returned==4&&!nr->unknown);
    assert(nr->hash_count[0]==5&&nr->hash_count[1]==5&&queries==0&&saves==restores);
    assert(!strcmp((char*)nr->node[0][0].name_raw,"/arc/client/rail_cx"));checks++;
    assert(!pwnpa_collect(&ops,2,enumeration,c,nr,nw)&&bs_calls==4);checks++;
    for(unsigned k=1;k<=12;k++) {
        npa_reset(k);ops.memory.system=s;assert(!pwnpa_collect(&ops,2,enumeration,c,nr,nw)&&nr->error);
        assert(queries==0);
        if(k==3||k==4||k>=10)assert(nr->unknown&&nr->outstanding&&pwnpa_ticket.outstanding&&pgcd_uncertain(c));
        if(k==2||k==5||k==7)assert(nr->error==PWNPA_CHANGED);
        if(k==8)assert(nr->error==PWNPA_HASH);
        checks++;
    }
    npa_reset(0);ops.memory.system=s;put(links+0x100,(uintptr_t)links,8);
    assert(!pwnpa_collect(&ops,2,enumeration,c,nr,nw)&&nr->error==PWNPA_GRAPH&&nr->nodes[0]==2);checks++;
    npa_reset(0);ops.memory.system=s;memset(links+0x200,'x',64);
    assert(!pwnpa_collect(&ops,2,enumeration,c,nr,nw)&&nr->error==PWNPA_GRAPH);checks++;
    npa_reset(0);ops.memory.system=s;put(links+24,0x86000000,8);
    assert(!pwnpa_collect(&ops,2,enumeration,c,nr,nw)&&nr->node[0][0].resource_bytes==0);checks++;
    npa_reset(0);ops.memory.system=s;enumeration->handle_status[0]=1;
    assert(!pwnpa_collect(&ops,2,enumeration,c,nr,nw)&&nr->error==PWNPA_OWNER);checks++;
    npa_reset(0);ops.memory.system=s;npa_status=0x8000000000000005ULL;
    assert(!pwnpa_collect(&ops,2,enumeration,c,nr,nw)&&nr->error==PWNPA_MAP&&nr->returned==2);checks++;
    npa_reset(0);ops.memory.system=s;
    for(unsigned j=0;j<=PWNPA_NODES;j++) {
        uint8_t *node=links+32*j;put(node,j==PWNPA_NODES?0:(uintptr_t)node+32,8);
        put(node+16,(uintptr_t)arena+0xe0000,8);put(node+24,0,8);
    }
    strcpy((char*)arena+0xe0000,"node");
    assert(!pwnpa_collect(&ops,2,enumeration,c,nr,nw)&&nr->error==PWNPA_LIMIT&&nr->nodes[0]==128);checks++;
    npa_reset(0);ops.memory.system=s;enumeration->handle_count=2;enumeration->loaded_address[1]=enumeration->loaded_address[0];
    assert(!pwnpa_collect(&ops,2,enumeration,c,nr,nw)&&nr->error==PWNPA_OWNER&&nr->owner_matches==2);checks++;
    npa_reset(0);ops.memory.system=s;self->bytes=r->self_owner.bytes=r->self_bytes=0xc3000;
    assert(!pwnpa_collect(&ops,2,enumeration,c,nr,nw)&&nr->error==PWNPA_OWNER);checks++;
    printf("{\"checks\":%u,\"raw_bytes\":%zu,\"node_bytes\":%zu,\"original_NPA_API_calls\":0,\"SOFTWARE_UEFI_FP_arch_only\":true,\"physical_MMIO_or_radio\":false}\n",checks,sizeof(*nr),sizeof(struct pwnpa_node));
    free(original);free(npa_original);free(arena);return 0;
}
