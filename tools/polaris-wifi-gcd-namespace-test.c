/* The existing original-PE private client fixture is a SOFTWARE peer only. */
#define POLARIS_POWER_PATH_FIXTURE_ONLY 1
#include "polaris-wifi-power-path-test.c"
#define EFI_XNU_WIFI_GCD_NAMESPACE_RO_AVAILABLE 1
#include "uefi-wifi-gcd-namespace.h"
_Static_assert(sizeof(struct pgns_result)<=0x40000,"resident test extent");
static unsigned nf,ntrans,flipped;
static struct pgns_result *ns;
static struct pgcd_context *ng;
static uint8_t *nodes;
static int ns_map(void *ctx,struct efi_system *sys,uint8_t *out,struct paic_map_sample *m)
{
    (void)ctx;assert(sys==s);
    struct efi_memory map[5]={{3,0,(uintptr_t)arena,0,0x600000/4096,8},
        {4,0,(uintptr_t)arena+0x600000,0,16,8},
        {nf==25?3:4,0,(uintptr_t)arena+0x610000,0,16,8},
        {3,0,(uintptr_t)arena+0x620000,0,(0x800000-0x620000)/4096,8},
        {0,0,0x85fe0000,0,32,8}};
    memcpy(out,map,sizeof(map));m->bytes=sizeof(map);m->key=map_key;m->stride=sizeof(map[0]);m->version=1;m->status=0;return 1;
}
static int ns_arch(void *ctx,struct pgcd_arch *a)
{int ok=path_arch(ctx,a);if(nf==16&&ntrans>4)a->cpu.ticks=ng->record->before.cpu.ticks+3840001;return ok;}
static int ns_AT(void *ctx,struct pgns_translation *t)
{
    (void)ctx;ntrans++;t->saved=t->restored=0x12345678;t->issued=t->returned=1;
    t->par=UINT64_C(0xff00000000000b80)|t->page;
    if(nf==8)t->par^=0x200;
    if(nf==9)t->restored++;
    if(nf==10)return 0;
    if(nf==14&&!flipped&&ns->phase==2){put(nodes+80+48,9,8);flipped=1;}
    if(nf==15&&!flipped&&ns->phase==1&&ns->pass[0].count==3){put(core+PGNS_HEAD_RVA,(uintptr_t)nodes+88,8);flipped=1;}
    return 1;
}
static void fill_namespace(unsigned count)
{
    uint64_t head=(uintptr_t)core+PGNS_HEAD_RVA;nodes=links+0x11000;
    put(core+PGNS_HEAD_RVA,(uintptr_t)nodes+8,8);put(core+PGNS_HEAD_RVA+8,(uintptr_t)nodes+(count-1)*80+8,8);
    for(unsigned k=0;k<count;k++){
        uint8_t *n=nodes+80*k;memset(n,0,80);put(n,PGNS_SIGNATURE,8);
        put(n+8,k+1<count?(uintptr_t)n+88:head,8);put(n+16,k?(uintptr_t)n-72:head,8);
        uint64_t base=k<count-2?(uint64_t)k*4096:k==count-2?0x85fe0000:0x86000000;
        uint64_t end=k<count-3?base+4095:k==count-3?0x85fdffff:k==count-2?0x85ffffff:UINT64_C(0xfffffffff);
        put(n+24,base,8);put(n+32,end,8);put(n+40,8,8);put(n+48,k==count-2?8:0,8);put(n+56,k==count-2?2:1,4);
    }
    if(nf==1)put(core+PGNS_HEAD_RVA,head,8);
    if(nf==2)put(core+PGNS_HEAD_RVA+8,(uintptr_t)nodes+8,8);
    if(nf==3)put(nodes+80+8,(uintptr_t)nodes+88,8);
    if(nf==4)nodes[0]^=1;
    if(nf==5)put(nodes+80+24,0x85fd0000,8);
    if(nf==6)put(nodes+8,(uintptr_t)nodes+16,8);
    if(nf==7)put(core+PGNS_HEAD_RVA,(uintptr_t)path+8,8);
    if(nf==11)core[PGNS_TEMPLATE_RVA]^=1;
    if(nf==12)core[0x1000]^=1;
    if(nf==13)put(core+PGNS_LOCK_RVA+16,2,8);
    if(nf==19)put(nodes+80+16,head,8);
    if(nf==20)put(core+PGNS_HEAD_RVA,(uintptr_t)nodes+12,8);
    if(nf==23)put(nodes+80+56,4,4);
    if(nf==24)put(nodes+80+48,0,8);
    if(nf==27)put(nodes+80+56,99,4);
}
static int ns_body(void *ctx,const struct paic_io *memory,struct pwrcl_result *p,
    struct pwrph_work *work,struct pgcd_context *g)
{
    (void)ctx;ng=g;g->io.arch=ns_arch;fill_namespace(nf==17?512:nf==18?513:3);
    struct pgns_io io={memory,0,ns_AT};return pgns_collect(&io,p,work,g,ns);
}
static int execute_namespace(unsigned fault)
{
    configure(0);nf=fault;ntrans=flipped=0;ns=(void*)(arena+(fault==26?0x700000:0x380000));memset(ns,0,sizeof(*ns));
    memset(links+0x10000,0,0x10000);
    const struct pwrcl_io client={{{s,0,path_memory_arch,path_identity,order},rp_locate,ns_map},client_create,client_drop,own_name};
    c->io.arch=path_arch;c->io.map=path_core_map;
    return pwrcl_run_body(&client,enumeration,2,c,early,cr,rw,ns_body,0);
}
int main(int argc,char **argv)
{
    assert(argc==5&&!posix_memalign((void**)&arena,4096,0x800000));
    original=malloc(PGCI_IMAGE_BYTES);npa_original=malloc(PWNPI_IMAGE_BYTES);rp_original=malloc(PWRPI_IMAGE_BYTES);cmd_original=malloc(PWCDI_IMAGE_BYTES);
    uint8_t *dst[]={original,npa_original,rp_original,cmd_original};size_t sizes[]={PGCI_IMAGE_BYTES,PWNPI_IMAGE_BYTES,PWRPI_IMAGE_BYTES,PWCDI_IMAGE_BYTES};
    for(unsigned k=0;k<4;k++){FILE *f=fopen(argv[k+1],"rb");assert(f&&fread(dst[k],1,sizes[k],f)==sizes[k]&&!fclose(f));}
    unsigned checks=0;
    for(unsigned fault=0;fault<=27;fault++){
        if(fault==21||fault==22)continue;
        int ok=execute_namespace(fault);assert(!api_queries&&!psci_calls&&!mask_calls&&!modeled_stores&&!requests&&!acks);
        if(fault==0||fault==17||fault==23||fault==24){
            if(!ok)fprintf(stderr,"namespace%u error%u count%u/%u client%u core%u unknown%u\n",fault,ns->error,ns->pass[0].count,ns->pass[1].count,cr->error,cr->core.error,ns->unknown);
            assert(ok&&ns->stable&&ns->returned&&!pgns_unsafe(ns)&&cr->client_returned&&delete_calls==1);
            assert(ns->pass[0].complete&&ns->pass[1].complete&&ns->pass[0].count==(fault==17?512u:3u));
            struct pgcd_descriptor d;assert(pgns_descriptor(ns,0x85fe0000,&d)&&d.base==0x85fe0000&&d.length==0x20000);
            assert(d.type==(fault==23?4u:2u)&&d.attributes==(fault==24?0u:8u));
            assert(!pgns_descriptor(ns,0x179e0000,&d)&&!pgns_descriptor(ns,0x85fe0001,&d));
        }else{
            assert(!ok&&ns->error&&!ns->stable&&cr->client_held&&!delete_calls);
            if(fault==13)assert(ns->error==PGNS_LOCK&&!ns->unknown&&!ns->outstanding);
            if(fault==18)assert(ns->error==PGNS_LIMIT&&ns->pass[0].count==512&&!ns->pass[0].complete);
            if(fault==3)assert(ns->error==PGNS_CYCLE);
            if(fault==8||fault==9||fault==10)assert(ns->error==PGNS_TRANSLATION&&ns->outstanding);
            if(fault==14||fault==15)assert(ns->error==PGNS_CHANGED);
            if(fault==25)assert(!ns->pass[0].node[0].bytes);
        }checks++;
    }
    assert(execute_namespace(0));struct pgns_io io={0};assert(!pgns_collect(&io,cr,rw,early,ns)&&ns->error==PGNS_REENTRY&&pgns_unsafe(ns));checks++;
    printf("{\"passed\":true,\"checks\":%u,\"raw_bytes\":%zu,\"max_nodes\":512,\"original_GCD_API\":0,\"lock_or_TPL_calls\":0,\"SMC_MMIO\":0,\"physical_firmware_executed\":false}\n",checks,sizeof(*ns));
    free(original);free(npa_original);free(rp_original);free(cmd_original);free(arena);return 0;
}
