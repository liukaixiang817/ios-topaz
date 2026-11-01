/* Same original-PE SOFTWARE preparation -> real known-client wrapper ->
 * current selected bytes -> known retirement. No physical API/AT/MMIO. */
#define EFI_XNU_WIFI_PREPARED_POWER_AVAILABLE 1
#define POLARIS_CMDDB_STAGED_FIXTURE_ONLY 1
#include "polaris-wifi-cmddb-staged-test.c"
#include "uefi-wifi-cmddb-prepared.h"
static struct pwcp_result *bound;
static unsigned prepared_fault,body_entered;
static void relocate_image(uint8_t *to,uint8_t *from,size_t bytes,const uint32_t *relocs,unsigned count)
{
    memcpy(to,from,bytes);uint64_t delta=(uintptr_t)to-(uintptr_t)from;
    for(unsigned k=0;k<count;k++){uint64_t p=pwfi_le(to+relocs[k],8);if(p>=(uintptr_t)from&&p<(uintptr_t)from+bytes)put(to+relocs[k],p+delta,8);}
}
static int current_map(void *ctx,struct efi_system *sys,struct pgcd_map *m,void *out)
{
    struct paic_map_sample a={0};assert(ns_map(ctx,sys,out,&a));maps++;
    m->status=a.status;m->bytes=a.bytes;m->key=a.key;m->stride=a.stride;m->version=a.version;return 1;
}
static int current_AT(void *ctx,struct pgns_translation *t)
{
    if(prepared_fault==9){t->issued=1;return 0;}
    if(prepared_fault==10){int ok=ns_AT(ctx,t);t->restored++;return ok;}
    return ns_AT(ctx,t);
}
static int bound_body(void *ctx,const struct paic_io *m,struct pwrcl_result *p,struct pwrph_work *w,struct pgcd_context *g)
{
    (void)ctx;body_entered++;ns=&bound->namespace;ng=g;
    if(prepared_fault==1)prep->complete=0;
    if(prepared_fault==2)prep->phase[3].after.cpu.ticks=g->record->before.cpu.ticks+1;
    if(prepared_fault==3)prep->phase[1].ticket.result++;
    if(prepared_fault==4)cmd_database[prep->resources[1][0].entry+8]^=1;
    if(prepared_fault==5)cmd_database[prep->resources[1][1].aux_offset+4]^=1;
    if(prepared_fault==6)cmd_database[0]^=1;
    if(prepared_fault==7)cmd_image[0x5088+8]^=1;
    if(prepared_fault==8)cmd_image[0x1000]^=1;
    if(prepared_fault==11)put(core+PGNS_LOCK_RVA+16,2,8);
    if(prepared_fault==12)prep->database[1][PWCD_DB_BYTES-1]^=1;
    if(prepared_fault==13)prep->resources[1][0].index--;
    if(prepared_fault==14)prep->phase[2].reader.closed=0;
    if(prepared_fault==15)prep->phase[0].context.finished=0;
    const struct pwcp_io io={m,0,path_locate,current_AT};
    return pwcp_collect(&io,p,w,g,prep,bound)&&pwcp_finish(&io,p,w,g,prep,bound);
}
static void reset_bound(unsigned f)
{
    configure(0);sf=nf=0;ntrans=flipped=injected=original_queries=locates=0;
    uint8_t *oldrp=rimage,*oldcmd=cmd_image;
    relocate_image(arena+0x700000,oldrp,PWRPI_IMAGE_BYTES,pwrpi_relocs,PWRPI_RELOC_COUNT);rimage=arena+0x700000;
    relocate_image(arena+0x720000,oldcmd,PWCDI_IMAGE_BYTES,pwcdi_relocs,PWCDI_RELOC_COUNT);cmd_image=arena+0x720000;
    ((struct efi_loaded*)(arena+0x188000))->base=rimage;
    ((struct efi_loaded*)(arena+0x188100))->base=cmd_image;
    put(own_client+8,(uintptr_t)rimage+0xaf50,8);
    self->bytes=r->self_owner.bytes=r->self_bytes=0x600000;
    prep=(void*)(arena+0x440000);memset(prep,0,sizeof(*prep));assert((uint8_t*)prep+sizeof(*prep)<arena+0x600000);
    bound=(void*)(arena+0x1c0000);memset(bound,0,sizeof(*bound));assert((uint8_t*)bound+sizeof(*bound)<arena+0x200000);
    c->io.arch=staged_arch;c->io.map=staged_map;c->io.query=no_original_GCD;c->io.identity=path_identity;
    ns=&prep->phase[0].namespace;ng=&prep->phase[0].context;fill_namespace(3);
    assert(staged_execute()&&prep->complete&&prep->parts==4&&!pwsp_unsafe(prep));
    assert(!create_calls&&!delete_calls&&!api_queries&&!psci_calls&&!modeled_stores);
    c->io.arch=path_arch;c->io.map=current_map;c->io.query=no_original_GCD;
    prepared_fault=f;body_entered=0;
}
static int execute_bound(void)
{
    const struct pwrcl_io io={{{s,0,path_memory_arch,path_identity,order},path_locate,ns_map},client_create,client_drop,own_name};
    return pwrcl_run_body(&io,enumeration,2,c,early,cr,rw,bound_body,0);
}
#ifndef POLARIS_CMDDB_PREPARED_FIXTURE_ONLY
int main(int argc,char **argv)
{
    assert(argc==5&&!posix_memalign((void**)&arena,4096,0x800000));
    original=malloc(PGCI_IMAGE_BYTES);npa_original=malloc(PWNPI_IMAGE_BYTES);rp_original=malloc(PWRPI_IMAGE_BYTES);cmd_original=malloc(PWCDI_IMAGE_BYTES);
    uint8_t *dst[]={original,npa_original,rp_original,cmd_original};size_t sizes[]={PGCI_IMAGE_BYTES,PWNPI_IMAGE_BYTES,PWRPI_IMAGE_BYTES,PWCDI_IMAGE_BYTES};
    for(unsigned k=0;k<4;k++){FILE*f=fopen(argv[k+1],"rb");assert(f&&fread(dst[k],1,sizes[k],f)==sizes[k]&&!fclose(f));}
    unsigned checks=0;reset_bound(0);int ok=execute_bound();
    if(!ok)fprintf(stderr,"bound error%u ns%u private%u provider%u pages%u\n",bound->error,bound->namespace.error,cr->error,cr->reader.error,bound->pages);
    assert(ok&&body_entered==1&&bound->complete&&bound->stable&&!pwcp_unsafe(bound)&&cr->client_returned&&!cr->client_held&&cr->retired&&create_calls==1&&delete_calls==1);
    assert(!api_queries&&!original_queries&&!psci_calls&&!mask_calls&&!modeled_stores&&!ticket->spent);
    assert(bound->namespace.stable&&bound->pages==2&&!memcmp(bound->resources[1],prep->resources[1],sizeof(bound->resources[1])));
    for(unsigned pass=0;pass<3;pass++)for(unsigned k=0;k<PWCP_RANGES;k++)assert(bound->range[k].read[pass]==bound->range[k].bytes);
    assert(bound->before.ticks>=cr->core.before.cpu.ticks&&prep->phase[3].after.cpu.ticks<=cr->core.before.cpu.ticks);checks++;
    for(unsigned f=1;f<=15;f++){
        reset_bound(f);assert(!execute_bound()&&bound->unknown&&pwcp_unsafe(bound)&&cr->client_held&&!delete_calls);
        assert(!api_queries&&!original_queries&&!psci_calls&&!modeled_stores);checks++;
    }
    reset_bound(0);assert(execute_bound());unsigned calls=create_calls;
    const struct paic_io m={s,0,path_memory_arch,path_identity,order};const struct pwcp_io io={&m,0,path_locate,current_AT};
    assert(!pwcp_collect(&io,cr,rw,early,prep,bound)&&pwcp_unsafe(bound)&&create_calls==calls);checks++;
    printf("{\"passed\":true,\"checks\":%u,\"prepared_binding_raw_bytes\":%zu,\"current_ranges\":7,\"complete_current_namespace_passes\":2,\"same_private_ticket_not_rebased\":true,\"Query_PSCI_RSC\":0,\"physical_executed\":false}\n",checks,sizeof(*bound));
    free(original);free(npa_original);free(rp_original);free(cmd_original);free(arena);return 0;
}
#endif
