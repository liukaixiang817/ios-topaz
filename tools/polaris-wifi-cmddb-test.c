/* Execute the real CmdDb adapter against a SOFTWARE service peer. Original
 * EFI bytes are relocated DATA; no original instructions or MMIO execute. */
#define main old_gcd_test_main
#include "polaris-uefi-gcd-test.c"
#undef main
#include "uefi-audio-i2c-cache.h"
#define EFI_XNU_WIFI_RPMH_READONLY_AVAILABLE 1
#define EFI_XNU_WIFI_CMDDB_QUERY_AVAILABLE 1
#define POLARIS_CMDDB_SOFTWARE_TEST 1
#include "uefi-wifi-cmddb-query.h"
static struct pwcd_result *cd;
static struct pwrph_work *work;
static struct paic_result *enumeration;
static uint8_t *cd_original,*cd_image,db[PWCD_DB_BYTES];
static unsigned cf,locates,cdmaps,api_calls,descriptors;
static uint8_t pwcd_test_load(uint64_t at)
{assert(at>=0x861e0000&&at<0x86200000);return db[at-0x861e0000];}
static int cd_arch(void *ctx,struct paic_arch *a)
{
    struct pgcd_arch g;if(!arch(ctx,&g))return 0;
    *a=(struct paic_arch){g.cpu.el,g.cpu.mpidr,g.cpu.ttbr0,g.cpu.ttbr1,g.cpu.tcr,g.cpu.sctlr,g.cpu.mair,
        g.cpu.daif,g.cpu.sre,g.cpu.group1,g.cpu.frequency,g.cpu.ticks};
    if(cf==24&&api_calls)a->ticks=cd->before.ticks+PGCD_FRESH_TICKS+1;
    return 1;
}
static int cd_identity(void *ctx,uint64_t at,uint64_t bytes,uint64_t *where,uint64_t *par)
{
    (void)ctx;(void)bytes;*where=at;*par=at&~UINT64_C(4095);
    if(at>=0x86000000&&at<0x86200000){*par|=UINT64_C(0xff00000000000b80);if(cf==8)*par^=0x100;}
    return 1;
}
static int cd_core_map(void *ctx,struct efi_system *sys,struct pgcd_map *m,void *out)
{
    (void)ctx;assert(sys==s&&m->issued);maps++;
    struct efi_memory d[2]={{3,0,(uintptr_t)arena,0,0x240000/4096,8},{0,0,0x86000000,0,512,8}};
    memcpy(out,d,sizeof(d));m->bytes=sizeof(d);m->key=1;m->stride=sizeof(d[0]);m->version=1;m->status=0;return 1;
}
static int cd_locate(void *ctx,struct efi_system *sys,const efi_guid *guid,void **out,uint64_t *status)
{
    (void)ctx;assert(sys==s&&guid->a==0x1c34f691&&guid->b==0xd33d);locates++;
    *out=cd_image+0x5088;*status=cf==1?0x800000000000000eULL:0;return cf!=2;
}
static int cd_map(void *ctx,struct efi_system *sys,uint8_t *out,struct paic_map_sample *m)
{
    (void)ctx;assert(sys==s);cdmaps++;
    struct efi_memory d[2]={{3,0,(uintptr_t)arena,0,0x240000/4096,8},{cf==7?7:0,0,0x86000000,0,512,8}};
    memset(out,0,4096);memcpy(out,d,sizeof(d));m->bytes=sizeof(d);m->key=cf==23&&cdmaps==2?2:1;
    m->stride=sizeof(d[0]);m->version=1;m->status=0;return cf!=3;
}
static int cd_descriptor(void *ctx,uint64_t fn,uint64_t page,struct pgcd_descriptor *d,uint64_t *status)
{
    (void)ctx;assert(fn==(uintptr_t)core+0x2c68&&page>=0x861e0000&&page<0x86200000);descriptors++;
    int pages=cf==30||cf==31;
    *d=(struct pgcd_descriptor){pages?page:0x86000000,pages?4096:0x200000,8,8,2,0,0,0};*status=0;
    if(cf==6)d->type=1;
    if(cf==31&&page==0x861e1000)d->length=1;
    return cf!=4;
}
static void fill_db(void)
{
    memset(db,0,sizeof(db));put(db,1,4);put(db+4,0x0c0330db,4);
    put(db+8,3,2);put(db+10,0,2);put(db+12,0x1000,2);put(db+14,3,2);put(db+16,0x100,2);
    const uint16_t levels[3][16]={{0,16,48,64,128,192,256,384},{0,16,16,256,384},{0,16,48,64,128,192,256,384}};
    for(unsigned k=0;k<3;k++){
        uint8_t *e=db+144+24*k;memcpy(e,pwcd_names[k],8);put(e+8,k==1?0:4,4);put(e+12,1,4);
        put(e+16,pwcd_addresses[k],4);put(e+20,32,2);put(e+22,32*k,2);
        for(unsigned j=0;j<16;j++)put(db+144+0x1000+32*k+2*j,levels[k][j],2);
    }
}
static uint64_t modeled_query(void *This,void *query_data,void *response_data,void *aux,uint32_t *result)
{
    assert(This==cd_image+0x5088);uint8_t *q=query_data,*out=response_data;unsigned k;
    for(k=0;k<3;k++)if(!memcmp(q,pwcd_names[k],9))break;
    assert(k<3&&pwfi_le(q+16,4)==0&&pwfi_le(out+24,4)==32&&cd->outstanding&&r->outstanding);
    api_calls++;memcpy(out,q,9);memcpy(out+12,db+144+24*k+16,4);
    memcpy(out+16,db+144+24*k+8,8);put(out+24,32,4);put(out+28,0x100,2);
    memcpy(aux,db+144+0x1000+32*k,32);*result=0;
    if(cf==14)*result=1;
    if(cf==15)out[24]=31;
    if(cf==16)q[20]=1;
    if(cf==17)((uint8_t*)aux)[3]^=1;
    if(cf==18&&api_calls==6)db[0x1ffff]^=1;
    if(cf==19)cd_image[0x1000]^=1;
    if(cf==20)put(cd_image+0x5158,0x861c0000,8);
    if(cf==21)put(core+0x1b098,8,8);
    if(cf==32)db[14]^=1; /* live footprint changed, no second query allowed */
    if(cf==33)out[30]=1;
    return cf==13?0x8000000000000002ULL:0;
}
static int cd_query(void *ctx,uint64_t fn,uint64_t This,uint8_t *q,uint8_t *out,uint8_t *aux,uint32_t *result,uint64_t *status)
{
    assert(fn==(uintptr_t)cd_image+0x1878);
    /* Exercise the real This/u32-out/u64-return invocation adapter using a
     * host function of the exact original public ABI. */
    int returned=pwcd_actual_query(ctx,(uintptr_t)modeled_query,This,q,out,aux,result,status);
    return cf==22?0:returned;
}
static struct pwcd_io cd_reset(unsigned f)
{
    reset(0);memset(arena+0x100000,0,0x140000);memset(r,0,sizeof(*r));cf=f;locates=cdmaps=api_calls=descriptors=0;
    self->bytes=0x186000;assert(pgcd_bind(r,self));c->io.map=cd_core_map;c->io.query=cd_descriptor;
    struct pgcd_config saved=*cfg;cfg=(void*)(arena+0x230000);*cfg=saved;s->tables=cfg;
    cd=(void*)(arena+0x100000);work=(void*)(arena+0x184000);enumeration=(void*)(arena+0x190000);
    assert((uintptr_t)cd+sizeof(*cd)<(uintptr_t)work);
    cd_image=arena+0x200000;memcpy(cd_image,cd_original,PWCDI_IMAGE_BYTES);
    for(unsigned j=0;j<PWCDI_RELOC_COUNT;j++)put(cd_image+pwcdi_relocs[j],pwfi_le(cd_image+pwcdi_relocs[j],8)+(uintptr_t)cd_image,8);
    put(cd_image+0x5158,0x861e0000,8);put(cd_image+0x5198,0x861e0000,8);
    struct efi_loaded *owner=(void*)(arena+0x192000);
    *owner=(struct efi_loaded){.revision=0x1000,.system=s,.base=cd_image,.bytes=PWCDI_IMAGE_BYTES,.code_type=3,.data_type=4};
    enumeration->owner_matches=enumeration->cache_consistent=enumeration->handle_count=1;
    enumeration->loaded_address[0]=(uintptr_t)owner;fill_db();
    int opened=pgcd_open(c);if(!opened)fprintf(stderr,"open error%u mapstatus%llu maps%u bound%u\n",r->error,(unsigned long long)r->map[0].status,maps,r->self_bound);assert(opened);
    if(f==5)put(cd_image+0x5198,0x861c0000,8);
    if(f==9)put(db+14,513,2);
    if(f==10)put(db+144+20,33,2);
    if(f==11)memcpy(db+144+24,pwcd_names[0],8);
    if(f==12)put(db+144+0x1000+12,128,2); /* nonmonotone ARC levels */
    if(f==25)c->finished=1;
    if(f==26)ticket->result++;
    if(f==27)enumeration->handle_status[0]=1;
    if(f==28){enumeration->handle_count=2;enumeration->loaded_address[1]=enumeration->loaded_address[0];}
    if(f==29)owner->system=0;
    if(f==31)put(cd_image+0x5158,0x861e0000,8); /* separate per-page descriptor fault below */
    struct pwcd_io ops={{{s,0,cd_arch,cd_identity,order},cd_locate,cd_map},cd_query};return ops;
}
int main(int argc,char **argv)
{
    assert(argc==3&&!posix_memalign((void**)&arena,4096,0x240000));
    original=malloc(PGCI_IMAGE_BYTES);cd_original=malloc(PWCDI_IMAGE_BYTES);assert(original&&cd_original);
    FILE *f=fopen(argv[1],"rb");assert(f&&fread(original,1,PGCI_IMAGE_BYTES,f)==PGCI_IMAGE_BYTES&&!fclose(f));
    f=fopen(argv[2],"rb");assert(f&&fread(cd_original,1,PWCDI_IMAGE_BYTES,f)==PWCDI_IMAGE_BYTES&&!fclose(f));
    unsigned checks=0;struct pwcd_io ops=cd_reset(0);
    int ok=pwcd_collect(&ops,enumeration,c,cd,work);
    if(!ok)fprintf(stderr,"baseline err%u unknown%u gcd%u issued%u/%u api%u descriptors%u\n",cd->error,cd->unknown,r->error,cd->issued,cd->returned,api_calls,descriptors);
    assert(ok&&cd->stable&&!pwcd_unknown(cd)&&api_calls==6&&descriptors==2&&cd->issued==12&&cd->returned==12);
    assert(cd->resources[0][0].index==7&&cd->resources[0][1].index==4&&cd->resources[0][2].index==7);
    assert(pwfi_le(cd->resources[0][1].aux+2,2)==16&&pwfi_le(cd->resources[0][1].aux+4,2)==16);
    for(unsigned j=0;j<9;j++)assert(cd->hash_count[j]==5&&!cd->hash_failed[j]);
    assert(cd->verified_bytes[1]==PWCD_DB_BYTES&&cd->rereads[0]==3&&cd->rereads[1]==3&&cd->namespace[1][31].issued==0&&cd->descriptor_page[1][31]==0);
    assert(saves==restores&&ticket->spent==1&&r->phase==1&&!r->pre_mask);checks++;
    assert(!pwcd_collect(&ops,enumeration,c,cd,work)&&api_calls==6);checks++;
    for(unsigned j=1;j<=33;j++){
        ops=cd_reset(j);ok=pwcd_collect(&ops,enumeration,c,cd,work);
        if(j==30){assert(ok&&descriptors==64&&cd->issued==74&&cd->descriptor_page[1][31]==31);}
        else{
            if(ok||!cd->error)fprintf(stderr,"fault%u ok%d err%u api%u desc%u\n",j,ok,cd->error,api_calls,descriptors);
            assert(!ok&&cd->error);
            if(j==2||j==3||j==4||j==21||j==22)assert(pwcd_unknown(cd)&&pgcd_uncertain(c)&&cd->outstanding);
            if(j==18)assert(cd->error==PWCD_CHANGED&&api_calls==6&&cd->verified_bytes[1]==PWCD_DB_BYTES-1);
            if(j==19||j==20)assert(api_calls==1&&cd->error==PWCD_SOURCE);
            if(j<=12||(j>=25&&j<=31))assert(!api_calls);
            if(j==32)assert(cd->error==PWCD_CHANGED&&api_calls==1&&!cd->rereads[0]&&cd->verified_bytes[0]==14);
        }checks++;
    }
    printf("{\"checks\":%u,\"raw_bytes\":%zu,\"guard_bytes\":%zu,\"SOFTWARE_peer\":true,\"original_firmware_executed\":false,\"power_votes\":0,\"radio\":false}\n",checks,sizeof(*cd),sizeof(struct pgcd_service_guard));
    free(cd_original);free(original);free(arena);return 0;
}
