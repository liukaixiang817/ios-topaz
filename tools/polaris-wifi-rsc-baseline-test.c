/* Actual RAM-baseline caller with relocated original bytes as DATA and
 * software UEFI peers. No original code, MMIO, SMEM store or lease executes. */
#define POLARIS_RPMH_FIXTURE_ONLY 1
#include "polaris-wifi-rpmh-test.c"
#define EFI_XNU_WIFI_RPMH_CLIENT_AVAILABLE 1
#define EFI_XNU_WIFI_CMDDB_QUERY_AVAILABLE 1
#define EFI_XNU_WIFI_POWER_TRANSACTION_AVAILABLE 1
#include "uefi-wifi-rsc-baseline.h"
static struct pwrcl_result *provider;
static struct pwrpb_baseline *before,*after;
static struct paic_arch reference;
static unsigned mode;
static int baseline_arch(void *ctx,struct paic_arch *a)
{int ok=rp_arch(ctx,a);if(mode==21)a->ttbr1^=4096;if(mode==22){a->daif=0xc0;a->group1=0;}return ok;}
static int baseline_map(void *ctx,struct efi_system *sys,uint8_t *buffer,struct paic_map_sample *m)
{
    (void)ctx;assert(sys==s);rcalls++;
    struct efi_memory d[3]={{3,0,(uintptr_t)arena,0,0x1b0000/4096,8},
        {4,0,(uintptr_t)links,0,0x10000/4096,8},{3,0,(uintptr_t)arena+0x1c0000,0,0x80000/4096,8}};
    memset(buffer,0,4096);memcpy(buffer,d,sizeof(d));m->bytes=sizeof(d);m->key=1;m->stride=sizeof(d[0]);m->version=1;m->status=0;return 1;
}
static void list(uint8_t *h,unsigned offset,unsigned count,uint8_t *node)
{memset(h,0,24);put(h,offset,4);put(h+4,count,4);put(h+8,(uintptr_t)node,8);put(h+16,(uintptr_t)node,8);}
static const uint32_t values[3]={8,2,1};
static struct paic_io setup(unsigned which)
{
    rp_reset(0);mode=0;self->bytes=r->self_owner.bytes=r->self_bytes=0x186000;
    provider=(void*)(arena+0xa0000);before=(void*)(arena+0x50000);after=(void*)(arena+0x70000);
    memset(provider,0,sizeof(*provider));memset(before,0,sizeof(*before));memset(after,0,sizeof(*after));
    assert(sizeof(*before)<0x20000&&(uintptr_t)after+sizeof(*after)<(uintptr_t)provider);
    uint8_t *pool=links+0x1004,*active=links+0x1104,*free=links+0x1144,*client=links+0x2004;
    put(rimage+0xd300,(uintptr_t)pool,8);put(pool,(uintptr_t)active,8);put(pool+8,(uintptr_t)free,8);
    list(active,80,1,client);list(free,80,0,0);put(client,2,4);put(client+0x34,UINT32_MAX,4);
    for(unsigned j=0;j<4;j++){uint8_t *q=links+0x9004+32*j;put(client+0x10+8*j,(uintptr_t)q,8);list(q,j<2?16:24,0,0);}
    for(unsigned j=0;j<5;j++){uint8_t *q=links+0x200+64*j;list(q,40,0,0);}
    uint8_t *retired=links+0xa004,*commands=links+0xa104;
    list(links+0x200+64*2,40,1,retired);put(retired,(uintptr_t)commands,8);
    for(unsigned j=0;j<8;j++){put(links+0x400+24*j,j,4);put(links+0x404+24*j,j<4?0:3,4);put(links+0x408+24*j,1234,8);}
    memset(rimage+0xd538,0,8+16*24);rimage[0xd538]=1;put(rimage+0xd538+4,pwfi_le(rimage+0xd208+0x20,4),4);
    put(rimage+0xd538+48+0xc,0x179c0000,4);put(rimage+0xd538+48+0x10,2,4);rimage[0xd538+48+0x14]=1;
    put(rimage+0xd538+48+0x18,8,4);put(rimage+0xd538+48+0x1c,16,4);
    put(rimage+0xd2ec,3,4);put(rimage+0xd2f0,(uintptr_t)links+0x3004,8);
    for(unsigned j=0;j<3;j++){
        uint8_t *row=links+0x3004+24*j,*state=links+0x4004+128*j;
        put(row,pwcd_addresses[j],4);put(row+8,(uintptr_t)state,8);
        put(state,2,4);put(state+8,4,4);put(state+0xc,values[j],4);state[0x10]=1;
        put(state+0x18,values[j],4);state[0x1c]=1;
    }
    if(which==1)put(rimage+0xd2ec,129,4);
    if(which==2)put(rimage+0xd2f0,(uintptr_t)rimage+0xd300,8);
    if(which==3)put(links+0x3004+48,0x30070,4);
    if(which==4)links[0x4004+256+0x10]=0;
    if(which==5)put(links+0x4004+4,1,4);
    if(which==6)put(links+0x4004+0x40,(uintptr_t)links+0x4004,8);
    if(which==7)put(links+0x3004+24,0x30000,4);
    if(which==8)put(client+0x38,1,4);
    if(which==9)list(links+0x9004+64,24,1,links+0xb004);
    if(which==10)list(links+0x200,40,1,links+0xb004);
    if(which==11)list(links+0x200+128,40,129,retired);
    if(which==12)put(retired+40,(uintptr_t)retired,8);
    if(which==13)put(retired,(uintptr_t)rimage+0x1000,8);
    if(which==14)put(links+0x404,1,4);
    if(which==15)put(links+0x410,(uintptr_t)retired,8);
    if(which==16){put(links+0x4004+256+0x18,2,4);}
    if(which==17){put(links+0x4004+256+0xc,16,4);put(links+0x4004+256+0x18,16,4);}
    if(which==18)put(links+0x3004+8,(uintptr_t)links+0x3004,8);
    if(which==19){put(links+0x4004+256+0xc,0,4);put(links+0x4004+256+0x18,0,4);}
    if(which==22){put(rimage+0xd538+72+0xc,0x179c0000,4);put(rimage+0xd538+72+0x10,2,4);rimage[0xd538+72+0x14]=1;}
    if(which==23)rimage[0xd538+48+0x14]=0;
    if(which==24)put(rimage+0xd538+4,0,4);
    if(which==25)put(rimage+0xd538+48+0x18,7,4);
    struct pwrph_io ops={{s,0,baseline_arch,identity,order},rp_locate,baseline_map};
    assert(pwrph_collect(&ops,2,enumeration,c,rr,rw));provider->core=*r;provider->reader=*rr;
    assert(pwrcl_exclusions(&ops.memory,provider,rw,enumeration));
    assert(pwrcl_pool_pair(&ops.memory,provider,rw,0));
    assert(baseline_arch(0,&reference));
    if(which==20)put(pool,(uintptr_t)free,8); /* after the admitted pool pair */
    if(which==21)mode=21;
    return ops.memory;
}
#ifndef POLARIS_RSC_BASELINE_FIXTURE_ONLY
int main(int argc,char **argv)
{
    assert(argc==4&&!posix_memalign((void**)&arena,4096,0x240000));
    original=malloc(PGCI_IMAGE_BYTES);npa_original=malloc(PWNPI_IMAGE_BYTES);rp_original=malloc(PWRPI_IMAGE_BYTES);
    assert(original&&npa_original&&rp_original);
    const size_t sizes[]={PGCI_IMAGE_BYTES,PWNPI_IMAGE_BYTES,PWRPI_IMAGE_BYTES};uint8_t *dst[]={original,npa_original,rp_original};
    for(unsigned k=0;k<3;k++){FILE *f=fopen(argv[k+1],"rb");assert(f&&fread(dst[k],1,sizes[k],f)==sizes[k]&&!fclose(f));}
    struct pwcd_resource desired[3]={0};
    const uint16_t levels[16]={0,16,48,64,128,192,256,384,416};
    for(unsigned k=0;k<3;k++){
        desired[k].address=pwcd_addresses[k];desired[k].length=32;desired[k].index=7;
        for(unsigned j=0;j<16;j++)put(desired[k].aux+2*j,levels[j],2);
    }
    unsigned checks=0;struct paic_io io=setup(0);uint32_t saved[3]={99,99,99},requested[3]={99,99,99};
    int ok=pwrpb_capture(&io,provider,rw,&provider->pools[0][1],&reference,before);
    if(!ok)fprintf(stderr,"baseline err%u rows%u clients%u free%u mode%u bytes%zu\n",before->error,before->rows,before->clients,before->free_requests,before->active_mask,sizeof(*before));
    assert(ok&&before->complete&&before->rows==3&&before->clients==1&&before->free_requests==1&&before->active_mask==15);
    assert(pwrpb_capture(&io,provider,rw,&provider->pools[0][1],&reference,after)&&pwrpb_equal(before,after));checks++;
    assert(!pwrpb_capture(&io,provider,rw,&provider->pools[0][1],&reference,before));checks++;
    assert(pwrpb_plan(before,desired,saved,requested)&&!memcmp(saved,values,sizeof(saved)));checks++;
    for(unsigned k=1;k<=25;k++){
        io=setup(k);ok=pwrpb_capture(&io,provider,rw,&provider->pools[0][1],&reference,before);
        if(k==3||k==4||k==16||k==17||k==19){
            assert(ok);for(unsigned j=0;j<3;j++)saved[j]=requested[j]=99;
            int plan=pwrpb_plan(before,desired,saved,requested);
            if(k==19)assert(plan&&saved[2]==0); /* observed valid zero, not absent */
            else{assert(!plan);for(unsigned j=0;j<3;j++)assert(saved[j]==99&&requested[j]==99);}
        }else{
            if(ok||!before->error)fprintf(stderr,"fault%u ok%d error%u rows%u free%u\n",k,ok,before->error,before->rows,before->free_requests);
            assert(!ok&&before->error&&!before->complete);
            if(k==6||k==18||k==22)assert(before->error==PWRPB_ALIAS);
            if(k==12)assert(before->free_request[0].bytes==48&&before->free_request[0].command_bytes==128);
        }checks++;
    }
    io=setup(0);assert(pwrpb_capture(&io,provider,rw,&provider->pools[0][1],&reference,before));
    links[0x4004+0x3f]^=1; /* preserved unused byte changed between complete captures */
    assert(pwrpb_capture(&io,provider,rw,&provider->pools[0][1],&reference,after)&&!pwrpb_equal(before,after));checks++;
    io=setup(0);mode=22;reference.daif=0xc0;reference.group1=0;
    assert(pwrpb_capture(&io,provider,rw,&provider->pools[0][1],&reference,before)&&before->before.daif==0xc0&&!before->before.group1);checks++;
    io=setup(0);reference.daif=0xc0;reference.group1=0; /* expected mask was not actually observed */
    assert(!pwrpb_capture(&io,provider,rw,&provider->pools[0][1],&reference,before)&&before->error==PWRPB_TIME);checks++;
    printf("{\"checks\":%u,\"raw_bytes\":%zu,\"SOFTWARE_firmware_RAM_peer\":true,\"retired_driver_free_request_not_pending\":true,\"physical_cache_captured\":false,\"MMIO\":0,\"firmware_API_calls\":0,\"lease_granted\":false}\n",checks,sizeof(*before));
    free(original);free(npa_original);free(rp_original);free(arena);return 0;
}
#endif
