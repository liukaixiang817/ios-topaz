/* Actual collector with a software service peer; original firmware is DATA.
 * No original RPMh code, MMIO, driver API, client or vote executes here. */
#define POLARIS_NPA_FIXTURE_ONLY 1
#include "polaris-wifi-npa-test.c"
#define EFI_XNU_WIFI_RPMH_READONLY_AVAILABLE 1
#include "uefi-wifi-rpmh-readonly.h"
static struct pwrph_result *rr;
static struct pwrph_work *rw;
static uint8_t *rp_original;
static unsigned rf,rcalls;
static int rp_arch(void *ctx,struct paic_arch *a)
{ int ok=npa_arch(ctx,a);if(rf==15&&rcalls>=2)a->ticks=rr->before.ticks+3840001;return ok; }
static int rp_locate(void *ctx,struct efi_system *sys,const efi_guid *guid,void **table,uint64_t *status)
{
    (void)ctx;assert(sys==s&&guid->a==0xe1d0b573);rcalls++;
    *table=npa+0xd0d8;*status=0;
    if(rf==1)*status=0x800000000000000eULL;
    if(rf==2&&rcalls>2)*table=npa+0xd0e0;
    if(rf==3)put(core+0x1b098,8,8);
    if(rf==4)fault=2;
    return rf!=10;
}
static int rp_map(void *ctx,struct efi_system *sys,uint8_t *buffer,struct paic_map_sample *m)
{
    (void)ctx;assert(sys==s);rcalls++;struct efi_memory *d=(void*)buffer;
    *d=(struct efi_memory){3,0,(uintptr_t)arena,0,0x240000/4096,8};
    m->bytes=sizeof(*d);m->key=rf==5&&rcalls>3?2:1;m->stride=sizeof(*d);m->version=1;m->status=0;
    if(rf==6)d->type=7;
    if(rf==7&&rcalls>3)links[0x440]^=1; /* TCS RAM state changed */
    if(rf==8&&rcalls>3)npa[0x1000]^=1;
    if(rf==9)m->bytes=5000;
    if(rf==16&&rcalls>3)links[0x220]^=1; /* queue header changed */
    return rf!=11;
}
static void rp_reset(unsigned f)
{
    npa_reset(0);rf=f;rcalls=0;pwrph_ticket.used=pwrph_ticket.outstanding=0;
    rr=(void*)nr;rw=(void*)nw;memset(rr,0,sizeof(*rr));
    memcpy(npa,rp_original,PWRPI_IMAGE_BYTES);
    for(unsigned j=0;j<PWRPI_RELOC_COUNT;j++)put(npa+pwrpi_relocs[j],pwfi_le(npa+pwrpi_relocs[j],8)+(uintptr_t)npa,8);
    ((struct efi_loaded*)(arena+0x188000))->bytes=PWRPI_IMAGE_BYTES;
    put(npa+0xd2e8,1,4);put(npa+0xd2f8,(uintptr_t)links,8);
    put(npa+0xd3e0,(uintptr_t)links+0x40,8);put(npa+0xd3e8,(uintptr_t)links+0x80,8);
    memset(links,0,0x1000);put(links,(uintptr_t)links+0x100,8);put(links+0x40,(uintptr_t)links+0x400,8);
    put(links+0x100,16,4);
    for(unsigned k=0;k<5;k++)put(links+0x108+8*k,(uintptr_t)links+0x200+64*k,8);
    if(f==12)put(npa+0xd2f8,0,8); /* early-set init flag but missing queues */
    if(f==13)put(links+0x40,0x86000000,8); /* not BootServicesRAM */
    if(f==14)put(npa+0xd3e0,UINT64_MAX-3,8); /* overflow/malformed extent */
    if(f==17) {put(npa+0xd2e8,0,4);put(npa+0xd2f8,0,8);put(npa+0xd3e0,0,8);put(npa+0xd3e8,0,8);}
    if(f==18) {enumeration->handle_count=2;enumeration->loaded_address[1]=enumeration->loaded_address[0];}
    if(f==19)self->bytes=r->self_owner.bytes=r->self_bytes=0x1a3000;
}
int main(int argc,char **argv)
{
    assert(argc==4);assert(!posix_memalign((void**)&arena,4096,0x240000));
    original=malloc(PGCI_IMAGE_BYTES);npa_original=malloc(PWNPI_IMAGE_BYTES);rp_original=malloc(PWRPI_IMAGE_BYTES);
    assert(original&&npa_original&&rp_original);
    const size_t sizes[]={PGCI_IMAGE_BYTES,PWNPI_IMAGE_BYTES,PWRPI_IMAGE_BYTES};
    uint8_t *dst[]={original,npa_original,rp_original};
    for(unsigned j=0;j<3;j++){FILE *f=fopen(argv[j+1],"rb");assert(f&&fread(dst[j],1,sizes[j],f)==sizes[j]&&!fclose(f));}
    struct pwrph_io ops={{NULL,NULL,rp_arch,identity,order},rp_locate,rp_map};unsigned checks=0;
    rp_reset(0);ops.memory.system=s;
    int ok=pwrph_collect(&ops,2,enumeration,c,rr,rw);
    if(!ok)fprintf(stderr,"baseline error%u gcd%u calls%u hash%u/%u\n",rr->error,r->error,rcalls,rr->hash_count[0],rr->hash_failed[0]);
    assert(ok&&rr->stable&&rr->snapshot_complete[1]&&rr->issued==4&&rr->returned==4&&!rr->unknown);
    assert(rr->snapshot[0].initialized==1&&rr->snapshot[0].drv_count==1&&pwfi_le(rr->snapshot[0].drv[0].row,4)==2);
    assert(rr->snapshot[0].drv[0].tcs_bytes==8*24&&rr->snapshot[0].drv[0].queue_bytes[4]==40);
    assert(rr->hash_count[0]==5&&rr->hash_count[1]==5&&queries==0&&saves==restores);checks++;
    assert(!pwrph_collect(&ops,2,enumeration,c,rr,rw)&&rcalls==4);checks++;
    for(unsigned j=1;j<=19;j++) {
        rp_reset(j);ops.memory.system=s;ok=pwrph_collect(&ops,2,enumeration,c,rr,rw);
        if(j==17){assert(ok&&rr->stable&&!rr->snapshot[0].initialized&&!rr->snapshot[0].drv[0].tcs_bytes);}
        else {
            if(ok||!rr->error)fprintf(stderr,"fault%u ok%d err%u calls%u\n",j,ok,rr->error,rcalls);
            assert(!ok&&rr->error&&queries==0);
            if(j==3||j==4||j==10||j==11)assert(rr->unknown&&rr->outstanding&&pwrph_ticket.outstanding&&pgcd_uncertain(c));
            if(j==2||j==5||j==7||j==16)assert(rr->error==PWRPH_CHANGED);
            if(j==8)assert(rr->error==PWRPH_HASH);
            if(j==12)assert(rr->error==PWRPH_NOT_READY&&rr->snapshot[0].global_bytes==0x110&&!rr->unknown);
            if(j==13)assert(rr->snapshot[0].drv[0].tcs_bytes==0&&rr->snapshot[0].drv[0].tcs_ptr_bytes==8);
            if(j==15)assert(rr->error==PWRPH_BASELINE&&!rr->unknown);
        }
        checks++;
    }
    rp_reset(0);ops.memory.system=s;assert(!pwrph_collect(&ops,3,enumeration,c,rr,rw)&&!rcalls);checks++;
    printf("{\"checks\":%u,\"raw_bytes\":%zu,\"snapshot_bytes\":%zu,\"DRV_bytes\":%zu,\"original_RPMh_API_calls\":0,\"physical_MMIO_or_radio\":false}\n",checks,sizeof(*rr),sizeof(struct pwrph_snapshot),sizeof(struct pwrph_drv));
    free(original);free(npa_original);free(rp_original);free(arena);return 0;
}
