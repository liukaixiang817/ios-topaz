/* Real GCD guard -> NS read/write AT -> finite own-register load adapter.
 * Every external service, AT operation and register is a SOFTWARE peer. */
#define POLARIS_RSC_BASELINE_FIXTURE_ONLY 1
#include "polaris-wifi-rsc-baseline-test.c"
#include "uefi-wifi-rsc-device.h"
static struct pwrmd_result *device;
static unsigned device_fault,translations,loads,gcd_calls;
static int device_query(void *ctx,uint64_t fn,uint64_t page,struct pgcd_descriptor *d,uint64_t *status)
{
    (void)ctx;assert(fn==(uintptr_t)core+0x2c68&&r->outstanding&&device->outstanding);
    assert(page==pwrmd_pages[gcd_calls++]);
    *d=(struct pgcd_descriptor){page,4096,1,0,3,0,0x123,0x456};*status=0;
    if(device_fault==1)d->type=2;
    if(device_fault==17)self->bytes--;
    if(device_fault==22)*status=UINT64_C(0x800000000000000e);
    return device_fault!=2;
}
static int translation_peer(void *ctx,struct pwrmd_translation *t)
{
    (void)ctx;assert(device->outstanding&&!device->history[device->events-1].issued);translations++;
    t->saved=0x12345678;t->read_par=t->write_par=t->page|0x280;t->restored=t->saved;
    t->read_issued=t->read_returned=t->write_issued=t->write_returned=t->restore_issued=t->restore_returned=1;
    if(device_fault==4)t->write_par|=1;
    if(device_fault==5)t->restored++;
    if(device_fault==7)t->read_par=t->write_par=t->page|0x80;
    if(device_fault==8)t->read_par=t->write_par=t->page|UINT64_C(0xff00000000000280);
    if(device_fault==9)t->read_par=t->write_par=(t->page+4096)|0x280;
    if(device_fault==14)arches=50000;
    if(device_fault==19)t->write_returned=0;
    if(device_fault==21)mode=21;
    if(device_fault==23)t->read_par=t->write_par=t->page|UINT64_C(0x0400000000000280);
    if(device_fault==24){t->page+=4096;t->read_par=t->write_par=t->page|0x280;}
    return device_fault!=6;
}
static int load_peer(void *ctx,uint64_t at,uint32_t *value)
{
    (void)ctx;assert(pwrmd_readable(at)&&device->outstanding);
    assert(device->history[device->events-1].issued&&pwrmd_translation_valid(&device->history[device->events-1].translation));loads++;
    if(at==0x179e000c)*value=(16u<<27)|(8u<<12);
    else if(at==0x179e0d00)*value=15;
    else if(at==0x179e0d04)*value=0;
    else *value=(at-0x179e0d00)%672==0x18?1:0;
    if(device_fault==10&&at==0x179e000c)*value=(16u<<27)|(7u<<12);
    if(device_fault==11&&at==0x179e0d04)*value=1;
    if(device_fault==12&&at==0x179e0d1c)*value=1;
    if(device_fault==13&&loads>35&&at==0x179e0d10)*value=1;
    return device_fault!=20;
}
static int run_device(unsigned which)
{
    struct paic_io memory=setup(0);device_fault=which;translations=loads=gcd_calls=0;
    assert(pwrpb_capture(&memory,provider,rw,&provider->pools[0][1],&reference,before));
    device=(void*)(arena+0xe0000);memset(device,0,sizeof(*device));assert(sizeof(*device)<0x10000);
    c->io.query=device_query;
    if(which==16){struct efi_memory *m=(void*)(rw->map+rw->bytes);*m=(struct efi_memory){4,0,0x179e0000,0,1,8};rw->bytes+=rw->stride;}
    if(which==18)before->HAL_runtime[0]=0;
    if(which==25)provider->core.core+=4096;
    const struct pwrmd_io io={&memory,0,translation_peer,load_peer};
    return pwrmd_collect(&io,provider,rw,c,before,device);
}
int main(int argc,char **argv)
{
    assert(argc==4&&!posix_memalign((void**)&arena,4096,0x240000));
    original=malloc(PGCI_IMAGE_BYTES);npa_original=malloc(PWNPI_IMAGE_BYTES);rp_original=malloc(PWRPI_IMAGE_BYTES);assert(original&&npa_original&&rp_original);
    const size_t sizes[]={PGCI_IMAGE_BYTES,PWNPI_IMAGE_BYTES,PWRPI_IMAGE_BYTES};uint8_t *dst[]={original,npa_original,rp_original};
    for(unsigned k=0;k<3;k++){FILE *f=fopen(argv[k+1],"rb");assert(f&&fread(dst[k],1,sizes[k],f)==sizes[k]&&!fclose(f));}
    unsigned checks=0;int ok=run_device(0);
    if(!ok)fprintf(stderr,"device error%u unknown%u outstanding%x gcd%u events%u loads%u\n",device->error,device->unknown,device->outstanding,r->error,device->events,loads);
    assert(ok&&device->complete&&loads==70&&translations==70&&gcd_calls==3&&!device->unknown&&!device->outstanding&&saves==restores);checks++;
    const struct pwrmd_io io={0};assert(!pwrmd_collect(&io,provider,rw,c,before,device));checks++;
    assert(run_device(23)&&device->complete&&loads==70);checks++;
    for(unsigned k=1;k<=25;k++){
        if(k==3||k==15||k==23)continue;
        ok=run_device(k);
        if(ok||!device->error)fprintf(stderr,"device unexpected fault%u ok%d err%u loads%u\n",k,ok,device->error,loads);
        assert(!ok&&device->error&&!device->complete);
        if(k==2||k==5||k==6||k==14||k==17||k==19||k==20||k==21)assert(device->unknown&&device->outstanding);
        else assert(!device->unknown&&!device->outstanding);
        if(k==1||k==2||k==16||k==17||k==18||k==22||k==25)assert(!translations&&!loads);
        if(k==4||k==5||k==6||k==7||k==8||k==9||k==14||k==19||k==21||k==24)assert(!loads);
        if(k==20)assert(device->history[0].issued&&!device->history[0].returned&&device->history[0].unknown);
        checks++;
    }
    assert(!pwrmd_readable(0x179e0d08)&&!pwrmd_readable(0x179e0d0c)&&!pwrmd_readable(0x179e0d30)&&!pwrmd_readable(0x179e0d19)&&!pwrmd_readable(0xaf21c18));checks++;
    printf("{\"checks\":%u,\"raw_bytes\":%zu,\"event_bytes\":%zu,\"translation_bytes\":%zu,\"SOFTWARE_GCD_AT_MMIO\":true,\"real_MMIO_or_AT_executed\":false,\"write_callback_exposed\":false,\"hardware_lease_granted\":false}\n",checks,sizeof(*device),sizeof(struct pwrmd_event),sizeof(struct pwrmd_translation));
    free(original);free(npa_original);free(rp_original);free(arena);return 0;
}
