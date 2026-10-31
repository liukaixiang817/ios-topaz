/* Host-only synthetic BootServices/loaded-image fixture. Original PE is read
 * as data and relocated in host RAM; no instruction from it is executed. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void text(const char *s){(void)s;}
static void report(const char *s,uint64_t value);
#include "../shim/polaris/uefi-wifi-cache-readonly.h"
static void report(const char *s,uint64_t value){(void)s;(void)value;}
static uint8_t *arena,*image;
static struct efi_system *sys;
static struct efi_boot *bs;
static struct efi_loaded *loaded;
static efi_handle *handles;
static struct pwfc_result result;
static struct pwfc_workspace work;
static unsigned fault,calls,maps,orders,arches,releases;
static void put(uint8_t *p,uint64_t v,unsigned n)
{for(unsigned i=0;i<n;i++)p[i]=(uint8_t)(v>>(8*i));}
static efi_status locate(const efi_guid *guid,void *registration,void **out)
{
    (void)guid;(void)registration;calls++;
    *out=image+0x7090;
    if(fault==9&&maps>1)*out=image+0x7098;
    return fault==1?1:0;
}
static efi_status enumerate(uint32_t search,const efi_guid *guid,void *key,uint64_t *count,efi_handle **out)
{(void)guid;(void)key;assert(search==2);calls++;*count=fault==2?257:fault==3?2:1;*out=handles;return 0;}
static efi_status handle(efi_handle value,const efi_guid *guid,void **out)
{(void)value;(void)guid;calls++;*out=loaded;return fault==4?0x800000000000000eULL:0;}
static efi_status release(void *value)
{assert(value==handles);calls++;releases++;return fault==5?0x8000000000000002ULL:0;}
static efi_status map(uint64_t *bytes,void *out,uint64_t *key,uint64_t *stride,uint32_t *version)
{
    assert(*bytes>=sizeof(struct efi_memory));calls++;maps++;
    struct efi_memory m={fault==6?7:3,0,(uintptr_t)arena,0,0x20000/4096,8};
    memcpy(out,&m,sizeof(m));*bytes=sizeof(m);*stride=sizeof(m);*version=1;*key=fault==7&&maps==3?2:1;
    return 0;
}
static int arch(void *ctx,struct pwfc_arch *a)
{
    (void)ctx;arches++;
    *a=(struct pwfc_arch){.el=4,.mpidr=0,.ttbr0=0x180000001,.ttbr1=0,.tcr=0x80803520,
        .sctlr=0x30d00801,.mair=0xff44,.daif=0,.sre=1,.group1=1,.frequency=19200000,.ticks=1000+arches};
    if(fault==10)a->daif=0x3c0;
    if(fault==11&&arches==2)a->ttbr0++;
    if(fault==12&&arches==2)a->ticks=1;
    if(fault==14)a->sre=0;
    return 1;
}
static int identity(void *ctx,uint64_t address,uint64_t bytes,uint64_t *where,uint64_t *par)
{
    (void)ctx;(void)bytes;*where=address;*par=address&~UINT64_C(4095);
    return !(fault==13&&address==(uintptr_t)image);
}
static void order(void *ctx)
{
    (void)ctx;orders++;
    if(fault==8&&orders==2)image[PWFC_CACHE_RVA+20]^=1;
}
static void reset(void)
{
    memset(&result,0,sizeof(result));memset(&work,0,sizeof(work));calls=maps=orders=arches=releases=0;
    sys->boot=bs;bs->locate_protocol=locate;bs->locate_buffer=enumerate;bs->handle_protocol=handle;
    bs->get_map=map;bs->free_pool=release;
    *loaded=(struct efi_loaded){.revision=0x1000,.system=sys,.base=image,.bytes=PWFI_IMAGE_BYTES,.code_type=3,.data_type=4};
    handles[0]=(void*)1;handles[1]=(void*)2;
    uint8_t *p=image+PWFC_CACHE_RVA;memset(p,0,PWFC_CACHE_BYTES);
    put(p,0x86000000,8);put(p+8,0x86000000,8);put(p+16,0x200000,4);put(p+20,0xc0000,4);
    put(p+24,498,2);put(p+32,(uintptr_t)image+0x5cb0,8);put(p+40,3,4);
    put(p+96,0x86001000,8);put(p+104,0x4000,4);put(p+108,64,4);put(p+112,32,4);put(p+116,0x4000,4);
    put(p+528,0x49494953,4);put(p+532,0x200000,4);put(p+536,0x86000000,8);put(p+544,498,2);
    for(unsigned n=0;n<8;n++)put(p+552+8*n,0x1f40000+4096*n,8);
    put(p+616,0x1fd4000,8);put(p+624,0x1fd4004,8);
}
static int run(unsigned stage)
{const struct pwfc_io io={sys,0,arch,identity,order};return pwfc_collect(&io,stage,&result,&work);}
int main(int argc,char **argv)
{
    assert(argc==2);assert(!posix_memalign((void**)&arena,4096,0x20000));memset(arena,0,0x20000);
    image=arena+0x1000;loaded=(void*)(arena+0x11000);sys=(void*)(arena+0x12000);
    bs=(void*)(arena+0x13000);handles=(void*)(arena+0x14000);
    FILE *file=fopen(argv[1],"rb");assert(file);assert(fread(image,1,PWFI_IMAGE_BYTES,file)==PWFI_IMAGE_BYTES);assert(!fclose(file));
    for(unsigned n=0;n<PWFI_RELOC_COUNT;n++)put(image+pwfi_relocations[n],
        pwfi_le(image+pwfi_relocations[n],8)+(uintptr_t)image,8);
    unsigned checks=0;
    reset();assert(run(2)&&result.error==0&&result.snapshot_bytes[0]==632&&result.snapshot_bytes[1]==632&&
        result.release_attempted==1&&releases==1&&result.owner_matches==1&&result.cache_consistent);checks++;
    unsigned before=calls;assert(!run(2)&&calls==before);checks++;
    for(unsigned f=1;f<=14;f++){
        fault=f;reset();assert(!run(2)&&result.error);assert(calls<=8);
        if(f==1)assert(result.protocol_status==1&&calls==1);
        if(f==2||f==6)assert(!result.release_attempted&&!releases);
        if(f==3)assert(result.owner_matches==2&&result.error==PWFC_PROVENANCE);
        if(f==7)assert(result.error==PWFC_CHANGED_MAP&&result.snapshot_bytes[1]==632);
        if(f==8)assert(result.error==PWFC_CHANGED_CACHE&&result.snapshot[0][20]!=result.snapshot[1][20]);
        if(f==10||f==14)assert(!calls&&result.error==PWFC_ARCH);
        if(f==11||f==12)assert(result.error==PWFC_LIFETIME);
        checks++;
    }
    fault=0;reset();assert(!run(4)&&!calls&&result.error==PWFC_STAGE);checks++;
    reset();image[0x1100]^=1;assert(!run(2)&&result.error==PWFC_HASH&&result.hash_failed==2);image[0x1100]^=1;checks++;
    reset();image[pwfi_relocations[0]]^=1;assert(!run(2)&&result.error==PWFC_HASH);image[pwfi_relocations[0]]^=1;checks++;
    reset();image[0x800f]^=1;assert(!run(2)&&result.error==PWFC_HASH&&result.hash_failed==4);image[0x800f]^=1;checks++;
    reset();image[PWFI_IMAGEBASE_RVA]=1;assert(!run(2)&&result.error==PWFC_HASH);image[PWFI_IMAGEBASE_RVA]=0;checks++;
    reset();put(image+PWFI_IMAGEBASE_RVA,(uintptr_t)image,8);assert(run(2));put(image+PWFI_IMAGEBASE_RVA,0,8);checks++;
    reset();memset(image+PWFC_CACHE_RVA,0,632);assert(!run(2)&&result.error==PWFC_CACHE&&result.snapshot_bytes[1]==632);checks++;
    reset();put(image+PWFC_CACHE_RVA+96,0x86200000,8);assert(!run(2)&&result.error==PWFC_CACHE);checks++;
    reset();loaded->bytes--;assert(!run(2)&&result.error==PWFC_IMAGE);checks++;
    reset();loaded->system=0;assert(!run(2)&&result.error==PWFC_IMAGE);checks++;
    reset();bs->locate_protocol=0;assert(!run(2)&&result.error==PWFC_PROTOCOL&&!calls);checks++;
    reset();memset(image+PWFC_CACHE_RVA+96,0,48);assert(run(2)&&!result.mpss_cached&&result.hash_count==4);checks++;
    free(arena);printf("{\"checks\":%u,\"original_code_executed\":false,\"SMEM_reads\":0,\"radio\":false}\n",checks);return 0;
}
