/* Host-only synthetic BootServices/loaded-image fixture. Original PE is read
 * as data and relocated in host RAM; no instruction from it is executed. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static char logged[32768];
static size_t log_bytes;
static unsigned log_calls,max_log_calls,max_log_lines;
static void text(const char *s)
{
    size_t bytes=strlen(s);assert(bytes<=126&&log_bytes+bytes<sizeof(logged));
    memcpy(logged+log_bytes,s,bytes);log_bytes+=bytes;logged[log_bytes]=0;log_calls++;
}
static void report(const char *s,uint64_t value);
#include "../shim/polaris/uefi-audio-i2c-cache.h"
static void report(const char *s,uint64_t value)
{
    char raw[19]={'0','x'};
    for(unsigned n=0;n<16;n++)raw[2+n]="0123456789abcdef"[(value>>(60-4*n))&15];
    raw[18]=0;text(s);text(raw);text("\r\n");
}
static uint8_t *arena,*image;
static struct efi_system *sys;
static struct efi_boot *bs;
static struct efi_loaded *loaded;
static efi_handle *handles;
static struct paic_result result __attribute__((aligned(4096)));
static struct paic_workspace work __attribute__((aligned(4096)));
static unsigned fault,calls,maps,orders,arches,releases;
static void put(uint8_t *p,uint64_t v,unsigned n)
{for(unsigned i=0;i<n;i++)p[i]=(uint8_t)(v>>(8*i));}
static efi_status locate(const efi_guid *guid,void *registration,void **out)
{
    (void)guid;(void)registration;calls++;
    *out=image+0x6098;
    if(fault==9&&maps>1)*out=image+0x60a0;
    return fault==1?1:0;
}
static efi_status enumerate(uint32_t search,const efi_guid *guid,void *key,uint64_t *count,efi_handle **out)
{(void)guid;(void)key;assert(search==2);calls++;*count=fault==2?257:fault==3?2:fault==19?256:1;*out=handles;return 0;}
static efi_status handle(efi_handle value,const efi_guid *guid,void **out)
{(void)value;(void)guid;calls++;*out=loaded;return fault==4?0x800000000000000eULL:0;}
static efi_status release(void *value)
{assert(value==handles);calls++;releases++;return fault==5?0x8000000000000002ULL:0;}
static efi_status map(uint64_t *bytes,void *out,uint64_t *key,uint64_t *stride,uint32_t *version)
{
    assert(*bytes>=sizeof(struct efi_memory));calls++;maps++;
    struct efi_memory m[3]={{fault==6?7:3,0,(uintptr_t)arena,0,0x20000/4096,8},
        {4,0,(uintptr_t)&result,0,(sizeof(result)+4095)/4096,8},
        {4,0,(uintptr_t)&work,0,(sizeof(work)+4095)/4096,8}};
    if(fault==18&&maps==3)m[0].type=7;
    memcpy(out,m,sizeof(m));*bytes=sizeof(m);*stride=sizeof(m[0]);
    *version=(fault==15||(fault==16&&maps==3))?2:1;*key=fault==7&&maps==3?2:1;
    return fault==17&&maps==2?0x8000000000000002ULL:0;
}
static int arch(void *ctx,struct paic_arch *a)
{
    (void)ctx;arches++;
    *a=(struct paic_arch){.el=4,.mpidr=0,.ttbr0=0x180000001,.ttbr1=0,.tcr=0x80803520,
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
    if(fault==8&&orders==2)image[PAIC_CACHE_RVA+20]^=1;
}
static void reset(void)
{
    memset(&result,0,sizeof(result));memset(&work,0,sizeof(work));calls=maps=orders=arches=releases=0;
    sys->boot=bs;bs->locate_protocol=locate;bs->locate_buffer=enumerate;bs->handle_protocol=handle;
    bs->get_map=map;bs->free_pool=release;
    *loaded=(struct efi_loaded){.revision=0x1000,.system=sys,.base=image,.bytes=PAII_IMAGE_BYTES,.code_type=3,.data_type=4};
    for(unsigned n=0;n<PAIC_HANDLES;n++)handles[n]=(void*)(uintptr_t)(n+1);
    uint8_t *p=image+PAIC_CACHE_RVA;memset(p,0,PAIC_CACHE_BYTES);
    put(p+0x40,UINT64_C(0xdead000000000001),8);
    put(p+0x48,UINT64_C(0xc10c000000000001),8);
    put(p+0x50,UINT64_C(0x7100000000000001),8);
}
static int run(unsigned stage)
{const struct paic_io io={sys,0,arch,identity,order};return paic_collect(&io,stage,&result,&work);}
static unsigned nibble(char value)
{assert((value>='0'&&value<='9')||(value>='a'&&value<='f'));return value<='9'?(unsigned)(value-'0'):(unsigned)(value-'a'+10);}
static void save_log(const char *prefix,const char *name)
{
    if(!prefix)return;
    char path[4096];int bytes=snprintf(path,sizeof(path),"%s-%s.log",prefix,name);assert(bytes>0&&(size_t)bytes<sizeof(path));
    FILE *file=fopen(path,"wb");assert(file);assert(fwrite(logged,1,log_bytes,file)==log_bytes);assert(!fclose(file));
}
static void check_complete_compact_log(void)
{
    unsigned before=calls;log_bytes=log_calls=0;logged[0]=0;paic_report_record(&result);assert(calls==before);
    const char *begin=strstr(logged,"AUDIO_I2C_CACHE_RAW_V1_BEGIN\r\n");assert(begin);
    begin+=strlen("AUDIO_I2C_CACHE_RAW_V1_BEGIN\r\n");
    const char *end=strstr(begin,"\r\nAUDIO_I2C_CACHE_RAW_V1_END\r\n");assert(end&&end-begin==2*(ptrdiff_t)sizeof(result));
    for(size_t n=0;n<sizeof(result);n++)assert((nibble(begin[2*n])*16+nibble(begin[2*n+1]))==((const uint8_t*)&result)[n]);
    unsigned lines=0;for(size_t n=0;n<log_bytes;n++)lines+=logged[n]=='\n';
    assert(lines==8&&log_calls<=110); /* Includes all256 status/address slots without per-handle reports. */
    if(log_calls>max_log_calls)max_log_calls=log_calls;if(lines>max_log_lines)max_log_lines=lines;
}
static void print_wire_schema(void)
{
    printf("\"wire_schema\":{\"version\":1,\"bytes\":%zu,\"endian\":\"little\",\"members\":{",sizeof(result));
    const char *comma="";
#define FIELD(member) printf("%s\"%s\":[%zu,%zu]",comma,#member,offsetof(struct paic_result,member),sizeof(result.member));comma=",";
    FIELD(cookie) FIELD(protocol) FIELD(image) FIELD(protocol_status) FIELD(enumerate_status) FIELD(map_status) FIELD(release_status)
    FIELD(handle_count) FIELD(map_key) FIELD(map_bytes) FIELD(map_stride) FIELD(identity_address) FIELD(identity_par)
    FIELD(map_version) FIELD(map_sample) FIELD(map_samples) FIELD(handle_status) FIELD(loaded_address)
    FIELD(before) FIELD(after) FIELD(owner) FIELD(handles) FIELD(owner_address) FIELD(protocol_after_status) FIELD(protocol_after)
    FIELD(error) FIELD(attempted) FIELD(owner_matches) FIELD(hash_failed) FIELD(hash_count) FIELD(snapshot_bytes)
    FIELD(cache_consistent) FIELD(release_attempted) FIELD(map_keys_before_release_only)
    FIELD(raw_context_head) FIELD(raw_clock_handle) FIELD(raw_TLMM_handle) FIELD(hashes) FIELD(snapshot)
#undef FIELD
    printf("},\"struct_bytes\":{\"arch\":%zu,\"map_sample\":%zu,\"owner\":%zu}}",sizeof(struct paic_arch),sizeof(struct paic_map_sample),sizeof(struct efi_loaded));
}
int main(int argc,char **argv)
{
    assert(argc==2||argc==3);const char *log_prefix=argc==3?argv[2]:0;
    assert(!posix_memalign((void**)&arena,4096,0x20000));memset(arena,0,0x20000);
    image=arena+0x1000;loaded=(void*)(arena+0x11000);sys=(void*)(arena+0x12000);
    bs=(void*)(arena+0x13000);handles=(void*)(arena+0x14000);
    FILE *file=fopen(argv[1],"rb");assert(file);assert(fread(image,1,PAII_IMAGE_BYTES,file)==PAII_IMAGE_BYTES);assert(!fclose(file));
    for(unsigned n=0;n<PAII_RELOC_COUNT;n++)put(image+paii_relocations[n],
        paii_le(image+paii_relocations[n],8)+(uintptr_t)image,8);
    unsigned checks=0;
    reset();assert(run(2)&&result.error==0&&result.snapshot_bytes[0]==120&&result.snapshot_bytes[1]==120&&
        result.release_attempted==1&&releases==1&&result.owner_matches==1&&result.cache_consistent&&
        result.map_samples==3&&result.map_sample[0].version==1&&result.map_sample[2].key==1);checks++;
    check_complete_compact_log();save_log(log_prefix,"positive");checks++;
    unsigned before=calls;assert(!run(2)&&calls==before);checks++;
    for(unsigned f=1;f<=18;f++){
        fault=f;reset();assert(!run(2)&&result.error);assert(calls<=8);
        if(f==1)assert(result.protocol_status==1&&calls==1);
        if(f==2||f==6)assert(!result.release_attempted&&!releases);
        if(f==3)assert(result.owner_matches==2&&result.error==PAIC_PROVENANCE);
        if(f==7)assert(result.error==PAIC_CHANGED_MAP&&result.snapshot_bytes[1]==120);
        if(f==8)assert(result.error==PAIC_CHANGED_CACHE&&result.snapshot[0][20]!=result.snapshot[1][20]);
        if(f==10||f==14)assert(!calls&&result.error==PAIC_ARCH);
        if(f==11||f==12)assert(result.error==PAIC_LIFETIME);
        if(f>=15&&f<=17)assert(result.error==PAIC_MAP&&!result.release_attempted&&!releases);
        if(f==17)assert(result.map_samples==2&&result.map_sample[1].status==0x8000000000000002ULL);
        if(f==18)assert(result.error==PAIC_ARRAY&&!result.release_attempted&&!releases);
        check_complete_compact_log();
        if(f==8)save_log(log_prefix,"changed-cache");
        if(f==17)save_log(log_prefix,"partial-map");
        checks++;
    }
    fault=0;reset();assert(!run(4)&&!calls&&result.error==PAIC_STAGE);checks++;
    reset();image[0x1100]^=1;assert(!run(2)&&result.error==PAIC_HASH&&result.hash_failed==2);image[0x1100]^=1;checks++;
    reset();image[paii_relocations[0]]^=1;assert(!run(2)&&result.error==PAIC_HASH);image[paii_relocations[0]]^=1;checks++;
    reset();image[0x700f]^=1;assert(!run(2)&&result.error==PAIC_HASH&&result.hash_failed==4);image[0x700f]^=1;checks++;
    reset();image[PAII_IMAGEBASE_RVA]=1;assert(!run(2)&&result.error==PAIC_HASH);image[PAII_IMAGEBASE_RVA]=0;checks++;
    reset();put(image+PAII_IMAGEBASE_RVA,(uintptr_t)image,8);assert(run(2));put(image+PAII_IMAGEBASE_RVA,0,8);checks++;
    reset();memset(image+PAIC_CACHE_RVA,0,120);assert(run(2)&&result.cache_consistent&&!result.raw_context_head);checks++;
    reset();assert(run(2)&&result.raw_context_head==UINT64_C(0xdead000000000001)&&result.raw_clock_handle==UINT64_C(0xc10c000000000001)&&result.raw_TLMM_handle==UINT64_C(0x7100000000000001));checks++;
    reset();loaded->bytes--;assert(!run(2)&&result.error==PAIC_IMAGE);checks++;
    reset();loaded->system=0;assert(!run(2)&&result.error==PAIC_IMAGE);checks++;
    reset();bs->locate_protocol=0;assert(!run(2)&&result.error==PAIC_PROTOCOL&&!calls);checks++;
    reset();image[0x6059]^=1;assert(!run(2)&&result.error==PAIC_HASH&&result.hash_failed==3);image[0x6059]^=1;checks++;
    reset();image[0x6100]^=1;assert(run(2));image[0x6100]^=1;checks++; /* mutable SCM scratch not hashed/followed */
    fault=19;reset();assert(!run(2)&&result.error==PAIC_PROVENANCE&&result.owner_matches==256&&result.handle_count==256);
    check_complete_compact_log();save_log(log_prefix,"max-handles");assert(calls==261&&releases==1);checks++;
    free(arena);printf("{\"checks\":%u,\"original_code_executed\":false,\"MMIO_reads\":0,\"protocol_methods_called\":0,\"compact_log_max_text_calls\":%u,\"compact_log_lines\":%u,",checks,max_log_calls,max_log_lines);
    print_wire_schema();printf("}\n");return 0;
}
