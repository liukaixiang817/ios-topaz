/* Original ClockDxe PE relocated AS DATA ONLY. Query callbacks below are an
 * explicit SOFTWARE peer: no original instruction or register is executed. */
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
static void text(const char *s){(void)s;}
static void report(const char *s,uint64_t n){(void)s;(void)n;}
#include "../shim/polaris/uefi-audio-clock-query.h"
enum {F_NONE,F_PROTOCOL,F_HASH,F_SIZE,F_DAL,F_VTABLE,F_DESCRIPTOR,F_BSP,F_STATUS,F_VALUE,F_UNKNOWN,
    F_ARCH,F_CHANGED_MAP,F_CHANGED_CONTEXT,F_RELEASE,F_COUNT,F_MAP_VERSION,F_MAP_OWNER,F_NULL_FREQ,F_SYNC,
    F_RELEASE_SYNC,F_LOCATE_SYNC,F_MAP_SYNC,F_HANDLE_SYNC,F_LATE_CLOCK,F_OLD_I2C,
    F_MMIO_TYPE,F_MMIO_ATTR,F_MMIO_ALIAS,F_MMIO_ABORT,F_MMIO_SECURE,F_MMIO_NO_DESC,F_MMIO_STRIDE};
static uint8_t *arena,*image,*handle,*client,*device,*driver,*bsp;
static struct efi_system *sys;
static struct efi_boot *boot;
static struct efi_loaded *loaded;
static efi_handle *handles;
static struct paic_result actual_i2c;
static struct pacq_result result __attribute__((aligned(4096)));
static struct pacq_work work __attribute__((aligned(4096)));
static unsigned fault,calls,maps,queries,releases,orders,arches,last_query_order;
static char ram_log[40000];static size_t ram_bytes;static unsigned ram_calls,ram_max;
static jmp_buf synchronous_fault;
static void put(uint8_t *p,uint64_t v,unsigned n){for(unsigned i=0;i<n;i++)p[i]=(uint8_t)(v>>(8*i));}
static void bs_boundary(unsigned operation)
{assert(result.outstanding==(UINT32_C(0x80000000)|operation)&&pacq_ticket.outstanding==result.outstanding&&result.bs_operation==operation&&result.bs_issued==result.bs_completed+1&&orders);}
static efi_status locate(const efi_guid *g,void *registration,void **out)
{(void)g;(void)registration;bs_boundary(result.protocol?5:1);if(fault==F_LOCATE_SYNC)longjmp(synchronous_fault,1);calls++;*out=image+0x28140;return fault==F_PROTOCOL?EFI_ERROR|14:0;}
static efi_status enumerate(uint32_t search,const efi_guid *g,void *key,uint64_t *count,efi_handle **out)
{(void)g;(void)key;bs_boundary(2);assert(search==2);calls++;*count=fault==F_COUNT?257:1;*out=handles;return 0;}
static efi_status loaded_protocol(efi_handle h,const efi_guid *g,void **out)
{(void)h;(void)g;bs_boundary(4);if(fault==F_HANDLE_SYNC)longjmp(synchronous_fault,1);calls++;*out=loaded;return 0;}
static efi_status free_pool(void *pointer)
{bs_boundary(6);assert(result.release_attempted&&result.release_status==UINT64_MAX&&pointer==handles);if(fault==F_RELEASE_SYNC)longjmp(synchronous_fault,1);calls++;releases++;return fault==F_RELEASE?EFI_ERROR|2:0;}
static efi_status get_map(uint64_t *bytes,void *out,uint64_t *key,uint64_t *stride,uint32_t *version)
{
    bs_boundary(3);if(fault==F_MAP_SYNC)longjmp(synchronous_fault,1);calls++;maps++;assert(*bytes>=5*48);
    struct {struct efi_memory descriptor;uint64_t extension;} entries[5]={
        {{fault==F_MAP_OWNER?7:3,0,(uintptr_t)arena,0,0x100000/4096,8},0},
        {{4,0,(uintptr_t)&result,0,(sizeof(result)+4095)/4096,8},0},
        {{4,0,(uintptr_t)&work,0,(sizeof(work)+4095)/4096,8},0},
        {{11,0,0x100000,0,0x100000/4096,1},0x77553311},
        {{11,0,0xad00000,0,0x10000/4096,1},0x88996644}};
    if(fault==F_MMIO_TYPE)entries[3].descriptor.type=4;
    if(fault==F_MMIO_ATTR)entries[3].descriptor.attributes=8;
    if(fault==F_MMIO_NO_DESC)entries[3].descriptor.physical=0x200000;
    memcpy(out,entries,sizeof(entries));*bytes=sizeof(entries);*stride=sizeof(entries[0]);
    if(fault==F_MMIO_STRIDE){for(unsigned n=0;n<5;n++)memcpy((uint8_t*)out+n*40,&entries[n].descriptor,40);*bytes=5*40;*stride=40;}
    *key=fault==F_CHANGED_MAP&&maps==3?11:10;*version=fault==F_MAP_VERSION?2:1;return 0;
}
static int arch(void *context,struct paic_arch *out)
{
    (void)context;arches++;*out=actual_i2c.after;out->ticks=actual_i2c.after.ticks+100+arches*32;
    if(fault==F_ARCH&&queries)out->ttbr0++;
    if(fault==F_LATE_CLOCK&&queries)out->ticks+=3840001;
    if(fault==F_OLD_I2C)out->ticks+=192000000;
    return 1;
}
static int identity(void *context,uint64_t at,uint64_t bytes,uint64_t *where,uint64_t *raw)
{(void)context;(void)bytes;*where=at&~UINT64_C(4095);*raw=*where;return 1;}
static void order(void *context){(void)context;paic_actual_order(0);orders++;}
static int mmio_translation(void *context,uint64_t page,uint64_t *par)
{(void)context;*par=page|0x200;
    if(fault==F_MMIO_ALIAS)*par+=4096;
    if(fault==F_MMIO_ABORT)*par|=1;
    if(fault==F_MMIO_SECURE)*par&=~UINT64_C(0x200);
    return 1;}
static int query(void *context,uint64_t function,uint64_t protocol,uint64_t id,uint64_t *status,uint8_t *value)
{
    (void)context;unsigned index=queries++;assert(index<PACQ_CALL_TARGETS*2&&protocol==(uintptr_t)image+0x28140);
    assert(function==(uintptr_t)image+((index&1)?0x1eb0:0x1e30)&&id==(uintptr_t)image+pacq_targets[index/2].descriptor);
    const struct pacq_query *q=&result.query[index];
    assert(result.outstanding==index+1&&pacq_ticket.outstanding==index+1&&q->issued==1&&q->delivery==0&&
        q->status==UINT64_MAX&&q->value==0xa5&&orders>last_query_order);last_query_order=orders;
    if(fault==F_SYNC)longjmp(synchronous_fault,1);
    *status=fault==F_STATUS?EFI_ERROR|2:0;*value=fault==F_VALUE?0xa5:(uint8_t)(index&1);
    if(fault==F_CHANGED_CONTEXT)driver[0]=1;
    return fault==F_UNKNOWN?0:1;
}
static void reset(unsigned which)
{
    fault=which;calls=maps=queries=releases=orders=arches=last_query_order=0;
    memset(&result,0,sizeof(result));memset(&work,0,sizeof(work));pacq_software_reset_ticket();
    sys->boot=boot;boot->locate_protocol=locate;boot->locate_buffer=enumerate;boot->handle_protocol=loaded_protocol;boot->get_map=get_map;boot->free_pool=free_pool;
    *loaded=(struct efi_loaded){.revision=0x1000,.system=sys,.base=image,.bytes=PACQI_IMAGE_BYTES,.code_type=3,.data_type=4};handles[0]=(void*)1;
    memset(handle,0,32);memset(client,0,24);memset(device,0,24);memset(driver,0,208);memset(bsp,0,48);
    put(image+0x3cf48,(uintptr_t)handle,8);put(handle+8,(uintptr_t)image+0x111b0,8);put(handle+0x10,(uintptr_t)client,8);
    put(client+0x10,(uintptr_t)device,8);put(device+0x10,(uintptr_t)driver,8);put(driver+0x90,(uintptr_t)bsp,8);
    put(bsp+0x20,(uintptr_t)image+0x28328,8);put(bsp+0x28,640,4);
    if(which==F_SIZE)loaded->bytes--;
    if(which==F_DAL)put(image+0x3cf48,0,8);
    if(which==F_VTABLE)put(handle+8,(uintptr_t)image+0x111b8,8);
    if(which==F_BSP)put(bsp+0x20,0,8);
}
static int run(void)
{const struct pacq_io io={{sys,0,arch,identity,order},query,mmio_translation};return pacq_collect(&io,&actual_i2c,2,&result,&work);}
static void schema(void)
{
    printf("\"wire_schema\":{\"version\":1,\"endian\":\"little\",\"bytes\":%zu,\"members\":{",sizeof(result));const char *comma="";
#define FIELD(m) printf("%s\"%s\":[%zu,%zu]",comma,#m,offsetof(struct pacq_result,m),sizeof(result.m));comma=",";
    FIELD(attempted) FIELD(error) FIELD(uncertain) FIELD(outstanding) FIELD(issued) FIELD(completed) FIELD(owner_matches) FIELD(handle_count)
    FIELD(bs_issued) FIELD(bs_completed) FIELD(bs_operation) FIELD(bs_index)
    FIELD(protocol_status) FIELD(protocol_after_status) FIELD(enumerate_status) FIELD(release_status) FIELD(protocol) FIELD(protocol_after) FIELD(image)
    FIELD(enumerated_count) FIELD(handle_array) FIELD(maps) FIELD(map_samples) FIELD(release_attempted) FIELD(handle_status) FIELD(loaded_address)
    FIELD(owner_address) FIELD(owner) FIELD(before) FIELD(after) FIELD(last_identity_address) FIELD(last_identity_par) FIELD(chain) FIELD(clock_array)
    FIELD(clock_count) FIELD(hash_failed) FIELD(hash_count) FIELD(target_count) FIELD(hashes) FIELD(context_raw) FIELD(descriptor_raw)
    FIELD(context_bytes) FIELD(descriptor_bytes) FIELD(query_count) FIELD(target_refused)
    FIELD(baseline_expected) FIELD(baseline_completed) FIELD(baseline_complete) FIELD(mmio) FIELD(query)
#undef FIELD
    printf("},\"query_bytes\":%zu,\"query_value_offset\":%zu}",sizeof(struct pacq_query),offsetof(struct pacq_query,value));
}
static void ram_append(const char *s)
{size_t n=strlen(s);assert(n<=126&&ram_bytes+n<sizeof(ram_log));memcpy(ram_log+ram_bytes,s,n);ram_bytes+=n;ram_log[ram_bytes]=0;ram_calls++;if(n>ram_max)ram_max=(unsigned)n;}
int main(int argc,char **argv)
{
    assert((argc==3||argc==4)&&sizeof(actual_i2c)==5096);FILE *f=fopen(argv[1],"rb");assert(f&&fread(&actual_i2c,1,5096,f)==5096&&!fclose(f));
    assert(pacq_i2c_admitted(&actual_i2c,2));assert(!posix_memalign((void**)&arena,4096,0x100000));memset(arena,0,0x100000);
    image=arena+0x1000;loaded=(void*)(arena+0x50000);sys=(void*)(arena+0x51000);boot=(void*)(arena+0x52000);handles=(void*)(arena+0x54000);
    actual_i2c.owner.system=sys; /* Host-only sys pointer relocation, never a new phone witness. */
    handle=arena+0x60000;client=arena+0x61000;device=arena+0x62000;driver=arena+0x63000;bsp=arena+0x64000;
    f=fopen(argv[2],"rb");assert(f&&fread(image,1,PACQI_IMAGE_BYTES,f)==PACQI_IMAGE_BYTES&&!fclose(f));
    for(unsigned n=0;n<PACQI_RELOC_COUNT;n++)put(image+pacqi_relocations[n],pacqi_le(image+pacqi_relocations[n],8)+(uintptr_t)image,8);
    unsigned checks=0;reset(F_NONE);assert(run()&&result.issued==PACQ_CALL_TARGETS*2&&result.completed==result.issued&&result.query_count==PACQ_TARGETS*2&&
        !result.outstanding&&result.hash_count==6&&result.release_attempted&&releases==1&&result.context_bytes[0]==336&&result.context_bytes[1]==336&&result.bs_issued==result.bs_completed&&result.baseline_complete);checks++;
    for(unsigned n=PACQ_CALL_TARGETS;n<PACQ_TARGETS;n++){assert(result.target_refused[n]==PACQ_TARGET_COLD_CAMCC_UNQUALIFIED&&result.mmio[n][0].admitted);
        for(unsigned m=0;m<2;m++)assert(!result.query[n*2+m].issued&&!result.query[n*2+m].delivery&&result.query[n*2+m].status==UINT64_MAX);}
    checks++;
    pacq_preboot_i2c=actual_i2c;pacq_preboot_record=result;pacq_report_preboot(ram_append);
    assert(strstr(ram_log,"AUDIO_I2C_CACHE_RAW_V1_BEGIN\r\n")&&strstr(ram_log,"AUDIO_CLOCK_QUERY_RAW_V1_BEGIN\r\n")&&ram_max==126);
    if(argc==4){f=fopen(argv[3],"wb");assert(f&&fwrite(ram_log,1,ram_bytes,f)==ram_bytes&&!fclose(f));}checks++;
    unsigned before=queries;struct pacq_result other={0};const struct pacq_io io={{sys,0,arch,identity,order},query,mmio_translation};
    assert(!pacq_collect(&io,&actual_i2c,2,&other,&work)&&!other.attempted&&queries==before);checks++;
    for(unsigned n=F_PROTOCOL;n<=F_MAP_OWNER;n++){
        reset(n);if(n==F_HASH)image[0x1100]^=1;if(n==F_DESCRIPTOR)image[pacq_targets[0].descriptor+0x30]^=1;
        assert(!run()&&result.error);
        if(n==F_HASH)image[0x1100]^=1;if(n==F_DESCRIPTOR)image[pacq_targets[0].descriptor+0x30]^=1;
        if(n<=F_BSP||n==F_COUNT||n==F_MAP_VERSION||n==F_MAP_OWNER)assert(!queries);
        if(n==F_UNKNOWN)assert(result.issued==1&&!result.completed&&result.uncertain&&result.outstanding==1&&pacq_ticket.outstanding==1&&!releases);
        if(n==F_VALUE)assert(result.query[0].value==0xa5&&result.query[0].delivery==1&&result.query[0].status==0);
        if(n==F_STATUS)assert(result.query[0].status==(EFI_ERROR|2)&&result.completed==1);
        if(n==F_ARCH)assert(queries==1&&result.uncertain&&!releases);
        if(n==F_VTABLE)assert(result.context_bytes[0]==32); /* Refuse before following another module's context. */
        if(n==F_COUNT)assert(result.enumerated_count==257);
        checks++;
    }
    reset(F_NULL_FREQ);uint64_t saved[PACQ_TARGETS];for(unsigned n=0;n<PACQ_TARGETS;n++){uint8_t *d=image+pacq_targets[n].descriptor;saved[n]=pacqi_le(d+8,8);put(d+8,0,8);}
    assert(run()&&queries==PACQ_CALL_TARGETS*2);for(unsigned n=0;n<PACQ_TARGETS;n++)put(image+pacq_targets[n].descriptor+8,saved[n],8);checks++;
    reset(F_NONE);actual_i2c.hashes[0][0]^=1;assert(!run()&&!calls&&!queries&&result.error==PACQ_I2C_CACHE);actual_i2c.hashes[0][0]^=1;checks++;
    reset(F_SYNC);if(!setjmp(synchronous_fault)){(void)run();assert(!"synchronous SOFTWARE query fault must not return");}
    assert(result.issued==1&&!result.completed&&result.outstanding==1&&pacq_ticket.outstanding==1&&result.query[0].delivery==0&&result.query[0].status==UINT64_MAX&&!releases);checks++;
    for(unsigned which=F_RELEASE_SYNC;which<=F_HANDLE_SYNC;which++){
        reset(which);if(!setjmp(synchronous_fault)){(void)run();assert(!"synchronous SOFTWARE BootServices fault must not return");}
        assert(result.outstanding&UINT32_C(0x80000000));assert(pacq_ticket.outstanding==result.outstanding&&result.bs_issued==result.bs_completed+1&&!releases);
        if(which==F_RELEASE_SYNC)assert(result.release_attempted&&result.release_status==UINT64_MAX&&result.completed==PACQ_CALL_TARGETS*2);
        if(which==F_LOCATE_SYNC)assert(result.protocol_status==UINT64_MAX&&!queries);
        if(which==F_MAP_SYNC)assert(result.map_samples==1&&result.maps[0].status==UINT64_MAX&&!queries);
        if(which==F_HANDLE_SYNC)assert(result.handle_status[0]==UINT64_MAX&&!queries);
        checks++;
    }
    reset(F_LATE_CLOCK);assert(!run()&&result.error==PACQ_ARCH&&result.uncertain&&queries==1&&!releases);checks++;
    reset(F_OLD_I2C);assert(run()&&queries==PACQ_CALL_TARGETS*2&&!result.uncertain);checks++;
    for(unsigned which=F_MMIO_TYPE;which<=F_MMIO_STRIDE;which++){
        reset(which);assert(run()&&!result.error&&!result.baseline_complete&&!result.baseline_completed&&!queries&&releases==1);
        for(unsigned n=0;n<PACQ_CALL_TARGETS;n++){assert(result.target_refused[n]==PACQ_TARGET_MMIO_UNQUALIFIED&&result.mmio[n][0].error);
            for(unsigned m=0;m<2;m++)assert(!result.query[n*2+m].issued&&!result.query[n*2+m].delivery&&result.query[n*2+m].status==UINT64_MAX);}
        checks++;
    }
    free(arena);printf("{\"checks\":%u,\"targets\":%u,\"queries_per_success\":%u,\"CAMCC_NOT_ISSUED\":%u,\"original_code_executed\":false,\"actual_MMIO\":0,\"RAM_only_log_bytes\":%zu,\"RAM_text_calls\":%u,\"RAM_max_chunk\":%u,",checks,PACQ_TARGETS,PACQ_CALL_TARGETS*2,PACQ_TARGETS-PACQ_CALL_TARGETS,ram_bytes,ram_calls,ram_max);schema();printf("}\n");return 0;
}
