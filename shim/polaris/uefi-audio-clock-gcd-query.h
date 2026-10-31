/* NEW GCD-qualified source: original ClockDxe IsEnabled/IsOn baseline.
 * The frozen0142 BootServices-map-only gate and actual refusal stay unchanged.
 * Four registered GCD MMIO pages + no BS RAM/reserved/unknown overlap, then
 * our own actual Device/NS identity AT immediately before EACH original API.
 * No GetFreq fallback, GetID traversal, Enable/Disable/Open/DAL attach, GPIO,
 * SE5/CCI MMIO, power/PLL/reset or lease is implemented or authorized here.
 * The original two query wrappers drop inner DAL status. Therefore every
 * pointer, descriptor, HAL table and non-null leaf route is validated before
 * invocation; raw outer status/boolean/partial delivery remain observations,
 * never a clock/pin/bus/power owner capability. */
#ifndef POLARIS_UEFI_AUDIO_CLOCK_GCD_QUERY_H
#define POLARIS_UEFI_AUDIO_CLOCK_GCD_QUERY_H
#include "uefi-audio-i2c-cache.h"
#include "uefi-gcd-mmio-readonly.h"
#include "../../tools/polaris-audio-clock-identity.h"
#ifndef EFI_XNU_AUDIO_CLOCK_GCD_QUERY_AVAILABLE
#define EFI_XNU_AUDIO_CLOCK_GCD_QUERY_AVAILABLE 0
#endif
#ifndef EFI_XNU_AUDIO_CLOCK_QUERY_CAMERA_READONLY
#define EFI_XNU_AUDIO_CLOCK_QUERY_CAMERA_READONLY 0
#endif
#ifndef EFI_XNU_AUDIO_CLOCK_QUERY_MSS_READONLY
#define EFI_XNU_AUDIO_CLOCK_QUERY_MSS_READONLY 0
#endif
#if EFI_XNU_AUDIO_CLOCK_GCD_QUERY_AVAILABLE && (!EFI_XNU_GCD_MMIO_QUERY_AVAILABLE || \
    !EFI_XNU_AUDIO_I2C_CACHE_AVAILABLE || !EFI_XNU_AUDIO_CLOCK_QUERY_CAMERA_READONLY || !EFI_XNU_AUDIO_CLOCK_QUERY_MSS_READONLY)
#error "NEW Clock GCD scope requires real registered GCD provider, original I2C witness and exact15 readonly descriptors"
#endif
#if EFI_XNU_AUDIO_CLOCK_QUERY_MSS_READONLY && !EFI_XNU_AUDIO_CLOCK_QUERY_CAMERA_READONLY
#error "MSS readonly Clock scope requires the explicit combined GCC baseline"
#endif
#define PACGQ_HANDLES 256u
#define PACGQ_CONTEXT_BYTES 336u
#if EFI_XNU_AUDIO_CLOCK_QUERY_CAMERA_READONLY
#if EFI_XNU_AUDIO_CLOCK_QUERY_MSS_READONLY
#define PACGQ_TARGETS 15u
#define PACGQ_CALL_TARGETS 8u
#else
#define PACGQ_TARGETS 12u
#define PACGQ_CALL_TARGETS 5u
#endif
#else
#define PACGQ_TARGETS 3u
#define PACGQ_CALL_TARGETS 3u
#endif
struct pacgq_target {uint32_t descriptor,name;uint64_t branch,vote;uint32_t mask;};
static const struct pacgq_target pacgq_targets[PACGQ_TARGETS]={
    {0x2d248,0x126e7,0x117620,0x15200c,0x8000}, /* own GENI SE5 */
    {0x2b148,0x125ee,0x117004,0x15200c,0x40}, /* wrapper0 mAHB */
    {0x2ba48,0x125d3,0x117008,0x15200c,0x80}, /* wrapper0 sAHB */
#if EFI_XNU_AUDIO_CLOCK_QUERY_CAMERA_READONLY
    /* GCC camera prerequisites ONLY; even both ON cannot admit CAMCC. */
    {0x2b628,0x149f5,0x10b008,0,0}, /* GCC camera AHB */
    {0x2eaa8,0x12d3b,0x10b02c,0,0}, /* GCC camera XO */
#if EFI_XNU_AUDIO_CLOCK_QUERY_MSS_READONLY
    /* Own source/name/descriptor correspondences, never DT numeric IDs or
     * MSS/PIL/carveout access. All three access only the GCC 0x18a000 page. */
    {0x2b7a8,0x14a3d,0x18a000,0,0}, /* MSS config AHB */
    {0x2b088,0x1496a,0x18a150,0,0}, /* MSS SNOC AXI */
    {0x2c708,0x14c2d,0x18a154,0,0}, /* MSS Q6 MEMNOC AXI */
#endif
    /* Separately admitted camera readonly Clock API baseline ONLY. These
     * source correspondences cannot grant CAMCC/GDSC/CCI/rails permission. */
    {0x283e8,0x144eb,0xad0b0f0,0,0}, /* CCI */
    {0x291c8,0x146f8,0xad0401c,0,0}, /* MCLK0 */
    {0x29288,0x1471a,0xad0405c,0,0}, /* MCLK2 */
    {0x292e8,0x1472b,0xad0407c,0,0}, /* MCLK3 */
    {0x2c288,0x12986,0xad0b124,0,0}, /* CAMNOC AXI */
    {0x29408,0x1474f,0xad0b11c,0,0}, /* CPAS AHB */
    {0x2b4a8,0x149b3,0xad0b13c,0,0}, /* SOC AHB */
#endif
};
enum pacgq_error {PACGQ_OK,PACGQ_DISABLED,PACGQ_I2C_CACHE,PACGQ_ARCH,PACGQ_BS,PACGQ_MAP,
    PACGQ_OWNER,PACGQ_HASH,PACGQ_CONTEXT,PACGQ_DESCRIPTOR,PACGQ_QUERY,PACGQ_UNKNOWN,
    PACGQ_CHANGED,PACGQ_RELEASE};
struct pacgq_query {
    uint64_t function,clock_id,status,before_ticks,after_ticks;
    uint32_t issued,delivery;uint8_t value,padding[7];
    uint64_t mmio_page,mmio_par,AT_before_ticks,AT_after_ticks;
    uint32_t AT_issued,AT_returned,AT_admitted,AT_error;
    struct pgcd_service_guard service_guard;
};
struct pacgq_mmio {
    uint64_t address,page,par;
    uint8_t descriptor[48];
    uint32_t descriptor_bytes,attempted,admitted,error,gcd_index;
};
enum pacgq_refusal {PACGQ_TARGET_ALLOWED,PACGQ_TARGET_MMIO_UNQUALIFIED,PACGQ_TARGET_COLD_CAMCC_UNQUALIFIED};
struct pacgq_result {
    uint64_t gcd_context_address;
    uint32_t gcd_cached[4],gcd_finish_attempted,gcd_finish_completed;
    struct pgcd_observation gcd[4];
    uint32_t map_raw_bytes[3],map_extent_unknown[3];
    uint8_t map_raw[3][4096];
    uint32_t prestart_checked,prestart_passed;
    uint32_t attempted,error,uncertain,outstanding,issued,completed,owner_matches,handle_count;
    uint32_t bs_issued,bs_completed,bs_operation,bs_index;
    uint64_t protocol_status,protocol_after_status,enumerate_status,release_status,protocol,protocol_after,image;
    uint64_t enumerated_count,handle_array;
    struct paic_map_sample maps[3];uint32_t map_samples,release_attempted;
    uint64_t handle_status[PACGQ_HANDLES],loaded_address[PACGQ_HANDLES],owner_address;
    struct efi_loaded owner;
    struct paic_arch before,after;
    uint64_t last_identity_address,last_identity_par,chain[6],clock_array;uint32_t clock_count,hash_failed,hash_count,target_count;
    uint8_t hashes[PACQI_RANGE_COUNT][32],context_raw[2][PACGQ_CONTEXT_BYTES],descriptor_raw[2][PACGQ_TARGETS][96];
    uint32_t context_bytes[2],descriptor_bytes[2][PACGQ_TARGETS],query_count;
    uint32_t target_refused[PACGQ_TARGETS],baseline_expected,baseline_completed,baseline_complete;
    struct pacgq_mmio mmio[PACGQ_TARGETS][2];
    struct pacgq_query query[PACGQ_TARGETS*2];
};
struct pacgq_work {uint8_t map[4096] __attribute__((aligned(8)));struct efi_loaded *loaded[PACGQ_HANDLES];efi_handle *handles;uint64_t bytes,stride,key;};
struct pacgq_io {
    struct paic_io memory;
    /* Return1 only after the API call returned (even an EFI error). Return0
     * means UNKNOWN, never NOT_ISSUED. A synchronous non-return leaves the
     * already-published query/outstanding at UNKNOWN. Actual adapter below
     * calls only the two validated original EFI methods. */
    int (*query)(void *,uint64_t,uint64_t,uint64_t,uint64_t *,uint8_t *);
    /* Architectural translation only; no register is dereferenced. Return1
     * after AT/PAR completed and preserve its raw fault/success PAR either way. */
    int (*translate_mmio)(void *,uint64_t,uint64_t *);
};
static struct {uint32_t used,outstanding;uintptr_t result;} pacgq_ticket;
#if defined(PACGQ_SOFTWARE_PEER_ONLY)
static inline void pacgq_software_reset_ticket(void)
{pacgq_ticket.used=pacgq_ticket.outstanding=0;pacgq_ticket.result=0;}
#endif
static inline void pacgq_fail(struct pacgq_result *r,unsigned error,int uncertain)
{if(!r->error)r->error=error;if(uncertain)r->uncertain=1;paic_actual_order(0);}
/* Every actual BootServices call publishes an UNKNOWN operation before entry.
 * The wrappers have no NOT_ISSUED fallback. A synchronous non-return retains
 * its operation/ticket/allocation, including FreePool itself. */
static inline void pacgq_bs_begin(const struct pacgq_io *io,struct pacgq_result *r,unsigned operation,unsigned index)
{r->bs_operation=operation;r->bs_index=index;r->bs_issued++;r->outstanding=UINT32_C(0x80000000)|operation;pacgq_ticket.outstanding=r->outstanding;io->memory.order(io->memory.context);}
static inline void pacgq_bs_complete(const struct pacgq_io *io,struct pacgq_result *r)
{r->bs_completed++;io->memory.order(io->memory.context);r->outstanding=0;pacgq_ticket.outstanding=0;io->memory.order(io->memory.context);}
static inline int pacgq_owned(const struct pacgq_io *io,struct pacgq_result *r,struct pacgq_work *w,uint64_t address,uint64_t bytes)
{
    if(!address||!bytes||address>UINT64_MAX-bytes||address+bytes>UINT64_MAX-4095)return 0;
    for(uint64_t p=address&~UINT64_C(4095);p<address+bytes;p+=4096)
        if(!polaris_efi_range_owned(w->map,w->bytes,w->stride,p,4096,3)&&
           !polaris_efi_range_owned(w->map,w->bytes,w->stride,p,4096,4))return 0;
    return io->memory.identity(io->memory.context,address,bytes,&r->last_identity_address,&r->last_identity_par);
}
static inline int pacgq_map(const struct pacgq_io *io,struct efi_boot *bs,struct pacgq_result *r,struct pacgq_work *w)
{
    if(r->map_samples==3)return 0;
    uint64_t bytes=sizeof(w->map),key=0,stride=0;uint32_t version=0;
    unsigned slot=r->map_samples++;r->maps[slot].status=UINT64_MAX;
    pacgq_bs_begin(io,r,3,slot);
    uint64_t status=bs->get_map(&bytes,w->map,&key,&stride,&version);
    r->maps[slot]=(struct paic_map_sample){status,key,bytes,stride,version};pacgq_bs_complete(io,r);
    /* Copy the WHOLE actual output capacity before interpreting status or
     * geometry. A failed/partial GetMap has unknown written extent: its
     * original prefix, stale tail, required bytes and raw status all survive. */
    for(unsigned n=0;n<sizeof(w->map);n++)r->map_raw[slot][n]=w->map[n];
    r->map_raw_bytes[slot]=sizeof(w->map);r->map_extent_unknown[slot]=1;
    struct polaris_efi_memory checked;
    if(!status&&bytes>sizeof(w->map)){pacgq_fail(r,PACGQ_MAP,1);return 0;} /* Claimed success beyond supplied capacity. */
    if(status||version!=1||!polaris_efi_memory_check(w->map,bytes,sizeof(w->map),stride,&checked))return 0;
    r->map_extent_unknown[slot]=0;
    w->bytes=bytes;w->stride=stride;w->key=key;return 1;
}
static inline int pacgq_copy_owned(const struct pacgq_io *io,struct pacgq_result *r,struct pacgq_work *w,uint8_t *dest,uint64_t source,unsigned bytes)
{
    if(!pacgq_owned(io,r,w,source,bytes))return 0;
    for(unsigned n=0;n<bytes;n++)dest[n]=((const volatile uint8_t*)(uintptr_t)source)[n];
    return 1;
}
static inline int pacgq_mmio_admit(const struct pacgq_io *io,struct pacgq_result *r,struct pacgq_work *w,
    struct pgcd_context *gcd_context,uint64_t address,struct pacgq_mmio *m)
{
    static const uint64_t pages[4]={0x10b000,0x117000,0x152000,0x18a000};
    m->address=address;m->page=address&~UINT64_C(4095);m->par=UINT64_MAX;m->attempted=1;
    unsigned index=4;for(unsigned n=0;n<4;n++)if(m->page==pages[n])index=n;
    if(index==4){m->error=6;return 0;}m->gcd_index=index;
    /* BS map remains an exclusion map. No missing descriptor is fabricated
     * into an MMIO descriptor; actual GCD registration provides namespace. */
    if(w->stride!=48){m->error=1;return 0;}
    for(uint64_t at=0;at<w->bytes;at+=w->stride){const struct efi_memory *d=(const void*)(w->map+at);
        if(d->physical<=m->page&&m->page-d->physical<d->pages*4096){
            for(unsigned n=0;n<48;n++)m->descriptor[n]=w->map[at+n];m->descriptor_bytes=48;
            if(d->type!=11||(d->attributes!=0&&d->attributes!=1)||d->virtual_address){m->error=2;return 0;}break;}
    }
    if(!r->gcd_cached[index]){
        r->gcd_cached[index]=1;r->gcd[index].page=m->page;r->gcd[index].status=UINT64_MAX;
        r->outstanding=UINT32_C(0x20000000)|(index+1);pacgq_ticket.outstanding=r->outstanding;
        io->memory.order(io->memory.context);
        const struct pgcd_observation *raw=0;(void)pgcd_query_page(gcd_context,m->page,&raw);
        /* The helper returned; retain its exact resident raw observation only
         * after our own RAM ownership/identity check, never follow blindly. */
        if(raw&&pacgq_owned(io,r,w,(uintptr_t)raw,sizeof(*raw)))
            for(unsigned n=0;n<sizeof(*raw);n++)((uint8_t*)&r->gcd[index])[n]=((const volatile uint8_t*)raw)[n];
        else if(raw||pgcd_uncertain(gcd_context)){m->error=7;pacgq_fail(r,PACGQ_OWNER,1);return 0;}
        else { /* Known helper refusal, no original getter issued. */
            m->error=7;io->memory.order(io->memory.context);r->outstanding=0;pacgq_ticket.outstanding=0;io->memory.order(io->memory.context);return 0;}
        if(r->gcd[index].unknown||(r->gcd[index].issued&&!r->gcd[index].returned)){
            m->error=8;pacgq_fail(r,PACGQ_UNKNOWN,1);return 0;}
        io->memory.order(io->memory.context);r->outstanding=0;pacgq_ticket.outstanding=0;io->memory.order(io->memory.context);
    }
    const struct pgcd_observation *g=&r->gcd[index];const struct pgcd_descriptor *d=&g->descriptor;
    if(g->page!=m->page||g->issued!=1||g->returned!=1||g->unknown||g->status||!g->before_ticks||g->after_ticks<g->before_ticks||
       d->type!=3||!(d->capabilities&1)||(d->attributes!=0&&d->attributes!=1)||d->base>m->page||
       !d->length||d->base>UINT64_MAX-d->length||d->base+d->length<m->page+4096){m->error=9;return 0;}
    /* Attributes0 is retained as UNSET. It is not relabeled UC. The actual
     * CPU Device type is checked separately immediately before every API. */
    m->admitted=1;return 1;
}
static inline int pacgq_query_at(const struct pacgq_io *io,struct pacgq_result *r,struct pacgq_query *q,
    const struct pacgq_mmio *m,const struct paic_arch *before)
{
    const struct pgcd_observation *g=&r->gcd[m->gcd_index];
    if(before->ticks<g->after_ticks||before->ticks-g->after_ticks>3840000){q->AT_error=1;return 0;}
    q->mmio_page=m->page;q->mmio_par=UINT64_MAX;q->AT_before_ticks=before->ticks;q->AT_issued=1;
    r->outstanding=UINT32_C(0x40000000)|((uint32_t)(q-r->query)+1);pacgq_ticket.outstanding=r->outstanding;
    io->memory.order(io->memory.context);
    int translated=io->translate_mmio(io->memory.context,m->page,&q->mmio_par);q->AT_returned=translated?1u:0u;
    io->memory.order(io->memory.context);
    if(!translated){q->AT_error=2;pacgq_fail(r,PACGQ_UNKNOWN,1);return 0;}
    r->outstanding=0;pacgq_ticket.outstanding=0;io->memory.order(io->memory.context);
    struct paic_arch now;
    if(!io->memory.arch(io->memory.context,&now)){q->AT_error=3;pacgq_fail(r,PACGQ_ARCH,1);return 0;}
    q->AT_after_ticks=now.ticks;
    if(!paic_arch_stable(before,&now)||!paic_arch_stable(&r->before,&now)||now.ticks-r->before.ticks>3840000||
       now.ticks<g->after_ticks||now.ticks-g->after_ticks>3840000){q->AT_error=4;pacgq_fail(r,PACGQ_ARCH,1);return 0;}
    uint64_t attributes=q->mmio_par>>56;
    if((q->mmio_par&1)||!(q->mmio_par&0x200)||(attributes!=0&&attributes!=4)||
       (q->mmio_par&UINT64_C(0x0000fffffffff000))!=m->page){q->AT_error=5;return 0;}
    q->AT_admitted=1;return 1;
}
static inline int pacgq_i2c_admitted(const struct paic_result *c,uint32_t stage)
{
    if(!c||stage!=2||c->error||c->attempted!=1||c->owner_matches!=1||c->hash_count!=4||c->hash_failed||
       !c->cache_consistent||c->snapshot_bytes[0]!=120||c->snapshot_bytes[1]!=120||
       !c->release_attempted||c->release_status||!c->map_keys_before_release_only||c->map_samples!=3||
       c->map_key[0]!=c->map_key[1]||!paic_arch_stable(&c->before,&c->after)||
       !paic_equal(c->snapshot[0],c->snapshot[1],120))return 0;
    for(unsigned n=0;n<4;n++)if(!paic_equal(c->hashes[n],paii_ranges[n].sha256,32))return 0;
    return c->cookie&&c->image&&c->image<=UINT64_MAX-32768&&!(c->image&4095)&&c->protocol==c->image+0x6098&&c->protocol_after==c->protocol&&
        (uintptr_t)c->owner.base==c->image&&c->owner.revision==0x1000&&c->owner.bytes==32768&&c->owner.code_type==3&&c->owner.data_type==4&&
        !c->protocol_status&&!c->protocol_after_status&&!c->enumerate_status&&!c->map_status&&c->map_version[0]==1&&c->map_version[1]==1;
}
static inline int pacgq_fresh(const struct paic_arch *before,const struct paic_arch *now)
{return paic_arch_stable(before,now)&&now->ticks-before->ticks<=UINT64_C(3840000);}
static inline int pacgq_environment(const struct paic_arch *cached,const struct paic_arch *now)
{/* Clock establishes its own fresh interval; console age of the independently
   * completed I2C RAM witness cannot turn it into a clock-access capability. */
    struct paic_arch same=*cached;same.ticks=now->ticks;return paic_arch_stable(&same,now);
}
static inline int pacgq_context(const struct pacgq_io *io,struct pacgq_result *r,struct pacgq_work *w,unsigned pass)
{
    static const unsigned starts[5]={0,32,56,80,288},sizes[5]={32,24,24,208,48};
    if(pass==0){
        r->chain[0]=pacqi_le((const uint8_t*)(uintptr_t)r->image+0x3cf48,8);
        for(unsigned n=0;n<5;n++){
            uint64_t at=r->chain[n];
            if(!pacgq_copy_owned(io,r,w,r->context_raw[0]+starts[n],at,sizes[n]))return 0;
            r->context_bytes[0]=starts[n]+sizes[n];
            if(n==0&&pacqi_le(r->context_raw[0]+8,8)!=r->image+0x111b0)return 0;
            if(n<3)r->chain[n+1]=pacqi_le(r->context_raw[0]+starts[n]+0x10,8);
            else if(n==3)r->chain[4]=pacqi_le(r->context_raw[0]+starts[n]+0x90,8);
        }
        if(pacqi_le(r->context_raw[0]+8,8)!=r->image+0x111b0)return 0;
        r->chain[5]=r->chain[3]+0x90; /* Internal context, never a new caller-controlled ClockID. */
        r->clock_array=pacqi_le(r->context_raw[0]+288+0x20,8);
        r->clock_count=(uint32_t)pacqi_le(r->context_raw[0]+288+0x28,4);
        uint64_t bytes=(uint64_t)r->clock_count*96;
        if(!r->clock_count||r->clock_count>2048||r->clock_array<r->image+0x28000||
           r->clock_array>r->image+0x3f000||bytes>r->image+0x3f000-r->clock_array)return 0;
    }else{
        if(pacqi_le((const uint8_t*)(uintptr_t)r->image+0x3cf48,8)!=r->chain[0])return 0;
        for(unsigned n=0;n<5;n++){
            if(!pacgq_copy_owned(io,r,w,r->context_raw[1]+starts[n],r->chain[n],sizes[n]))return 0;
            r->context_bytes[1]=starts[n]+sizes[n];
        }
        if(!paic_equal(r->context_raw[0],r->context_raw[1],PACGQ_CONTEXT_BYTES))return 0;
    }
    for(unsigned n=0;n<PACGQ_TARGETS;n++){
        const struct pacgq_target *t=&pacgq_targets[n];uint64_t id=r->image+t->descriptor;
        if(id<r->clock_array||id-r->clock_array>=(uint64_t)r->clock_count*96||(id-r->clock_array)%96)return 0;
        if(!pacgq_copy_owned(io,r,w,r->descriptor_raw[pass][n],id,96))return 0;r->descriptor_bytes[pass][n]=96;
        const uint8_t *d=r->descriptor_raw[pass][n];
        if(pacqi_le(d,8)!=r->image+t->name||pacqi_le(d+0x18,8)!=t->branch||pacqi_le(d+0x28,8)!=t->vote||
           pacqi_le(d+0x30,4)!=t->mask||pacqi_le(d+0x38,8)!=r->image+0x3ce50){pacgq_fail(r,PACGQ_DESCRIPTOR,0);return 0;}
        if(pass&&!paic_equal(r->descriptor_raw[0][n],d,96))return 0;
    }
    return 1;
}
static inline int pacgq_collect(const struct pacgq_io *io,const struct paic_result *i2c,uint32_t stage,struct pacgq_result *r,struct pacgq_work *w,struct pgcd_context *gcd_context)
{
    if(!r||!w||r->attempted||pacgq_ticket.used)return 0;
    r->attempted=pacgq_ticket.used=1;pacgq_ticket.result=(uintptr_t)r;
#if !EFI_XNU_AUDIO_CLOCK_GCD_QUERY_AVAILABLE || defined(POLARIS_EFI_TEST_QEMU)
    (void)io;(void)i2c;(void)stage;(void)gcd_context;r->error=PACGQ_DISABLED;return 0;
#else
    static const efi_guid protocol={0x241afae6,0x885f,0x4f6c,{0xa7,0xea,0xc2,0x8e,0xab,0x79,0xc3,0xe5}};
    static const efi_guid loaded={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
    if(!gcd_context){pacgq_fail(r,PACGQ_BS,0);return 0;}
    r->gcd_context_address=(uintptr_t)gcd_context;
    if(!pacgq_i2c_admitted(i2c,stage)){pacgq_fail(r,PACGQ_I2C_CACHE,0);return 0;}
    if(!io||!io->memory.system||!io->memory.system->boot||!io->memory.arch||!io->memory.identity||!io->memory.order||!io->query||!io->translate_mmio||
       !io->memory.arch(io->memory.context,&r->before)||!paic_arch_admitted(&r->before)||
       !pacgq_environment(&i2c->after,&r->before)){pacgq_fail(r,PACGQ_ARCH,0);return 0;}
    if(i2c->owner.system!=io->memory.system){pacgq_fail(r,PACGQ_I2C_CACHE,0);return 0;}
    struct efi_boot *bs=io->memory.system->boot;void *table=0;uint64_t count=0;int handles_owned=0;
    if(!bs->locate_protocol||!bs->locate_buffer||!bs->handle_protocol||!bs->get_map||!bs->free_pool){pacgq_fail(r,PACGQ_BS,0);return 0;}
    r->protocol_status=UINT64_MAX;pacgq_bs_begin(io,r,1,0);
    r->protocol_status=bs->locate_protocol(&protocol,0,&table);r->protocol=(uintptr_t)table;pacgq_bs_complete(io,r);
    if(r->protocol_status||!table){pacgq_fail(r,PACGQ_BS,0);return 0;}
    r->enumerate_status=UINT64_MAX;pacgq_bs_begin(io,r,2,0);
    r->enumerate_status=bs->locate_buffer(2,&loaded,0,&count,&w->handles);
    r->enumerated_count=count;r->handle_array=(uintptr_t)w->handles;pacgq_bs_complete(io,r);
    if(r->enumerate_status||!w->handles||!count||count>PACGQ_HANDLES){pacgq_fail(r,PACGQ_OWNER,0);return 0;}
    r->handle_count=(uint32_t)count;
    if(!pacgq_map(io,bs,r,w)){pacgq_fail(r,PACGQ_MAP,0);goto finish;}
    if(!pacgq_owned(io,r,w,(uintptr_t)r,sizeof(*r))||!pacgq_owned(io,r,w,(uintptr_t)w,sizeof(*w))||
       !pacgq_owned(io,r,w,(uintptr_t)w->handles,count*sizeof(efi_handle))){pacgq_fail(r,PACGQ_OWNER,0);goto finish;}handles_owned=1;
    for(unsigned n=0;n<count;n++){
        r->handle_status[n]=UINT64_MAX;pacgq_bs_begin(io,r,4,n);
        r->handle_status[n]=bs->handle_protocol(w->handles[n],&loaded,(void**)&w->loaded[n]);r->loaded_address[n]=(uintptr_t)w->loaded[n];pacgq_bs_complete(io,r);
        if(r->handle_status[n]||!w->loaded[n]){pacgq_fail(r,PACGQ_OWNER,0);goto finish;}
    }
    handles_owned=0;
    if(!pacgq_map(io,bs,r,w)){pacgq_fail(r,PACGQ_MAP,0);goto finish;}
    if(!pacgq_owned(io,r,w,(uintptr_t)w->handles,count*sizeof(efi_handle))){pacgq_fail(r,PACGQ_OWNER,0);goto finish;}handles_owned=1;
    for(unsigned n=0;n<count;n++){
        if(!pacgq_owned(io,r,w,r->loaded_address[n],sizeof(struct efi_loaded))){pacgq_fail(r,PACGQ_OWNER,0);goto finish;}
        const struct efi_loaded *image=w->loaded[n];uint64_t base=(uintptr_t)image->base;
        if(base>UINT64_MAX-0x28140||base+0x28140!=r->protocol)continue;r->owner_matches++;r->owner=*image;r->image=base;r->owner_address=r->loaded_address[n];
        if(image->revision!=0x1000||image->system!=io->memory.system||image->bytes!=PACQI_IMAGE_BYTES||image->code_type!=3||image->data_type!=4||(base&4095)){
            pacgq_fail(r,PACGQ_OWNER,0);goto finish;
        }
    }
    if(r->owner_matches!=1||!pacgq_owned(io,r,w,r->image,PACQI_IMAGE_BYTES)){pacgq_fail(r,PACGQ_OWNER,0);goto finish;}
    if(!pacqi_verify((const uint8_t*)(uintptr_t)r->image,r->image,PACQI_IMAGE_BYTES,r->hashes,&r->hash_failed,&r->hash_count)){
        pacgq_fail(r,PACGQ_HASH,0);goto finish;
    }
    if(!pacgq_context(io,r,w,0)){pacgq_fail(r,PACGQ_CONTEXT,0);goto finish;}
    r->target_count=PACGQ_TARGETS;r->baseline_expected=PACGQ_CALL_TARGETS;r->query_count=PACGQ_TARGETS*2;
    for(unsigned n=0;n<PACGQ_TARGETS;n++){
        for(unsigned mode=0;mode<2;mode++){struct pacgq_query *q=&r->query[n*2+mode];
            q->function=r->image+(mode?0x1eb0:0x1e30);q->clock_id=r->image+pacgq_targets[n].descriptor;q->status=UINT64_MAX;q->value=0xa5;}
        if(n>=PACGQ_CALL_TARGETS){r->target_refused[n]=PACGQ_TARGET_COLD_CAMCC_UNQUALIFIED;continue;}
        int branch=pacgq_mmio_admit(io,r,w,gcd_context,pacgq_targets[n].branch,&r->mmio[n][0]);
        if(r->error)goto finish;
        int vote=!pacgq_targets[n].vote||pacgq_mmio_admit(io,r,w,gcd_context,pacgq_targets[n].vote,&r->mmio[n][1]);
        if(r->error)goto finish;
        if(!branch||!vote)r->target_refused[n]=PACGQ_TARGET_MMIO_UNQUALIFIED;
    }
    for(unsigned n=0;n<PACGQ_CALL_TARGETS;n++){
      if(r->target_refused[n])continue;
      for(unsigned mode=0;mode<2;mode++){
        struct paic_arch now;
        if(!io->memory.arch(io->memory.context,&now)||!pacgq_fresh(&r->before,&now)){pacgq_fail(r,PACGQ_ARCH,1);goto finish;}
        struct pacgq_query *q=&r->query[n*2+mode];
        const struct pacgq_mmio *permission=&r->mmio[n][!mode&&pacgq_targets[n].vote?1:0];
        if(!pacgq_query_at(io,r,q,permission,&now)){
            if(r->error)goto finish;r->target_refused[n]=PACGQ_TARGET_MMIO_UNQUALIFIED;break;}
        if(!pgcd_service_enter(gcd_context,&q->service_guard)){
            if(pgcd_uncertain(gcd_context))pacgq_fail(r,PACGQ_UNKNOWN,1);
            else r->target_refused[n]=PACGQ_TARGET_MMIO_UNQUALIFIED;
            if(r->error)goto finish;break;}
        q->before_ticks=q->AT_after_ticks;q->delivery=0;q->issued=1;r->issued++;r->outstanding=n*2+mode+1;pacgq_ticket.outstanding=r->outstanding;
        io->memory.order(io->memory.context); /* Published UNKNOWN before original code can fault. */
        int returned=io->query(io->memory.context,q->function,r->protocol,q->clock_id,&q->status,&q->value);
        q->delivery=returned?1u:0u;
        if(returned)r->completed++;
        int service_safe=pgcd_service_leave(gcd_context,&q->service_guard,returned?1:0);
        if(!service_safe)pacgq_fail(r,PACGQ_UNKNOWN,1);
        if(!returned)pacgq_fail(r,PACGQ_UNKNOWN,1);else if(q->status||q->value>1)pacgq_fail(r,PACGQ_QUERY,0);
        if(io->memory.arch(io->memory.context,&now)){q->after_ticks=now.ticks;if(!pacgq_fresh(&r->before,&now))pacgq_fail(r,PACGQ_ARCH,1);}else pacgq_fail(r,PACGQ_ARCH,1);
        io->memory.order(io->memory.context);
        if(returned&&service_safe){r->outstanding=0;pacgq_ticket.outstanding=0;io->memory.order(io->memory.context);}
        if(r->error)goto finish;
      }
      if(r->query[n*2].delivery==1&&r->query[n*2+1].delivery==1)r->baseline_completed++;
    }
    r->baseline_complete=r->baseline_completed==r->baseline_expected;
    table=0;r->protocol_after_status=UINT64_MAX;pacgq_bs_begin(io,r,5,0);
    r->protocol_after_status=bs->locate_protocol(&protocol,0,&table);r->protocol_after=(uintptr_t)table;pacgq_bs_complete(io,r);
    if(r->protocol_after_status||r->protocol_after!=r->protocol){pacgq_fail(r,PACGQ_CHANGED,0);goto finish;}
    handles_owned=0;
    if(!pacgq_map(io,bs,r,w)){pacgq_fail(r,PACGQ_MAP,0);goto finish;}
    if(!pacgq_owned(io,r,w,(uintptr_t)w->handles,count*sizeof(efi_handle))){pacgq_fail(r,PACGQ_OWNER,0);goto finish;}handles_owned=1;
    if(r->maps[1].key!=w->key||!pacgq_owned(io,r,w,r->image,PACQI_IMAGE_BYTES)||
       !pacgq_owned(io,r,w,r->owner_address,sizeof(r->owner))||
       !paic_equal((const uint8_t*)&r->owner,(const uint8_t*)(uintptr_t)r->owner_address,sizeof(r->owner))||!pacgq_context(io,r,w,1))pacgq_fail(r,PACGQ_CHANGED,0);
finish:
    /* Unknown original call retains outstanding and its entire raw prefix.
     * Do not release its supporting allocation while completion is unknown. */
    if(!io->memory.arch(io->memory.context,&r->after)||!pacgq_fresh(&r->before,&r->after))pacgq_fail(r,PACGQ_ARCH,1);
    if(!r->uncertain&&!r->outstanding&&(r->gcd_cached[0]||r->gcd_cached[1]||r->gcd_cached[2]||r->gcd_cached[3])){
        r->gcd_finish_attempted=1;r->outstanding=UINT32_C(0x20000010);pacgq_ticket.outstanding=r->outstanding;
        io->memory.order(io->memory.context);
        int done=pgcd_finish(gcd_context);r->gcd_finish_completed=done?1u:0u;io->memory.order(io->memory.context);
        if(!pgcd_uncertain(gcd_context)){r->outstanding=0;pacgq_ticket.outstanding=0;io->memory.order(io->memory.context);
            if(!done)pacgq_fail(r,PACGQ_CHANGED,0);}
        else pacgq_fail(r,PACGQ_CHANGED,1);
    }
    if(handles_owned&&!r->uncertain&&!r->outstanding&&r->map_samples<3){
        handles_owned=0;
        if(pacgq_map(io,bs,r,w)&&pacgq_owned(io,r,w,(uintptr_t)w->handles,count*sizeof(efi_handle)))handles_owned=1;
        else pacgq_fail(r,PACGQ_MAP,0);
    }
    if(handles_owned&&!r->uncertain&&!r->outstanding){r->release_attempted=1;r->release_status=UINT64_MAX;pacgq_bs_begin(io,r,6,0);
        r->release_status=bs->free_pool(w->handles);pacgq_bs_complete(io,r);if(r->release_status)pacgq_fail(r,PACGQ_RELEASE,0);}
    if(!r->uncertain&&!r->outstanding&&!pgcd_prestart_check(gcd_context))pacgq_fail(r,PACGQ_UNKNOWN,1);
    if(!io->memory.arch(io->memory.context,&r->after)||!pacgq_fresh(&r->before,&r->after))pacgq_fail(r,PACGQ_ARCH,1);
    io->memory.order(io->memory.context);return r->error==PACGQ_OK;
#endif
}
static inline int pacgq_actual_query(void *context,uint64_t function,uint64_t protocol,uint64_t id,uint64_t *status,uint8_t *value)
{
    (void)context;
    typedef efi_status (*getter)(void *,uint64_t,uint8_t *);
    *status=((getter)(uintptr_t)function)((void*)(uintptr_t)protocol,id,value);
    return 1;
}
static inline int pacgq_actual_mmio_translation(void *context,uint64_t page,uint64_t *raw)
{
    (void)context;
#if defined(__aarch64__) || defined(__arm64__)
    uint64_t saved;
    __asm__ volatile("mrs %0,par_el1\n\tat s1e1r,%2\n\tisb\n\tmrs %1,par_el1\n\tmsr par_el1,%0"
        :"=&r"(saved),"=&r"(*raw):"r"(page):"memory");return 1;
#else
    (void)page;(void)raw;return 0;
#endif
}
/* NEW combined coordinator. No change to the frozen I2C-only prepare entry.
 * All actual methods run before any console reporting and before CPU0's
 * DAIF/Group1 ownership changes. The caller supplies NEW-scope RAM-only text
 * for the full raw records; this callback must never be firmware Console. */
#if EFI_XNU_AUDIO_CLOCK_GCD_QUERY_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
static struct paic_result pacgq_preboot_i2c;
static struct paic_workspace pacgq_preboot_i2c_work;
static struct pacgq_result pacgq_preboot_record;
static struct pacgq_work pacgq_preboot_work;
#endif
static inline void pacgq_collect_preboot(struct efi_system *system,uint32_t stage,void *gcd_context)
{
#if !EFI_XNU_AUDIO_CLOCK_GCD_QUERY_AVAILABLE || defined(POLARIS_EFI_TEST_QEMU)
    (void)system;(void)stage;(void)gcd_context;
#else
    if(pacgq_preboot_i2c.attempted||pacgq_preboot_record.attempted||pacgq_ticket.used)return;
    const struct paic_io io={system,0,paic_actual_arch,paic_actual_identity,paic_actual_order};
    (void)paic_collect(&io,stage,&pacgq_preboot_i2c,&pacgq_preboot_i2c_work);
    const struct pacgq_io clock={io,pacgq_actual_query,pacgq_actual_mmio_translation};
    (void)pacgq_collect(&clock,&pacgq_preboot_i2c,stage,&pacgq_preboot_record,&pacgq_preboot_work,(struct pgcd_context*)gcd_context);
#endif
}
static inline void pacgq_ram_hex(void (*append)(const char *),const uint8_t *raw,size_t bytes)
{
    char chunk[127];
    for(size_t at=0;at<bytes;){unsigned n=(unsigned)(bytes-at);if(n>63)n=63;
        for(unsigned j=0;j<n;j++){chunk[2*j]="0123456789abcdef"[raw[at+j]>>4];chunk[2*j+1]="0123456789abcdef"[raw[at+j]&15];}
        chunk[n*2]=0;append(chunk);at+=n;}
}
static inline void pacgq_ram_number(void (*append)(const char *),const char *key,uint64_t value)
{
    char reverse[20],number[23];unsigned count=0;
    do{reverse[count++]=(char)('0'+value%10);value/=10;}while(value);
    for(unsigned n=0;n<count;n++)number[n]=reverse[count-1-n];number[count]='\r';number[count+1]='\n';number[count+2]=0;
    append(key);append(number);
}
static inline void pacgq_report_preboot(void (*ram_append)(const char *))
{
    if(!ram_append)return;
#if !EFI_XNU_AUDIO_CLOCK_GCD_QUERY_AVAILABLE || defined(POLARIS_EFI_TEST_QEMU)
    ram_append("AUDIO_CLOCK_QUERY_PHYSICAL_BODY_COMPILED_OUT=1\r\n");
#else
    pacgq_ram_number(ram_append,"AUDIO_I2C_CACHE_ERROR=",pacgq_preboot_i2c.error);
    pacgq_ram_number(ram_append,"AUDIO_I2C_CACHE_RAW_V1_BYTES=",sizeof(pacgq_preboot_i2c));
    ram_append("AUDIO_I2C_CACHE_RAW_V1_BEGIN\r\n");pacgq_ram_hex(ram_append,(const uint8_t*)&pacgq_preboot_i2c,sizeof(pacgq_preboot_i2c));
    ram_append("\r\nAUDIO_I2C_CACHE_RAW_V1_END\r\n");
    ram_append("AUDIO_I2C_CACHE_SOURCE_SHA256=" PAII_SOURCE_SHA256 "\r\n");
    ram_append("AUDIO_I2C_CACHE_SCOPE=RAM_ONLY I2C_DAL=0 MMIO=0 POINTER_FOLLOW=0\r\n");
    ram_append("AUDIO_I2C_CACHE_PROVES=NO_SE5_OWNER NO_TAS_ID NO_PCM\r\n");
    pacgq_ram_number(ram_append,"AUDIO_CLOCK_QUERY_ERROR=",pacgq_preboot_record.error);
    pacgq_ram_number(ram_append,"AUDIO_CLOCK_QUERY_RAW_V2_BYTES=",sizeof(pacgq_preboot_record));
    pacgq_ram_number(ram_append,"AUDIO_CLOCK_QUERY_BASELINE_COMPLETE=",pacgq_preboot_record.baseline_complete);
    pacgq_ram_number(ram_append,"AUDIO_CLOCK_QUERY_CAMCC_BLOCKED=",PACGQ_TARGETS-PACGQ_CALL_TARGETS);
    ram_append("AUDIO_CLOCK_QUERY_RAW_V2_BEGIN\r\n");pacgq_ram_hex(ram_append,(const uint8_t*)&pacgq_preboot_record,sizeof(pacgq_preboot_record));
    ram_append("\r\nAUDIO_CLOCK_QUERY_RAW_V2_END\r\n");
    ram_append("AUDIO_CLOCK_QUERY_SOURCE_SHA256=" PACQI_SOURCE_SHA256 "\r\n");
    ram_append("AUDIO_CLOCK_QUERY_SCOPE=GCD_NAMESPACE_PLUS_ACTUAL_AT_THEN_READONLY_API_BOOL_NOT_RAW_CSR\r\n");
    ram_append("AUDIO_CLOCK_QUERY_NO_PERMISSION=NO_CLOCK_OR_PIN_WRITE NO_BUS_LEASE\r\n");
    ram_append("AUDIO_CLOCK_QUERY_CAMCC=NOT_ISSUED COLD_CAMCC_UNQUALIFIED EVEN_IF_GCC_PARENTS_ON\r\n");
#endif
}
/* CACHED verdict ONLY, including safe zero/never-issued refusal. This can be
 * read by reset/receipt gates without a third firmware environment check.
 * CPU_ON still requires the separate final checkpoint immediately below. */
static inline int pacgq_prestart_safe(const void *gcd_context)
{
#if !EFI_XNU_AUDIO_CLOCK_GCD_QUERY_AVAILABLE || defined(POLARIS_EFI_TEST_QEMU)
    (void)gcd_context;return 1;
#else
    return !pacgq_preboot_record.uncertain&&!pacgq_preboot_record.outstanding&&!pacgq_ticket.outstanding&&
        (!gcd_context||!pgcd_uncertain((const struct pgcd_context*)gcd_context));
#endif
}
/* Main calls ONCE after its last original service/Console and BEFORE its
 * deliberate DAIF/Group1 change or CPU_ON. Repeated callers receive only the
 * cached result. Internal post-FreePool check1 plus this check2 are the only
 * two physical restoration checkpoints; neither renews MMIO permission. */
static inline int pacgq_prestart_checkpoint(void *gcd_context)
{
#if !EFI_XNU_AUDIO_CLOCK_GCD_QUERY_AVAILABLE || defined(POLARIS_EFI_TEST_QEMU)
    (void)gcd_context;return 1;
#else
    struct pacgq_result *r=&pacgq_preboot_record;
    if(r->prestart_checked)return r->prestart_passed&&pacgq_prestart_safe(gcd_context);
    r->prestart_checked=1;paic_actual_order(0);
    if(!pacgq_prestart_safe(gcd_context)||!r->attempted||!gcd_context)return 0;
    if(!pgcd_prestart_check((struct pgcd_context*)gcd_context)){pacgq_fail(r,PACGQ_UNKNOWN,1);return 0;}
    r->prestart_passed=1;paic_actual_order(0);return 1;
#endif
}
#endif
