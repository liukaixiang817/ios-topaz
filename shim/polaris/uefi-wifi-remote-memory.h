/* Owned EFI pages for a future MSS/MSA/RMTFS caller. Default OFF, no parent
 * hook yet. These are actual AllocatePages/FreePages adapters, not an MPU,
 * VMID, remote-DMA or radio grant. The original Core is never patched.
 * Each call has a NEW resident source context; no closed GCD ticket is reused
 * or renewed. An allocation persists as an EFI claim, not a CPU/power lease.
 * Once external exposure might be issued, this local-only release path locks
 * out permanently until a real secure/remote handback provider is integrated.
 */
#ifndef POLARIS_UEFI_WIFI_REMOTE_MEMORY_H
#define POLARIS_UEFI_WIFI_REMOTE_MEMORY_H
#ifndef EFI_XNU_WIFI_REMOTE_MEMORY_AVAILABLE
#define EFI_XNU_WIFI_REMOTE_MEMORY_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_REMOTE_MEMORY_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
#include "uefi-gcd-mmio-readonly.h"
#define PWMC_PAGES 514u
#define PWMC_BS_BYTES 376u
#define PWMC_ALLOC_RVA UINT64_C(0xc258)
#define PWMC_FREE_RVA UINT64_C(0xc32c)
#define PWMC_RAISE_RVA UINT64_C(0xa2c8)
#define PWMC_RESTORE_RVA UINT64_C(0xc6d4)
#define PWMC_EVENT_MAX 128u
#define PWMC_MAP_NODE_MAX 256u
#define PWMC_TIMER_MAX 32u
#define PWMC_IRQ_IMAGES 3u
#define PWMC_IRQ_PAGES 9u
#define PWMC_IRQ_HANDLERS 1024u
struct pwmc_irq_binding {
    uint32_t bytes,imagebase,table,table_bytes,state,state_bytes,range_count,reloc_count;
    const uint32_t*relocations;
    struct pgci_range ranges[5];
};
#include "uefi-wifi-irq-source-binding.h"
struct pwmc_irq_AT {uint64_t page,raw;volatile uint32_t issued,returned;};
struct pwmc_irq_regs {
    uint64_t el,vbar,ctl,cval,frequency,ticks;
    volatile uint32_t issued,returned;
};
struct pwmc_irq_image {
    uint64_t base,bytes;
    uint32_t attempted,AT_count,hash_count[5],hash_failed[5],complete,reserved;
    struct pwmc_irq_AT AT[PWMC_IRQ_PAGES];
    uint8_t hashes[5][5][32],table[72],state[104];
};
struct pwmc_irq_path {
    uint64_t tables[3],handlers,handler_count,scope_end_ticks,catchup_bound,notify_product;
    uint64_t raise_ticks,final_ticks;
    uint64_t core_advance_bound;
    uint32_t attempted,complete,table_AT_count,array_AT_count,finalized,reserved;
    struct pwmc_irq_AT table_AT[2],array_AT[3];
    uint8_t unbound_hardware_table[40];
    struct pwmc_irq_image image[PWMC_IRQ_IMAGES];
    struct pwmc_irq_regs regs[2];
    uint64_t handler[PWMC_IRQ_HANDLERS];
    uint8_t digest[32];
};
/* RestoreTPL(4) dispatches pending levels5..16 too. Preserve those queues
 * before Raise/page/Restore, without walking, clearing or calling them. */
struct pwmc_deferred_sample {
    uint64_t pending,counter,head[12][2];
    uint32_t attempted,complete,head_count,reserved;
};
struct pwmc_deferred_path {
    uint64_t restore_entry,checker;
    uint32_t attempted,complete,checks,refusal_timer;
    struct pwmc_deferred_sample sample[3];
    uint8_t digest[32];
};
struct pwmc_timer_node {
    uint64_t address,AT_page[2],AT_raw[2];
    uint32_t issued,returned,AT_count,reserved;
    uint8_t raw[184];
};
/* Current nonperiodic timers only. This is a bounded source path, never a
 * promise that future firmware/interrupts cannot create or rearm a timer. */
struct pwmc_timer_path {
    uint64_t checker,counter,head[2];
    uint8_t lock[2][24];
    uint32_t attempted,complete,count,reserved;
    struct pwmc_timer_node checker_node,node[PWMC_TIMER_MAX];
    uint8_t digest[32];
};
struct pwmc_tpl_transition {
    uint64_t entry,argument,value,TPL_before,TPL_after,native_address;
    uint64_t pending[2],higher[2][15][2];
    struct pgcd_arch before,after;
    uint32_t issued,returned,unknown,native_before,native_after,observed,higher_count[2];
    uint8_t BS_before[PWMC_BS_BYTES],BS_after[PWMC_BS_BYTES];
};
struct pwmc_tpl_scope {
    uint32_t attempted,unknown,held,completed;
    struct pwmc_tpl_transition transition[2];
    struct pgcd_map map;
    uint64_t map_entry;
    uint32_t map_unknown,map_native_before,map_native_after,hash_count,hash_failed,reserved;
    uint8_t maps[PGCD_MAP_CAP] __attribute__((aligned(8)));
    uint8_t hashes[PGCI_RANGE_COUNT][32],intent_digest[2][32],digest[32];
};
/* Original MEMORY_MAP_ENTRY is64B, with Link+8, Type+28,
 * inclusive Start/End+32/+40, VirtualStart+48 and Attributes+56.
 * Preserve both complete original lists; never splice or reserve nodes. */
struct pwmc_map_node {
    uint64_t address,AT_page[2],AT_raw[2];
    uint32_t issued,returned,AT_count,reserved;
    uint8_t raw[64];
};
struct pwmc_allocator_path {
    uint64_t head[2][2],map_key,stack_depth,flushing;
    uint8_t lock[24];
    uint32_t attempted,complete,count[2],selected,reserved[3];
    struct pwmc_map_node node[2][PWMC_MAP_NODE_MAX];
    uint8_t digest[32];
};
/* Actual Core ca2c scans GroupLink at +0x10 and compares the GUID at
 * +0x38; c7f0 queues NotifyLink at +0x48. The standard memory-map-change
 * group must have no subscribers before either mutating page service.
 * Never invoke a callback, unlink an event or suppress firmware dispatch. */
static const efi_guid pwmc_map_change_group={0x78bee926,0x692f,0x48fd,
    {0x9e,0xdb,0x01,0x42,0x2e,0xf0,0xd7,0xab}};
struct pwmc_event_node {
    uint64_t address,AT_page[2],AT_raw[2];
    uint32_t issued,returned,AT_count,reserved;
    uint8_t raw[88];
};
struct pwmc_event_path {
    uint64_t head[2],pending;
    uint8_t lock[24],group[16];
    uint32_t attempted,count,complete,reserved;
    struct pwmc_event_node node[PWMC_EVENT_MAX];
    uint8_t digest[32]; /* returned-prefix integrity, never callback authority */
};
enum pwmc_kind {PWMC_MSA,PWMC_RMTFS};
enum pwmc_error {PWMC_OK,PWMC_ARGUMENT,PWMC_REUSED,PWMC_SOURCE,PWMC_RANGE,
    PWMC_CONTEXT,PWMC_SERVICE,PWMC_MAP,PWMC_TRANSLATION,PWMC_EXPOSED};
struct pwmc_range {uint64_t base,bytes;};
/* Fixed reg ranges of the original own reserved-memory node, plus SMEM.
 * Dynamic size-only DT pools have no PA to borrow; current EFI type7 is still
 * required. Current loader/payload/native/root allocations are excluded by
 * the complete map; none of their type2/3/4 pages can pass selection.
 */
static const struct pwmc_range pwmc_exclusions[]={
    {0x85700000,0x600000},{0x85d00000,0x200000},{0x85fc0000,0x4940000},
    {0x8ab00000,0x1400000},{0x8bf00000,0x500000},{0x8c400000,0x10000},
    {0x8c410000,0x5000},{0x8c415000,0x2000},{0x8c500000,0x1e00000},
    {0x8e300000,0x100000},{0x8e400000,0x7800000},{0x95c00000,0x500000},
    {0x96100000,0x800000},{0x96900000,0x200000},{0x96b00000,0x1400000},
    {0x97f00000,0x100000},{0x9d400000,0x2400000},{0xb0000000,0x400000},
    {0xaf000000,0x1000000},{0x86000000,0x200000}
};
struct pwmc_translation {
    uint64_t page,saved,read_par,write_par,restored;
    uint32_t read_issued,read_returned,write_issued,write_returned;
};
struct pwmc_call {
    /* Legacy RAW field name profile_hook: Core+1cb78 actually binds SMM
     * Base2.InSmm (GUID f4ccbfb7-f6e0-47fd-9dd4-10a8f150c191), not a
     * profiler. Keep the RAW layout and the fresh-zero refusal unchanged;
     * this adapter never invokes an unqualified SMM protocol. */
    uint64_t requested,returned_address,pages,status,entry,profile_hook,pending_events;
    uint64_t native_address;uint32_t native_before,native_after;
    uint32_t issued,returned,unknown,map_checked;
    struct pgcd_service_guard guard;
    uint8_t BS_before[PWMC_BS_BYTES],BS_after[PWMC_BS_BYTES];
};
struct pwmc_result {
    uint32_t bound,attempted,error,unknown,held,allocated,released,external_issued;
    uint32_t kind,bound_kind,pages,translated,translation_pending,native_reads[2],native_last[2];
    uint32_t release_translated,release_pending,final_hash_count[2],final_hash_failed[2];
    uint64_t backing,backing_bytes,exposed,exposed_bytes,native_flag,bound_native_flag;
    struct pgcd_result source[2];
    struct pgcd_context context[2];struct pgcd_lifetime ticket[2];
    struct pwmc_call call[2];
    struct pwmc_translation AT[PWMC_PAGES],release_AT[PWMC_PAGES];
    uint8_t final_hashes[2][PGCI_RANGE_COUNT][32];
    struct pwmc_event_path events[2];
    struct pwmc_allocator_path allocator[2];
    struct pwmc_tpl_scope TPL[2];
    struct pwmc_timer_path timers[2];
    struct pwmc_irq_path irq[2];
    struct pwmc_deferred_path deferred[2];
    struct pgcd_io bound_io;
};
_Static_assert(sizeof(struct pwmc_translation)==56,"both returned PAR translations and exact restore");
_Static_assert(sizeof(struct pwmc_map_node)==120,"complete64B original descriptor plus returned translations");
_Static_assert(sizeof(struct pwmc_result)==((121344+2*sizeof(struct pwmc_event_path)+2*sizeof(struct pwmc_allocator_path)+2*sizeof(struct pwmc_tpl_scope)+2*sizeof(struct pwmc_timer_path)+2*sizeof(struct pwmc_irq_path)+2*sizeof(struct pwmc_deferred_path)+sizeof(struct pgcd_io)+15)&~15u),"complete allocation, release, notification, allocator, TPL, timer, IRQ and deferred dispatch evidence");
static inline int pwmc_fail(struct pwmc_result*r,unsigned error,unsigned unknown)
{if(!r->error)r->error=error;if(unknown)r->unknown=1;return 0;}
static inline int pwmc_zero(const void*p,size_t n)
{const uint8_t*b=p;for(size_t k=0;k<n;k++)if(b[k])return 0;return 1;}
static inline uint64_t pwmc_bytes(unsigned kind)
{return kind==PWMC_MSA?UINT64_C(0x200000):kind==PWMC_RMTFS?UINT64_C(0x202000):0;}
static inline int pwmc_allowed(uint64_t base,uint64_t bytes)
{
    if(!bytes||(bytes&4095)||bytes>0x202000||(base&4095)||base<UINT64_C(0x80000000)||base>UINT64_C(0x100000000)-bytes)return 0;
    for(unsigned k=0;k<sizeof(pwmc_exclusions)/sizeof(pwmc_exclusions[0]);k++){
        const struct pwmc_range*s=&pwmc_exclusions[k];if(base<s->base+s->bytes&&s->base<base+bytes)return 0;
    }return 1;
}
/* Reuse the complete existing map validator; do not parse a selected subset.
 * Compare semantic descriptor partitions in both directions, preserving all
 * attribute, virtual, padding and extension bytes. Only type/physical/pages
 * may differ through a split/merge, and type only inside the exact claim.
 */
static inline int pwmc_descriptor_equal(const uint8_t*a,const uint8_t*b,unsigned stride,
    uint32_t before,uint32_t after,unsigned inside)
{
    if(((const struct efi_memory*)a)->type!=(inside?before:((const struct efi_memory*)b)->type)||
       (inside&&((const struct efi_memory*)b)->type!=after))return 0;
    for(unsigned k=4;k<stride;k++)if(!((k>=8&&k<16)||(k>=24&&k<32))&&a[k]!=b[k])return 0;
    return 1;
}
static inline int pwmc_delta_direction(const uint8_t*a,uint64_t na,const uint8_t*b,uint64_t nb,
    unsigned stride,uint64_t base,uint64_t bytes,uint32_t before,uint32_t after)
{
    for(uint64_t at=0;at<na;at+=stride){
        const struct efi_memory*d=(const void*)(a+at);uint64_t cursor=d->physical,end=cursor+d->pages*4096;
        while(cursor<end){
            unsigned found=0;uint64_t next=end;
            for(uint64_t bt=0;bt<nb;bt+=stride){const struct efi_memory*e=(const void*)(b+bt);
                uint64_t stop=e->physical+e->pages*4096;if(e->physical<=cursor&&cursor<stop){
                    unsigned inside=cursor>=base&&cursor<base+bytes;found++;
                    if(!pwmc_descriptor_equal(a+at,b+bt,stride,before,after,inside))return 0;
                    if(stop<next)next=stop;
                }
            }
            if(found!=1||next<=cursor)return 0;
            if(cursor<base&&base<next)next=base;
            if(cursor<base+bytes&&base+bytes<next)next=base+bytes;
            cursor=next;
        }
    }return 1;
}
static inline int pwmc_maps_delta(const struct pgcd_map*a,const uint8_t*raw_a,
    const struct pgcd_map*b,const uint8_t*raw_b,uint64_t base,uint64_t bytes,unsigned release)
{
    struct polaris_efi_memory checked;
    uint32_t before=release?2:7,after=release?7:2;
    if(!a->valid||!b->valid||a->status||b->status||!a->key||!b->key||a->key==b->key||a->version!=1||b->version!=1||
       a->stride!=b->stride||!pwmc_allowed(base,bytes)||
       !polaris_efi_memory_check(raw_a,a->bytes,PGCD_MAP_CAP,a->stride,&checked)||
       !polaris_efi_memory_check(raw_b,b->bytes,PGCD_MAP_CAP,b->stride,&checked)||
       !polaris_efi_range_owned(raw_a,a->bytes,a->stride,base,bytes,before)||
       !polaris_efi_range_owned(raw_b,b->bytes,b->stride,base,bytes,after))return 0;
    return pwmc_delta_direction(raw_a,a->bytes,raw_b,b->bytes,(unsigned)a->stride,base,bytes,before,after)&&
        pwmc_delta_direction(raw_b,b->bytes,raw_a,a->bytes,(unsigned)a->stride,base,bytes,after,before);
}
static inline int pwmc_map_delta(const struct pgcd_result*s,uint64_t base,uint64_t bytes,unsigned release)
{return pwmc_maps_delta(&s->map[0],s->maps[0],&s->map[1],s->maps[1],base,bytes,release);}
static inline int pwmc_select(const struct pgcd_result*s,unsigned kind,uint64_t*out)
{
    struct polaris_efi_memory checked;const struct pgcd_map*m=&s->map[0];uint64_t bytes=pwmc_bytes(kind);
    uint64_t alignment=kind==PWMC_MSA?UINT64_C(0x200000):4096;
    if(!out||!bytes||!m->valid||!polaris_efi_memory_check(s->maps[0],m->bytes,PGCD_MAP_CAP,m->stride,&checked))return 0;
    uint64_t best=0;
    for(uint64_t at=0;at<m->bytes;at+=m->stride){const struct efi_memory*d=(const void*)(s->maps[0]+at);
        if(d->type!=7||d->attributes>>63||d->virtual_address)continue;
        uint64_t lo=d->physical<UINT64_C(0x80000000)?UINT64_C(0x80000000):d->physical;
        uint64_t hi=d->physical+d->pages*4096;if(hi>UINT64_C(0x100000000))hi=UINT64_C(0x100000000);
        if(hi<bytes||lo>hi-bytes)continue;
        uint64_t candidate=(hi-bytes)&~(alignment-1);
        /* Each collision moves below one exact excluded interval; at most
         *20 exclusions can be crossed, with no unbounded page scan. */
        for(unsigned attempt=0;attempt<=sizeof(pwmc_exclusions)/sizeof(pwmc_exclusions[0]);attempt++){
            if(candidate<lo)break;
            if(pwmc_allowed(candidate,bytes)){if(candidate>best)best=candidate;break;}
            uint64_t limit=UINT64_MAX;
            for(unsigned k=0;k<sizeof(pwmc_exclusions)/sizeof(pwmc_exclusions[0]);k++){
                const struct pwmc_range*x=&pwmc_exclusions[k];
                if(candidate<x->base+x->bytes&&x->base<candidate+bytes&&x->base<limit)limit=x->base;
            }
            if(limit<bytes||limit==UINT64_MAX)break;
            uint64_t lower=(limit-bytes)&~(alignment-1);if(lower>=candidate)break;candidate=lower;
        }
    }
    if(!best)return 0;*out=best;return 1;
}
static inline int pwmc_layout(const struct pwmc_result*r)
{
    uint64_t bytes=pwmc_bytes(r->kind);return bytes&&r->backing_bytes==bytes&&r->pages==bytes/4096&&
        pwmc_allowed(r->backing,bytes)&&!(r->backing&(r->kind==PWMC_MSA?0x1fffffu:4095u))&&
        r->exposed==r->backing+(r->kind==PWMC_RMTFS?4096:0)&&
        r->exposed_bytes==(r->kind==PWMC_MSA?0x100000u:0x200000u);
}
static inline int pwmc_parameters(const struct pwmc_result*r)
{
    if(r->kind!=r->bound_kind||r->native_flag!=r->bound_native_flag||!pwmc_layout(r))return 0;
    uint64_t selected=0;
    return pwmc_select(&r->source[0],r->bound_kind,&selected)&&selected==r->backing;
}
/* The original service guard marks its exact resident call pending BEFORE
 * the final source/native check. Recognize only that unissued own call;
 * never clear outstanding, accept a foreign pending call or sample UNKNOWN. */
static inline int pwmc_call_guard_valid(const struct pwmc_result*r,unsigned operation)
{
    const struct pwmc_call*q=&r->call[operation];const struct pgcd_result*s=&r->source[operation];
    const struct pgcd_service_guard*g=&q->guard;
    return !s->uncertain&&s->outstanding==0x10000&&
        q->requested==r->backing&&q->returned_address==r->backing&&q->pages==r->pages&&
        q->entry==s->core+(operation?PWMC_FREE_RVA:PWMC_ALLOC_RVA)&&q->native_address==r->bound_native_flag&&
        g->entered==1&&g->unknown==1&&g->left==0&&g->foreign_returned==0&&g->fp.saved==1&&g->fp.restored==0&&
        g->TPL_before==4&&g->boot_before==s->core+0x1b800&&g->tables_before==s->config_pointer&&g->count_before==s->config_count;
}
static inline int pwmc_own_prepared_call(const struct pwmc_result*r,unsigned operation)
{
    const struct pwmc_call*q=&r->call[operation];
    return ((!q->issued&&!q->returned&&!q->unknown)||
        (q->issued==1&&q->returned<=1&&q->unknown==1))&&pwmc_call_guard_valid(r,operation);
}
static inline int pwmc_context_intact(const struct pwmc_result*r,unsigned operation)
{
    const struct pgcd_context*c=&r->context[operation];const struct pgcd_result*s=&r->source[operation];
    return c->record==s&&c->ticket==&r->ticket[operation]&&c->stage==2&&c->opened==1&&!c->finished&&
        c->ticket->spent==1&&c->ticket->result==(uintptr_t)s&&s->self_system==(uintptr_t)r->bound_io.system&&
        s->self_owner_address==r->source[1-operation].self_owner_address&&s->self_base==r->source[1-operation].self_base&&
        s->self_bytes==r->source[1-operation].self_bytes&&pgcd_equal(&s->self_owner,&r->source[1-operation].self_owner,sizeof(s->self_owner))&&
        pgcd_equal(&c->io,&r->bound_io,sizeof(c->io))&&r->kind==r->bound_kind&&r->native_flag==r->bound_native_flag&&
        r->bound_io.system&&(uintptr_t)r->bound_io.system->boot==s->core+0x1b800&&
        s->config_pointer==(uintptr_t)r->bound_io.system->tables&&s->config_count==r->bound_io.system->table_count&&s->config_count&&s->config_count<=PGCD_CONFIG_MAX;
}
static inline int pwmc_live(struct pwmc_result*r,unsigned op,struct pgcd_arch*out)
{
    struct pgcd_result*s=&r->source[op];struct pgcd_arch now={0};struct pgcd_io expected=r->bound_io;
    if(!pwmc_context_intact(r,op))return pwmc_fail(r,PWMC_CONTEXT,1);uint64_t previous=s->after.cpu.ticks;s->arch_issued++;
    int returned=expected.arch(expected.opaque,&now);
    if(returned){s->arch_returned++;*out=now;s->after=now;}
    if(!returned||!pgcd_equal(&expected,&r->bound_io,sizeof(expected))||!pwmc_context_intact(r,op))return pwmc_fail(r,PWMC_CONTEXT,1);
    if(!pwfc_arch_admitted(&now.cpu)||now.cpu.mair!=UINT64_C(0xffbb4400)||((now.cpacr>>20)&3)!=3||
       !pwfc_arch_stable(&s->before.cpu,&now.cpu)||now.cpacr!=s->before.cpacr||now.cpu.ticks<previous||
       now.cpu.ticks<s->before.cpu.ticks||now.cpu.ticks-s->before.cpu.ticks>PGCD_FRESH_TICKS)return pwmc_fail(r,PWMC_CONTEXT,1);
    return 1;
}
static inline uint64_t pwmc_expected_TPL(const struct pwmc_result*r,unsigned operation)
{
    const struct pwmc_tpl_scope*p=&r->TPL[operation];const struct pwmc_tpl_transition*a=&p->transition[0],*b=&p->transition[1];
    if(!p->attempted)return pwmc_zero(p,sizeof(*p))?4:0;
    if(p->unknown||p->attempted!=1)return 0;
    if(!a->issued)return !a->returned&&!b->issued&&!b->returned?4:0;
    if(a->issued!=1||a->returned!=1||a->unknown||a->argument!=16||a->value!=4||a->TPL_before!=4||a->TPL_after!=16)return 0;
    if(!b->issued)return !b->returned?16:0;
    if(b->issued!=1||b->argument!=a->value)return 0;
    if(!b->returned)return 16;
    return b->returned==1&&!b->unknown&&b->TPL_before==16&&b->TPL_after==4?4:0;
}
static inline int pwmc_source(struct pwmc_result*r,unsigned operation)
{
    struct pgcd_context*c=&r->context[operation];struct pgcd_result*s=c->record;struct pgcd_arch a;
    if(r->error||r->unknown||r->kind!=r->bound_kind||r->native_flag!=r->bound_native_flag||
       (r->backing&&!pwmc_parameters(r))||!pgcd_equal(&c->io,&r->bound_io,sizeof(c->io))||s!=&r->source[operation]||c->ticket!=&r->ticket[operation]||c->finished||!c->opened||s->error||
       s->uncertain||(s->outstanding&&!pwmc_own_prepared_call(r,operation))||!pwmc_live(r,operation,&a)||!pwmc_context_intact(r,operation)||a.cpu.daif||a.cpu.group1!=1||
       !pgcd_cached_owner_stable(c)||!pgcd_in_self(s,(uintptr_t)r,sizeof(*r))||
       !pgcd_in_self(s,r->native_flag,4)||!pgcd_owned(c,0,r->native_flag,4)||!pwmc_context_intact(r,operation)||
       (uintptr_t)c->io.system!=s->self_system||(uintptr_t)c->io.system->boot!=s->core+0x1b800||
       !pwmc_expected_TPL(r,operation)||pwfi_le((const void*)(uintptr_t)(s->core+0x1b098),8)!=pwmc_expected_TPL(r,operation)||
       (uintptr_t)c->io.system->boot->raise_tpl!=s->core+PWMC_RAISE_RVA||
       (uintptr_t)c->io.system->boot->restore_tpl!=s->core+PWMC_RESTORE_RVA||
       (uintptr_t)c->io.system->boot->allocate_pages!=s->core+PWMC_ALLOC_RVA||
       (uintptr_t)c->io.system->boot->free_pages!=s->core+PWMC_FREE_RVA||
       pwfi_le((const void*)(uintptr_t)(s->core+0x1cb78),8))return pwmc_fail(r,PWMC_SOURCE,operation||r->held);
    if(c->record!=s||c->ticket!=&r->ticket[operation]||!pgcd_equal(&c->io,&r->bound_io,sizeof(c->io))||r->kind!=r->bound_kind||r->native_flag!=r->bound_native_flag||
       (r->backing&&!pwmc_parameters(r))||s->uncertain||(s->outstanding&&!pwmc_own_prepared_call(r,operation)))return pwmc_fail(r,PWMC_CONTEXT,1);
    r->native_reads[operation]++;r->native_last[operation]=*(const volatile uint32_t*)(uintptr_t)r->native_flag;
    if(r->native_last[operation])return pwmc_fail(r,PWMC_CONTEXT,operation||r->held);
    return 1;
}
/* The original generic guard assumes its own context remains valid across
 * callbacks. This adapter retains the exact context and checks immediately
 * after each callback, before any subsequent dereference or restoration. */
static inline int pwmc_service_enter(struct pwmc_result*r,unsigned op)
{
    struct pgcd_context*c=&r->context[op];struct pgcd_result*s=&r->source[op];struct pgcd_service_guard*g=&r->call[op].guard;
    if(!pwmc_context_intact(r,op)||!pwmc_zero(g,sizeof(*g))||!pgcd_in_self(s,(uintptr_t)g,sizeof(*g))||
       !pgcd_owned(c,0,(uintptr_t)g,sizeof(*g))||!pwmc_context_intact(r,op)||!pwmc_live(r,op,&g->before))return pwmc_fail(r,PWMC_CONTEXT,1);
    g->TPL_before=pwfi_le((const void*)(uintptr_t)(s->core+0x1b098),8);g->boot_before=(uintptr_t)c->io.system->boot;
    g->tables_before=(uintptr_t)c->io.system->tables;g->count_before=c->io.system->table_count;
    if(g->TPL_before!=4||g->boot_before!=s->core+0x1b800||g->tables_before!=s->config_pointer||g->count_before!=s->config_count||
       !pgcd_equal(s->DS_raw[0],(const void*)(uintptr_t)s->DS,168)||!pgcd_cached_owner_stable(c))return pwmc_fail(r,PWMC_CONTEXT,1);
    int saved=r->bound_io.fp_save(r->bound_io.opaque,&g->fp);
    if(!saved||!pwmc_context_intact(r,op)||g->fp.saved!=1||g->fp.restored)return pwmc_fail(r,PWMC_CONTEXT,1);
    g->entered=g->unknown=1;s->outstanding=0x10000;r->bound_io.order(r->bound_io.opaque);
    if(!pwmc_context_intact(r,op)||g->entered!=1||g->unknown!=1||g->left||g->foreign_returned||g->fp.saved!=1||g->fp.restored||s->outstanding!=0x10000)return pwmc_fail(r,PWMC_CONTEXT,1);
    return 1;
}
static inline int pwmc_service_leave(struct pwmc_result*r,unsigned op,int returned)
{
    struct pgcd_context*c=&r->context[op];struct pgcd_result*s=&r->source[op];struct pgcd_service_guard*g=&r->call[op].guard;
    if(!pwmc_context_intact(r,op)||g->entered!=1||g->left||g->unknown!=1)return pwmc_fail(r,PWMC_CONTEXT,1);
    g->foreign_returned=returned?1:0;if(!returned||!pwmc_live(r,op,&g->after))return pwmc_fail(r,PWMC_CONTEXT,1);
    int restored=r->bound_io.fp_restore(r->bound_io.opaque,&g->fp);
    if(!restored||!pwmc_context_intact(r,op)||g->fp.restored!=1)return pwmc_fail(r,PWMC_CONTEXT,1);
    g->TPL_after=pwfi_le((const void*)(uintptr_t)(s->core+0x1b098),8);g->boot_after=(uintptr_t)c->io.system->boot;
    g->tables_after=(uintptr_t)c->io.system->tables;g->count_after=c->io.system->table_count;g->left=1;r->bound_io.order(r->bound_io.opaque);
    if(!pwmc_context_intact(r,op)||g->TPL_before!=g->TPL_after||g->boot_before!=g->boot_after||g->tables_before!=g->tables_after||g->count_before!=g->count_after||
       !pgcd_equal(s->DS_raw[0],(const void*)(uintptr_t)s->DS,168)||!pgcd_cached_owner_stable(c))return pwmc_fail(r,PWMC_CONTEXT,1);
    s->outstanding=0;r->bound_io.order(r->bound_io.opaque);
    if(!pwmc_context_intact(r,op)||s->outstanding)return pwmc_fail(r,PWMC_CONTEXT,1);g->unknown=0;return 1;
}
/* Pure replay of the complete returned notification prefix. A local page
 * operation must not newly queue the memory-map-change callback fanout.
 * This does not make asynchronous firmware interrupts or other callbacks
 * ours; the caller still needs the normal original-service qualification. */
struct pwmc_irq_map_view {const uint8_t*data;uint64_t bytes,stride,self_base,self_bytes;};
static inline void pwmc_events_digest(const struct pwmc_event_path*p,uint8_t out[32])
{
    struct pwfi_sha256 hash;pwfi_init(&hash);const uint8_t*bytes=(const void*)p;
    for(size_t k=0;k<offsetof(struct pwmc_event_path,digest);k++)pwfi_byte(&hash,bytes[k]);
    pwfi_final(&hash,out);
}
static inline int pwmc_events_replay_map(const struct pwmc_event_path*p,uint64_t core,const struct pwmc_irq_map_view*m)
{
    uint64_t head=core+0x1c368,previous=head;uint8_t digest[32];pwmc_events_digest(p,digest);
    if(p->attempted!=1||p->complete!=1||p->reserved||p->count>PWMC_EVENT_MAX||p->pending||
       pwfi_le(p->lock,8)!=31||pwfi_le(p->lock+16,4)!=1||
       !pgcd_equal(p->group,&pwmc_map_change_group,16)||!pgcd_equal(p->digest,digest,32))return 0;
    for(unsigned k=0;k<p->count;k++){
        const struct pwmc_event_node*n=&p->node[k];uint64_t first=n->address&~UINT64_C(4095);
        unsigned pages=(unsigned)(((n->address+sizeof(n->raw)-1)&~UINT64_C(4095))-first)/4096+1;
        if(!n->address||(n->address&7)||n->address>UINT64_MAX-sizeof(n->raw)||
           (m->self_bytes>=sizeof(n->raw)&&n->address>=m->self_base&&n->address-m->self_base<=m->self_bytes-sizeof(n->raw))||n->issued!=1||n->returned!=1||n->reserved||
           pwfi_le(n->raw,8)!=UINT64_C(0x746e7665)||pages>2||n->AT_count!=pages||
           pwfi_le(n->raw+24,8)!=previous||
           (k?pwfi_le(p->node[k-1].raw+16,8):p->head[0])!=n->address+16||
           pgcd_equal(n->raw+56,&pwmc_map_change_group,16))return 0;
        for(unsigned j=0;j<pages;j++)if(n->AT_page[j]!=first+4096*j||
           n->AT_raw[j]!=(UINT64_C(0xff00000000000b80)|n->AT_page[j])||
           (!polaris_efi_range_owned(m->data,m->bytes,m->stride,n->AT_page[j],4096,3)&&
            !polaris_efi_range_owned(m->data,m->bytes,m->stride,n->AT_page[j],4096,4)))return 0;
        if(pages==1&&(n->AT_page[1]||n->AT_raw[1]))return 0;
        for(unsigned j=0;j<k;j++)if(p->node[j].address==n->address)return 0;
        previous=n->address+16;
    }
    if(p->head[1]!=previous||(p->count?pwfi_le(p->node[p->count-1].raw+16,8):p->head[0])!=head)return 0;
    return pwmc_zero(p->node+p->count,(PWMC_EVENT_MAX-p->count)*sizeof(p->node[0]));
}
static inline int pwmc_events_replay(const struct pwmc_result*r,unsigned operation)
{const struct pgcd_result*s=&r->source[operation];const struct pwmc_irq_map_view m={s->maps[0],s->map[0].bytes,s->map[0].stride,s->self_base,s->self_bytes};return pwmc_events_replay_map(&r->events[operation],s->core,&m);}
/* No callback follows the last equality check on the physical path: the
 * ordinary source checks run first, then these RAM comparisons, then only
 * the source-bound ABI leaf. The software peer can mutate at order/clock
 * boundaries and must be refused before the first allocator call. */
static inline int pwmc_events_current_map(const struct pwmc_event_path*p,uint64_t core,const struct pwmc_irq_map_view*m)
{
    if(!pwmc_events_replay_map(p,core,m)||
       !pgcd_equal(p->lock,(const void*)(uintptr_t)(core+0x1c350),24)||
       !pgcd_equal(p->head,(const void*)(uintptr_t)(core+0x1c368),16)||
       pwfi_le((const void*)(uintptr_t)(core+0x1dbc0),8))return 0;
    for(unsigned k=0;k<p->count;k++)if(!pgcd_equal(p->node[k].raw,
        (const void*)(uintptr_t)p->node[k].address,sizeof(p->node[k].raw)))return 0;
    return 1;
}
static inline int pwmc_events_current(const struct pwmc_result*r,unsigned operation)
{const struct pgcd_result*s=&r->source[operation];const struct pwmc_irq_map_view m={s->maps[0],s->map[0].bytes,s->map[0].stride,s->self_base,s->self_bytes};return pwmc_events_current_map(&r->events[operation],s->core,&m);}
struct pwmc_capture_context {struct pwmc_result*r;unsigned operation;};
static inline int pwmc_event_capture_node(void*opaque,struct pwmc_event_node*n,uint64_t address)
{
    const struct pwmc_capture_context*x=opaque;struct pwmc_result*r=x->r;unsigned operation=x->operation;struct pgcd_context*c=&r->context[operation];
    n->address=address;
    if(address>UINT64_MAX-sizeof(n->raw)||pgcd_in_self(c->record,address,sizeof(n->raw)))return pwmc_fail(r,PWMC_CONTEXT,operation||r->held);
    uint64_t end=address+sizeof(n->raw);n->issued=1;
    for(uint64_t at=address&~UINT64_C(4095);at<end;at+=4096){
        if(n->AT_count==2||(!polaris_efi_range_owned(c->record->maps[0],c->record->map[0].bytes,c->record->map[0].stride,at,4096,3)&&
           !polaris_efi_range_owned(c->record->maps[0],c->record->map[0].bytes,c->record->map[0].stride,at,4096,4)))return pwmc_fail(r,PWMC_CONTEXT,operation||r->held);
        unsigned k=n->AT_count;uint64_t where=0;n->AT_page[k]=at;
        if(!pwmc_context_intact(r,operation)||!pwmc_parameters(r)||
           !c->io.identity(c->io.opaque,at,4096,&where,&n->AT_raw[k])||!pwmc_context_intact(r,operation)||!pwmc_parameters(r)||
           n->address!=address||n->AT_page[k]!=at||where!=at||
           n->AT_raw[k]!=(UINT64_C(0xff00000000000b80)|at))return pwmc_fail(r,PWMC_TRANSLATION,1);
        n->AT_count=k+1;
    }
    pgcd_copy(n->raw,(const void*)(uintptr_t)address,sizeof(n->raw));n->returned=1;return 1;
}
/* Same bounded DATA walk, shared with the actual incoming-contract caller.
 * read_node qualifies each real node before any pointer is followed. */
static inline int pwmc_events_read(struct pwmc_event_path*p,uint64_t core,void*opaque,
    int(*read_node)(void*,struct pwmc_event_node*,uint64_t))
{
    uint64_t head=core+0x1c368,previous=head,next;
    if(!pwmc_zero(p,sizeof(*p))||!read_node)return 0;
    p->attempted=1;pgcd_copy(p->lock,(const void*)(uintptr_t)(core+0x1c350),24);
    pgcd_copy(p->head,(const void*)(uintptr_t)head,16);pgcd_copy(p->group,(const void*)(uintptr_t)(core+0x1b130),16);
    p->pending=pwfi_le((const void*)(uintptr_t)(core+0x1dbc0),8);next=p->head[0];
    if(pwfi_le(p->lock,8)!=31||pwfi_le(p->lock+16,4)!=1||p->pending||!pgcd_equal(p->group,&pwmc_map_change_group,16))return 0;
    while(next!=head){
        unsigned index=p->count;if(index>=PWMC_EVENT_MAX||next<16||(next&7))return 0;
        struct pwmc_event_node*n=&p->node[index];uint64_t address=next-16;
        if(address>UINT64_MAX-sizeof(n->raw))return 0;
        for(unsigned k=0;k<index;k++)if(p->node[k].address==address)return 0;
        if(!read_node(opaque,n,address)||p->count!=index||n->address!=address||n->issued!=1||n->returned!=1)return 0;p->count=index+1;
        if(pwfi_le(n->raw,8)!=UINT64_C(0x746e7665)||pwfi_le(n->raw+24,8)!=previous||pgcd_equal(n->raw+56,&pwmc_map_change_group,16))return 0;
        previous=next;next=pwfi_le(n->raw+16,8);
    }
    p->complete=1;pwmc_events_digest(p,p->digest);return 1;
}
static inline int pwmc_events_capture(struct pwmc_result*r,unsigned operation)
{
    struct pwmc_event_path*p=&r->events[operation];
    if(!pwmc_zero(p,sizeof(*p))||!pwmc_source(r,operation))return pwmc_fail(r,PWMC_CONTEXT,operation||r->held);
    struct pwmc_capture_context context={r,operation};
    if(!pwmc_events_read(p,r->source[operation].core,&context,pwmc_event_capture_node))return pwmc_fail(r,PWMC_CONTEXT,operation||r->held);
    if(!pwmc_source(r,operation)||!pwmc_events_current(r,operation))return pwmc_fail(r,PWMC_CONTEXT,1);return 1;
}
static inline void pwmc_timers_digest(const struct pwmc_timer_path*p,uint8_t out[32])
{
    struct pwfi_sha256 hash;pwfi_init(&hash);const uint8_t*b=(const void*)p;
    for(size_t k=0;k<offsetof(struct pwmc_timer_path,digest);k++)pwfi_byte(&hash,b[k]);pwfi_final(&hash,out);
}
static inline int pwmc_timer_metadata_map(const struct pwmc_timer_node*n,const struct pwmc_irq_map_view*m)
{
    if(!n->address||(n->address&7)||n->address>UINT64_MAX-sizeof(n->raw)||(m->self_bytes>=sizeof(n->raw)&&n->address>=m->self_base&&n->address-m->self_base<=m->self_bytes-sizeof(n->raw))||
       n->issued!=1||n->returned!=1||n->reserved)return 0;
    uint64_t first=n->address&~UINT64_C(4095);unsigned pages=(unsigned)(((n->address+sizeof(n->raw)-1)&~UINT64_C(4095))-first)/4096+1;
    if(pages>2||n->AT_count!=pages)return 0;
    for(unsigned k=0;k<pages;k++)if(n->AT_page[k]!=first+4096*k||n->AT_raw[k]!=(UINT64_C(0xff00000000000b80)|n->AT_page[k])||
       (!polaris_efi_range_owned(m->data,m->bytes,m->stride,n->AT_page[k],4096,3)&&
        !polaris_efi_range_owned(m->data,m->bytes,m->stride,n->AT_page[k],4096,4)))return 0;
    return pages==2||(!n->AT_page[1]&&!n->AT_raw[1]);
}
static inline int pwmc_timer_metadata(const struct pwmc_result*r,unsigned operation,const struct pwmc_timer_node*n)
{const struct pgcd_result*s=&r->source[operation];const struct pwmc_irq_map_view m={s->maps[0],s->map[0].bytes,s->map[0].stride,s->self_base,s->self_bytes};return pwmc_timer_metadata_map(n,&m);}
static inline int pwmc_timers_replay_map(const struct pwmc_timer_path*p,const struct pwmc_event_path*e,uint64_t core,const struct pwmc_irq_map_view*m)
{
    uint64_t head=core+0x1c3f0,prior=head,last=0;uint8_t digest[32];pwmc_timers_digest(p,digest);
    if(!pwmc_events_replay_map(e,core,m)||p->attempted!=1||p->complete!=1||p->reserved||p->count>PWMC_TIMER_MAX||!pgcd_equal(digest,p->digest,32)||
       pwfi_le(p->lock[0],8)!=31||pwfi_le(p->lock[1],8)!=30||pwfi_le(p->lock[0]+16,4)!=1||pwfi_le(p->lock[1]+16,4)!=1)return 0;
    unsigned checker_seen=0;
    for(unsigned k=0;k<e->count;k++){
        const struct pwmc_event_node*n=&e->node[k];uint64_t level=pwfi_le(n->raw+32,8);
        if(level<=16)continue;
        if(!p->checker||n->address!=p->checker||level!=30||pwfi_le(n->raw+8,4)!=0x200||
           pwfi_le(n->raw+40,8)!=core+0xcb24||pwfi_le(n->raw+48,8)||++checker_seen!=1)return 0;
    }
    if(p->checker){
        const struct pwmc_timer_node*n=&p->checker_node;const uint8_t*b=n->raw;
        if(checker_seen!=1||n->address!=p->checker||!pwmc_timer_metadata_map(n,m)||pwfi_le(b,8)!=UINT64_C(0x746e7665)||
           pwfi_le(b+8,4)!=0x200||pwfi_le(b+12,4)||pwfi_le(b+32,8)!=30||pwfi_le(b+40,8)!=core+0xcb24||
           pwfi_le(b+48,8)||pwfi_le(b+72,8)||b[88]||pwfi_le(b+152,8)||pwfi_le(b+176,8))return 0;
        for(unsigned k=0;k<e->count;k++)if(e->node[k].address==p->checker&&!pgcd_equal(e->node[k].raw,b,88))return 0;
    }else if(p->count||!pwmc_zero(&p->checker_node,sizeof(p->checker_node)))return 0;
    for(unsigned k=0;k<p->count;k++){
        const struct pwmc_timer_node*n=&p->node[k];const uint8_t*b=n->raw;uint32_t type=(uint32_t)pwfi_le(b+8,4);uint64_t when=pwfi_le(b+168,8);
        if(!pwmc_timer_metadata_map(n,m)||pwfi_le(b,8)!=UINT64_C(0x746e7665)||b[88]||pwfi_le(b+176,8)||
           (type!=UINT32_C(0x80000000)&&type!=UINT32_C(0x80000100)&&type!=UINT32_C(0x80000200))||
           pwfi_le(b+160,8)!=prior||(k?pwfi_le(p->node[k-1].raw+152,8):p->head[0])!=n->address+152||(k&&when<last))return 0;
        if(type&0x300){uint64_t level=pwfi_le(b+32,8);if((level!=8&&level!=16)||!pwfi_le(b+40,8))return 0;}
        else if(pwfi_le(b+32,8)||pwfi_le(b+40,8)||pwfi_le(b+48,8))return 0;
        if(p->checker&&n->address<p->checker+184&&p->checker<n->address+184)return 0;
        for(unsigned j=0;j<k;j++)if(n->address<p->node[j].address+184&&p->node[j].address<n->address+184)return 0;
        prior=n->address+152;last=when;
    }
    if(p->head[1]!=prior||(p->count?pwfi_le(p->node[p->count-1].raw+152,8):p->head[0])!=head||
       !pwmc_zero(p->node+p->count,(PWMC_TIMER_MAX-p->count)*sizeof(p->node[0])))return 0;
    return 1;
}
static inline int pwmc_timers_replay(const struct pwmc_result*r,unsigned operation)
{const struct pgcd_result*s=&r->source[operation];const struct pwmc_irq_map_view m={s->maps[0],s->map[0].bytes,s->map[0].stride,s->self_base,s->self_bytes};return pwmc_timers_replay_map(&r->timers[operation],&r->events[operation],s->core,&m);}
static inline int pwmc_timers_current_map(const struct pwmc_timer_path*p,const struct pwmc_event_path*e,uint64_t core,const struct pwmc_irq_map_view*m)
{
    if(!pwmc_timers_replay_map(p,e,core,m)||pwfi_le((const void*)(uintptr_t)(core+0x1cbc8),8)!=p->checker||
       !pgcd_equal(p->head,(const void*)(uintptr_t)(core+0x1c3f0),16)||
       !pgcd_equal(p->lock[0],(const void*)(uintptr_t)(core+0x1c3d8),24)||
       !pgcd_equal(p->lock[1],(const void*)(uintptr_t)(core+0x1c400),24))return 0;
    if(p->checker&&!pgcd_equal(p->checker_node.raw,(const void*)(uintptr_t)p->checker,184))return 0;
    for(unsigned k=0;k<p->count;k++)if(!pgcd_equal(p->node[k].raw,(const void*)(uintptr_t)p->node[k].address,184))return 0;
    return 1;
}
static inline int pwmc_timers_current(const struct pwmc_result*r,unsigned operation)
{const struct pgcd_result*s=&r->source[operation];const struct pwmc_irq_map_view m={s->maps[0],s->map[0].bytes,s->map[0].stride,s->self_base,s->self_bytes};return pwmc_timers_current_map(&r->timers[operation],&r->events[operation],s->core,&m);}
static inline int pwmc_timer_capture_node(struct pwmc_result*r,unsigned operation,struct pwmc_timer_node*n,uint64_t address)
{
    struct pgcd_context*c=&r->context[operation];
    if(!address||(address&7)||address>UINT64_MAX-184||pgcd_in_self(c->record,address,184))return pwmc_fail(r,PWMC_CONTEXT,operation||r->held);
    n->address=address;n->issued=1;
    for(uint64_t at=address&~UINT64_C(4095);at<address+184;at+=4096){
        if(n->AT_count==2||(!polaris_efi_range_owned(c->record->maps[0],c->record->map[0].bytes,c->record->map[0].stride,at,4096,3)&&
           !polaris_efi_range_owned(c->record->maps[0],c->record->map[0].bytes,c->record->map[0].stride,at,4096,4)))return pwmc_fail(r,PWMC_CONTEXT,operation||r->held);
        unsigned k=n->AT_count;uint64_t where=0;n->AT_page[k]=at;
        if(!pwmc_source(r,operation)||!c->io.identity(c->io.opaque,at,4096,&where,&n->AT_raw[k])||
           !pwmc_context_intact(r,operation)||!pwmc_parameters(r)||n->issued!=1||n->returned||n->reserved||n->AT_count!=k||
           !pwmc_zero(n->raw,sizeof(n->raw))||n->address!=address||n->AT_page[k]!=at||where!=at||
           n->AT_raw[k]!=(UINT64_C(0xff00000000000b80)|at))return pwmc_fail(r,PWMC_TRANSLATION,1);
        n->AT_count=k+1;
    }
    pgcd_copy(n->raw,(const void*)(uintptr_t)address,184);n->returned=1;return 1;
}
static inline int pwmc_timer_capture_bridge(void*opaque,struct pwmc_timer_node*n,uint64_t address)
{const struct pwmc_capture_context*x=opaque;return pwmc_timer_capture_node(x->r,x->operation,n,address);}
static inline int pwmc_timers_read(struct pwmc_timer_path*p,uint64_t core,void*opaque,
    int(*read_node)(void*,struct pwmc_timer_node*,uint64_t))
{
    if(!pwmc_zero(p,sizeof(*p))||!read_node)return 0;
    p->attempted=1;p->checker=pwfi_le((const void*)(uintptr_t)(core+0x1cbc8),8);p->counter=pwfi_le((const void*)(uintptr_t)(core+0x1dc00),8);
    pgcd_copy(p->head,(const void*)(uintptr_t)(core+0x1c3f0),16);pgcd_copy(p->lock[0],(const void*)(uintptr_t)(core+0x1c3d8),24);pgcd_copy(p->lock[1],(const void*)(uintptr_t)(core+0x1c400),24);
    if(p->checker&&!read_node(opaque,&p->checker_node,p->checker))return 0;
    uint64_t head=core+0x1c3f0,next=p->head[0],prior=head;
    while(next!=head){
        unsigned index=p->count;if(index>=PWMC_TIMER_MAX||next<152||(next&7))return 0;
        struct pwmc_timer_node*n=&p->node[index];uint64_t address=next-152;
        if(p->checker&&address<p->checker+184&&p->checker<address+184)return 0;
        for(unsigned k=0;k<index;k++)if(address<p->node[k].address+184&&p->node[k].address<address+184)return 0;
        if(!read_node(opaque,n,address)||p->count!=index)return 0;p->count=index+1;
        if(pwfi_le(n->raw+160,8)!=prior)return 0;prior=next;next=pwfi_le(n->raw+152,8);
    }
    p->complete=1;pwmc_timers_digest(p,p->digest);return 1;
}
static inline int pwmc_timers_capture(struct pwmc_result*r,unsigned operation)
{
    struct pwmc_timer_path*p=&r->timers[operation];
    if(!pwmc_zero(p,sizeof(*p))||!pwmc_source(r,operation))return pwmc_fail(r,PWMC_CONTEXT,operation||r->held);
    struct pwmc_capture_context context={r,operation};
    if(!pwmc_timers_read(p,r->source[operation].core,&context,pwmc_timer_capture_bridge))return pwmc_fail(r,PWMC_CONTEXT,operation||r->held);
    if(!pwmc_timers_replay(r,operation)||!pwmc_source(r,operation)||!pwmc_timers_current(r,operation))return pwmc_fail(r,PWMC_CONTEXT,1);return 1;
}
#if defined(POLARIS_WIFI_MEMORY_SOFTWARE_PEER)
#if !__STDC_HOSTED__
#error Software IRQ register leaves must never enter physical firmware
#endif
static int pwmc_test_irq_regs(struct pwmc_result*,unsigned,unsigned);
static uint64_t pwmc_test_irq_ticks(struct pwmc_result*,unsigned,unsigned);
#endif
/* Retained typed-map DATA, never an opened context or ownership lease.
 * Real callers retain their own current source/native/callback interval. */
static inline int pwmc_irq_AT_view(const struct pwmc_irq_map_view*m,uint64_t address,uint64_t bytes,
    const struct pwmc_irq_AT*AT,unsigned capacity,unsigned count)
{
    if(!address||!bytes||address>UINT64_MAX-bytes||address+bytes>UINT64_MAX-4095||(m->self_bytes>=bytes&&address>=m->self_base&&address-m->self_base<=m->self_bytes-bytes))return 0;
    uint64_t first=address&~UINT64_C(4095);unsigned pages=(unsigned)(((address+bytes-1)&~UINT64_C(4095))-first)/4096+1;
    if(pages>capacity||count!=pages)return 0;
    for(unsigned k=0;k<count;k++)if(AT[k].page!=first+4096*k||AT[k].raw!=(UINT64_C(0xff00000000000b80)|AT[k].page)||AT[k].issued!=1||AT[k].returned!=1||
       (!polaris_efi_range_owned(m->data,m->bytes,m->stride,AT[k].page,4096,3)&&
        !polaris_efi_range_owned(m->data,m->bytes,m->stride,AT[k].page,4096,4)))return 0;
    return pwmc_zero(AT+count,(capacity-count)*sizeof(*AT));
}
static inline int pwmc_irq_AT_replay(const struct pgcd_result*s,uint64_t address,uint64_t bytes,
    const struct pwmc_irq_AT*AT,unsigned capacity,unsigned count)
{
    const struct pwmc_irq_map_view m={s->maps[0],s->map[0].bytes,s->map[0].stride,s->self_base,s->self_bytes};
    return pwmc_irq_AT_view(&m,address,bytes,AT,capacity,count);
}
static inline int pwmc_irq_owned(struct pwmc_result*r,unsigned op,uint64_t address,uint64_t bytes,
    struct pwmc_irq_AT*AT,unsigned capacity,uint32_t*count)
{
    struct pgcd_context*c=&r->context[op];
    if(!address||!bytes||address>UINT64_MAX-bytes||address+bytes>UINT64_MAX-4095||pgcd_in_self(c->record,address,bytes)||*count)return pwmc_fail(r,PWMC_CONTEXT,1);
    for(uint64_t page=address&~UINT64_C(4095);page<address+bytes;page+=4096){
        if(*count==capacity||(!polaris_efi_range_owned(c->record->maps[0],c->record->map[0].bytes,c->record->map[0].stride,page,4096,3)&&
           !polaris_efi_range_owned(c->record->maps[0],c->record->map[0].bytes,c->record->map[0].stride,page,4096,4)))return pwmc_fail(r,PWMC_CONTEXT,1);
        unsigned k=*count;struct pwmc_irq_AT*a=&AT[k];a->page=page;a->issued=1;uint64_t where=0;
        if(!pwmc_source(r,op))return 0;int returned=c->io.identity(c->io.opaque,page,4096,&where,&a->raw);a->returned=returned?1:0;
        if(!returned||!pwmc_context_intact(r,op)||!pwmc_parameters(r)||*count!=k||a->issued!=1||a->returned!=1||a->page!=page||where!=page||
           a->raw!=(UINT64_C(0xff00000000000b80)|page))return pwmc_fail(r,PWMC_TRANSLATION,1);
        *count=k+1;
    }return 1;
}
/* Original canonical immutable-image hash leaf, after the caller's genuine
 * page/translation/source qualification. It reads DATA and invokes no method. */
static inline int pwmc_irq_hash_image(struct pwmc_irq_image*p,unsigned image,unsigned phase)
{
    if(image>=PWMC_IRQ_IMAGES||phase>4)return 0;
    const struct pwmc_irq_binding*b=&pwmc_irq_bindings[image];const uint8_t*data=(const void*)(uintptr_t)p->base;
    if(p->hash_count[phase]||p->hash_failed[phase]||!pwmc_zero(p->hashes[phase],sizeof(p->hashes[phase]))||p->bytes!=b->bytes)return 0;
    uint64_t original=pwfi_le(data+b->imagebase,8);if(original&&original!=p->base)return 0;
    for(unsigned span=0;span<b->range_count;span++){
        const struct pgci_range*q=&b->ranges[span];struct pwfi_sha256 hash;pwfi_init(&hash);
        for(uint32_t first=q->rva;first<q->rva+q->bytes;){
            uint8_t chunk[64];unsigned take=q->rva+q->bytes-first;if(take>64)take=64;pgcd_copy(chunk,data+first,take);
            for(unsigned k=0;k<b->reloc_count;k++){uint32_t at=b->relocations[k];if(at>=first+take)break;if(at+8<=first)continue;
                pgci_patch_chunk(chunk,first,take,at,8,pwfi_le(data+at,8)-p->base);}
            pgci_patch_chunk(chunk,first,take,b->imagebase,8,0);
            if(take==64){pgci_transform_blocks(&hash,chunk);hash.bytes+=64;}else for(unsigned k=0;k<take;k++)pwfi_byte(&hash,chunk[k]);first+=take;
        }
        pwfi_final(&hash,p->hashes[phase][span]);p->hash_count[phase]=span+1;
        if(!pgcd_equal(p->hashes[phase][span],q->sha256,32)){p->hash_failed[phase]=span+1;return 0;}
    }return 1;
}
static inline int pwmc_irq_hash(struct pwmc_result*r,unsigned op,unsigned image,unsigned phase)
{
    struct pwmc_irq_image*p=&r->irq[op].image[image];const struct pwmc_irq_binding*b=&pwmc_irq_bindings[image];
    if(phase>4||p->hash_count[phase]||p->hash_failed[phase]||!pwmc_zero(p->hashes[phase],sizeof(p->hashes[phase]))||p->bytes!=b->bytes||
       !pwmc_irq_AT_replay(&r->source[op],p->base,p->bytes,p->AT,PWMC_IRQ_PAGES,p->AT_count))return pwmc_fail(r,PWMC_SOURCE,1);
    if(!pwmc_irq_hash_image(p,image,phase))return pwmc_fail(r,PWMC_SOURCE,1);return 1;
}
static inline int pwmc_irq_image_capture(struct pwmc_result*r,unsigned op,unsigned image,uint64_t base)
{
    struct pwmc_irq_image*p=&r->irq[op].image[image];const struct pwmc_irq_binding*b=&pwmc_irq_bindings[image];
    if(!base||(base&4095)||base>UINT64_MAX-b->bytes||!pwmc_zero(p,sizeof(*p)))return pwmc_fail(r,PWMC_SOURCE,1);
    for(unsigned k=0;k<image;k++)if(base<r->irq[op].image[k].base+r->irq[op].image[k].bytes&&r->irq[op].image[k].base<base+b->bytes)return pwmc_fail(r,PWMC_SOURCE,1);
    if(base<r->source[op].core+PGCI_IMAGE_BYTES&&r->source[op].core<base+b->bytes)return pwmc_fail(r,PWMC_SOURCE,1);
    p->base=base;p->bytes=b->bytes;p->attempted=1;
    if(!pwmc_irq_owned(r,op,base,b->bytes,p->AT,PWMC_IRQ_PAGES,&p->AT_count)||p->base!=base||p->bytes!=b->bytes||!pwmc_irq_hash(r,op,image,0))return 0;
    if(!pwmc_source(r,op)||p->base!=base||p->bytes!=b->bytes)return pwmc_fail(r,PWMC_SOURCE,1);
    pgcd_copy(p->state,(const void*)(uintptr_t)(base+b->state),b->state_bytes);p->complete=1;return 1;
}
/* Same original six readonly MRS operations, shared by the allocator and
 * the incoming-contract bootstrap caller. Callers retain their own source,
 * typed-page/native/FP/callback envelopes; this leaf grants none of those. */
static inline int pwmc_irq_regs_native(struct pwmc_irq_regs*p)
{
#if (defined(__aarch64__) || defined(__arm64__)) && !defined(POLARIS_WIFI_MEMORY_SOFTWARE_PEER) && !defined(POLARIS_WIFI_CACHE_TIMER_SOFTWARE_PEER)
    p->issued|=1;__asm__ volatile("mrs %0,CurrentEL":"=r"(p->el)::"memory");__asm__ volatile("":::"memory");p->returned|=1;
    p->issued|=2;__asm__ volatile("mrs %0,VBAR_EL1":"=r"(p->vbar)::"memory");__asm__ volatile("":::"memory");p->returned|=2;
    p->issued|=4;__asm__ volatile("mrs %0,CNTP_CTL_EL0":"=r"(p->ctl)::"memory");__asm__ volatile("":::"memory");p->returned|=4;
    p->issued|=8;__asm__ volatile("mrs %0,CNTP_CVAL_EL0":"=r"(p->cval)::"memory");__asm__ volatile("":::"memory");p->returned|=8;
    p->issued|=16;__asm__ volatile("mrs %0,CNTFRQ_EL0":"=r"(p->frequency)::"memory");__asm__ volatile("":::"memory");p->returned|=16;
    p->issued|=32;__asm__ volatile("mrs %0,CNTPCT_EL0":"=r"(p->ticks)::"memory");__asm__ volatile("":::"memory");p->returned|=32;
    return 1;
#else
    (void)p;return 0;
#endif
}
static inline int pwmc_irq_regs_read(struct pwmc_result*r,unsigned op,unsigned slot)
{
    struct pwmc_irq_regs*p=&r->irq[op].regs[slot];if(!pwmc_zero(p,sizeof(*p))||!pwmc_source(r,op))return pwmc_fail(r,PWMC_CONTEXT,1);
#if defined(POLARIS_WIFI_MEMORY_SOFTWARE_PEER)
    int returned=pwmc_test_irq_regs(r,op,slot);
#else
    int returned=pwmc_irq_regs_native(p);
#endif
    if(!returned||!pwmc_context_intact(r,op)||!pwmc_parameters(r)||p->issued!=63||p->returned!=63)return pwmc_fail(r,PWMC_CONTEXT,1);return 1;
}
static inline void pwmc_irq_digest(const struct pwmc_irq_path*p,uint8_t out[32])
{struct pwfi_sha256 s;pwfi_init(&s);const uint8_t*b=(const void*)p;for(size_t k=0;k<offsetof(struct pwmc_irq_path,digest);k++)pwfi_byte(&s,b[k]);pwfi_final(&s,out);}
static inline void pwmc_irq_input_digest(const struct pwmc_irq_path*p,unsigned slot,uint8_t out[32])
{
    struct pwfi_sha256 hash;pwfi_init(&hash);const uint8_t*b=(const void*)p;
    size_t first=offsetof(struct pwmc_irq_path,regs)+slot*sizeof(struct pwmc_irq_regs),end=first+sizeof(struct pwmc_irq_regs);
    for(size_t k=0;k<offsetof(struct pwmc_irq_path,digest);k++)if(k<first||k>=end)pwfi_byte(&hash,b[k]);pwfi_final(&hash,out);
}
static inline int pwmc_irq_bindings_map(const struct pwmc_irq_path*p,uint64_t core,uint64_t system,
    const struct pwmc_irq_map_view*m)
{
    if(p->attempted!=1||p->reserved)return 0;
    for(unsigned image=0;image<3;image++){
        const struct pwmc_irq_image*i=&p->image[image];const struct pwmc_irq_binding*b=&pwmc_irq_bindings[image];
        if(i->attempted!=1||i->complete!=1||i->reserved||i->bytes!=b->bytes||!pwmc_irq_AT_view(m,i->base,i->bytes,i->AT,PWMC_IRQ_PAGES,i->AT_count)||
           !pwmc_zero(i->table+b->table_bytes,sizeof(i->table)-b->table_bytes)||!pwmc_zero(i->state+b->state_bytes,sizeof(i->state)-b->state_bytes))return 0;
        if(p->finalized>3)return 0;
        for(unsigned phase=0;phase<2+p->finalized;phase++){
            if(i->hash_count[phase]!=b->range_count||i->hash_failed[phase])return 0;
            for(unsigned k=0;k<b->range_count;k++)if(!pgcd_equal(i->hashes[phase][k],b->ranges[k].sha256,32))return 0;
            if(!pwmc_zero(i->hashes[phase]+b->range_count,(5-b->range_count)*32))return 0;
        }
    }
    const uint8_t*t=p->image[0].table,*g=p->image[1].table,*c=p->image[2].table;uint64_t timer=p->image[0].base,gic=p->image[1].base,cpu=p->image[2].base;
    if(p->tables[0]!=timer+0x2038||p->tables[2]!=cpu+0x53d8||(p->tables[1]!=gic+0x30b8&&p->tables[1]!=gic+0x30e0)||!pgcd_equal(p->unbound_hardware_table,g,40))return 0;
    unsigned v3=p->tables[1]==gic+0x30e0;const uint32_t tm[]={0x1000,0x1214,0x1034,0x1058},cm[]={0x1b68,0x1598,0x15b0,0x15c8,0x1000,0x1208,0x1008,0x2324};
    const uint32_t gm[2][5]={{0x1040,0x1474,0x1570,0x1730,0x125c},{0x1040,0x14b4,0x1654,0x185c,0x1a98}};
    for(unsigned k=0;k<4;k++)if(pwfi_le(t+8*k,8)!=timer+tm[k])return 0;
    for(unsigned k=0;k<5;k++)if(pwfi_le(g+8*k,8)!=gic+gm[v3][k])return 0;
    for(unsigned k=0;k<8;k++)if(pwfi_le(c+8*k,8)!=cpu+cm[k])return 0;
    const uint8_t*ts=p->image[0].state,*gs=p->image[1].state,*cs=p->image[2].state;
    if(pwfi_le(ts+16,8)!=core+0x1b800||pwfi_le(ts+24,8)!=p->tables[1]||pwfi_le(ts+32,8)!=system||pwfi_le(ts+48,8)!=core+0xcbf8||
       pwfi_le(gs+8,8)!=core+0x1b800||pwfi_le(gs+24,8)!=p->handlers||pwfi_le(gs+32,8)!=system||pwfi_le(gs+72,8)!=p->handler_count||
       pwfi_le(cs,8)!=core+0x1b800||pwfi_le(cs+16,8)||pwfi_le(cs+24,8)!=gic+(v3?0x1acc:0x1294)||pwfi_le(cs+32,8)||pwfi_le(cs+40,8)||pwfi_le(cs+48,8)!=system)return 0;
    if(p->handler_count<32||p->handler_count>1020||!pwmc_irq_AT_view(m,p->handlers,p->handler_count*8,p->array_AT,3,p->array_AT_count)||
       !pwmc_irq_AT_view(m,p->tables[1],40,p->table_AT,2,p->table_AT_count))return 0;
    if(p->handlers<core+PGCI_IMAGE_BYTES&&core<p->handlers+p->handler_count*8)return 0;
    for(unsigned k=0;k<3;k++)if(p->handlers<p->image[k].base+p->image[k].bytes&&p->image[k].base<p->handlers+p->handler_count*8)return 0;
    for(unsigned k=0;k<p->handler_count;k++)if(p->handler[k]!=((k==18||k==19||k==26||k==29)?timer+0x10c8:0))return 0;
    return pwmc_zero(p->handler+p->handler_count,(PWMC_IRQ_HANDLERS-p->handler_count)*8);
}
static inline int pwmc_irq_bindings_valid(const struct pwmc_result*r,unsigned op)
{
    const struct pgcd_result*s=&r->source[op];
    const struct pwmc_irq_map_view m={s->maps[0],s->map[0].bytes,s->map[0].stride,s->self_base,s->self_bytes};
    return pwmc_irq_bindings_map(&r->irq[op],s->core,(uintptr_t)r->bound_io.system,&m);
}
static inline int pwmc_irq_current(const struct pwmc_result*r,unsigned op)
{
    const struct pwmc_irq_path*p=&r->irq[op];uint64_t core=r->source[op].core;
    if(!pwmc_irq_bindings_valid(r,op)||pwfi_le((const void*)(uintptr_t)(core+0x1cb80),8)!=p->tables[0]||pwfi_le((const void*)(uintptr_t)(core+0x1c8f8),8)!=p->tables[2]||
       !pgcd_equal(p->handler,(const void*)(uintptr_t)p->handlers,p->handler_count*8))return 0;
    for(unsigned k=0;k<3;k++){const struct pwmc_irq_image*i=&p->image[k];const struct pwmc_irq_binding*b=&pwmc_irq_bindings[k];
        if(!pgcd_equal(i->table,(const void*)(uintptr_t)p->tables[k],b->table_bytes)||!pgcd_equal(i->state,(const void*)(uintptr_t)(i->base+b->state),b->state_bytes))return 0;}
    return 1;
}
static inline int pwmc_irq_math(const struct pwmc_result*,unsigned,unsigned,uint64_t*,uint64_t*,uint64_t*);
static inline int pwmc_irq_capture(struct pwmc_result*r,unsigned op)
{
    struct pwmc_irq_path*p=&r->irq[op];uint64_t core=r->source[op].core;
    if(!pwmc_zero(p,sizeof(*p))||!pwmc_source(r,op))return pwmc_fail(r,PWMC_CONTEXT,1);p->attempted=1;
    p->tables[0]=pwfi_le((const void*)(uintptr_t)(core+0x1cb80),8);p->tables[2]=pwfi_le((const void*)(uintptr_t)(core+0x1c8f8),8);
    if(p->tables[0]<0x2038||p->tables[2]<0x53d8||!pwmc_irq_image_capture(r,op,0,p->tables[0]-0x2038))return pwmc_fail(r,PWMC_SOURCE,1);
    p->tables[1]=pwfi_le(p->image[0].state+24,8);
    if(!pwmc_irq_owned(r,op,p->tables[1],40,p->table_AT,2,&p->table_AT_count))return 0;
    pgcd_copy(p->unbound_hardware_table,(const void*)(uintptr_t)p->tables[1],40);uint64_t reg=pwfi_le(p->unbound_hardware_table,8);
    if(reg<0x1040||!pwmc_irq_image_capture(r,op,1,reg-0x1040)||!pwmc_irq_image_capture(r,op,2,p->tables[2]-0x53d8))return pwmc_fail(r,PWMC_SOURCE,1);
    for(unsigned k=0;k<3;k++)pgcd_copy(p->image[k].table,(const void*)(uintptr_t)p->tables[k],pwmc_irq_bindings[k].table_bytes);
    p->handlers=pwfi_le(p->image[1].state+24,8);p->handler_count=pwfi_le(p->image[1].state+72,8);
    if(p->handler_count<32||p->handler_count>1020||!pwmc_irq_owned(r,op,p->handlers,p->handler_count*8,p->array_AT,3,&p->array_AT_count))return pwmc_fail(r,PWMC_SOURCE,1);
    pgcd_copy(p->handler,(const void*)(uintptr_t)p->handlers,p->handler_count*8);
    uint64_t end,steps,notify;uint8_t before[32],after[32];pwmc_irq_input_digest(p,0,before);
    if(!pwmc_irq_regs_read(r,op,0))return pwmc_fail(r,PWMC_SOURCE,1);struct pwmc_irq_regs returned=p->regs[0];
    if(!pwmc_source(r,op))return pwmc_fail(r,PWMC_SOURCE,1);pwmc_irq_input_digest(p,0,after);
    if(!pgcd_equal(before,after,32)||!pgcd_equal(&returned,&p->regs[0],sizeof(returned)))return pwmc_fail(r,PWMC_SOURCE,1);
    for(unsigned k=0;k<3;k++)if(!pwmc_irq_hash(r,op,k,1))return 0;
    if(!pwmc_irq_current(r,op)||!pwmc_irq_math(r,op,0,&end,&steps,&notify))return pwmc_fail(r,PWMC_SOURCE,1);
    p->complete=1;pwmc_irq_digest(p,p->digest);return 1;
}
/* CNTP_CVAL/CNTPCT use the physical counter. The original source opening uses
 * CNTVCT; their epochs need not agree. Bound work conservatively through one
 * full duration AFTER the first physical sample, without deriving an offset.
 * This ceiling is not an admission deadline: pwmc_live still enforces the
 * unchanged original virtual opening's200ms. Neither grants interrupt ownership
 * or bounds preemption, faults, memory latency or whole-call wall time. */
/* Shared finite-work arithmetic over already qualified DATA. Physical ticks
 * and CVAL stay in their own domain; virtual_before is only overflow-checked.
 * The first physical sample plus200ms overestimates work, never renews a lease. */
static inline int pwmc_irq_work_math(const struct pwmc_irq_path*p,
    const struct pwmc_irq_regs*first,const struct pwmc_irq_regs*a,uint64_t virtual_before,
    uint64_t frequency,uint64_t counter,uint64_t minimum,
    uint64_t*end,uint64_t*steps,uint64_t*notify)
{
    const uint8_t*t=p->image[0].state;
    uint64_t period=pwfi_le(t+56,8),step=pwfi_le(t+64,8),missed=pwfi_le(t,8);
    if(a->issued!=63||a->returned!=63||a->el!=4||a->vbar!=p->image[2].base+0x4000||a->ctl>7||(a->ctl&3)!=1||
       a->frequency!=frequency||frequency!=19200000||!period||!step||!missed||period>UINT64_MAX/frequency||
       period*frequency/10000000!=step||period>UINT64_MAX/missed||virtual_before>UINT64_MAX-PGCD_FRESH_TICKS||
       first->issued!=63||first->returned!=63||!first->ticks||first->ticks>UINT64_MAX-PGCD_FRESH_TICKS)return 0;
    *end=first->ticks+PGCD_FRESH_TICKS;
    if(a->ticks<first->ticks||a->ticks>*end||a->ticks<minimum)return 0;
    uint64_t debt=*end>a->cval?*end-a->cval:0;*steps=debt/step+(debt%step!=0);if(!*steps)*steps=1;
    *notify=period*missed;
    if(*steps>(UINT64_MAX-a->cval)/step||*steps>UINT64_MAX-2||missed>UINT64_MAX-*steps-2)return 0;
    uint64_t count=missed+*steps+2;if(period>UINT64_MAX/count)return 0;
    return counter<=UINT64_MAX-period*count;
}
static inline int pwmc_irq_math(const struct pwmc_result*r,unsigned op,unsigned slot,
    uint64_t*end,uint64_t*steps,uint64_t*notify)
{
    if(slot>1)return 0;const struct pwmc_irq_path*p=&r->irq[op];
    return pwmc_irq_work_math(p,&p->regs[0],&p->regs[slot],r->source[op].before.cpu.ticks,
        r->source[op].before.cpu.frequency,r->timers[op].counter,slot?p->raise_ticks:0,end,steps,notify);
}
static inline int pwmc_irq_replay(const struct pwmc_result*r,unsigned op)
{
    const struct pwmc_irq_path*p=&r->irq[op];uint8_t digest[32];uint64_t end,steps,notify;pwmc_irq_digest(p,digest);
    return p->attempted==1&&p->complete==1&&p->finalized==3&&pwmc_irq_bindings_valid(r,op)&&pgcd_equal(p->digest,digest,32)&&
        pwmc_irq_math(r,op,0,&end,&steps,&notify)&&pwmc_irq_math(r,op,1,&end,&steps,&notify)&&
        p->scope_end_ticks==end&&p->catchup_bound==steps&&p->notify_product==notify&&
        p->core_advance_bound==pwfi_le(p->image[0].state+56,8)*(pwfi_le(p->image[0].state,8)+steps+2)&&
        p->raise_ticks>=p->regs[0].ticks&&p->raise_ticks<=end&&p->final_ticks>=p->regs[1].ticks&&p->final_ticks<=end;
}
static inline void pwmc_deferred_digest(const struct pwmc_deferred_path*p,uint8_t out[32])
{struct pwfi_sha256 h;pwfi_init(&h);for(size_t k=0;k<offsetof(struct pwmc_deferred_path,digest);k++)pwfi_byte(&h,((const uint8_t*)p)[k]);pwfi_final(&h,out);}
/* Shared ordinary-RAM capture for already-qualified original Core pages.
 * The caller supplies the current source/typed/native/FP/lifetime envelope.
 * Preserve pending/counter and the complete prefix through the first bad head;
 * never follow a queue link, clear it or dispatch a callback. */
static inline int pwmc_deferred_read(uint64_t core,unsigned first,unsigned count,
    uint64_t*pending,uint64_t*counter,uint64_t head[][2],uint32_t*captured)
{
    if(first<5||first>31||!count||count>32-first||*captured)return 0;
    *pending=pwfi_le((const void*)(uintptr_t)(core+0x1dbc0),8);
    *counter=pwfi_le((const void*)(uintptr_t)(core+0x1dc00),8);
    if(*pending&~UINT64_C(31))return 0;
    for(unsigned k=0;k<count;k++){
        uint64_t address=core+0x1c928+16*(k+first);pgcd_copy(head[k],(const void*)(uintptr_t)address,16);*captured=k+1;
        if(head[k][0]!=address||head[k][1]!=address)return 0;
    }return 1;
}
/* In this original checker, SignalEvent ca90 skips c7f0 when Type.bit9 is
 * clear. Timer-only and NotifyWait events cannot enqueue their NotifyFn from
 * this path. A NotifySignal timer could queue arbitrary8/16 code, so refuse
 * it irrespective of its current trigger/count: a future-time guess is not
 * callback authority. Unrelated unqueued signal subscribers are not called
 * by this source path; the existing map-change fanout refusal stays exact. */
static inline int pwmc_timer_signal_refusal(const struct pwmc_timer_path*t,unsigned*bad)
{for(unsigned k=0;k<t->count;k++)if(pwfi_le(t->node[k].raw+8,4)&0x200){*bad=k+1;return 0;}return 1;}
static inline int pwmc_deferred_timers(const struct pwmc_result*r,unsigned op,unsigned*bad)
{if(!pwmc_timers_replay(r,op)||!pwmc_irq_bindings_valid(r,op))return 0;return pwmc_timer_signal_refusal(&r->timers[op],bad);}
static inline int pwmc_deferred_replay(const struct pwmc_result*r,unsigned op,unsigned count)
{
    const struct pwmc_deferred_path*p=&r->deferred[op];uint64_t core=r->source[op].core;uint8_t digest[32];unsigned bad=0;
    if(count>3||p->attempted!=1||p->checks!=count||p->complete!=(count==3)||p->refusal_timer||
       p->restore_entry!=core+PWMC_RESTORE_RVA||p->checker!=r->timers[op].checker||!pwmc_deferred_timers(r,op,&bad))return 0;
    for(unsigned s=0;s<count;s++){
        const struct pwmc_deferred_sample*q=&p->sample[s];
        if(q->attempted!=1||q->complete!=1||q->head_count!=12||q->reserved||(q->pending&~UINT64_C(31)))return 0;
        for(unsigned k=0;k<12;k++){uint64_t head=core+0x1c928+16*(k+5);if(q->head[k][0]!=head||q->head[k][1]!=head)return 0;}
    }
    if(!pwmc_zero(p->sample+count,(3-count)*sizeof(p->sample[0])))return 0;
    pwmc_deferred_digest(p,digest);return pgcd_equal(digest,p->digest,32);
}
static inline int pwmc_deferred_step(struct pwmc_result*r,unsigned op,unsigned stage)
{
    struct pwmc_deferred_path*p=&r->deferred[op];uint64_t core=r->source[op].core;unsigned bad=0;
    if(stage>2||!pwmc_context_intact(r,op)||!pwmc_parameters(r)||!pwmc_call_guard_valid(r,op)||
       !pwmc_events_current(r,op)||!pwmc_timers_current(r,op)||!pwmc_irq_current(r,op))return pwmc_fail(r,PWMC_CONTEXT,1);
    if(!stage){
        if(!pwmc_zero(p,sizeof(*p)))return pwmc_fail(r,PWMC_REUSED,1);
        p->attempted=1;p->restore_entry=core+PWMC_RESTORE_RVA;p->checker=r->timers[op].checker;
    }else if(!pwmc_deferred_replay(r,op,stage))return pwmc_fail(r,PWMC_CONTEXT,1);
    if(!pwmc_deferred_timers(r,op,&bad)){p->refusal_timer=bad;return pwmc_fail(r,PWMC_CONTEXT,1);}
    struct pwmc_deferred_sample*q=&p->sample[stage];q->attempted=1;
    if(!pwmc_deferred_read(core,5,12,&q->pending,&q->counter,q->head,&q->head_count))return pwmc_fail(r,PWMC_CONTEXT,1);
    /* No clock, callback, firmware method or state-changing instruction
     * occurs between these final live equalities and the caller's ABI leaf. */
    if(pwfi_le((const void*)(uintptr_t)(core+0x1dbc0),8)!=q->pending||!pwmc_events_current(r,op)||!pwmc_timers_current(r,op)||!pwmc_irq_current(r,op))return pwmc_fail(r,PWMC_CONTEXT,1);
    for(unsigned k=0;k<12;k++){uint64_t head=core+0x1c928+16*(k+5);if(!pgcd_equal(q->head[k],(const void*)(uintptr_t)head,16))return pwmc_fail(r,PWMC_CONTEXT,1);}
    q->complete=1;p->checks=stage+1;p->complete=stage==2;pwmc_deferred_digest(p,p->digest);return 1;
}
static inline int pwmc_irq_seal_raise(struct pwmc_result*r,unsigned op)
{
    struct pwmc_irq_path*p=&r->irq[op];uint8_t digest[32];uint64_t end,steps,notify;pwmc_irq_digest(p,digest);
    if(p->complete!=1||p->finalized||p->raise_ticks||!pgcd_equal(p->digest,digest,32)||!pwmc_irq_current(r,op)||!pwmc_irq_math(r,op,0,&end,&steps,&notify))return pwmc_fail(r,PWMC_SOURCE,1);
    for(unsigned k=0;k<3;k++)if(!pwmc_irq_hash(r,op,k,2))return 0;p->finalized=1;
#if defined(POLARIS_WIFI_MEMORY_SOFTWARE_PEER)
    p->raise_ticks=pwmc_test_irq_ticks(r,op,0);
#elif defined(__aarch64__) || defined(__arm64__)
    __asm__ volatile("mrs %0,CNTPCT_EL0":"=r"(p->raise_ticks));
#endif
    if(!pwmc_context_intact(r,op)||!pwmc_parameters(r)||!pwmc_call_guard_valid(r,op)||!pwmc_irq_current(r,op)||p->raise_ticks<p->regs[0].ticks||p->raise_ticks>end)return pwmc_fail(r,PWMC_CONTEXT,1);
    pwmc_irq_digest(p,p->digest);return pwmc_deferred_step(r,op,0);
}
static inline int pwmc_irq_finalize(struct pwmc_result*r,unsigned op)
{
    struct pwmc_irq_path*p=&r->irq[op];uint64_t end,steps,notify;uint8_t digest[32],before[32],after[32];pwmc_irq_digest(p,digest);pwmc_irq_input_digest(p,1,before);
    if(p->complete!=1||p->finalized!=1||p->final_ticks||!pgcd_equal(p->digest,digest,32)||!pwmc_irq_current(r,op)||!pwmc_irq_regs_read(r,op,1))return pwmc_fail(r,PWMC_CONTEXT,1);
    pwmc_irq_input_digest(p,1,after);
    if(!pgcd_equal(before,after,32)||
       !pwmc_irq_math(r,op,0,&end,&steps,&notify)||!pwmc_irq_math(r,op,1,&end,&steps,&notify))return pwmc_fail(r,PWMC_CONTEXT,1);
    p->scope_end_ticks=end;p->catchup_bound=steps;p->notify_product=notify;
    p->core_advance_bound=pwfi_le(p->image[0].state+56,8)*(pwfi_le(p->image[0].state,8)+steps+2);
    /* All external clock/architectural leaves have returned BEFORE these
     * final complete immutable-source hashes. No callback follows them. */
    for(unsigned k=0;k<3;k++)if(!pwmc_irq_hash(r,op,k,3))return 0;p->finalized=2;
#if defined(POLARIS_WIFI_MEMORY_SOFTWARE_PEER)
    p->final_ticks=pwmc_test_irq_ticks(r,op,1); /* Explicit hosted physical counter leaf only. */
#elif defined(__aarch64__) || defined(__arm64__)
    __asm__ volatile("mrs %0,CNTPCT_EL0":"=r"(p->final_ticks));
#endif
    if(!pwmc_context_intact(r,op)||!pwmc_parameters(r)||!pwmc_call_guard_valid(r,op)||
       !pwmc_irq_current(r,op)||p->final_ticks<p->regs[1].ticks||p->final_ticks>end)return pwmc_fail(r,PWMC_CONTEXT,1);
    pwmc_irq_digest(p,p->digest);return pwmc_deferred_step(r,op,1);
}
static inline int pwmc_irq_retire(struct pwmc_result*r,unsigned op)
{
    struct pwmc_irq_path*p=&r->irq[op];uint8_t digest[32];pwmc_irq_digest(p,digest);
    if(p->finalized!=2||!pgcd_equal(p->digest,digest,32)||!pwmc_source(r,op)||!pwmc_irq_current(r,op))return pwmc_fail(r,PWMC_SOURCE,1);
    for(unsigned k=0;k<3;k++)if(!pwmc_irq_hash(r,op,k,4))return 0;p->finalized=3;pwmc_irq_digest(p,p->digest);
    if(!pwmc_irq_replay(r,op))return pwmc_fail(r,PWMC_SOURCE,1);return 1;
}
static inline void pwmc_allocator_digest(const struct pwmc_allocator_path*p,uint8_t out[32])
{
    struct pwfi_sha256 hash;pwfi_init(&hash);const uint8_t*bytes=(const void*)p;
    for(size_t k=0;k<offsetof(struct pwmc_allocator_path,digest);k++)pwfi_byte(&hash,bytes[k]);
    pwfi_final(&hash,out);
}
/* For one original map entry,165d0 needs at most two temporary descriptors:
 * one preserved right part and one inserted type. With initial stack depth0
 * and two distinct free descriptors, b2a8 need not enter c16c's recursive page
 * allocation. No descriptor is borrowed, reserved or modified by this check. */
static inline int pwmc_allocator_replay(const struct pwmc_result*r,unsigned operation)
{
    const struct pwmc_allocator_path*p=&r->allocator[operation];const struct pgcd_result*s=&r->source[operation];
    uint8_t digest[32];pwmc_allocator_digest(p,digest);
    if(p->attempted!=1||p->complete!=1||p->stack_depth||p->flushing||
       !p->map_key||p->map_key!=s->map[0].key||pwfi_le(p->lock,8)!=16||pwfi_le(p->lock+16,4)!=1||
       !pwmc_zero(p->reserved,sizeof(p->reserved))||!pgcd_equal(digest,p->digest,32)||
       !p->count[0]||p->count[0]>PWMC_MAP_NODE_MAX||p->count[1]<2||p->count[1]>PWMC_MAP_NODE_MAX||p->selected>=p->count[0])return 0;
    for(unsigned list=0;list<2;list++){
        uint64_t head=s->core+(list?0x1bcc0:0x1b358),previous=head;
        for(unsigned k=0;k<p->count[list];k++){
            const struct pwmc_map_node*n=&p->node[list][k];uint64_t first=n->address&~UINT64_C(4095);
            if(!n->address||(n->address&7)||n->address>UINT64_MAX-sizeof(n->raw)||pgcd_in_self(s,n->address,sizeof(n->raw))||
               n->issued!=1||n->returned!=1||n->reserved||pwfi_le(n->raw,8)!=UINT64_C(0x70616d6d)||n->raw[24]>1||
               pwfi_le(n->raw+16,8)!=previous||(k?pwfi_le(p->node[list][k-1].raw+8,8):p->head[list][0])!=n->address+8)return 0;
            unsigned pages=(unsigned)(((n->address+sizeof(n->raw)-1)&~UINT64_C(4095))-first)/4096+1;
            if(pages>2||n->AT_count!=pages)return 0;
            for(unsigned j=0;j<pages;j++)if(n->AT_page[j]!=first+4096*j||
               n->AT_raw[j]!=(UINT64_C(0xff00000000000b80)|n->AT_page[j])||
               (!polaris_efi_range_owned(s->maps[0],s->map[0].bytes,s->map[0].stride,n->AT_page[j],4096,3)&&
                !polaris_efi_range_owned(s->maps[0],s->map[0].bytes,s->map[0].stride,n->AT_page[j],4096,4)))return 0;
            if(pages==1&&(n->AT_page[1]||n->AT_raw[1]))return 0;
            for(unsigned earlier=0;earlier<=list;earlier++)for(unsigned j=0;j<(earlier==list?k:p->count[earlier]);j++){
                uint64_t other=p->node[earlier][j].address;
                if(n->address<other+64&&other<n->address+64)return 0;
            }
            if(!list){uint64_t lo=pwfi_le(n->raw+32,8),hi=pwfi_le(n->raw+40,8);
                if((lo&4095)||(hi&4095)!=4095||hi>=UINT64_C(0x1000000000000)||lo>hi)return 0;
                for(unsigned j=0;j<k;j++){uint64_t a=pwfi_le(p->node[0][j].raw+32,8),b=pwfi_le(p->node[0][j].raw+40,8);
                    if(lo<=b&&a<=hi)return 0;}
            }
            previous=n->address+8;
        }
        if(p->head[list][1]!=previous||(p->count[list]?pwfi_le(p->node[list][p->count[list]-1].raw+8,8):p->head[list][0])!=head||
           !pwmc_zero(p->node[list]+p->count[list],(PWMC_MAP_NODE_MAX-p->count[list])*sizeof(p->node[list][0])))return 0;
    }
    const uint8_t*selected=p->node[0][p->selected].raw;uint32_t type=operation?2:7;
    uint64_t lo=pwfi_le(selected+32,8),hi=pwfi_le(selected+40,8),attrs=pwfi_le(selected+56,8);
    if(pwfi_le(selected+28,4)!=type||pwfi_le(selected+48,8)||attrs>>63||lo>r->backing||r->backing+r->backing_bytes-1>hi||
       !polaris_efi_range_owned(s->maps[0],s->map[0].bytes,s->map[0].stride,r->backing,r->backing_bytes,type))return 0;
    for(uint64_t at=0;at<s->map[0].bytes;at+=s->map[0].stride){const struct efi_memory*d=(const void*)(s->maps[0]+at);
        if(r->backing<d->physical+d->pages*4096&&d->physical<r->backing+r->backing_bytes&&
           (d->type!=type||d->attributes!=attrs||d->virtual_address))return 0;
    }return 1;
}
static inline int pwmc_allocator_current(const struct pwmc_result*r,unsigned operation)
{
    const struct pwmc_allocator_path*p=&r->allocator[operation];uint64_t core=r->source[operation].core;
    if(!pwmc_allocator_replay(r,operation)||
       !pgcd_equal(p->lock,(const void*)(uintptr_t)(core+0x1b340),24)||
       !pgcd_equal(p->head[0],(const void*)(uintptr_t)(core+0x1b358),16)||
       !pgcd_equal(p->head[1],(const void*)(uintptr_t)(core+0x1bcc0),16)||
       pwfi_le((const void*)(uintptr_t)(core+0x1cdb0),8)!=p->map_key||
       pwfi_le((const void*)(uintptr_t)(core+0x1cc08),8)||pwfi_le((const void*)(uintptr_t)(core+0x1dc10),8))return 0;
    for(unsigned list=0;list<2;list++)for(unsigned k=0;k<p->count[list];k++)if(!pgcd_equal(p->node[list][k].raw,
        (const void*)(uintptr_t)p->node[list][k].address,64))return 0;
    return 1;
}
static inline int pwmc_allocator_capture(struct pwmc_result*r,unsigned operation)
{
    struct pwmc_allocator_path*p=&r->allocator[operation];struct pgcd_context*c=&r->context[operation];uint64_t core=c->record->core;
    if(!pwmc_zero(p,sizeof(*p))||!pwmc_source(r,operation))return pwmc_fail(r,PWMC_CONTEXT,operation||r->held);
    p->attempted=1;p->selected=UINT32_MAX;
    pgcd_copy(p->lock,(const void*)(uintptr_t)(core+0x1b340),24);
    p->map_key=pwfi_le((const void*)(uintptr_t)(core+0x1cdb0),8);
    p->stack_depth=pwfi_le((const void*)(uintptr_t)(core+0x1cc08),8);p->flushing=pwfi_le((const void*)(uintptr_t)(core+0x1dc10),8);
    if(pwfi_le(p->lock,8)!=16||pwfi_le(p->lock+16,4)!=1||p->map_key!=c->record->map[0].key||p->stack_depth||p->flushing)return pwmc_fail(r,PWMC_CONTEXT,operation||r->held);
    for(unsigned list=0;list<2;list++){
        uint64_t head=core+(list?0x1bcc0:0x1b358),previous=head,next;
        pgcd_copy(p->head[list],(const void*)(uintptr_t)head,16);next=p->head[list][0];
        while(next!=head){
            if(p->count[list]==PWMC_MAP_NODE_MAX||next<8||(next&7))return pwmc_fail(r,PWMC_CONTEXT,operation||r->held);
            struct pwmc_map_node*n=&p->node[list][p->count[list]];n->address=next-8;
            if(n->address>UINT64_MAX-64||pgcd_in_self(c->record,n->address,64))return pwmc_fail(r,PWMC_CONTEXT,operation||r->held);
            for(unsigned earlier=0;earlier<=list;earlier++)for(unsigned k=0;k<(earlier==list?p->count[list]:p->count[earlier]);k++){
                uint64_t other=p->node[earlier][k].address;if(n->address<other+64&&other<n->address+64)return pwmc_fail(r,PWMC_CONTEXT,operation||r->held);
            }
            n->issued=1;
            for(uint64_t at=n->address&~UINT64_C(4095);at<n->address+64;at+=4096){
                if(n->AT_count==2||(!polaris_efi_range_owned(c->record->maps[0],c->record->map[0].bytes,c->record->map[0].stride,at,4096,3)&&
                   !polaris_efi_range_owned(c->record->maps[0],c->record->map[0].bytes,c->record->map[0].stride,at,4096,4)))return pwmc_fail(r,PWMC_CONTEXT,operation||r->held);
                unsigned k=n->AT_count;uint64_t where=0;n->AT_page[k]=at;
                if(!pwmc_context_intact(r,operation)||!pwmc_parameters(r)||
                   !c->io.identity(c->io.opaque,at,4096,&where,&n->AT_raw[k])||!pwmc_context_intact(r,operation)||!pwmc_parameters(r)||
                   n->address!=next-8||n->AT_page[k]!=at||where!=at||
                   n->AT_raw[k]!=(UINT64_C(0xff00000000000b80)|at))return pwmc_fail(r,PWMC_TRANSLATION,1);
                n->AT_count=k+1;
            }
            pgcd_copy(n->raw,(const void*)(uintptr_t)n->address,64);n->returned=1;p->count[list]++;
            if(pwfi_le(n->raw,8)!=UINT64_C(0x70616d6d)||pwfi_le(n->raw+16,8)!=previous)return pwmc_fail(r,PWMC_CONTEXT,operation||r->held);
            if(!list&&pwfi_le(n->raw+32,8)<=r->backing&&r->backing+r->backing_bytes-1<=pwfi_le(n->raw+40,8)){
                if(p->selected!=UINT32_MAX)return pwmc_fail(r,PWMC_CONTEXT,operation||r->held);p->selected=p->count[0]-1;
            }
            previous=next;next=pwfi_le(n->raw+8,8);
        }
    }
    p->complete=1;pwmc_allocator_digest(p,p->digest);
    if(!pwmc_allocator_replay(r,operation))return pwmc_fail(r,PWMC_CONTEXT,operation||r->held);
    if(!pwmc_source(r,operation)||!pwmc_allocator_current(r,operation))return pwmc_fail(r,PWMC_CONTEXT,1);
    return 1;
}
/* No mutable lookup is executed: actual source-bound ABI entries only.
 * The software peer replaces only these two call leaves in hosted tests. */
#if defined(POLARIS_WIFI_MEMORY_SOFTWARE_PEER)
#if !__STDC_HOSTED__
#error Software EFI allocation leaves must never enter the physical firmware
#endif
static int pwmc_test_call(struct pwmc_result*,unsigned);
static int pwmc_test_TPL(struct pwmc_result*,unsigned,unsigned);
#endif
static inline int pwmc_retained_claim(const struct pwmc_result*);
static inline int pwmc_higher_queues(struct pwmc_result*r,unsigned operation,
    struct pwmc_tpl_transition*t,unsigned sample)
{
    uint64_t core=r->source[operation].core;t->pending[sample]=pwfi_le((const void*)(uintptr_t)(core+0x1dbc0),8);
    if(t->pending[sample]&~UINT64_C(0x1ffff))return 0;
    for(unsigned level=17;level<32;level++){
        uint64_t head=core+0x1c928+16*level;pgcd_copy(t->higher[sample][level-17],(const void*)(uintptr_t)head,16);
        t->higher_count[sample]=level-16;
        if(t->higher[sample][level-17][0]!=head||t->higher[sample][level-17][1]!=head)return 0;
    }return 1;
}
static inline int pwmc_tpl_transition_valid(const struct pwmc_result*r,unsigned operation,unsigned restore)
{
    const struct pwmc_tpl_scope*p=&r->TPL[operation];const struct pwmc_tpl_transition*t=&p->transition[restore];
    uint64_t core=r->source[operation].core;
    if(t->issued!=1||t->returned!=1||t->unknown||t->observed!=0x1ff||t->higher_count[0]!=15||t->higher_count[1]!=15||
       t->entry!=core+(restore?PWMC_RESTORE_RVA:PWMC_RAISE_RVA)||t->argument!=(restore?4:16)||
       t->value!=(restore?UINT64_MAX:4)||t->TPL_before!=(restore?16:4)||t->TPL_after!=(restore?4:16)||
       t->native_address!=r->bound_native_flag||t->native_before||t->native_after||
       !pwfc_arch_stable(&t->before.cpu,&t->after.cpu)||t->before.cpu.daif||t->before.cpu.group1!=1||
       t->after.cpu.daif||t->after.cpu.group1!=1||t->before.cpacr!=t->after.cpacr||((t->before.cpacr>>20)&3)!=3||
       !pgcd_equal(t->BS_before,t->BS_after,PWMC_BS_BYTES)||!pgcd_equal(t->BS_before,r->call[operation].BS_before,PWMC_BS_BYTES))return 0;
    for(unsigned sample=0;sample<2;sample++){
        if(t->pending[sample]&~UINT64_C(0x1ffff))return 0;
        for(unsigned level=17;level<32;level++){uint64_t head=core+0x1c928+16*level;
            if(t->higher[sample][level-17][0]!=head||t->higher[sample][level-17][1]!=head)return 0;}
    }return 1;
}
static inline int pwmc_higher_current(const struct pwmc_result*r,unsigned operation)
{
    uint64_t core=r->source[operation].core;
    if(pwfi_le((const void*)(uintptr_t)(core+0x1dbc0),8)&~UINT64_C(0x1ffff))return 0;
    for(unsigned level=17;level<32;level++){
        uint64_t head=core+0x1c928+16*level;
        if(pwfi_le((const void*)(uintptr_t)head,8)!=head||pwfi_le((const void*)(uintptr_t)(head+8),8)!=head)return 0;
    }return 1;
}
static inline void pwmc_tpl_intent_digest(const struct pwmc_tpl_transition*t,uint8_t out[32])
{
    struct pwfi_sha256 s;pwfi_init(&s);
    const void*part[]={&t->entry,&t->argument,&t->TPL_before,&t->native_address,&t->pending[0],
        t->higher[0],&t->before,&t->native_before,&t->higher_count[0],t->BS_before};
    const size_t bytes[]={8,8,8,8,8,sizeof(t->higher[0]),sizeof(t->before),4,4,PWMC_BS_BYTES};
    for(unsigned n=0;n<sizeof(bytes)/sizeof(bytes[0]);n++)for(size_t k=0;k<bytes[n];k++)pwfi_byte(&s,((const uint8_t*)part[n])[k]);
    pwfi_final(&s,out);
}
static inline int pwmc_tpl_intent(const struct pwmc_result*r,unsigned operation,unsigned restore,unsigned returned,unsigned observed)
{
    const struct pwmc_tpl_scope*p=&r->TPL[operation];const struct pwmc_tpl_transition*t=&p->transition[restore];uint8_t digest[32];
    if(!pwmc_context_intact(r,operation)||r->error||r->unknown||p->unknown||p->attempted!=1||p->held!=1||p->completed||
       !pwmc_parameters(r)||!pwmc_call_guard_valid(r,operation)||t->issued!=1||t->returned!=returned||t->unknown!=1||
       t->observed!=observed||t->higher_count[0]!=15||t->higher_count[1]||t->pending[1]||!pwmc_zero(t->higher[1],sizeof(t->higher[1]))||
       t->entry!=r->source[operation].core+(restore?PWMC_RESTORE_RVA:PWMC_RAISE_RVA)||
       t->argument!=(restore?4:16)||t->TPL_before!=(restore?16:4)||t->native_address!=r->bound_native_flag||t->native_before||
       t->value!=(returned&&!restore?4:UINT64_MAX)||
       (observed==15&&(t->TPL_after||t->native_after||!pwmc_zero(&t->after,sizeof(t->after))||!pwmc_zero(t->BS_after,PWMC_BS_BYTES)))||
       (observed==255&&(t->TPL_after!=(restore?4:16)||t->native_after||!pgcd_equal(t->BS_before,t->BS_after,PWMC_BS_BYTES))))return 0;
    pwmc_tpl_intent_digest(t,digest);return pgcd_equal(digest,p->intent_digest[restore],32);
}
static inline int pwmc_tpl_actual(struct pwmc_result*r,unsigned operation,unsigned restore)
{
    const struct pwmc_tpl_scope*p=&r->TPL[operation];const struct pwmc_tpl_transition*t=&p->transition[restore];
    const struct pwmc_call*q=&r->call[operation];const struct pgcd_context*c=&r->context[operation];
    if(!pwmc_tpl_intent(r,operation,restore,0,15)||r->unknown||r->error||p->unknown||p->attempted!=1||p->held!=1||p->completed||
       !pwmc_context_intact(r,operation)||!pwmc_parameters(r)||!pwmc_call_guard_valid(r,operation)||!pwmc_higher_current(r,operation)||!pwmc_timers_current(r,operation)||!pgcd_equal(&c->io,&r->bound_io,sizeof(c->io))||
       t->issued!=1||t->returned||t->unknown!=1||t->observed!=15||t->higher_count[0]!=15||t->higher_count[1]||
       t->entry!=c->record->core+(restore?PWMC_RESTORE_RVA:PWMC_RAISE_RVA)||
       t->argument!=(restore?p->transition[0].value:16)||t->value!=UINT64_MAX||t->TPL_before!=(restore?16:4)||
       t->native_address!=r->bound_native_flag||t->native_before||
       pwfi_le((const void*)(uintptr_t)(c->record->core+0x1b098),8)!=(restore?16:4)||
       *(const volatile uint32_t*)(uintptr_t)r->bound_native_flag||
       !pgcd_equal(t->BS_before,c->io.system->boot,PWMC_BS_BYTES)||!pgcd_equal(t->BS_before,q->BS_before,PWMC_BS_BYTES)||
       (uintptr_t)c->io.system->boot->raise_tpl!=c->record->core+PWMC_RAISE_RVA||
       (uintptr_t)c->io.system->boot->restore_tpl!=c->record->core+PWMC_RESTORE_RVA)return 0;
    if(!restore&&!pwmc_irq_seal_raise(r,operation))return 0;
    if(restore){
        if(!pwmc_tpl_transition_valid(r,operation,0)||q->issued!=1||q->returned!=1||q->status||q->unknown!=1||
           p->map.issued!=1||p->map.returned!=1||!p->map.valid||p->map.status||p->map_unknown||
           p->hash_count!=5||p->hash_failed)return 0;
        for(unsigned k=0;k<5;k++)if(!pgcd_equal(p->hashes[k],pgci_ranges[k].sha256,32))return 0;
        if(!pwmc_maps_delta(&c->record->map[0],c->record->maps[0],&p->map,p->maps,r->backing,r->backing_bytes,operation))return 0;
        if(!pwmc_deferred_step(r,operation,2))return 0;
    }else if(q->issued||q->returned||q->unknown||p->transition[1].issued||p->map.issued)return 0;
#if defined(POLARIS_WIFI_MEMORY_SOFTWARE_PEER)
    return pwmc_test_TPL(r,operation,restore);
#else
    if(restore)c->io.system->boot->restore_tpl(t->argument);
    else r->TPL[operation].transition[0].value=c->io.system->boot->raise_tpl(t->argument);
    return 1;
#endif
}
static inline int pwmc_tpl_step(struct pwmc_result*r,unsigned operation,unsigned restore)
{
    struct pwmc_tpl_scope*p=&r->TPL[operation];struct pwmc_tpl_transition*t=&p->transition[restore];
    struct pgcd_context*c=&r->context[operation];uint64_t core=c->record->core;
    if(!pwmc_zero(t,sizeof(*t))||!pwmc_source(r,operation))return pwmc_fail(r,PWMC_CONTEXT,1);
    t->entry=core+(restore?PWMC_RESTORE_RVA:PWMC_RAISE_RVA);t->argument=restore?p->transition[0].value:16;t->value=UINT64_MAX;
    t->TPL_before=pwfi_le((const void*)(uintptr_t)(core+0x1b098),8);t->before=c->record->after;t->observed=1;
    if(t->TPL_before!=(restore?16:4))return pwmc_fail(r,PWMC_CONTEXT,1);
    t->native_address=r->bound_native_flag;t->native_before=*(const volatile uint32_t*)(uintptr_t)t->native_address;t->observed|=2;
    if(t->native_before)return pwmc_fail(r,PWMC_CONTEXT,1);
    pgcd_copy(t->BS_before,c->io.system->boot,PWMC_BS_BYTES);t->observed|=4;
    if(!pwmc_higher_queues(r,operation,t,0))return pwmc_fail(r,PWMC_CONTEXT,1);t->observed|=8;
    pwmc_tpl_intent_digest(t,p->intent_digest[restore]);t->issued=t->unknown=p->held=1;c->io.order(c->io.opaque);
    int returned=pwmc_tpl_actual(r,operation,restore);t->returned=returned?1:0;c->io.order(c->io.opaque);
    if(!returned){p->unknown=1;return pwmc_fail(r,PWMC_SERVICE,1);} /* No sampling or guessed restoration. */
    if(!pwmc_tpl_intent(r,operation,restore,1,15)){p->unknown=1;return pwmc_fail(r,PWMC_CONTEXT,1);}
    t->TPL_after=pwfi_le((const void*)(uintptr_t)(core+0x1b098),8);t->observed|=16;
    if(t->TPL_after!=(restore?4:16)||(!restore&&t->value!=4)){p->unknown=1;return pwmc_fail(r,PWMC_CONTEXT,1);}
    t->native_after=*(const volatile uint32_t*)(uintptr_t)t->native_address;t->observed|=32;
    if(t->native_after){p->unknown=1;return pwmc_fail(r,PWMC_CONTEXT,1);}
    pgcd_copy(t->BS_after,c->io.system->boot,PWMC_BS_BYTES);t->observed|=64;
    if(!pgcd_equal(t->BS_before,t->BS_after,PWMC_BS_BYTES)){p->unknown=1;return pwmc_fail(r,PWMC_CONTEXT,1);}
    struct pgcd_result*source=&r->source[operation];unsigned before=source->arch_returned;int arch=pwmc_live(r,operation,&t->after);
    if(source->arch_returned==before+1)t->observed|=128;
    if(!arch||!pwmc_tpl_intent(r,operation,restore,1,255)||!pwmc_higher_queues(r,operation,t,1)){p->unknown=1;return pwmc_fail(r,PWMC_CONTEXT,1);}
    t->observed|=256;
    t->unknown=0;
    if(!pwmc_tpl_transition_valid(r,operation,restore)||!pwmc_source(r,operation)){t->unknown=p->unknown=1;return pwmc_fail(r,PWMC_CONTEXT,1);}
    return 1;
}
static inline int pwmc_tpl_post_map(struct pwmc_result*r,unsigned operation)
{
    struct pwmc_tpl_scope*p=&r->TPL[operation];struct pgcd_context*c=&r->context[operation];struct polaris_efi_memory checked;
    if(!pwmc_source(r,operation)||p->map.issued||!pwmc_zero(p->maps,sizeof(p->maps)))return pwmc_fail(r,PWMC_CONTEXT,1);
    p->map_entry=c->record->original_GetMap;p->map.status=UINT64_MAX;p->map.bytes=PGCD_MAP_CAP;
    p->map_native_before=*(const volatile uint32_t*)(uintptr_t)r->bound_native_flag;p->map.issued=p->map_unknown=1;c->io.order(c->io.opaque);
    if(p->map_native_before||p->map_entry!=c->record->core+0xd3ec||p->map_entry!=(uintptr_t)c->io.system->boot->get_map||
       !pwmc_source(r,operation)||!pwmc_timers_current(r,operation)||!pgcd_equal(r->call[operation].BS_before,c->io.system->boot,PWMC_BS_BYTES))return pwmc_fail(r,PWMC_SOURCE,1);
    int returned=c->io.map(c->io.opaque,c->io.system,&p->map,p->maps);p->map.returned=returned?1:0;c->io.order(c->io.opaque);
    if(!returned||p->map.status)return pwmc_fail(r,PWMC_MAP,1);
    if(!pwmc_context_intact(r,operation)||!pwmc_parameters(r)||!pwmc_call_guard_valid(r,operation)||
       pwmc_expected_TPL(r,operation)!=16||!pwmc_tpl_transition_valid(r,operation,0)||p->held!=1||p->completed||
       p->map.issued!=1||p->map.returned!=1||
       p->map_entry!=c->record->original_GetMap)return pwmc_fail(r,PWMC_CONTEXT,1);
    if(!polaris_efi_memory_check(p->maps,p->map.bytes,PGCD_MAP_CAP,p->map.stride,&checked)||p->map.version!=1||
       !p->map.key||!pgcd_equal(r->call[operation].BS_before,c->io.system->boot,PWMC_BS_BYTES))return pwmc_fail(r,PWMC_MAP,1);
    p->map.valid=1;p->map_native_after=*(const volatile uint32_t*)(uintptr_t)r->bound_native_flag;
    if(p->map_native_after||!pwmc_source(r,operation)||
       !pwmc_maps_delta(&c->record->map[0],c->record->maps[0],&p->map,p->maps,r->backing,r->backing_bytes,operation))return pwmc_fail(r,PWMC_MAP,1);
    p->map_unknown=0;
    if(!pgci_verify((const void*)(uintptr_t)c->record->core,c->record->core,PGCI_IMAGE_BYTES,p->hashes,&p->hash_failed,&p->hash_count)||
       !pwmc_source(r,operation))return pwmc_fail(r,PWMC_SOURCE,1);
    return 1;
}
static inline void pwmc_tpl_digest(const struct pwmc_tpl_scope*p,uint8_t out[32])
{
    struct pwfi_sha256 hash;pwfi_init(&hash);const uint8_t*bytes=(const void*)p;
    for(size_t k=0;k<offsetof(struct pwmc_tpl_scope,digest);k++)pwfi_byte(&hash,bytes[k]);pwfi_final(&hash,out);
}
static inline int pwmc_tpl_replay(const struct pwmc_result*r,unsigned operation)
{
    const struct pwmc_tpl_scope*p=&r->TPL[operation];const struct pgcd_result*s=&r->source[operation];uint8_t digest[32];
    pwmc_tpl_digest(p,digest);
    if(p->attempted!=1||p->unknown||p->held||p->completed!=1||p->reserved||p->hash_count!=5||p->hash_failed||
       !pgcd_equal(p->digest,digest,32)||!pwmc_tpl_transition_valid(r,operation,0)||!pwmc_tpl_transition_valid(r,operation,1)||
       p->map.issued!=1||p->map.returned!=1||!p->map.valid||p->map.status||p->map_unknown||p->map_native_before||p->map_native_after||
       p->map_entry!=s->core+0xd3ec||!p->map.bytes||p->map.bytes>PGCD_MAP_CAP||
       p->map.bytes!=s->map[1].bytes||p->map.key!=s->map[1].key||p->map.stride!=s->map[1].stride||p->map.version!=s->map[1].version||
       !pgcd_equal(p->maps,s->maps[1],p->map.bytes)||!pwmc_zero(p->maps+p->map.bytes,PGCD_MAP_CAP-p->map.bytes)||
       !pwmc_maps_delta(&s->map[0],s->maps[0],&p->map,p->maps,r->backing,r->backing_bytes,operation))return 0;
    for(unsigned k=0;k<5;k++)if(!pgcd_equal(p->hashes[k],pgci_ranges[k].sha256,32))return 0;
    return 1;
}
static inline int pwmc_actual_call(struct pwmc_result*r,unsigned operation)
{
    struct pwmc_call*q=&r->call[operation];
    if(!pwmc_context_intact(r,operation)||!pwmc_parameters(r)||q->requested!=r->backing||q->returned_address!=r->backing||q->pages!=r->pages||
       q->native_address!=r->bound_native_flag||q->entry!=r->source[operation].core+(operation?PWMC_FREE_RVA:PWMC_ALLOC_RVA)||
       q->issued!=1||q->returned||q->unknown!=1||q->guard.entered!=1||q->guard.left||q->guard.unknown!=1||
       pwmc_expected_TPL(r,operation)!=16||r->TPL[operation].held!=1||r->TPL[operation].transition[1].issued||
       pwfi_le((const void*)(uintptr_t)(r->source[operation].core+0x1b098),8)!=16||
       *(const volatile uint32_t*)(uintptr_t)r->bound_native_flag||
       !pgcd_equal(q->BS_before,r->context[operation].io.system->boot,PWMC_BS_BYTES)||
       !pwmc_call_guard_valid(r,operation)||!pwmc_higher_current(r,operation)||
       !pwmc_events_current(r,operation)||!pwmc_allocator_current(r,operation)||!pwmc_timers_current(r,operation)||!pwmc_irq_current(r,operation)||(operation&&!pwmc_retained_claim(r)))return 0;
    if(!pwmc_irq_finalize(r,operation)||!pwmc_call_guard_valid(r,operation)||!pwmc_timers_current(r,operation)||
       !pwmc_context_intact(r,operation)||!pwmc_parameters(r))return 0;
#if defined(POLARIS_WIFI_MEMORY_SOFTWARE_PEER)
    return pwmc_test_call(r,operation);
#else
    struct efi_boot*b=r->context[operation].io.system->boot;
    if(operation)q->status=b->free_pages(q->requested,q->pages);
    else q->status=b->allocate_pages(2,2,q->pages,&q->returned_address);
    return 1;
#endif
}
static inline int pwmc_close_source(struct pwmc_result*r,unsigned operation)
{
    struct pgcd_context*c=&r->context[operation];
    if(!pgcd_map_read(c,1)||!pgcd_equal(r->call[operation].BS_before,c->io.system->boot,PWMC_BS_BYTES)||
       !pgcd_snapshot(c,1)||!pwmc_source(r,operation))return pwmc_fail(r,PWMC_SOURCE,1);
    if(!pgcd_equal(r->call[operation].BS_before,r->call[operation].BS_after,PWMC_BS_BYTES))return pwmc_fail(r,PWMC_SOURCE,1);
    const struct pwmc_tpl_scope*p=&r->TPL[operation];const struct pgcd_map*m=&c->record->map[1];
    if(p->map.bytes!=m->bytes||p->map.key!=m->key||p->map.stride!=m->stride||p->map.version!=m->version||
       !pgcd_equal(p->maps,c->record->maps[1],m->bytes))return pwmc_fail(r,PWMC_MAP,1);
    /* This is an expected-mutating allocation source operation, not an
     * original read-only GCD finish. Keep that original RAW phase unchanged. */
    return 1;
}
static inline int pwmc_invoke(struct pwmc_result*r,unsigned operation)
{
    struct pgcd_context*c=&r->context[operation];struct pgcd_result*s=c->record;struct pwmc_call*q=&r->call[operation];
    struct pwmc_tpl_scope*p=&r->TPL[operation];
    if(!pwmc_zero(p,sizeof(*p)))return pwmc_fail(r,PWMC_REUSED,operation||r->held);
    if(!pwmc_allocator_capture(r,operation)||!pwmc_events_capture(r,operation)||!pwmc_timers_capture(r,operation)||!pwmc_irq_capture(r,operation)||!pwmc_service_enter(r,operation))return pwmc_fail(r,PWMC_CONTEXT,operation||r->held);
    q->entry=s->core+(operation?PWMC_FREE_RVA:PWMC_ALLOC_RVA);q->pages=r->pages;
    q->requested=q->returned_address=r->backing;q->status=UINT64_MAX;q->native_address=r->native_flag;
    q->native_before=*(const volatile uint32_t*)(uintptr_t)r->native_flag;
    q->profile_hook=pwfi_le((const void*)(uintptr_t)(s->core+0x1cb78),8);
    q->pending_events=pwfi_le((const void*)(uintptr_t)(s->core+0x1dbc0),8);
    pgcd_copy(q->BS_before,c->io.system->boot,PWMC_BS_BYTES);
    if(q->native_before||q->profile_hook||!pwmc_source(r,operation))return pwmc_fail(r,PWMC_CONTEXT,1);
    p->attempted=1;
    if(!pwmc_tpl_step(r,operation,0))return 0;
    if(!pwmc_source(r,operation)||!pwmc_events_current(r,operation)||!pwmc_allocator_current(r,operation)||!pwmc_timers_current(r,operation)){
        p->unknown=1;return pwmc_fail(r,PWMC_CONTEXT,1);
    }
    q->issued=q->unknown=r->held=1;c->io.order(c->io.opaque);
    int returned=pwmc_actual_call(r,operation);q->returned=returned?1:0;c->io.order(c->io.opaque);
    if(!returned||q->status){p->unknown=1;return pwmc_fail(r,PWMC_SERVICE,1);} /* No post-failure sampling or cleanup. */
    q->native_after=*(const volatile uint32_t*)(uintptr_t)r->native_flag;
    if(q->native_after||!pwmc_tpl_post_map(r,operation)||!pwmc_tpl_step(r,operation,1)){
        p->unknown=1;return pwmc_fail(r,PWMC_CONTEXT,1);
    }
    pgcd_copy(q->BS_after,c->io.system->boot,PWMC_BS_BYTES);
    if(!pwmc_service_leave(r,operation,returned)||q->native_after||
       !pgcd_equal(q->BS_before,c->io.system->boot,PWMC_BS_BYTES)||!pwmc_close_source(r,operation)||!pwmc_irq_retire(r,operation))return pwmc_fail(r,PWMC_SERVICE,1);
    p->held=0;p->completed=1;pwmc_tpl_digest(p,p->digest);
    if(!pwmc_tpl_replay(r,operation)||!pwmc_deferred_replay(r,operation,3))return pwmc_fail(r,PWMC_CONTEXT,1);
    q->unknown=0;c->io.order(c->io.opaque);return 1;
}
static inline int pwmc_translation_valid(const struct pwmc_translation*t)
{
    return t->read_issued==1&&t->read_returned==1&&t->write_issued==1&&t->write_returned==1&&
        t->saved==t->restored&&t->read_par==(UINT64_C(0xff00000000000b80)|t->page)&&t->write_par==t->read_par;
}
static inline int pwmc_retained_claim(const struct pwmc_result*r)
{
    const struct pgcd_result*s=&r->source[0];const struct pwmc_call*q=&r->call[0];const struct pgcd_service_guard*g=&q->guard;
    if(r->bound!=1||!r->attempted||!r->allocated||!r->held||r->released||r->error||r->unknown||r->external_issued||
       !pwmc_parameters(r)||r->translated!=r->pages||r->translation_pending||
       q->issued!=1||q->returned!=1||q->unknown||q->status||q->map_checked!=1||q->requested!=r->backing||
       q->returned_address!=r->backing||q->pages!=r->pages||q->entry!=s->core+PWMC_ALLOC_RVA||
       q->native_address!=r->bound_native_flag||q->native_before||q->native_after||q->profile_hook||
       g->entered!=1||g->left!=1||g->foreign_returned!=1||g->unknown||g->fp.saved!=1||g->fp.restored!=1||
       g->TPL_before!=4||g->TPL_after!=4||g->boot_before!=s->core+0x1b800||g->boot_before!=g->boot_after||
       g->tables_before!=g->tables_after||g->count_before!=g->count_after||
       !r->context[0].finished||r->context[0].record!=s||r->context[0].ticket!=&r->ticket[0]||
       r->ticket[0].spent!=1||r->ticket[0].result!=(uintptr_t)s||s->attempted!=1||s->error||s->uncertain||s->outstanding||
       s->hash_count[0]!=5||s->hash_count[1]!=5||s->hash_failed[0]||s->hash_failed[1]||
       r->final_hash_count[0]!=5||r->final_hash_failed[0]||!r->native_reads[0]||r->native_last[0]||
       !pgcd_equal(q->BS_before,q->BS_after,PWMC_BS_BYTES)||!pwmc_events_replay(r,0)||!pwmc_allocator_replay(r,0)||!pwmc_tpl_replay(r,0)||!pwmc_timers_replay(r,0)||!pwmc_irq_replay(r,0)||!pwmc_deferred_replay(r,0,3)||!pwmc_map_delta(s,r->backing,r->backing_bytes,0))return 0;
    for(unsigned k=0;k<5;k++)if(!pgcd_equal(s->hashes[0][k],pgci_ranges[k].sha256,32)||
       !pgcd_equal(s->hashes[1][k],pgci_ranges[k].sha256,32)||!pgcd_equal(r->final_hashes[0][k],pgci_ranges[k].sha256,32))return 0;
    for(unsigned k=0;k<r->pages;k++)if(r->AT[k].page!=r->backing+4096*k||!pwmc_translation_valid(&r->AT[k]))return 0;
    return pwmc_zero(r->AT+r->pages,(PWMC_PAGES-r->pages)*sizeof(r->AT[0]));
}
static inline int pwmc_actual_translate(struct pwmc_translation*t)
{
#if defined(__aarch64__) || defined(__arm64__)
    __asm__ volatile("mrs %0,par_el1":"=r"(t->saved));t->read_issued=1;
    __asm__ volatile("at s1e1r,%1\n\tisb\n\tmrs %0,par_el1":"=r"(t->read_par):"r"(t->page):"memory");t->read_returned=1;
    t->write_issued=1;
    __asm__ volatile("at s1e1w,%1\n\tisb\n\tmrs %0,par_el1":"=r"(t->write_par):"r"(t->page):"memory");t->write_returned=1;
    __asm__ volatile("msr par_el1,%1\n\tisb\n\tmrs %0,par_el1":"=r"(t->restored):"r"(t->saved):"memory");return 1;
#else
    (void)t;return 0;
#endif
}
static inline int pwmc_final_source(struct pwmc_result*r,unsigned operation)
{
    struct pgcd_result*s=&r->source[operation];
    if(!pwmc_source(r,operation)||r->final_hash_count[operation]||
       !pgci_verify((const void*)(uintptr_t)s->core,s->core,PGCI_IMAGE_BYTES,r->final_hashes[operation],
        &r->final_hash_failed[operation],&r->final_hash_count[operation])||!pwmc_source(r,operation))return pwmc_fail(r,PWMC_SOURCE,1);
    return 1;
}
static inline int pwmc_claim(struct pwmc_result*r,int(*translate)(struct pwmc_translation*))
{
    if(!r||!r->bound||r->attempted)return 0;r->attempted=1;
    if(!translate||r->kind>PWMC_RMTFS||r->error||r->unknown||r->held||r->allocated||r->released||r->external_issued||
       r->translated||r->translation_pending||!pwmc_zero(r->AT,sizeof(r->AT))||
       r->context[0].opened||r->context[0].finished||r->ticket[0].spent||r->source[0].attempted)return pwmc_fail(r,PWMC_ARGUMENT,0);
    struct pgcd_context*c=&r->context[0];
    if(c->record!=&r->source[0]||c->ticket!=&r->ticket[0]||!pgcd_equal(&c->io,&r->bound_io,sizeof(c->io)))return pwmc_fail(r,PWMC_ARGUMENT,0);
    /* This first pgcd_open still uses the incoming UEFI GetMap contract;
     * the later paired-page gates do not qualify its bootstrap. Original
     * GetMap also walks the distinct80B GCD list at Core+1bd60 and uses the
     *15x48B memory-type policy, not just our64B allocator lists. The actual
     * parent's map_snapshot omits its local map key and precedes subsequent
     * payload allocation. Never treat that snapshot, a closed GCD context or
     * an unobserved native flag as fresh bootstrap/callback authority. */
    if(!pgcd_open(c)||!pwmc_source(r,0))return pwmc_fail(r,PWMC_SOURCE,pgcd_uncertain(c));
    if(!pwmc_select(c->record,r->kind,&r->backing))return pwmc_fail(r,PWMC_RANGE,0);
    r->backing_bytes=pwmc_bytes(r->kind);r->pages=(uint32_t)(r->backing_bytes/4096);
    r->exposed=r->backing+(r->kind==PWMC_RMTFS?4096:0);r->exposed_bytes=r->kind==PWMC_MSA?0x100000:0x200000;
    if(!pwmc_layout(r)||!pwmc_invoke(r,0))return 0;
    /* Even a returned EFI error may have partial effects: retain the claim
     * UNKNOWN unless a future explicit error-path full-map proof is added. */
    if(r->call[0].status||r->call[0].returned_address!=r->backing||!pwmc_map_delta(c->record,r->backing,r->backing_bytes,0))return pwmc_fail(r,PWMC_MAP,1);
    r->call[0].map_checked=1;
    for(unsigned k=0;k<r->pages;k++){
        struct pwmc_translation*t=&r->AT[k];t->page=r->backing+4096*k;r->translation_pending=k+1;c->io.order(c->io.opaque);
        if(!pwmc_source(r,0)||!translate(t)||t->page!=r->backing+4096*k||!pwmc_translation_valid(t)||!pwmc_source(r,0))return pwmc_fail(r,PWMC_TRANSLATION,1);
        r->translated=k+1;r->translation_pending=0;c->io.order(c->io.opaque);
    }
    if(!pwmc_zero(r->AT+r->pages,(PWMC_PAGES-r->pages)*sizeof(r->AT[0])))return pwmc_fail(r,PWMC_TRANSLATION,1);
    if(!pwmc_final_source(r,0))return 0;
    r->allocated=1;c->finished=1;c->io.order(c->io.opaque);return 1;
}
static inline int pwmc_exposure_intent(struct pwmc_result*r)
{
    if(!r||!r->attempted||r->released||r->error||r->unknown||r->external_issued)return 0;
    if(!pwmc_retained_claim(r))return pwmc_fail(r,PWMC_CONTEXT,1);
    /* Preserve exposure intent in two independently checked lifecycle fields;
     * clearing just the veto flag cannot make local-only release eligible. */
    r->bound=2;r->external_issued=1;r->context[0].io.order(r->context[0].io.opaque);return 1;
}
/* Local, NEVER-exposed pages only. This is deliberately not a callback bool
 * asserting remote retirement. No release path exists for exposed/UNKNOWN. */
static inline int pwmc_release_local(struct pwmc_result*r,int(*translate)(struct pwmc_translation*))
{
    if(!r||!translate||!r->attempted||r->released||r->error||r->unknown||r->external_issued)return 0;
    if(!pwmc_retained_claim(r)||r->release_translated||r->release_pending||
       !pwmc_zero(r->release_AT,sizeof(r->release_AT)))return pwmc_fail(r,PWMC_CONTEXT,1);
    struct pgcd_context*c=&r->context[1];
    if(c->record!=&r->source[1]||c->ticket!=&r->ticket[1]||!pgcd_equal(&c->io,&r->bound_io,sizeof(c->io)))return pwmc_fail(r,PWMC_ARGUMENT,1);
    if(c->opened||c->finished||r->ticket[1].spent||r->source[1].attempted)return pwmc_fail(r,PWMC_REUSED,1);
    if(!pgcd_open(c)||!pwmc_source(r,1)||c->record->core!=r->source[0].core||
       !pwfc_arch_stable(&r->source[0].before.cpu,&r->source[1].before.cpu)||
       r->source[0].before.cpacr!=r->source[1].before.cpacr||
       !polaris_efi_range_owned(c->record->maps[0],c->record->map[0].bytes,c->record->map[0].stride,r->backing,r->backing_bytes,2))return pwmc_fail(r,PWMC_SOURCE,1);
    for(unsigned k=0;k<r->pages;k++)if(r->AT[k].page!=r->backing+4096*k||!pwmc_translation_valid(&r->AT[k]))return pwmc_fail(r,PWMC_TRANSLATION,1);
    if(!pwmc_zero(r->AT+r->pages,(PWMC_PAGES-r->pages)*sizeof(r->AT[0])))return pwmc_fail(r,PWMC_TRANSLATION,1);
    for(unsigned k=0;k<r->pages;k++){
        struct pwmc_translation*t=&r->release_AT[k];t->page=r->backing+4096*k;r->release_pending=k+1;c->io.order(c->io.opaque);
        if(!pwmc_source(r,1)||!translate(t)||t->page!=r->backing+4096*k||!pwmc_translation_valid(t)||!pwmc_source(r,1))return pwmc_fail(r,PWMC_TRANSLATION,1);
        r->release_translated=k+1;r->release_pending=0;c->io.order(c->io.opaque);
    }
    if(!pwmc_retained_claim(r)||!pwmc_zero(r->release_AT+r->pages,(PWMC_PAGES-r->pages)*sizeof(r->release_AT[0]))||!pwmc_final_source(r,1))return pwmc_fail(r,PWMC_SOURCE,1);
    if(!pwmc_invoke(r,1))return 0;
    if(r->call[1].status||!pwmc_map_delta(c->record,r->backing,r->backing_bytes,1))return pwmc_fail(r,PWMC_MAP,1);
    r->call[1].map_checked=1;r->held=0;r->released=1;c->finished=1;c->io.order(c->io.opaque);return 1;
}
/* Allocation initializer for a future qualified MSS parent. The incoming
 * map-call witness below is separate and never opens these contexts. */
static inline int pwmc_bind(struct pwmc_result*r,const struct efi_loaded*self,
    struct efi_system*system,const volatile uint32_t*native_flag,unsigned kind,const struct pgcd_io*io)
{
    if(!r||!self||!system||!native_flag||!io||io->system!=system||kind>PWMC_RMTFS||!pwmc_zero(r,sizeof(*r)))return 0;
    r->kind=r->bound_kind=kind;r->native_flag=r->bound_native_flag=(uintptr_t)native_flag;r->bound_io=*io;
    for(unsigned k=0;k<2;k++){
        if(!pgcd_bind(&r->source[k],self)||!pgcd_in_self(&r->source[k],(uintptr_t)r,sizeof(*r))||
           !pgcd_in_self(&r->source[k],r->native_flag,4))return pwmc_fail(r,PWMC_ARGUMENT,0);
        r->context[k]=(struct pgcd_context){.io=*io,.record=&r->source[k],.ticket=&r->ticket[k],.stage=2};
    }
    r->bound=1;return 1;
}
/* Actual incoming UEFI call evidence, not private MSS/bootstrap authority.
 * These two phases describe the parent's existing maps around its kernel-bank
 * claim. They explicitly precede payload allocation and cannot be renamed a
 * later current map. No context/ticket/opened/owner permission is synthesized. */
#define PWMC_PARENT_MAP_CAP 65536u
struct pwmc_parent_input {
    struct efi_system*system;const struct efi_loaded*image;
    const volatile uint32_t*native_flag;void*output;
    uint64_t capacity,image_handle,phase,bank,bank_bytes;
    uint64_t payload,payload_bytes,log_snapshot,log_snapshot_bytes;
};
struct pwmc_parent_map {
    struct pwmc_parent_input input;struct pgcd_io io;
    struct efi_loaded image_before;
    uint8_t BS_before[PWMC_BS_BYTES];uint64_t boot_address,entry;
    struct pgcd_map map;struct pgcd_arch before,after;
    struct pgcd_fp_guard fp;struct efi_loaded image_after;
    uint8_t BS_after[PWMC_BS_BYTES];
    uint32_t attempted,issued,returned,unknown,error,complete;
    uint32_t native_values[5],native_issued,native_returned,arch_issued,arch_returned;
    uint32_t fp_save_issued,fp_save_returned,fp_restore_issued,fp_restore_returned;
    uint8_t data[PWMC_PARENT_MAP_CAP] __attribute__((aligned(8)));
    uint8_t digest[32];
};
static inline int pwmc_parent_fail(struct pwmc_parent_map*r,unsigned error)
{if(!r->error)r->error=error;r->unknown=1;return 0;}
static inline void pwmc_parent_input_digest(const struct pwmc_parent_map*r,uint8_t out[32])
{
    struct pwfi_sha256 h;pwfi_init(&h);
    for(size_t k=0;k<offsetof(struct pwmc_parent_map,map);k++)pwfi_byte(&h,((const uint8_t*)r)[k]);pwfi_final(&h,out);
}
static inline void pwmc_parent_intent_digest(const struct pwmc_parent_map*r,uint8_t out[32])
{
    struct pwfi_sha256 h;pwfi_init(&h);uint8_t input[32];pwmc_parent_input_digest(r,input);
    const void*part[]={input,&r->before,&r->fp.cpacr_before,&r->fp.fpcr,&r->fp.saved,&r->native_values[0],&r->attempted,&r->fp_save_issued};
    const size_t size[]={32,sizeof(r->before),8,16+sizeof(r->fp.q8_q15),4,4,4,8};
    for(unsigned n=0;n<8;n++)for(size_t k=0;k<size[n];k++)pwfi_byte(&h,((const uint8_t*)part[n])[k]);pwfi_final(&h,out);
}
static inline uint32_t pwmc_parent_native(struct pwmc_parent_map*r,const volatile uint32_t*flag,unsigned slot)
{r->native_issued|=1u<<slot;__asm__ volatile("":::"memory");r->native_values[slot]=*flag;__asm__ volatile("":::"memory");r->native_returned|=1u<<slot;return r->native_values[slot];}
static inline void pwmc_parent_return_digest(const struct pwmc_parent_map*r,uint8_t out[32])
{
    struct pwfi_sha256 h;pwfi_init(&h);for(size_t k=0;k<sizeof(r->map);k++)pwfi_byte(&h,((const uint8_t*)&r->map)[k]);
    for(size_t k=0;k<sizeof(r->data);k++)pwfi_byte(&h,r->data[k]);pwfi_final(&h,out);
}
static inline int pwmc_parent_in_image(const struct efi_loaded*i,uint64_t at,uint64_t bytes)
{return bytes&&i->bytes>=bytes&&at>=(uintptr_t)i->base&&at-(uintptr_t)i->base<=i->bytes-bytes;}
static inline int pwmc_parent_overlap(uint64_t a,uint64_t n,uint64_t b,uint64_t z)
{return a<b+z&&b<a+n;}
static inline int pwmc_parent_stable(const struct pwmc_parent_map*r,const struct pwmc_parent_input*input,
    const struct pgcd_io*io,const struct pwmc_parent_input*saved,const struct pgcd_io*saved_io,const uint8_t seal[32])
{
    uint8_t digest[32];pwmc_parent_input_digest(r,digest);
    if(!pgcd_equal(digest,seal,32)||!pgcd_equal(input,saved,sizeof(*saved))||!pgcd_equal(io,saved_io,sizeof(*io)))return 0;
    return (uintptr_t)saved->system->boot==r->boot_address&&
        pgcd_equal(saved->image,&r->image_before,sizeof(r->image_before))&&
        pgcd_equal((const void*)(uintptr_t)r->boot_address,r->BS_before,PWMC_BS_BYTES);
}
static inline int pwmc_parent_controls(const struct pwmc_parent_map*r,unsigned arch_count,unsigned restored)
{
    unsigned mask=arch_count==1?3:restored?15:7;
    return r->attempted==1&&r->issued==1&&r->returned==1&&r->unknown==1&&!r->error&&!r->complete&&
        r->native_issued==mask&&r->native_returned==mask&&pwmc_zero(r->native_values,sizeof(r->native_values))&&
        r->map.issued==1&&r->map.returned==1&&!r->map.valid&&!r->map.status&&
        r->arch_issued==arch_count&&r->arch_returned==arch_count&&r->fp_save_issued==1&&r->fp_save_returned==1&&
        r->fp_restore_issued==restored&&r->fp_restore_returned==restored;
}
static inline int pwmc_parent_map_valid(const struct pwmc_parent_map*r)
{
    struct polaris_efi_memory checked;return r->map.key&&r->map.version==1&&
        polaris_efi_memory_check(r->data,r->map.bytes,r->input.capacity,r->map.stride,&checked)&&
        polaris_efi_range_owned(r->data,r->map.bytes,r->map.stride,r->input.bank,r->input.bank_bytes,r->input.phase==1?7:2)&&
        (r->input.phase<3||
         (polaris_efi_range_owned(r->data,r->map.bytes,r->map.stride,r->input.payload,r->input.payload_bytes,2)&&
          polaris_efi_range_owned(r->data,r->map.bytes,r->map.stride,r->input.log_snapshot,r->input.log_snapshot_bytes,2)));
}
/* Private common relay. Phase3 is a separate later-parent caller below, not
 * an incoming phase2 record relabeled current. The incoming public entry
 * continues to reject it. Phase4 witnesses the existing final cache-map
 * call at its original64KiB capacity, before handle-array release. Neither
 * record is a later owner grant. No context/ticket is opened by this relay. */
static inline int pwmc_parent_map_call_window(struct pwmc_parent_map*r,const struct pwmc_parent_input*input,const struct pgcd_io*io,uint64_t opening)
{
    if(!r||!input||!io||!pwmc_zero(r,sizeof(*r)))return 0;
    struct pwmc_parent_input saved=*input;struct pgcd_io saved_io=*io;uint8_t seal[32],intent[32],actual[32],result[32];r->attempted=1;
    if(!saved.system||!saved.image||!saved.native_flag||!saved.output||saved_io.system!=saved.system||
       !saved_io.arch||!saved_io.map||!saved_io.fp_save||!saved_io.fp_restore||!saved_io.order||
       !saved.image_handle||
       !((saved.phase==1||saved.phase==2)?
          (saved.capacity==PWMC_PARENT_MAP_CAP&&!saved.payload&&!saved.payload_bytes&&!saved.log_snapshot&&!saved.log_snapshot_bytes):
          ((saved.phase==3||saved.phase==4)&&saved.capacity==(saved.phase==3?PGCD_MAP_CAP:PWMC_PARENT_MAP_CAP)&&
           saved.payload&&saved.payload_bytes&&saved.log_snapshot&&saved.log_snapshot_bytes))||
       !saved.bank_bytes||(saved.bank&4095)||(saved.bank_bytes&4095)||saved.bank>UINT64_MAX-saved.bank_bytes||
       (saved.phase>=3&&((saved.payload&4095)||saved.payload>UINT64_MAX-saved.payload_bytes||
        saved.log_snapshot>UINT64_MAX-saved.log_snapshot_bytes||
        pwmc_parent_overlap(saved.payload,saved.payload_bytes,saved.bank,saved.bank_bytes)||
        pwmc_parent_overlap(saved.log_snapshot,saved.log_snapshot_bytes,saved.bank,saved.bank_bytes)||
        pwmc_parent_overlap(saved.payload,saved.payload_bytes,saved.log_snapshot,saved.log_snapshot_bytes))))return pwmc_parent_fail(r,PWMC_ARGUMENT);
    r->input=saved;r->io=saved_io;r->image_before=*saved.image;
    const struct efi_loaded*i=&r->image_before;uint64_t base=(uintptr_t)i->base;
    if(i->revision!=0x1000||i->system!=saved.system||i->code_type!=3||i->data_type!=4||!base||!i->bytes||base>UINT64_MAX-i->bytes||
       !pwmc_parent_in_image(i,(uintptr_t)r,sizeof(*r))||!pwmc_parent_in_image(i,(uintptr_t)saved.native_flag,4)||
       !pwmc_parent_in_image(i,(uintptr_t)saved.output,saved.capacity)||
       pwmc_parent_overlap((uintptr_t)r,sizeof(*r),(uintptr_t)saved.output,saved.capacity)||
       pwmc_parent_overlap((uintptr_t)r,sizeof(*r),(uintptr_t)saved.native_flag,4)||
       pwmc_parent_overlap((uintptr_t)saved.output,saved.capacity,(uintptr_t)saved.native_flag,4)||
       pwmc_parent_overlap((uintptr_t)saved.output,saved.capacity,(uintptr_t)input,sizeof(*input))||
       pwmc_parent_overlap((uintptr_t)saved.output,saved.capacity,(uintptr_t)io,sizeof(*io))||
       pwmc_parent_overlap((uintptr_t)saved.output,saved.capacity,(uintptr_t)saved.image,sizeof(*saved.image))||
       pwmc_parent_overlap((uintptr_t)saved.output,saved.capacity,(uintptr_t)saved.system,sizeof(*saved.system))||
       pwmc_parent_overlap(base,i->bytes,saved.bank,saved.bank_bytes)||
       (saved.phase>=3&&(pwmc_parent_overlap(base,i->bytes,saved.payload,saved.payload_bytes)||
        pwmc_parent_overlap(base,i->bytes,saved.log_snapshot,saved.log_snapshot_bytes))))return pwmc_parent_fail(r,PWMC_ARGUMENT);
    r->boot_address=(uintptr_t)saved.system->boot;
    if(r->boot_address<0x1b800||((r->boot_address-0x1b800)&4095))return pwmc_parent_fail(r,PWMC_SOURCE);
    r->entry=(uintptr_t)saved.system->boot->get_map;
    if(r->entry!=r->boot_address-0x1b800+0xd3ec||pwmc_parent_overlap((uintptr_t)saved.output,saved.capacity,r->boot_address,PWMC_BS_BYTES))return pwmc_parent_fail(r,PWMC_SOURCE);
    pgcd_copy(r->BS_before,saved.system->boot,PWMC_BS_BYTES);pwmc_parent_input_digest(r,seal);
    if(pwmc_parent_native(r,saved.native_flag,0))return pwmc_parent_fail(r,PWMC_CONTEXT);
    r->arch_issued=1;int arch=saved_io.arch(saved_io.opaque,&r->before);r->arch_returned=arch?1:0;
    if(!arch||!pwmc_parent_stable(r,input,io,&saved,&saved_io,seal)||!pwfc_arch_admitted(&r->before.cpu)||
       r->before.cpu.mair!=UINT64_C(0xffbb4400)||r->before.cpu.daif||r->before.cpu.group1!=1||((r->before.cpacr>>20)&3)!=3||
       r->attempted!=1||r->issued||r->returned||r->unknown||r->error||r->complete||r->arch_issued!=1||r->arch_returned!=1||
       r->native_issued!=1||r->native_returned!=1||!pwmc_zero(r->native_values,sizeof(r->native_values))||
       r->fp_save_issued||r->fp_save_returned||r->fp_restore_issued||r->fp_restore_returned||!pwmc_zero(&r->map,sizeof(r->map))||!pwmc_zero(&r->fp,sizeof(r->fp)))return pwmc_parent_fail(r,PWMC_CONTEXT);
    if(opening&&(r->before.cpu.ticks<opening||r->before.cpu.ticks-opening>PGCD_FRESH_TICKS))return pwmc_parent_fail(r,PWMC_CONTEXT);
    r->fp_save_issued=1;int fp=saved_io.fp_save(saved_io.opaque,&r->fp);r->fp_save_returned=fp?1:0;
    if(!fp||!pwmc_parent_stable(r,input,io,&saved,&saved_io,seal)||r->fp.saved!=1||r->fp.restored||r->fp.cpacr_before!=r->before.cpacr||
       r->fp_save_issued!=1||r->fp_save_returned!=1||r->fp_restore_issued||r->fp_restore_returned||r->attempted!=1||r->issued||r->returned||r->unknown||r->error||r->complete)return pwmc_parent_fail(r,PWMC_CONTEXT);
    r->map.bytes=saved.capacity;r->map.status=UINT64_MAX;pwmc_parent_intent_digest(r,intent);saved_io.order(saved_io.opaque);
    pwmc_parent_intent_digest(r,actual);
    if(!pwmc_parent_stable(r,input,io,&saved,&saved_io,seal)||pwmc_parent_native(r,saved.native_flag,1)||r->map.bytes!=saved.capacity||r->map.status!=UINT64_MAX||r->map.issued||r->map.returned||r->map.valid||r->map.key||r->map.stride||r->map.version||
       !pgcd_equal(intent,actual,32)||r->fp.restored||r->issued||r->returned||r->unknown||r->error||r->complete||r->native_issued!=3||r->native_returned!=3||
       !pwmc_zero(r->native_values,sizeof(r->native_values))||!pwmc_zero(r->data,sizeof(r->data)))return pwmc_parent_fail(r,PWMC_CONTEXT);
    r->issued=r->map.issued=r->unknown=1;__asm__ volatile("":::"memory");
    int returned=saved_io.map(saved_io.opaque,saved.system,&r->map,r->data);r->returned=r->map.returned=returned?1:0;
    if(!returned||r->map.status)return pwmc_parent_fail(r,PWMC_SERVICE); /* No failure sampling or guessed FP restoration. */
    pwmc_parent_intent_digest(r,actual);
    if(!pgcd_equal(intent,actual,32)||!pwmc_parent_stable(r,input,io,&saved,&saved_io,seal)||!pwmc_parent_controls(r,1,0))return pwmc_parent_fail(r,PWMC_CONTEXT);
    if(!pwmc_parent_map_valid(r))return pwmc_parent_fail(r,PWMC_MAP);
    pwmc_parent_return_digest(r,result);
    if(pwmc_parent_native(r,saved.native_flag,2))return pwmc_parent_fail(r,PWMC_CONTEXT);
    r->arch_issued=2;arch=saved_io.arch(saved_io.opaque,&r->after);if(arch)r->arch_returned=2;
    pwmc_parent_intent_digest(r,actual);
    if(!arch||!pgcd_equal(intent,actual,32)||!pwmc_parent_stable(r,input,io,&saved,&saved_io,seal)||!pwmc_parent_controls(r,2,0)||!pwfc_arch_admitted(&r->after.cpu)||
       !pwfc_arch_stable(&r->before.cpu,&r->after.cpu)||r->after.cpacr!=r->before.cpacr||
       r->after.cpu.daif||r->after.cpu.group1!=1||r->after.cpu.ticks<r->before.cpu.ticks||
       r->after.cpu.ticks-r->before.cpu.ticks>PGCD_FRESH_TICKS)return pwmc_parent_fail(r,PWMC_CONTEXT);
    if(opening&&(r->after.cpu.ticks<opening||r->after.cpu.ticks-opening>PGCD_FRESH_TICKS))return pwmc_parent_fail(r,PWMC_CONTEXT);
    pwmc_parent_return_digest(r,actual);if(!pgcd_equal(result,actual,32))return pwmc_parent_fail(r,PWMC_CONTEXT);
    if(pwmc_parent_native(r,saved.native_flag,3))return pwmc_parent_fail(r,PWMC_CONTEXT);
    r->fp_restore_issued=1;fp=saved_io.fp_restore(saved_io.opaque,&r->fp);r->fp_restore_returned=fp?1:0;pwmc_parent_intent_digest(r,actual);
    if(!fp||!pgcd_equal(intent,actual,32)||!pwmc_parent_stable(r,input,io,&saved,&saved_io,seal)||!pwmc_parent_controls(r,2,1)||r->fp.restored!=1||r->fp.cpacr_after!=r->before.cpacr)return pwmc_parent_fail(r,PWMC_CONTEXT);
    pwmc_parent_return_digest(r,actual);if(!pgcd_equal(result,actual,32))return pwmc_parent_fail(r,PWMC_CONTEXT);
    if(r->attempted!=1||r->issued!=1||r->returned!=1||r->unknown!=1||r->error||r->complete||r->arch_issued!=2||r->arch_returned!=2||
       r->fp_save_issued!=1||r->fp_save_returned!=1||r->fp_restore_issued!=1||r->fp_restore_returned!=1||
       pwmc_parent_native(r,saved.native_flag,4)||r->native_issued!=31||r->native_returned!=31)return pwmc_parent_fail(r,PWMC_CONTEXT);
    if(!pwmc_parent_map_valid(r))return pwmc_parent_fail(r,PWMC_MAP);
    pgcd_copy(r->BS_after,(const void*)(uintptr_t)r->boot_address,PWMC_BS_BYTES);r->image_after=*saved.image;
    pgcd_copy(saved.output,r->data,r->map.bytes);r->map.valid=r->complete=1;r->unknown=0;
    struct pwfi_sha256 hash;pwfi_init(&hash);for(size_t k=0;k<offsetof(struct pwmc_parent_map,digest);k++)pwfi_byte(&hash,((const uint8_t*)r)[k]);pwfi_final(&hash,r->digest);return 1;
}
static inline int pwmc_parent_map_call(struct pwmc_parent_map*r,const struct pwmc_parent_input*input,const struct pgcd_io*io)
{return pwmc_parent_map_call_window(r,input,io,0);}
static inline int pwmc_parent_map_read(struct pwmc_parent_map*r,const struct pwmc_parent_input*input,const struct pgcd_io*io)
{
    if(!r||!input||!io||!pwmc_zero(r,sizeof(*r)))return 0;
    if(input->phase!=1&&input->phase!=2){r->attempted=1;return pwmc_parent_fail(r,PWMC_ARGUMENT);}
    return pwmc_parent_map_call(r,input,io);
}
#endif
#endif
