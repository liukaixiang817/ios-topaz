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
    struct pgcd_io bound_io;
};
_Static_assert(sizeof(struct pwmc_translation)==56,"both returned PAR translations and exact restore");
_Static_assert(sizeof(struct pwmc_map_node)==120,"complete64B original descriptor plus returned translations");
_Static_assert(sizeof(struct pwmc_result)==((121344+2*sizeof(struct pwmc_event_path)+2*sizeof(struct pwmc_allocator_path)+2*sizeof(struct pwmc_tpl_scope)+2*sizeof(struct pwmc_timer_path)+sizeof(struct pgcd_io)+15)&~15u),"complete allocation, release, notification, allocator, registered TPL and timer evidence");
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
        pgcd_equal(&c->io,&r->bound_io,sizeof(c->io))&&r->kind==r->bound_kind&&r->native_flag==r->bound_native_flag&&
        r->bound_io.system&&(uintptr_t)r->bound_io.system->boot==s->core+0x1b800;
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
       s->uncertain||(s->outstanding&&!pwmc_own_prepared_call(r,operation))||!pgcd_live(c,&a,0)||!pwmc_context_intact(r,operation)||a.cpu.daif||a.cpu.group1!=1||
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
/* Pure replay of the complete returned notification prefix. A local page
 * operation must not newly queue the memory-map-change callback fanout.
 * This does not make asynchronous firmware interrupts or other callbacks
 * ours; the caller still needs the normal original-service qualification. */
static inline void pwmc_events_digest(const struct pwmc_event_path*p,uint8_t out[32])
{
    struct pwfi_sha256 hash;pwfi_init(&hash);const uint8_t*bytes=(const void*)p;
    for(size_t k=0;k<offsetof(struct pwmc_event_path,digest);k++)pwfi_byte(&hash,bytes[k]);
    pwfi_final(&hash,out);
}
static inline int pwmc_events_replay(const struct pwmc_result*r,unsigned operation)
{
    const struct pwmc_event_path*p=&r->events[operation];const struct pgcd_result*s=&r->source[operation];
    uint64_t head=s->core+0x1c368,previous=head;uint8_t digest[32];pwmc_events_digest(p,digest);
    if(p->attempted!=1||p->complete!=1||p->reserved||p->count>PWMC_EVENT_MAX||p->pending||
       pwfi_le(p->lock,8)!=31||pwfi_le(p->lock+16,4)!=1||
       !pgcd_equal(p->group,&pwmc_map_change_group,16)||!pgcd_equal(p->digest,digest,32))return 0;
    for(unsigned k=0;k<p->count;k++){
        const struct pwmc_event_node*n=&p->node[k];uint64_t first=n->address&~UINT64_C(4095);
        unsigned pages=(unsigned)(((n->address+sizeof(n->raw)-1)&~UINT64_C(4095))-first)/4096+1;
        if(!n->address||(n->address&7)||n->address>UINT64_MAX-sizeof(n->raw)||
           pgcd_in_self(s,n->address,sizeof(n->raw))||n->issued!=1||n->returned!=1||n->reserved||
           pwfi_le(n->raw,8)!=UINT64_C(0x746e7665)||pages>2||n->AT_count!=pages||
           pwfi_le(n->raw+24,8)!=previous||
           (k?pwfi_le(p->node[k-1].raw+16,8):p->head[0])!=n->address+16||
           pgcd_equal(n->raw+56,&pwmc_map_change_group,16))return 0;
        for(unsigned j=0;j<pages;j++)if(n->AT_page[j]!=first+4096*j||
           n->AT_raw[j]!=(UINT64_C(0xff00000000000b80)|n->AT_page[j])||
           (!polaris_efi_range_owned(s->maps[0],s->map[0].bytes,s->map[0].stride,n->AT_page[j],4096,3)&&
            !polaris_efi_range_owned(s->maps[0],s->map[0].bytes,s->map[0].stride,n->AT_page[j],4096,4)))return 0;
        if(pages==1&&(n->AT_page[1]||n->AT_raw[1]))return 0;
        for(unsigned j=0;j<k;j++)if(p->node[j].address==n->address)return 0;
        previous=n->address+16;
    }
    if(p->head[1]!=previous||(p->count?pwfi_le(p->node[p->count-1].raw+16,8):p->head[0])!=head)return 0;
    return pwmc_zero(p->node+p->count,(PWMC_EVENT_MAX-p->count)*sizeof(p->node[0]));
}
/* No callback follows the last equality check on the physical path: the
 * ordinary source checks run first, then these RAM comparisons, then only
 * the source-bound ABI leaf. The software peer can mutate at order/clock
 * boundaries and must be refused before the first allocator call. */
static inline int pwmc_events_current(const struct pwmc_result*r,unsigned operation)
{
    const struct pwmc_event_path*p=&r->events[operation];uint64_t core=r->source[operation].core;
    if(!pwmc_events_replay(r,operation)||
       !pgcd_equal(p->lock,(const void*)(uintptr_t)(core+0x1c350),24)||
       !pgcd_equal(p->head,(const void*)(uintptr_t)(core+0x1c368),16)||
       pwfi_le((const void*)(uintptr_t)(core+0x1dbc0),8))return 0;
    for(unsigned k=0;k<p->count;k++)if(!pgcd_equal(p->node[k].raw,
        (const void*)(uintptr_t)p->node[k].address,sizeof(p->node[k].raw)))return 0;
    return 1;
}
static inline int pwmc_events_capture(struct pwmc_result*r,unsigned operation)
{
    struct pwmc_event_path*p=&r->events[operation];struct pgcd_context*c=&r->context[operation];
    uint64_t core=c->record->core,head=core+0x1c368,previous=head,next;
    if(!pwmc_zero(p,sizeof(*p))||!pwmc_source(r,operation))return pwmc_fail(r,PWMC_CONTEXT,operation||r->held);
    p->attempted=1;pgcd_copy(p->lock,(const void*)(uintptr_t)(core+0x1c350),24);
    pgcd_copy(p->head,(const void*)(uintptr_t)head,16);pgcd_copy(p->group,(const void*)(uintptr_t)(core+0x1b130),16);
    p->pending=pwfi_le((const void*)(uintptr_t)(core+0x1dbc0),8);next=p->head[0];
    if(pwfi_le(p->lock,8)!=31||pwfi_le(p->lock+16,4)!=1||p->pending||
       !pgcd_equal(p->group,&pwmc_map_change_group,16))return pwmc_fail(r,PWMC_CONTEXT,operation||r->held);
    while(next!=head){
        if(p->count==PWMC_EVENT_MAX||next<16||(next&7))return pwmc_fail(r,PWMC_CONTEXT,operation||r->held);
        struct pwmc_event_node*n=&p->node[p->count];n->address=next-16;
        if(n->address>UINT64_MAX-sizeof(n->raw)||pgcd_in_self(c->record,n->address,sizeof(n->raw)))return pwmc_fail(r,PWMC_CONTEXT,operation||r->held);
        for(unsigned k=0;k<p->count;k++)if(p->node[k].address==n->address)return pwmc_fail(r,PWMC_CONTEXT,operation||r->held);
        uint64_t first=n->address&~UINT64_C(4095),end=n->address+sizeof(n->raw);
        n->issued=1;
        for(uint64_t at=first;at<end;at+=4096){
            if(n->AT_count==2||(!polaris_efi_range_owned(c->record->maps[0],c->record->map[0].bytes,c->record->map[0].stride,at,4096,3)&&
               !polaris_efi_range_owned(c->record->maps[0],c->record->map[0].bytes,c->record->map[0].stride,at,4096,4)))return pwmc_fail(r,PWMC_CONTEXT,operation||r->held);
            unsigned k=n->AT_count;uint64_t where=0;n->AT_page[k]=at;
            if(!pwmc_context_intact(r,operation)||!pwmc_parameters(r)||
               !c->io.identity(c->io.opaque,at,4096,&where,&n->AT_raw[k])||!pwmc_context_intact(r,operation)||!pwmc_parameters(r)||
               n->address!=next-16||n->AT_page[k]!=at||where!=at||
               n->AT_raw[k]!=(UINT64_C(0xff00000000000b80)|at))return pwmc_fail(r,PWMC_TRANSLATION,1);
            n->AT_count=k+1;
        }
        pgcd_copy(n->raw,(const void*)(uintptr_t)n->address,sizeof(n->raw));n->returned=1;p->count++;
        if(pwfi_le(n->raw,8)!=UINT64_C(0x746e7665)||pwfi_le(n->raw+24,8)!=previous||
           pgcd_equal(n->raw+56,&pwmc_map_change_group,16))return pwmc_fail(r,PWMC_CONTEXT,operation||r->held);
        previous=next;next=pwfi_le(n->raw+16,8);
    }
    p->complete=1;pwmc_events_digest(p,p->digest);
    if(!pwmc_source(r,operation)||!pwmc_events_current(r,operation))return pwmc_fail(r,PWMC_CONTEXT,1);
    return 1;
}
static inline void pwmc_timers_digest(const struct pwmc_timer_path*p,uint8_t out[32])
{
    struct pwfi_sha256 hash;pwfi_init(&hash);const uint8_t*b=(const void*)p;
    for(size_t k=0;k<offsetof(struct pwmc_timer_path,digest);k++)pwfi_byte(&hash,b[k]);pwfi_final(&hash,out);
}
static inline int pwmc_timer_metadata(const struct pwmc_result*r,unsigned operation,const struct pwmc_timer_node*n)
{
    const struct pgcd_result*s=&r->source[operation];
    if(!n->address||(n->address&7)||n->address>UINT64_MAX-sizeof(n->raw)||pgcd_in_self(s,n->address,sizeof(n->raw))||
       n->issued!=1||n->returned!=1||n->reserved)return 0;
    uint64_t first=n->address&~UINT64_C(4095);unsigned pages=(unsigned)(((n->address+sizeof(n->raw)-1)&~UINT64_C(4095))-first)/4096+1;
    if(pages>2||n->AT_count!=pages)return 0;
    for(unsigned k=0;k<pages;k++)if(n->AT_page[k]!=first+4096*k||n->AT_raw[k]!=(UINT64_C(0xff00000000000b80)|n->AT_page[k])||
       (!polaris_efi_range_owned(s->maps[0],s->map[0].bytes,s->map[0].stride,n->AT_page[k],4096,3)&&
        !polaris_efi_range_owned(s->maps[0],s->map[0].bytes,s->map[0].stride,n->AT_page[k],4096,4)))return 0;
    return pages==2||(!n->AT_page[1]&&!n->AT_raw[1]);
}
static inline int pwmc_timers_replay(const struct pwmc_result*r,unsigned operation)
{
    const struct pwmc_timer_path*p=&r->timers[operation];const struct pwmc_event_path*e=&r->events[operation];
    uint64_t core=r->source[operation].core,head=core+0x1c3f0,prior=head,last=0;uint8_t digest[32];pwmc_timers_digest(p,digest);
    if(!pwmc_events_replay(r,operation)||p->attempted!=1||p->complete!=1||p->reserved||p->count>PWMC_TIMER_MAX||!pgcd_equal(digest,p->digest,32)||
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
        if(checker_seen!=1||n->address!=p->checker||!pwmc_timer_metadata(r,operation,n)||pwfi_le(b,8)!=UINT64_C(0x746e7665)||
           pwfi_le(b+8,4)!=0x200||pwfi_le(b+12,4)||pwfi_le(b+32,8)!=30||pwfi_le(b+40,8)!=core+0xcb24||
           pwfi_le(b+48,8)||pwfi_le(b+72,8)||b[88]||pwfi_le(b+152,8)||pwfi_le(b+176,8))return 0;
        for(unsigned k=0;k<e->count;k++)if(e->node[k].address==p->checker&&!pgcd_equal(e->node[k].raw,b,88))return 0;
    }else if(p->count||!pwmc_zero(&p->checker_node,sizeof(p->checker_node)))return 0;
    for(unsigned k=0;k<p->count;k++){
        const struct pwmc_timer_node*n=&p->node[k];const uint8_t*b=n->raw;uint32_t type=(uint32_t)pwfi_le(b+8,4);uint64_t when=pwfi_le(b+168,8);
        if(!pwmc_timer_metadata(r,operation,n)||pwfi_le(b,8)!=UINT64_C(0x746e7665)||b[88]||pwfi_le(b+176,8)||
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
static inline int pwmc_timers_current(const struct pwmc_result*r,unsigned operation)
{
    const struct pwmc_timer_path*p=&r->timers[operation];uint64_t core=r->source[operation].core;
    if(!pwmc_timers_replay(r,operation)||pwfi_le((const void*)(uintptr_t)(core+0x1cbc8),8)!=p->checker||
       !pgcd_equal(p->head,(const void*)(uintptr_t)(core+0x1c3f0),16)||
       !pgcd_equal(p->lock[0],(const void*)(uintptr_t)(core+0x1c3d8),24)||
       !pgcd_equal(p->lock[1],(const void*)(uintptr_t)(core+0x1c400),24))return 0;
    if(p->checker&&!pgcd_equal(p->checker_node.raw,(const void*)(uintptr_t)p->checker,184))return 0;
    for(unsigned k=0;k<p->count;k++)if(!pgcd_equal(p->node[k].raw,(const void*)(uintptr_t)p->node[k].address,184))return 0;
    return 1;
}
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
static inline int pwmc_timers_capture(struct pwmc_result*r,unsigned operation)
{
    struct pwmc_timer_path*p=&r->timers[operation];struct pgcd_context*c=&r->context[operation];uint64_t core=c->record->core;
    if(!pwmc_zero(p,sizeof(*p))||!pwmc_source(r,operation))return pwmc_fail(r,PWMC_CONTEXT,operation||r->held);
    p->attempted=1;p->checker=pwfi_le((const void*)(uintptr_t)(core+0x1cbc8),8);p->counter=pwfi_le((const void*)(uintptr_t)(core+0x1dc00),8);
    pgcd_copy(p->head,(const void*)(uintptr_t)(core+0x1c3f0),16);pgcd_copy(p->lock[0],(const void*)(uintptr_t)(core+0x1c3d8),24);pgcd_copy(p->lock[1],(const void*)(uintptr_t)(core+0x1c400),24);
    if(p->checker&&!pwmc_timer_capture_node(r,operation,&p->checker_node,p->checker))return 0;
    uint64_t head=core+0x1c3f0,next=p->head[0],prior=head;
    while(next!=head){
        if(p->count==PWMC_TIMER_MAX||next<152||(next&7))return pwmc_fail(r,PWMC_CONTEXT,operation||r->held);
        struct pwmc_timer_node*n=&p->node[p->count];uint64_t address=next-152;
        if(p->checker&&address<p->checker+184&&p->checker<address+184)return pwmc_fail(r,PWMC_CONTEXT,operation||r->held);
        for(unsigned k=0;k<p->count;k++)if(address<p->node[k].address+184&&p->node[k].address<address+184)return pwmc_fail(r,PWMC_CONTEXT,operation||r->held);
        if(!pwmc_timer_capture_node(r,operation,n,address))return 0;p->count++;
        if(pwfi_le(n->raw+160,8)!=prior)return pwmc_fail(r,PWMC_CONTEXT,operation||r->held);
        prior=next;next=pwfi_le(n->raw+152,8);
    }
    p->complete=1;pwmc_timers_digest(p,p->digest);
    if(!pwmc_timers_replay(r,operation)||!pwmc_source(r,operation)||!pwmc_timers_current(r,operation))return pwmc_fail(r,PWMC_CONTEXT,1);
    return 1;
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
    if(restore){
        if(!pwmc_tpl_transition_valid(r,operation,0)||q->issued!=1||q->returned!=1||q->status||q->unknown!=1||
           p->map.issued!=1||p->map.returned!=1||!p->map.valid||p->map.status||p->map_unknown||
           p->hash_count!=5||p->hash_failed)return 0;
        for(unsigned k=0;k<5;k++)if(!pgcd_equal(p->hashes[k],pgci_ranges[k].sha256,32))return 0;
        if(!pwmc_maps_delta(&c->record->map[0],c->record->maps[0],&p->map,p->maps,r->backing,r->backing_bytes,operation))return 0;
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
    struct pgcd_result*source=&r->source[operation];unsigned before=source->arch_returned;int arch=pgcd_live(c,&t->after,1);
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
       !pwmc_events_current(r,operation)||!pwmc_allocator_current(r,operation)||!pwmc_timers_current(r,operation)||(operation&&!pwmc_retained_claim(r)))return 0;
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
    if(!pwmc_allocator_capture(r,operation)||!pwmc_events_capture(r,operation)||!pwmc_timers_capture(r,operation)||!pgcd_service_enter(c,&q->guard))return pwmc_fail(r,PWMC_CONTEXT,operation||r->held);
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
    if(!pgcd_service_leave(c,&q->guard,returned)||q->native_after||
       !pgcd_equal(q->BS_before,c->io.system->boot,PWMC_BS_BYTES)||!pwmc_close_source(r,operation))return pwmc_fail(r,PWMC_SERVICE,1);
    p->held=0;p->completed=1;pwmc_tpl_digest(p,p->digest);
    if(!pwmc_tpl_replay(r,operation))return pwmc_fail(r,PWMC_CONTEXT,1);
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
       !pgcd_equal(q->BS_before,q->BS_after,PWMC_BS_BYTES)||!pwmc_events_replay(r,0)||!pwmc_allocator_replay(r,0)||!pwmc_tpl_replay(r,0)||!pwmc_timers_replay(r,0)||!pwmc_map_delta(s,r->backing,r->backing_bytes,0))return 0;
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
/* Actual initializer is callable only from a future qualified parent. It
 * binds two independent Core source records to the same resident object.
 * No parent/CLI/build hook is added by this header. */
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
#endif
#endif
