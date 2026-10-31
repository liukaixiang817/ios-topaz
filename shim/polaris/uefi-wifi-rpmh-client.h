/* Default-OFF original RPMh private RAM-client lifecycle. No vote, commandset,
 * SMC, MMIO, MSS, shared-DMA grant or storage operation exists in this phase.
 * Its independent bootstrap guard is retired BEFORE Clock/final GCD begins. */
#ifndef POLARIS_UEFI_WIFI_RPMH_CLIENT_H
#define POLARIS_UEFI_WIFI_RPMH_CLIENT_H
#ifndef EFI_XNU_WIFI_RPMH_CLIENT_AVAILABLE
#define EFI_XNU_WIFI_RPMH_CLIENT_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_RPMH_CLIENT_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
#include "uefi-wifi-rpmh-readonly.h"
#define PWRCL_NODES 128u
struct pwrcl_node {uint64_t address;uint32_t bytes,reserved;uint8_t raw[88];};
struct pwrcl_list {uint64_t address;uint32_t bytes,count,visited,complete;uint8_t raw[24];struct pwrcl_node node[PWRCL_NODES];};
struct pwrcl_pool {uint64_t address;uint32_t bytes,complete;uint8_t root[16];struct pwrcl_list list[2];};
struct pwrcl_client {uint32_t bytes,queue_bytes[4];uint8_t raw[88],queue[4][24];};
struct pwrcl_result {
    uint32_t attempted,error,unknown,outstanding,retired,refused_before_API,client_held,client_returned;
    uint32_t issued,returned,provider_issued,provider_returned,pools_complete[3],final_context_untouched;
    uint64_t create_status,delete_status,functions[2],identity_address,identity_par,name_address;
    void *handle_output;
    struct pgcd_result core;struct pgcd_lifetime core_ticket;
    struct pwrph_result reader;struct pwrph_lifetime reader_ticket;
    struct pgcd_service_guard guard[4];
    struct paic_map_sample maps[2];uint8_t map_raw[2][4096];
    uint32_t exclusion_count;struct {uint64_t base,bytes;} exclusions[PAIC_HANDLES];
    uint32_t hash_count[3][2],hash_failed[3][2];uint8_t hashes[3][2][5][32];
    struct pwrcl_pool pools[3][2];
    struct pwrcl_client candidate,created,released;
    uint8_t globals[3][0x110],final_global[0x110];
};
_Static_assert(sizeof(struct pwrcl_result)==227104,"private zero-vote full raw V1 extent");
struct pwrcl_io {
    struct pwrph_io reader;
    int (*create)(void *,uint64_t,uint32_t,const char *,void **,uint64_t *);
    int (*drop)(void *,uint64_t,void *,uint64_t *);
    const char *name;
};
enum pwrcl_error {PWRCL_OK,PWRCL_STAGE,PWRCL_BASELINE,PWRCL_SOURCE,PWRCL_POOL,
    PWRCL_LIMIT,PWRCL_CHANGED,PWRCL_CLIENT,PWRCL_API,PWRCL_MAP,PWRCL_GUARD,PWRCL_TIME,PWRCL_BODY};
static const char pwrcl_name[]="polaris.wifi.private.zero";
static struct pwrcl_result pwrcl_record;
static struct pwrph_work pwrcl_work;
static struct pgcd_context pwrcl_early_context;
static inline void pwrcl_fail(struct pwrcl_result *r,unsigned e,int uncertain)
{if(!r->error)r->error=e;if(uncertain)r->unknown=1;paic_actual_order(0);}
static inline int pwrcl_overlap(uint64_t a,uint64_t n,uint64_t b,uint64_t z)
{return a>UINT64_MAX-n||b>UINT64_MAX-z||(a<b+z&&b<a+n);}
static inline int pwrcl_owned(const struct paic_io *io,struct pwrcl_result *r,
    const struct pwrph_work *w,uint64_t at,uint32_t n)
{
    if(!at||!n||at>UINT64_MAX-n||at+n>UINT64_MAX-4095)return 0;
    for(uint64_t p=at&~UINT64_C(4095);p<at+n;p+=4096)
        if(!polaris_efi_range_owned(w->map,w->bytes,w->stride,p,4096,3)&&
           !polaris_efi_range_owned(w->map,w->bytes,w->stride,p,4096,4))return 0;
    return io->identity(io->context,at,n,&r->identity_address,&r->identity_par);
}
static inline int pwrcl_copy(const struct paic_io *io,struct pwrcl_result *r,
    const struct pwrph_work *w,void *out,uint64_t at,uint32_t n,uint32_t *done)
{
    *done=0;if(!pwrcl_owned(io,r,w,at,n))return 0;
    for(uint32_t k=0;k<n;k++){((uint8_t*)out)[k]=((const volatile uint8_t*)(uintptr_t)at)[k];*done=k+1;}return 1;
}
/* This class admits reading the original provider's mutable pool only. We do
 * not directly store into it. No classification grants a hardware/DMA lease. */
static inline int pwrcl_heap(const struct paic_io *io,struct pwrcl_result *r,
    const struct pwrph_work *w,uint64_t at,uint32_t n)
{
    /* Original6ed8->9894 reserves a4B size prefix and returns allocation+4.
     * Actual0149 pool was4mod8 with type4+identityPASS. Require the original
     * 4B alignment; all page/source/image-exclusion gates still apply. */
    if(!pwrcl_owned(io,r,w,at,n)||(at&3))return 0;
    for(uint64_t p=at&~UINT64_C(4095);p<at+n;p+=4096)
        if(!polaris_efi_range_owned(w->map,w->bytes,w->stride,p,4096,4))return 0;
    if(pwrcl_overlap(at,n,r->core.self_base,r->core.self_bytes)||
       pwrcl_overlap(at,n,r->core.core,PGCI_IMAGE_BYTES))return 0;
    for(unsigned k=0;k<r->exclusion_count;k++)
        if(pwrcl_overlap(at,n,r->exclusions[k].base,r->exclusions[k].bytes))return 0;
    return 1;
}
static inline int pwrcl_fresh(const struct paic_io *io,struct pwrcl_result *r)
{
    struct paic_arch a;
    if(!io->arch(io->context,&a)||!paic_arch_stable(&r->reader.before,&a)||
       a.ticks-r->reader.before.ticks>UINT64_C(3840000)){
        pwrcl_fail(r,PWRCL_TIME,r->provider_issued!=0);return 0;
    }return 1;
}
static inline int pwrcl_exclusions(const struct paic_io *io,struct pwrcl_result *r,
    const struct pwrph_work *w,const struct paic_result *enumeration)
{
    for(unsigned k=0;k<enumeration->handle_count;k++){
        struct efi_loaded image;uint32_t done;
        if(enumeration->handle_status[k]||!pwrcl_copy(io,r,w,&image,enumeration->loaded_address[k],sizeof(image),&done))return 0;
        uint64_t b=(uintptr_t)image.base;
        if(image.revision!=0x1000||image.system!=io->system||!b||!image.bytes||b>UINT64_MAX-image.bytes)return 0;
        r->exclusions[k].base=b;r->exclusions[k].bytes=image.bytes;r->exclusion_count=k+1;
    }return 1;
}
static inline int pwrcl_pool_read(const struct paic_io *io,struct pwrcl_result *r,
    struct pwrph_work *w,struct pwrcl_pool *p)
{
    uint32_t done;uint8_t check[24];uint64_t pool=pwfi_le(r->reader.snapshot[1].global+0x18,8);
    p->address=pool;
    if(!pwrcl_fresh(io,r)||!pwrcl_heap(io,r,w,pool,16)||!pwrcl_copy(io,r,w,p->root,pool,16,&p->bytes))return 0;
    for(unsigned side=0;side<2;side++){
        struct pwrcl_list *l=&p->list[side];l->address=pwfi_le(p->root+side*8,8);
        if(pwrcl_overlap(pool,16,l->address,24)||!pwrcl_heap(io,r,w,l->address,24)||
           !pwrcl_copy(io,r,w,l->raw,l->address,24,&l->bytes))return 0;
        if(side&&pwrcl_overlap(l->address,24,p->list[0].address,24))return 0;
        l->count=(uint32_t)pwfi_le(l->raw+4,4);
        if(pwfi_le(l->raw,4)!=80){pwrcl_fail(r,PWRCL_POOL,r->provider_issued!=0);return 0;}
        if(l->count>PWRCL_NODES){pwrcl_fail(r,PWRCL_LIMIT,r->provider_issued!=0);return 0;}
        uint64_t cursor=pwfi_le(l->raw+8,8),tail=pwfi_le(l->raw+16,8);
        if(!l->count&&(cursor||tail))return 0;
        for(unsigned k=0;k<l->count;k++){
            if(!pwrcl_fresh(io,r)||!cursor)return 0;
            struct pwrcl_node *node=&l->node[k];node->address=cursor;l->visited=k+1;
            if(!pwrcl_heap(io,r,w,cursor,88)||pwrcl_overlap(cursor,88,pool,16)||pwrcl_overlap(cursor,88,l->address,24)||
               pwrcl_overlap(cursor,88,pwfi_le(p->root+(1-side)*8,8),24))return 0;
            for(unsigned s=0;s<=side;s++)for(unsigned j=0;j<(s==side?k:p->list[s].count);j++)
                if(pwrcl_overlap(cursor,88,p->list[s].node[j].address,88))return 0;
            if(!pwrcl_copy(io,r,w,node->raw,cursor,88,&node->bytes)||pwfi_le(node->raw,4)!=2)return 0;
            cursor=pwfi_le(node->raw+80,8);
            if(k+1==l->count&&(node->address!=tail||cursor))return 0;
        }
        if(cursor||(!l->count&&tail))return 0;
        if(!pwrcl_copy(io,r,w,check,l->address,24,&done)||!pgcd_equal(check,l->raw,24))return 0;
        l->complete=1;
    }
    if(!pwrcl_copy(io,r,w,check,pool,16,&done)||!pgcd_equal(check,p->root,16))return 0;
    p->complete=1;return 1;
}
static inline int pwrcl_pool_pair(const struct paic_io *io,struct pwrcl_result *r,
    struct pwrph_work *w,unsigned stage)
{
    for(unsigned pass=0;pass<2;pass++)if(!pwrcl_pool_read(io,r,w,&r->pools[stage][pass])){
        pwrcl_fail(r,PWRCL_POOL,r->provider_issued!=0);return 0;
    }
    if(!pgcd_equal(&r->pools[stage][0],&r->pools[stage][1],sizeof(struct pwrcl_pool))){
        pwrcl_fail(r,PWRCL_CHANGED,r->provider_issued!=0);return 0;
    }r->pools_complete[stage]=1;return 1;
}
static inline int pwrcl_client_read(const struct paic_io *io,struct pwrcl_result *r,
    struct pwrph_work *w,const struct pwrcl_pool *p,uint64_t handle,int live,struct pwrcl_client *v)
{
    if(!pwrcl_heap(io,r,w,handle,88)||!pwrcl_copy(io,r,w,v->raw,handle,88,&v->bytes))return 0;
    if(pwfi_le(v->raw+0x38,4)||pwfi_le(v->raw+0x40,8)||pwfi_le(v->raw+0x48,8))return 0;
    if(live){if(pwfi_le(v->raw,4)!=2||pwfi_le(v->raw+8,8)!=r->name_address||
        pwfi_le(v->raw+0x30,4)||pwfi_le(v->raw+0x34,4)!=UINT32_MAX)return 0;}
    else if(pwfi_le(v->raw+8,8)!=r->reader.image+0xaf50||pwfi_le(v->raw+0x30,8)!=UINT64_MAX)return 0;
    for(unsigned k=0;k<4;k++){
        uint64_t q=pwfi_le(v->raw+0x10+8*k,8);
        if(!pwrcl_heap(io,r,w,q,24)||pwrcl_overlap(q,24,p->address,16)||pwrcl_overlap(q,24,handle,88))return 0;
        for(unsigned a=0;a<2;a++){
            if(pwrcl_overlap(q,24,p->list[a].address,24))return 0;
            for(unsigned j=0;j<p->list[a].count;j++){
                const struct pwrcl_node *n=&p->list[a].node[j];
                if(pwrcl_overlap(q,24,n->address,88))return 0;
                if(n->address!=handle)for(unsigned z=0;z<4;z++)
                    if(pwrcl_overlap(q,24,pwfi_le(n->raw+0x10+8*z,8),24))return 0;
            }
        }
        for(unsigned j=0;j<k;j++)if(pwrcl_overlap(q,24,pwfi_le(v->raw+0x10+8*j,8),24))return 0;
        if(!pwrcl_copy(io,r,w,v->queue[k],q,24,&v->queue_bytes[k])||
           pwfi_le(v->queue[k],4)!=(k<2?16u:24u)||pwfi_le(v->queue[k]+4,4)||
           pwfi_le(v->queue[k]+8,8)||pwfi_le(v->queue[k]+16,8))return 0;
    }return 1;
}
static inline int pwrcl_source(const struct paic_io *io,struct pwrcl_result *r,
    struct pwrph_work *w,unsigned checkpoint)
{
    uint8_t table[PWRPH_PROTOCOL_BYTES];struct efi_loaded owner;uint32_t done;
    if(!pwrcl_copy(io,r,w,r->globals[checkpoint],r->reader.image+0xd2e8,0x110,&done)||
       !pgcd_equal(r->globals[checkpoint],r->reader.snapshot[1].global,0x110))return 0;
    if(!pwrcl_fresh(io,r)||!pwrcl_copy(io,r,w,&owner,r->reader.owner_address,sizeof(owner),&done)||
       !pgcd_equal(&owner,&r->reader.owner,sizeof(owner))||
       !pwrcl_copy(io,r,w,table,r->reader.protocol[1],sizeof(table),&done)||
       !pgcd_equal(table,r->reader.protocol_raw[1],sizeof(table))||
       pwfi_le(table+0x30,8)!=r->reader.image+0x1ab0||pwfi_le(table+0x48,8)!=r->reader.image+0x1b24||
       !pwrcl_owned(io,r,w,r->reader.image,PWRPI_IMAGE_BYTES)||!pwrcl_owned(io,r,w,r->core.core,PGCI_IMAGE_BYTES))return 0;
    if(!pwrpi_verify((const void*)(uintptr_t)r->reader.image,r->reader.image,r->hashes[checkpoint][0],
          &r->hash_count[checkpoint][0],&r->hash_failed[checkpoint][0])||
       !pgci_verify((const void*)(uintptr_t)r->core.core,r->core.core,PGCI_IMAGE_BYTES,r->hashes[checkpoint][1],
          &r->hash_failed[checkpoint][1],&r->hash_count[checkpoint][1]))return 0;
    return pwrcl_fresh(io,r);
}
static inline int pwrcl_enter(struct pgcd_context *g,struct pwrcl_result *r,unsigned op,int provider)
{
    if(!pgcd_service_enter(g,&r->guard[op])){pwrcl_fail(r,PWRCL_GUARD,pgcd_uncertain(g)||r->provider_issued!=0);return 0;}
    r->outstanding=op+1;r->issued++;if(provider)r->provider_issued++;paic_actual_order(0);return 1;
}
static inline int pwrcl_leave(struct pgcd_context *g,struct pwrcl_result *r,unsigned op,int returned,int provider)
{
    if(returned){r->returned++;if(provider)r->provider_returned++;}paic_actual_order(0);
    if(!pgcd_service_leave(g,&r->guard[op],returned)){pwrcl_fail(r,PWRCL_GUARD,1);return 0;}
    r->outstanding=0;paic_actual_order(0);return 1;
}
static inline int pwrcl_map(const struct pwrcl_io *ops,struct pgcd_context *g,
    struct pwrcl_result *r,struct pwrph_work *w,unsigned stage)
{
    unsigned op=stage?3:1;r->maps[stage]=(struct paic_map_sample){UINT64_MAX,0,sizeof(w->map),0,0};
    if(!pwrcl_enter(g,r,op,0))return 0;
    int returned=ops->reader.map(ops->reader.memory.context,ops->reader.memory.system,w->map,&r->maps[stage]);
    pgcd_copy(r->map_raw[stage],w->map,sizeof(w->map));
    if(!pwrcl_leave(g,r,op,returned,0))return 0;
    struct polaris_efi_memory checked;const struct paic_map_sample *m=&r->maps[stage];
    if(m->status||m->version!=1||!polaris_efi_memory_check(w->map,m->bytes,sizeof(w->map),m->stride,&checked)){
        pwrcl_fail(r,PWRCL_MAP,1);return 0;
    }w->bytes=m->bytes;w->stride=m->stride;return 1;
}
static inline int pwrcl_transition(struct pwrcl_result *r,int after_delete)
{
    const struct pwrcl_pool *before=&r->pools[0][1],*after=&r->pools[after_delete?2:1][1];
    uint64_t h=(uintptr_t)r->handle_output;unsigned active=before->list[0].count,free=before->list[1].count;
    if(before->address!=after->address||!pgcd_equal(before->root,after->root,16))return 0;
    unsigned expected_free=after_delete?(free?free:1):(free?free-1:0);
    if(after->list[0].count!=active+(after_delete?0:1)||after->list[1].count!=expected_free)return 0;
    for(unsigned k=0;k<active;k++){
        const struct pwrcl_node *a=&before->list[0].node[k],*b=&after->list[0].node[k];
        if(a->address!=b->address||!pgcd_equal(a->raw,b->raw,80))return 0;
        if(after_delete||k+1<active){if(!pgcd_equal(a->raw+80,b->raw+80,8))return 0;}
        else if(pwfi_le(b->raw+80,8)!=h)return 0;
    }
    if(!after_delete&&after->list[0].node[active].address!=h)return 0;
    unsigned left=free?(free-1):0;
    for(unsigned k=0;k<left;k++){
        const struct pwrcl_node *a=&before->list[1].node[k+1],*b=&after->list[1].node[k];
        if(a->address!=b->address||!pgcd_equal(a->raw,b->raw,80))return 0;
    }
    if(after_delete&&after->list[1].node[after->list[1].count-1].address!=h)return 0;
    return 1;
}
static inline int pwrcl_final_unopened(const struct pgcd_context *g)
{
    return g&&g->record&&g->ticket&&g->stage==2&&!g->opened&&!g->finished&&
        g->record->self_bound&&!g->record->attempted&&!g->record->error&&!g->record->phase&&
        !g->record->pre_mask&&!g->record->post_mask&&!g->record->prestart_count&&
        !pgcd_uncertain(g)&&!g->ticket->spent&&!g->ticket->result;
}
typedef int (*pwrcl_body_fn)(void *,const struct paic_io *,struct pwrcl_result *,struct pwrph_work *,struct pgcd_context *);
static inline int pwrcl_run_body(const struct pwrcl_io *ops,const struct paic_result *enumeration,unsigned stage,
    struct pgcd_context *final,struct pgcd_context *early,struct pwrcl_result *r,struct pwrph_work *w,
    pwrcl_body_fn body,void *body_context)
{
    if(!r||!w||!early||r->attempted)return 0;r->attempted=1;
    if(stage!=2){pwrcl_fail(r,PWRCL_STAGE,0);goto stopped;}
    if(!ops||!ops->create||!ops->drop||!ops->name){pwrcl_fail(r,PWRCL_BASELINE,0);goto stopped;}
    if(early->record||early->opened||early->finished||r->core_ticket.spent||r->core_ticket.result||
       r->reader_ticket.used||r->reader_ticket.outstanding||!pwrcl_final_unopened(final)){
        /* A used/forged/misordered context is a parent lifetime fault, not a
         * harmless optional observation refusal. Never continue Clock/native. */
        pwrcl_fail(r,PWRCL_BASELINE,1);goto stopped;
    }
    /* Bind from the entry's own immutable copy. pgcd_open validates the actual
     * LoadedImage address against that copy before following original services. */
    if(!pgcd_bind(&r->core,&final->record->self_owner)){pwrcl_fail(r,PWRCL_BASELINE,0);goto stopped;}
    r->core.self_owner_address=final->record->self_owner_address;
    if(!pgcd_in_self(&r->core,(uintptr_t)r,sizeof(*r))||!pgcd_in_self(&r->core,(uintptr_t)w,sizeof(*w))||
       !pgcd_in_self(&r->core,(uintptr_t)early,sizeof(*early))){pwrcl_fail(r,PWRCL_BASELINE,0);goto stopped;}
    early->io=final->io;early->record=&r->core;early->ticket=&r->core_ticket;early->stage=2;
    if(!pwrph_collect_once(&ops->reader,2,enumeration,early,&r->reader,w,&r->reader_ticket)){
        pwrcl_fail(r,PWRCL_BASELINE,pgcd_uncertain(early)||r->reader.unknown||r->reader.outstanding);goto stopped;
    }
    const struct paic_io *io=&ops->reader.memory;
    if(!pwrcl_owned(io,r,w,(uintptr_t)r,sizeof(*r))||!pwrcl_owned(io,r,w,(uintptr_t)w,sizeof(*w))){pwrcl_fail(r,PWRCL_BASELINE,0);goto stopped;}
    if(r->reader.snapshot[1].initialized!=1||r->reader.snapshot[1].drv_count!=1||
       pwfi_le(r->reader.snapshot[1].drv[0].row,4)!=2||
       !pwrcl_exclusions(io,r,w,enumeration)||!pwrcl_pool_pair(io,r,w,0)){
        pwrcl_fail(r,PWRCL_POOL,0);goto stopped;
    }
    const struct pwrcl_pool *before=&r->pools[0][1];
    if(before->list[0].count==PWRCL_NODES){pwrcl_fail(r,PWRCL_LIMIT,0);goto stopped;}
    if(before->list[1].count&&!pwrcl_client_read(io,r,w,before,before->list[1].node[0].address,0,&r->candidate)){
        pwrcl_fail(r,PWRCL_CLIENT,0);goto stopped;
    }
    r->name_address=(uintptr_t)ops->name;char name[sizeof(pwrcl_name)];uint32_t name_bytes;
    if(!pgcd_in_self(&r->core,r->name_address,sizeof(name))||
       !pwrcl_copy(io,r,w,name,r->name_address,sizeof(name),&name_bytes)||!pgcd_equal(name,pwrcl_name,sizeof(name))||!pwrcl_source(io,r,w,0)){
        pwrcl_fail(r,PWRCL_SOURCE,0);goto stopped;
    }
    r->functions[0]=r->reader.image+0x1ab0;r->functions[1]=r->reader.image+0x1b24;
    r->create_status=UINT64_MAX;
    if(!pwrcl_enter(early,r,0,1))goto stopped;
    int returned=ops->create(io->context,r->functions[0],2,ops->name,&r->handle_output,&r->create_status);
    if(!pwrcl_leave(early,r,0,returned,1))goto stopped;
    if(r->create_status||!r->handle_output){pwrcl_fail(r,PWRCL_API,1);goto stopped;}
    r->client_held=1;paic_actual_order(0);
    if(!pwrcl_map(ops,early,r,w,0)||!pwrcl_pool_pair(io,r,w,1)||
       !pwrcl_transition(r,0)||(before->list[1].count&&r->handle_output!=(void*)(uintptr_t)before->list[1].node[0].address)||
       !pwrcl_client_read(io,r,w,&r->pools[1][1],(uintptr_t)r->handle_output,1,&r->created)||!pwrcl_source(io,r,w,1)){
        pwrcl_fail(r,PWRCL_CLIENT,1);goto stopped;
    }
    /* A NEW source-bound body may use this known private client. Its return
     * means a completed, retired phase, not hardware permission. The body
     * must establish its own raw source/device/lifetime evidence. Unknown or
     * outstanding work never reaches Delete; the old no-body path is intact. */
    if(body&&(!body(body_context,io,r,w,early)||!pwrcl_final_unopened(final))){
        pwrcl_fail(r,PWRCL_BODY,1);goto stopped;
    }
    r->delete_status=UINT64_MAX;
    if(!pwrcl_enter(early,r,2,1))goto stopped;
    returned=ops->drop(io->context,r->functions[1],r->handle_output,&r->delete_status);
    if(!pwrcl_leave(early,r,2,returned,1))goto stopped;
    if(r->delete_status){pwrcl_fail(r,PWRCL_API,1);goto stopped;}
    if(!pwrcl_map(ops,early,r,w,1)||!pwrcl_pool_pair(io,r,w,2)||!pwrcl_transition(r,1)||
       !pwrcl_client_read(io,r,w,&r->pools[2][1],(uintptr_t)r->handle_output,0,&r->released)||
       !pwrcl_source(io,r,w,2)){
        pwrcl_fail(r,PWRCL_CLIENT,1);goto stopped;
    }
    uint32_t done;
    if(!pwrcl_copy(io,r,w,r->final_global,r->reader.image+0xd2e8,sizeof(r->final_global),&done)||
       !pgcd_equal(r->final_global,r->reader.snapshot[1].global,sizeof(r->final_global))||!pwrcl_fresh(io,r)||!pwrcl_final_unopened(final)){
        pwrcl_fail(r,PWRCL_CHANGED,1);goto stopped;
    }
    r->client_held=0;r->client_returned=1;r->retired=1;r->final_context_untouched=1;early->finished=1;paic_actual_order(0);return 1;
stopped:
    if(r->core.uncertain||r->core.outstanding||r->reader.unknown||r->reader.outstanding||r->reader_ticket.outstanding)r->unknown=1;
    if(!r->provider_issued&&!r->unknown&&!r->outstanding){r->refused_before_API=1;r->retired=1;early->finished=1;}
    paic_actual_order(0);return 0;
}
static inline int pwrcl_run(const struct pwrcl_io *ops,const struct paic_result *enumeration,unsigned stage,
    struct pgcd_context *final,struct pgcd_context *early,struct pwrcl_result *r,struct pwrph_work *w)
{return pwrcl_run_body(ops,enumeration,stage,final,early,r,w,0,0);}
static inline int pwrcl_result_unsafe(const struct pwrcl_result *r)
{return r->unknown||r->outstanding||r->client_held||
    (r->provider_issued&&!r->client_returned)||(r->attempted&&!r->retired);}
static inline int pwrcl_unsafe(void){return pwrcl_result_unsafe(&pwrcl_record);}
static inline int pwrcl_actual_create(void *ctx,uint64_t fn,uint32_t drv,const char *name,void **out,uint64_t *status)
{(void)ctx;*status=((uint64_t(*)(uint32_t,const char*,void**))(uintptr_t)fn)(drv,name,out);return 1;}
static inline int pwrcl_actual_drop(void *ctx,uint64_t fn,void *handle,uint64_t *status)
{(void)ctx;*status=((uint64_t(*)(void*))(uintptr_t)fn)(handle);return 1;}
static inline void pwrcl_preboot(const struct paic_io *io,const struct paic_result *enumeration,unsigned stage,struct pgcd_context *final)
{
    const struct pwrcl_io ops={{*io,pwrph_actual_locate,pwrph_actual_map},pwrcl_actual_create,pwrcl_actual_drop,pwrcl_name};
    (void)pwrcl_run(&ops,enumeration,stage,final,&pwrcl_early_context,&pwrcl_record,&pwrcl_work);
}
static inline void pwrcl_report(void (*append)(const char *))
{
    static const char hex[]="0123456789abcdef";char chunk[127];
    append("WIFI_RPMH_PRIVATE_RAW_V1_BEGIN\r\n");const uint8_t *p=(const void*)&pwrcl_record;
    for(size_t at=0;at<sizeof(pwrcl_record);){unsigned n=(unsigned)(sizeof(pwrcl_record)-at);if(n>63)n=63;
        for(unsigned j=0;j<n;j++){chunk[j*2]=hex[p[at+j]>>4];chunk[j*2+1]=hex[p[at+j]&15];}chunk[n*2]=0;append(chunk);at+=n;}
    append("\r\nWIFI_RPMH_PRIVATE_RAW_V1_END\r\nWIFI_RPMH_PRIVATE_SCOPE=ZERO_VOTE_RAM_CLIENT_ONLY NO_COMMANDSET NO_MMIO NO_SMC NO_MSS NO_NV_SERVE NO_RADIO_PERMISSION\r\n");
}
#else
static inline int pwrcl_unsafe(void){return 0;}
#endif
#endif
