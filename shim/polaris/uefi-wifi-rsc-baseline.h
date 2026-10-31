/* Source-bound current RPMh RAM input for the new power transaction.
 * No provider API, MMIO, allocator or shared store. This is part of the SAME
 * power caller, not a standalone inventory feature or a write/MPU lease.
 * Original RET locks and a stable snapshot do not confer exclusivity. */
#ifndef POLARIS_UEFI_WIFI_RSC_BASELINE_H
#define POLARIS_UEFI_WIFI_RSC_BASELINE_H
#ifndef EFI_XNU_WIFI_POWER_TRANSACTION_AVAILABLE
#define EFI_XNU_WIFI_POWER_TRANSACTION_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_POWER_TRANSACTION_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
#if !EFI_XNU_GCD_MMIO_QUERY_AVAILABLE || !EFI_XNU_WIFI_RPMH_CLIENT_AVAILABLE || !EFI_XNU_WIFI_CMDDB_QUERY_AVAILABLE
#error "Power components require exact original GCD/RPMh-client/CmdDb scopes; they never enable those dependencies"
#endif
#include <stddef.h>
#include "uefi-gcd-mmio-readonly.h"
#include "uefi-audio-i2c-cache.h"
#include "uefi-wifi-rpmh-client.h"
#include "uefi-wifi-cmddb-query.h"
#define PWRPB_ROWS 128u
#define PWRPB_STATES 4u
struct pwrpb_state {uint64_t address;uint32_t bytes,reserved;uint8_t raw[72];};
struct pwrpb_row {uint64_t address;uint32_t bytes,states;uint8_t raw[24];struct pwrpb_state state[PWRPB_STATES];};
struct pwrpb_free_request {uint64_t address;uint32_t bytes,command_bytes;uint8_t raw[48],commands[128];};
struct pwrpb_baseline {
    uint32_t attempted,error,complete,rows,clients,free_requests,active_mask;
    uint32_t global_bytes,config_bytes,root_bytes,row_bytes,mode_bytes,queue_bytes,tcs_bytes,HAL_runtime_bytes;
    uint64_t identity_address,identity_par,root,cache,queue;
    struct paic_arch before,after;
    uint8_t global[0x110],root_pointer[8],config[40],drv_row[48],mode[24],mode_pointer[8];
    uint8_t queue_pointer[8],queue_state[48],driver_queue[5][40],tcs_pointer[8],tcs[8*24],mode_index[4];
    uint8_t HAL_runtime[8+16*24];
    struct pwrcl_pool pool;
    uint32_t client_queue_bytes[PWRCL_NODES][4];uint8_t client_queue[PWRCL_NODES][4][24];
    struct pwrpb_free_request free_request[PWRCL_NODES];
    struct pwrpb_row row[PWRPB_ROWS];
};
enum pwrpb_error {PWRPB_OK,PWRPB_ARGUMENT,PWRPB_LIFETIME,PWRPB_SOURCE,PWRPB_TIME,
    PWRPB_RAM,PWRPB_LIMIT,PWRPB_ALIAS,PWRPB_CHANGED,PWRPB_PENDING,PWRPB_CACHE,PWRPB_SAVED};
static inline int pwrpb_fail(struct pwrpb_baseline *b,unsigned e)
{if(!b->error)b->error=e;return 0;}
static inline int pwrpb_live(const struct paic_io *io,struct pwrcl_result *p,
    struct pwrpb_baseline *b,const struct paic_arch *expected)
{
    /* The source-bound caller also re-reads RAM inside its masked critical
     * interval. This accepts only the exact normal/masked architecture pair;
     * it does not use the normal service guard to grant masked API calls. */
    unsigned normal=expected->daif==0&&expected->group1==1;
    unsigned masked=expected->daif==0xc0&&expected->group1==0;
    if(expected->el!=4||(expected->mpidr&0xffffff)||expected->frequency!=19200000||
       !(expected->sre&1)||!(expected->sctlr&1)||(!normal&&!masked)||
       !io->arch(io->context,&b->after)||expected->el!=b->after.el||expected->mpidr!=b->after.mpidr||
       expected->ttbr0!=b->after.ttbr0||expected->ttbr1!=b->after.ttbr1||expected->tcr!=b->after.tcr||
       expected->sctlr!=b->after.sctlr||expected->mair!=b->after.mair||expected->daif!=b->after.daif||
       expected->sre!=b->after.sre||expected->group1!=b->after.group1||expected->frequency!=b->after.frequency||
       b->after.ticks<expected->ticks||b->after.ticks-p->reader.before.ticks>PGCD_FRESH_TICKS)
        return pwrpb_fail(b,PWRPB_TIME);
    if(!b->before.frequency)b->before=b->after;return 1;
}
static inline int pwrpb_copy(const struct paic_io *io,struct pwrcl_result *p,const struct pwrph_work *w,
    struct pwrpb_baseline *b,void *out,uint64_t at,uint32_t bytes,uint32_t *done,int heap)
{
    *done=0;
    if((heap&&!pwrcl_heap(io,p,w,at,bytes))||!pwrcl_owned(io,p,w,at,bytes))return pwrpb_fail(b,PWRPB_RAM);
    b->identity_address=p->identity_address;b->identity_par=p->identity_par;
    for(unsigned k=0;k<bytes;k++){((uint8_t*)out)[k]=((const volatile uint8_t*)(uintptr_t)at)[k];*done=k+1;}return 1;
}
/* Re-read already admitted pool addresses. Do not follow a newly changed
 * pointer or relabel an unobserved/free allocation as a known object. */
static inline int pwrpb_pool(const struct paic_io *io,struct pwrcl_result *p,const struct pwrph_work *w,
    struct pwrpb_baseline *b,const struct pwrcl_pool *saved)
{
    uint32_t done;b->pool.address=saved->address;
    if(!saved->complete||!pwrpb_copy(io,p,w,b,b->pool.root,saved->address,16,&b->pool.bytes,1)||
       !pgcd_equal(b->pool.root,saved->root,16))return pwrpb_fail(b,PWRPB_CHANGED);
    for(unsigned side=0;side<2;side++){
        struct pwrcl_list *q=&b->pool.list[side];const struct pwrcl_list *old=&saved->list[side];
        q->address=old->address;q->count=old->count;
        if(!old->complete||old->count>PWRCL_NODES||!pwrpb_copy(io,p,w,b,q->raw,q->address,24,&q->bytes,1)||
           !pgcd_equal(q->raw,old->raw,24))return pwrpb_fail(b,PWRPB_CHANGED);
        for(unsigned k=0;k<old->count;k++){
            struct pwrcl_node *n=&q->node[k];n->address=old->node[k].address;q->visited=k+1;
            if(!pwrpb_copy(io,p,w,b,n->raw,n->address,88,&n->bytes,1)||!pgcd_equal(n->raw,old->node[k].raw,88))return pwrpb_fail(b,PWRPB_CHANGED);
        }q->complete=1;
    }b->pool.complete=1;
    /* All foreign clients must have no pending request/waiter. Their free
     * request queue can contain retired objects; do not treat it as live DMA. */
    b->clients=b->pool.list[0].count;
    for(unsigned k=0;k<b->clients;k++){
        const struct pwrcl_node *n=&b->pool.list[0].node[k];
        if(pwfi_le(n->raw+0x38,4)||pwfi_le(n->raw+0x34,4)!=UINT32_MAX)return pwrpb_fail(b,PWRPB_PENDING);
        for(unsigned j=0;j<4;j++){
            uint64_t at=pwfi_le(n->raw+0x10+8*j,8);
            if(!pwrpb_copy(io,p,w,b,b->client_queue[k][j],at,24,&b->client_queue_bytes[k][j],1))return 0;
            const uint8_t *q=b->client_queue[k][j];unsigned count=(unsigned)pwfi_le(q+4,4);
            if(pwfi_le(q,4)!=(j<2?16u:24u)||count>PWRCL_NODES)return pwrpb_fail(b,PWRPB_LIMIT);
            if((j!=1&&count)||(!count&&(pwfi_le(q+8,8)||pwfi_le(q+16,8))))return pwrpb_fail(b,PWRPB_PENDING);
            if(count&&(!pwfi_le(q+8,8)||!pwfi_le(q+16,8)))return pwrpb_fail(b,PWRPB_PENDING);
            /* Queue headers must not alias clients, pool roots or another
             * client's queue: the originals mutate those independently. */
            if(pwrcl_overlap(at,24,b->pool.address,16))return pwrpb_fail(b,PWRPB_ALIAS);
            for(unsigned side=0;side<2;side++){
                if(pwrcl_overlap(at,24,b->pool.list[side].address,24))return pwrpb_fail(b,PWRPB_ALIAS);
                for(unsigned z=0;z<b->pool.list[side].count;z++)if(pwrcl_overlap(at,24,b->pool.list[side].node[z].address,88))return pwrpb_fail(b,PWRPB_ALIAS);
            }
            for(unsigned a=0;a<=k;a++)for(unsigned z=0;z<(a==k?j:4);z++)
                if(pwrcl_overlap(at,24,pwfi_le(b->pool.list[0].node[a].raw+0x10+8*z,8),24))return pwrpb_fail(b,PWRPB_ALIAS);
        }
    }
    return pwrpb_copy(io,p,w,b,b->pool.root,saved->address,16,&done,1)&&pgcd_equal(b->pool.root,saved->root,16);
}
static inline int pwrpb_driver(const struct paic_io *io,struct pwrcl_result *p,const struct pwrph_work *w,
    struct pwrpb_baseline *b)
{
    const struct pwrph_snapshot *old=&p->reader.snapshot[1];const struct pwrph_drv *d=&old->drv[0];uint32_t done;
    if(!pwrpb_copy(io,p,w,b,b->root_pointer,p->reader.image+0xb100,8,&b->root_bytes,0))return 0;
    b->root=pwfi_le(b->root_pointer,8);
    if(!pwrpb_copy(io,p,w,b,b->config,b->root,40,&b->config_bytes,0)||!pgcd_equal(b->config,old->config,40)||
       !pwrpb_copy(io,p,w,b,b->drv_row,pwfi_le(b->config+0x20,8),48,&b->row_bytes,0)||!pgcd_equal(b->drv_row,d->row,48))return pwrpb_fail(b,PWRPB_CHANGED);
    if(pwfi_le(b->config,4)!=1||pwfi_le(b->drv_row,4)!=2||pwfi_le(b->drv_row+4,4)!=2||
       pwfi_le(b->drv_row+0x18,4)!=8||pwfi_le(b->drv_row+0x1c,4)!=16||pwfi_le(b->drv_row+0x20,4)!=1||pwfi_le(b->drv_row+0x14,4))return pwrpb_fail(b,PWRPB_SOURCE);
    if(!pwrpb_copy(io,p,w,b,b->mode_pointer,pwfi_le(b->drv_row+0x28,8),8,&done,0)||
       !pwrpb_copy(io,p,w,b,b->mode,pwfi_le(b->mode_pointer,8),24,&b->mode_bytes,0)||!pgcd_equal(b->mode,d->mode[0],24))return pwrpb_fail(b,PWRPB_CHANGED);
    unsigned active=(unsigned)pwfi_le(b->mode,4);if(!active||active>8)return pwrpb_fail(b,PWRPB_LIMIT);
    b->active_mask=(1u<<active)-1;
    /* Original6ee0 indexes16 fixed24B runtime HAL entries after the8B header
     * at image+d538; it uses header+24*DRV+c/+10/+14 for base/bank/init.
     * entry+14 must be initialized, +c is base and +10 selects the DRV bank.
     * Original7fb0 adds0x20d04 for bank2:179c0000->179e0d04. Read the actual
     * table; the static HAL config and a DT name are not substituted for it. */
    unsigned configured=(unsigned)pwfi_le(old->HAL_config+0x20,4);
    if(!configured||configured>16||
       !pwrpb_copy(io,p,w,b,b->HAL_runtime,p->reader.image+0xd538,sizeof(b->HAL_runtime),&b->HAL_runtime_bytes,0)||
       b->HAL_runtime[0]!=1||pwfi_le(b->HAL_runtime+4,4)!=configured||
       pwfi_le(b->HAL_runtime+48+0x18,4)!=8||pwfi_le(b->HAL_runtime+48+0x1c,4)!=16)return pwrpb_fail(b,PWRPB_SOURCE);
    unsigned matches=0;
    for(unsigned k=0;k<16;k++){
        const uint8_t *entry=b->HAL_runtime+24*k;
        if(entry[0x14]==1&&pwfi_le(entry+0xc,4)==0x179c0000&&pwfi_le(entry+0x10,4)==2){
            if(k!=2)return pwrpb_fail(b,PWRPB_ALIAS);matches++;
        }
    }
    if(matches!=1)return pwrpb_fail(b,PWRPB_SOURCE);
    if(!pwrpb_copy(io,p,w,b,b->queue_pointer,pwfi_le(b->global+0x10,8),8,&done,1)||
       !pwrpb_copy(io,p,w,b,b->queue_state,pwfi_le(b->queue_pointer,8),48,&b->queue_bytes,1)||
       !pgcd_equal(b->queue_state,d->queue_state,48)||pwfi_le(b->queue_state,4)!=16)return pwrpb_fail(b,PWRPB_CHANGED);
    b->queue=pwfi_le(b->queue_pointer,8);
    for(unsigned k=0;k<5;k++){
        if(!pwrpb_copy(io,p,w,b,b->driver_queue[k],pwfi_le(b->queue_state+8+8*k,8),40,&done,1)||
           !pgcd_equal(b->driver_queue[k],d->queue[k],40)||pwfi_le(b->driver_queue[k],4)!=40)return pwrpb_fail(b,PWRPB_CHANGED);
        unsigned count=(unsigned)pwfi_le(b->driver_queue[k]+4,4);
        if(count>PWRCL_NODES||(k!=2&&count))return pwrpb_fail(b,PWRPB_PENDING);
        if(!count&&(pwfi_le(b->driver_queue[k]+8,8)||pwfi_le(b->driver_queue[k]+16,8)))return pwrpb_fail(b,PWRPB_PENDING);
    }
    /* Original4b24 pulls a retired request from queue_state+0x18. Its ONE
     * observed free object is not active/pending work. Preserve all objects. */
    const uint8_t *free=b->driver_queue[2];unsigned count=(unsigned)pwfi_le(free+4,4);uint64_t cursor=pwfi_le(free+8,8);
    for(unsigned k=0;k<count;k++){
        struct pwrpb_free_request *x=&b->free_request[k];x->address=cursor;b->free_requests=k+1;
        if(!cursor)return pwrpb_fail(b,PWRPB_PENDING);
        for(unsigned j=0;j<k;j++)if(pwrcl_overlap(cursor,48,b->free_request[j].address,48))return pwrpb_fail(b,PWRPB_ALIAS);
        if(!pwrpb_copy(io,p,w,b,x->raw,cursor,48,&x->bytes,1)||
           !pwrpb_copy(io,p,w,b,x->commands,pwfi_le(x->raw,8),128,&x->command_bytes,1))return 0;
        cursor=pwfi_le(x->raw+40,8);
        if(k+1==count&&(cursor||x->address!=pwfi_le(free+16,8)))return pwrpb_fail(b,PWRPB_CHANGED);
    }
    if(cursor)return pwrpb_fail(b,PWRPB_CHANGED);
    if(!pwrpb_copy(io,p,w,b,b->tcs_pointer,pwfi_le(b->global+0xf8,8),8,&done,1)||
       !pwrpb_copy(io,p,w,b,b->tcs,pwfi_le(b->tcs_pointer,8),192,&b->tcs_bytes,1)||!pgcd_equal(b->tcs,d->tcs,192)||
       !pwrpb_copy(io,p,w,b,b->mode_index,pwfi_le(b->global+0x100,8),4,&done,1)||pwfi_le(b->mode_index,4))return pwrpb_fail(b,PWRPB_CHANGED);
    for(unsigned k=0;k<8;k++){
        const uint8_t *t=b->tcs+24*k;
        if(pwfi_le(t,4)!=k||pwfi_le(t+4,4)!=(k<active?0u:3u)||pwfi_le(t+16,8))return pwrpb_fail(b,PWRPB_PENDING);
        /* The +8 historical sent timestamp is retained, not relabeled busy. */
    }return 1;
}
static inline int pwrpb_capture(const struct paic_io *io,struct pwrcl_result *p,const struct pwrph_work *w,
    const struct pwrcl_pool *pool,const struct paic_arch *expected,struct pwrpb_baseline *b)
{
    if(!b||b->attempted)return 0;b->attempted=1;
    if(!io||!io->arch||!io->identity||!p||!w||!pool||!expected||!p->reader.stable||p->reader.error||
       p->reader.unknown||p->reader.outstanding||p->core.error||p->core.uncertain||p->core.outstanding||
       !pgcd_in_self(&p->core,(uintptr_t)b,sizeof(*b)))return pwrpb_fail(b,PWRPB_LIFETIME);
    if(!pwrpb_live(io,p,b,expected)||!pwrcl_owned(io,p,w,(uintptr_t)b,sizeof(*b))||
       !pwrpb_copy(io,p,w,b,b->global,p->reader.image+0xd2e8,0x110,&b->global_bytes,0)||
       !pgcd_equal(b->global,p->reader.snapshot[1].global,0x110))return pwrpb_fail(b,PWRPB_CHANGED);
    if(!pwrpb_driver(io,p,w,b)||!pwrpb_pool(io,p,w,b,pool))return 0;
    unsigned count=(unsigned)pwfi_le(b->global+4,4);b->cache=pwfi_le(b->global+8,8);
    if(count>PWRPB_ROWS||(!count&&b->cache)||(count&&!b->cache))return pwrpb_fail(b,PWRPB_LIMIT);
    if(count&&!pwrcl_heap(io,p,w,b->cache,count*24))return pwrpb_fail(b,PWRPB_RAM);
    for(unsigned k=0;k<count;k++){
        struct pwrpb_row *row=&b->row[k];row->address=b->cache+24*k;b->rows=k+1;
        if(!pwrpb_live(io,p,b,expected)||!pwrpb_copy(io,p,w,b,row->raw,row->address,24,&row->bytes,1))return 0;
        uint32_t resource=(uint32_t)pwfi_le(row->raw,4);
        if(!resource||(k&&resource<=pwfi_le(b->row[k-1].raw,4)))return pwrpb_fail(b,PWRPB_CACHE);
        uint64_t cursor=pwfi_le(row->raw+8,8);
        while(cursor){
            if(row->states==PWRPB_STATES)return pwrpb_fail(b,PWRPB_LIMIT);
            if(pwrcl_overlap(cursor,72,b->cache,count*24))return pwrpb_fail(b,PWRPB_ALIAS);
            for(unsigned a=0;a<=k;a++)for(unsigned j=0;j<b->row[a].states;j++)
                if(pwrcl_overlap(cursor,72,b->row[a].state[j].address,72))return pwrpb_fail(b,PWRPB_ALIAS);
            struct pwrpb_state *s=&row->state[row->states++];s->address=cursor;
            if(!pwrpb_copy(io,p,w,b,s->raw,cursor,72,&s->bytes,1))return 0;
            if(pwfi_le(s->raw,4)!=2||pwfi_le(s->raw+4,4)||s->raw[0x10]>1||s->raw[0x1c]>1)return pwrpb_fail(b,PWRPB_PENDING);
            if(row->states>1)return pwrpb_fail(b,PWRPB_CACHE); /* one configured DRV2, no duplicate/foreign state */
            cursor=pwfi_le(s->raw+0x40,8);
        }
    }
    if(!pwrpb_live(io,p,b,expected))return 0;b->complete=1;return 1;
}
static inline int pwrpb_equal(const struct pwrpb_baseline *a,const struct pwrpb_baseline *b)
{
    if(!a||!b||!a->complete||!b->complete||a->error||b->error||a->rows!=b->rows||a->clients!=b->clients||
       a->free_requests!=b->free_requests||a->active_mask!=b->active_mask||a->root!=b->root||a->cache!=b->cache||a->queue!=b->queue)return 0;
    /* Timestamps/AT observations are retained separately. Compare every byte
     * of the actual namespace, clients, queues, retired objects and states. */
    return pgcd_equal(a->global,b->global,sizeof(*a)-offsetof(struct pwrpb_baseline,global));
}
/* Baseline data only. A valid plan is NOT a same-EE/EL3/TCS/MPU lease. */
static inline int pwrpb_plan(const struct pwrpb_baseline *b,const struct pwcd_resource desired[3],uint32_t saved[3],uint32_t requested[3])
{
    if(!b||!b->complete||b->error||b->rows>PWRPB_ROWS||!desired||!saved||!requested)return 0;
    uint32_t originals[3],targets[3];
    for(unsigned k=0;k<3;k++){
        const struct pwrpb_state *s=0;
        if(desired[k].address!=pwcd_addresses[k]||desired[k].length!=32||desired[k].index>15||
           pwfi_le(desired[k].aux+2*desired[k].index,2)<384||
           (desired[k].index&&pwfi_le(desired[k].aux+2*(desired[k].index-1),2)>=384))return 0;
        for(unsigned j=0;j<b->rows;j++)if(pwfi_le(b->row[j].raw,4)==desired[k].address){
            if(b->row[j].states!=1)return 0;s=&b->row[j].state[0];
        }
        if(!s||s->bytes!=72||s->raw[0x10]!=1||s->raw[0x1c]!=1||pwfi_le(s->raw+0x20,4)||
           pwfi_le(s->raw+0xc,4)!=pwfi_le(s->raw+0x18,4)||pwfi_le(s->raw+0xc,4)>15)return 0;
        uint32_t index=(uint32_t)pwfi_le(s->raw+0xc,4);
        if(index&&pwfi_le(desired[k].aux+2*index,2)==0)return 0;
        originals[k]=index;targets[k]=desired[k].index;
    }
    for(unsigned k=0;k<3;k++){saved[k]=originals[k];requested[k]=targets[k];}return 1;
}
#endif
#endif
