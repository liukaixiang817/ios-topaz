/* Checked backend for the SAME power transaction. Default OFF in its new
 * pre-final-GCD parent scope. No caller-supplied permission boolean exists. The local
 * NS interval is derived from the original known client, complete provider
 * RAM, actual registered Device namespace/geometry and post-mask CPU evidence.
 * It is not an EL3/MPU/VMID grant and cannot start MSS or write SMEM/rails.
 * A physical candidate still needs its parent gate and exact host admission. */
#ifndef POLARIS_UEFI_WIFI_RSC_ACCESS_H
#define POLARIS_UEFI_WIFI_RSC_ACCESS_H
#include "uefi-wifi-power-critical.h"
#include "uefi-wifi-rsc-device.h"
#if EFI_XNU_WIFI_POWER_TRANSACTION_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
#define PWRA_EVENTS (PWRSC_HISTORY+96u)
struct pwra_event {
    struct pwrmd_event io;
    uint32_t operation,engine_event,native_before,native_after;
};
struct pwra_cmd_snapshot {
    uint32_t attempted,complete,owner_bytes,table_bytes,global_bytes,bytes;
    uint32_t hash_count,hash_failed,page_issued[PWCD_PAGES],page_returned[PWCD_PAGES];
    uint64_t where[PWCD_PAGES],par[PWCD_PAGES];
    struct efi_loaded owner;uint8_t table[72],globals[72],hashes[5][32],raw[PWCD_DB_BYTES];
};
struct pwra_result {
    uint32_t attempted,error,unknown,outstanding,local_held,retired,acquired;
    uint32_t events,reads,writes,clock_calls,clock_returned,pre_reads,post_reads;
    uint64_t client,transaction,provider,critical,normal_RAM,masked_RAM,namespace_record;
    uint32_t saved[3],desired[3],mask,config,IRQ_enable,IRQ_status,tcs[8][4],command_status_OR[3];
    struct pwra_event history[PWRA_EVENTS];
    struct pwra_cmd_snapshot CmdDb[2];
};
struct pwra_io {
    const struct paic_io *memory;void *context;
    int (*translate)(void *,struct pwrmd_translation *);
    int (*read)(void *,uint64_t,uint32_t *);
    int (*write)(void *,uint64_t,uint32_t);
};
struct pwra_context {
    struct pwra_io io;struct pgcd_context *core;
    struct pwrcl_result *provider;const struct pwrph_work *work;
    struct pwrpc_result *critical;struct pwrsc_transaction *transaction;
    const struct pwrmd_result *device;struct pwra_result *record;
    const struct pwcd_result *cmd;
};
enum pwra_error {PWRA_OK,PWRA_ARGUMENT,PWRA_SCOPE,PWRA_CLIENT,PWRA_SAVED,PWRA_CHANGED,
    PWRA_TRANSLATION,PWRA_IO,PWRA_TIME,PWRA_PREFIX,PWRA_HISTORY,PWRA_UNKNOWN_STATUS};
static inline int pwra_fail(struct pwra_context *c,unsigned e,int unknown)
{
    struct pwra_result *r=c->record;if(!r->error)r->error=e;
    if(unknown||r->writes||r->outstanding)r->unknown=1;paic_actual_order(0);return 0;
}
static inline int pwra_live(struct pwra_context *c,uint32_t *native,uint64_t *ticks)
{
    struct pwra_result *r=c->record;struct pwrpc_result *p=c->critical;
    if(r->error||r->unknown||r->retired||r->provider!=(uintptr_t)c->provider||r->critical!=(uintptr_t)p||
       r->transaction!=(uintptr_t)c->transaction||!pwrpc_local_held(p)||
       !pwrpc_live(c->core,p,1,&p->after)||
       !pwrcl_owned(c->io.memory,c->provider,c->work,p->cpu_on_address,4))return pwra_fail(c,PWRA_SCOPE,1);
    *native=*(const volatile uint32_t*)(uintptr_t)p->cpu_on_address;*ticks=p->after.cpu.ticks;
    if(*native)return pwra_fail(c,PWRA_SCOPE,1);return 1;
}
static inline int pwra_address(uint64_t at)
{
    if(at==0x179e000c||at==PWRSC_BASE||at==PWRSC_BASE+4||at==PWRSC_BASE+8)return 1;
    if((at&3)||at<PWRSC_BASE||at>=PWRSC_BASE+8*PWRSC_STRIDE)return 0;
    unsigned off=(unsigned)(at-PWRSC_BASE)%PWRSC_STRIDE;
    if(off==0x10||off==0x14||off==0x18||off==0x1c)return 1;
    for(unsigned k=0;k<3;k++)if(off>=0x30+20*k&&off<=0x40+20*k)return 1;
    return 0;
}
static inline int pwra_transfer(struct pwra_context *c,uint64_t at,uint32_t *value,unsigned write,unsigned engine)
{
    struct pwra_result *r=c->record;struct pwrsc_transaction *t=c->transaction;
    if(r->unknown||r->error||r->outstanding||r->retired||r->events==PWRA_EVENTS||!pwra_address(at)||(!write&&at==PWRSC_BASE+8)||
       (write&&(!r->acquired||!r->local_held||!engine||!pwrsc_writable(t,at,*value))))return pwra_fail(c,PWRA_SCOPE,write!=0);
    if(engine){
        if(!t->attempted||!t->outstanding||t->outstanding>t->events||t->events>PWRSC_HISTORY)return pwra_fail(c,PWRA_PREFIX,1);
        const struct pwrsc_event *e=&t->history[t->outstanding-1];
        if(e->address!=at||e->operation!=(write?2u:1u)||!e->issued||!e->unknown||
           (write&&e->value!=*value)||t->active_mask!=r->mask)return pwra_fail(c,PWRA_PREFIX,1);
        for(unsigned k=0;k<3;k++)if(t->saved_vote[k]!=r->saved[k]||t->raised_vote[k]!=(r->saved[k]>r->desired[k]?r->saved[k]:r->desired[k]))
            return pwra_fail(c,PWRA_SAVED,1);
    }else if(write||!pwrmd_readable(at))return pwra_fail(c,PWRA_SCOPE,1);
    struct pwra_event *event=&r->history[r->events++];struct pwrmd_event *q=&event->io;
    q->address=at;q->value=write?*value:UINT32_MAX;event->operation=write?2u:1u;event->engine_event=engine?t->outstanding:0;
    if(!pwra_live(c,&event->native_before,&q->before))return 0;
    uint64_t page=at&~UINT64_C(4095);unsigned k;for(k=0;k<3&&pwrmd_pages[k]!=page;k++){}
    if(k==3||!pwrmd_exclude(c->work,page)||!c->device->GCD[k].issued||!c->device->GCD[k].returned||c->device->GCD[k].unknown||c->device->GCD[k].status)
        return pwra_fail(c,PWRA_SCOPE,1);
    q->translation.page=page;r->outstanding=r->events;paic_actual_order(0);
    int returned=c->io.translate(c->io.context,&q->translation);paic_actual_order(0);
    if(!returned||q->translation.page!=page||!pwrmd_translation_valid(&q->translation))return pwra_fail(c,PWRA_TRANSLATION,1);
    unsigned match=0;
    for(unsigned j=0;j<c->device->events;j++){
        const struct pwrmd_event *old=&c->device->history[j];
        if(old->translation.page==page&&old->issued&&old->returned&&!old->unknown&&pwrmd_translation_valid(&old->translation)){
            if(old->translation.read_par!=q->translation.read_par)return pwra_fail(c,PWRA_TRANSLATION,1);match=1;break;
        }
    }
    if(!match||!pwra_live(c,&event->native_before,&q->before))return pwra_fail(c,PWRA_SCOPE,1);
    q->issued=q->unknown=1;if(write)r->writes++;else r->reads++;paic_actual_order(0);
    returned=write?c->io.write(c->io.context,at,*value):c->io.read(c->io.context,at,&q->value);
    q->returned=returned?1:0;paic_actual_order(0);
    if(returned&&!write)*value=q->value;
    if(!returned)return pwra_fail(c,PWRA_IO,1);
    if(!write&&engine){
        uint64_t tcs=pwrsc_tcs(t);
        for(unsigned k=0;k<3;k++)if(at==tcs+0x3c+20*k){
            r->command_status_OR[k]|=q->value;
            if(q->value&~PWRSC_DONE)return pwra_fail(c,PWRA_UNKNOWN_STATUS,1);
        }
    }
    if(!pwra_live(c,&event->native_after,&q->after))return 0;
    q->unknown=0;r->outstanding=0;*value=q->value;paic_actual_order(0);return 1;
}
static inline int pwra_snapshot(struct pwra_context *c,unsigned post)
{
    struct pwra_result *r=c->record;uint32_t value;
    if(!pwra_transfer(c,0x179e000c,&value,0,0))return 0;r->config=value;
    if(!pwra_transfer(c,PWRSC_BASE,&value,0,0))return 0;r->IRQ_enable=value;
    if(!pwra_transfer(c,PWRSC_BASE+4,&value,0,0))return 0;r->IRQ_status=value;
    if(r->config!=c->device->config[1]||r->IRQ_enable!=c->device->IRQ_enable[1]||r->IRQ_status)return pwra_fail(c,PWRA_CHANGED,1);
    static const unsigned offset[4]={0x10,0x14,0x18,0x1c};
    for(unsigned k=0;k<8;k++)for(unsigned j=0;j<4;j++){
        if(!pwra_transfer(c,PWRSC_BASE+k*PWRSC_STRIDE+offset[j],&r->tcs[k][j],0,0))return 0;
        if(j==2){
            if(r->mask&(1u<<k)){if(!(r->tcs[k][j]&1)||((r->tcs[k][j]^c->device->tcs[1][k][j])&~1u))return pwra_fail(c,PWRA_CHANGED,1);}
            else if(r->tcs[k][j]!=c->device->tcs[1][k][j])return pwra_fail(c,PWRA_CHANGED,1);
        }
        else if(r->tcs[k][j]!=c->device->tcs[1][k][j])return pwra_fail(c,PWRA_CHANGED,1);
    }
    if(post)r->post_reads=35;else r->pre_reads=35;return 1;
}
/* Pure bounded RO source/namespace check while locally masked. No original
 * Query/getter/allocator, MPU change or SMEM store. Keep both complete fresh
 * byte copies, each per-page AT and every partial count; never substitute the
 * earlier API success/record flag for this current immutable data check. */
static inline int pwra_cmddb(struct pwra_context *c,unsigned slot)
{
    if(slot>1)return pwra_fail(c,PWRA_SCOPE,1);
    struct pwra_cmd_snapshot *s=&c->record->CmdDb[slot];const struct pwcd_result *d=c->cmd;
    if(s->attempted||!d||!d->stable||d->error||d->unknown||d->outstanding||d->database[0]!=d->database[1]||
       d->database[1]!=PWCD_UEFI_DB_BASE)return pwra_fail(c,PWRA_SCOPE,1);
    s->attempted=1;c->record->outstanding=0x20000u|slot;paic_actual_order(0);
    struct pwrcl_result *p=c->provider;const struct paic_io *m=c->io.memory;uint32_t native;uint64_t ticks;
    if(!pwra_live(c,&native,&ticks)||!pwrcl_copy(m,p,c->work,&s->owner,d->owner_address,sizeof(s->owner),&s->owner_bytes)||
       !pgcd_equal(&s->owner,&d->owner,sizeof(s->owner))||
       !pwrcl_copy(m,p,c->work,s->table,d->protocol[1],sizeof(s->table),&s->table_bytes)||
       !pgcd_equal(s->table,d->protocol_raw[1],sizeof(s->table))||
       !pwrcl_copy(m,p,c->work,s->globals,d->image+0x5158,sizeof(s->globals),&s->global_bytes)||
       !pgcd_equal(s->globals,d->globals[1],sizeof(s->globals))||
       !pwrcl_owned(m,p,c->work,d->image,PWCDI_IMAGE_BYTES)||
       !pwcdi_verify((const void*)(uintptr_t)d->image,d->image,s->hashes,&s->hash_count,&s->hash_failed))return pwra_fail(c,PWRA_CHANGED,1);
    for(unsigned k=0;k<PWCD_PAGES;k++){
        uint64_t page=d->database[1]+4096u*k;unsigned index=d->descriptor_page[1][k];
        if(index>k)return pwra_fail(c,PWRA_SCOPE,1);
        const struct pgcd_observation *q=&d->namespace[1][index];const struct pgcd_descriptor *g=&q->descriptor;
        if(q->issued!=1||q->returned!=1||q->unknown||q->status||g->type!=2||!(g->capabilities&8)||g->attributes!=8||
           g->base>page||!g->length||g->base>UINT64_MAX-g->length||g->base+g->length<page+4096)return pwra_fail(c,PWRA_SCOPE,1);
        if(!pwra_live(c,&native,&ticks))return 0;
        s->page_issued[k]=1;paic_actual_order(0);
        int returned=m->identity(m->context,page,4096,&s->where[k],&s->par[k]);
        if(returned)s->page_returned[k]=1;paic_actual_order(0);
        if(!returned||s->where[k]!=page||(s->par[k]&1)||!(s->par[k]&0x200)||(s->par[k]>>56)!=0xff||
           (s->par[k]&UINT64_C(0x0000fffffffff000))!=page)return pwra_fail(c,PWRA_TRANSLATION,1);
        for(unsigned j=0;j<4096;j++){
            unsigned offset=4096*k+j;s->raw[offset]=PWCD_LOAD(page+j);s->bytes=offset+1;
            if(s->raw[offset]!=d->database_raw[1][offset])return pwra_fail(c,PWRA_CHANGED,1);
        }
    }
    if(!pwra_live(c,&native,&ticks))return 0;s->complete=1;c->record->outstanding=0;paic_actual_order(0);return 1;
}
static inline int pwra_acquire(struct pwra_context *c,const struct pwra_io *io,struct pgcd_context *g,
    struct pwrcl_result *provider,const struct pwrph_work *w,struct pwrpc_result *critical,
    const struct pwcd_result *cmd,const struct pwrpb_baseline *normal,const struct pwrpb_baseline *masked,
    const struct pwrmd_result *device,struct pwrsc_transaction *tx,struct pwra_result *r)
{
    if(!r||r->attempted)return 0;r->attempted=1;
    if(!c||!io||!io->memory||!io->translate||!io->read||!io->write||!g||!provider||!w||!critical||!cmd||!normal||!masked||!device||!tx){r->error=PWRA_ARGUMENT;return 0;}
    *c=(struct pwra_context){*io,g,provider,w,critical,tx,device,r,cmd};
    r->client=(uintptr_t)provider->handle_output;r->provider=(uintptr_t)provider;r->critical=(uintptr_t)critical;r->transaction=(uintptr_t)tx;
    r->normal_RAM=(uintptr_t)normal;r->masked_RAM=(uintptr_t)masked;r->namespace_record=(uintptr_t)device;
    const void *objects[]={c,provider,critical,cmd,normal,masked,device,tx,r};
    const uint64_t sizes[]={sizeof(*c),sizeof(*provider),sizeof(*critical),sizeof(*cmd),sizeof(*normal),sizeof(*masked),sizeof(*device),sizeof(*tx),sizeof(*r)};
    for(unsigned k=0;k<9;k++)if(!pgcd_in_self(&provider->core,(uintptr_t)objects[k],sizes[k])||
       !pwrcl_owned(io->memory,provider,w,(uintptr_t)objects[k],(uint32_t)sizes[k]))return pwra_fail(c,PWRA_SCOPE,1);
    for(unsigned k=0;k<9;k++)for(unsigned j=0;j<k;j++)
        if(pwrcl_overlap((uintptr_t)objects[k],sizes[k],(uintptr_t)objects[j],sizes[j]))return pwra_fail(c,PWRA_SCOPE,1);
    if(!provider->client_held||provider->client_returned||provider->retired||provider->unknown||provider->outstanding||provider->error||
       !provider->pools_complete[1]||provider->created.bytes!=88||!r->client||!pwrpc_local_held(critical)||
       !pwrpb_equal(normal,masked)||normal->before.daif||normal->before.group1!=1||masked->before.daif!=0xc0||masked->before.group1||
       !device->complete||device->error||device->unknown||device->outstanding||device->queries!=3||device->reads!=70||
       device->image!=provider->reader.image||device->core!=provider->core.core||device->self_base!=provider->core.self_base||
       device->self_bytes!=provider->core.self_bytes||device->after.ticks>critical->normal.cpu.ticks||
       !cmd->stable||cmd->error||cmd->unknown||cmd->outstanding||cmd->owner_matches!=1||
       cmd->after.ticks>critical->normal.cpu.ticks||cmd->before.ticks<g->record->before.cpu.ticks||
       !pgcd_equal(cmd->resources[0],cmd->resources[1],sizeof(cmd->resources[0]))||
       !pwrpb_plan(masked,cmd->resources[1],r->saved,r->desired))return pwra_fail(c,PWRA_SCOPE,1);
    unsigned matches=0;const struct pwrcl_list *active=&masked->pool.list[0];
    for(unsigned k=0;k<active->count;k++)if(active->node[k].address==r->client&&
       pgcd_equal(active->node[k].raw,provider->created.raw,88))matches++;
    if(matches!=1)return pwra_fail(c,PWRA_CLIENT,1);
    for(unsigned k=0;k<4;k++)if(provider->created.queue_bytes[k]!=24||pwfi_le(provider->created.queue[k]+4,4))return pwra_fail(c,PWRA_CLIENT,1);
    r->mask=masked->active_mask;
    if(!pwra_cmddb(c,0)||!pwra_snapshot(c,0))return 0;
    r->acquired=r->local_held=1;paic_actual_order(0);return 1;
}
static inline int pwra_read(void *context,uint64_t at,uint32_t *value)
{struct pwra_context *c=context;return c&&c->record->acquired?pwra_transfer(c,at,value,0,1):0;}
static inline int pwra_write(void *context,uint64_t at,uint32_t value)
{struct pwra_context *c=context;return c&&c->record->acquired?pwra_transfer(c,at,&value,1,1):0;}
static inline int pwra_clock(void *context,uint64_t *ticks,uint64_t *frequency)
{
    struct pwra_context *c=context;uint32_t native;c->record->clock_calls++;
    if(!pwra_live(c,&native,ticks))return 0;*frequency=c->critical->after.cpu.frequency;c->record->clock_returned++;return 1;
}
static inline void pwra_order(void *context){(void)context;paic_actual_order(0);}
static inline int pwra_retire(struct pwra_context *c)
{
    struct pwra_result *r=c->record;
    if(!r->acquired||!r->local_held||r->unknown||r->outstanding||r->error||!pwrsc_retired(c->transaction)||r->writes!=c->transaction->writes)
        return pwra_fail(c,PWRA_PREFIX,1);
    for(unsigned k=0;k<r->events;k++)if(r->history[k].io.issued!=1||r->history[k].io.returned!=1||r->history[k].io.unknown||
       !pwrmd_translation_valid(&r->history[k].io.translation))return pwra_fail(c,PWRA_PREFIX,1);
    if(!pwra_cmddb(c,1)||!pwra_snapshot(c,1))return 0;
    r->local_held=0;r->retired=1;paic_actual_order(0);return 1;
}
/* These leaves are wired only by a future exact physical caller. They do
 * not bypass the checked context: no naked address-based store is exported. */
static inline int pwra_actual_read(void *context,uint64_t at,uint32_t *value)
{
    struct pwra_context *c=context;if(!c||!c->record||!c->record->outstanding||!pwra_address(at))return 0;
#if defined(__aarch64__) || defined(__arm64__)
    *value=*(const volatile uint32_t*)(uintptr_t)at;paic_actual_order(0);return 1;
#else
    (void)value;return 0;
#endif
}
static inline int pwra_actual_write(void *context,uint64_t at,uint32_t value)
{
    struct pwra_context *c=context;
    if(!c||!c->record||!c->record->outstanding||!c->record->acquired||!c->record->local_held||
       !pwrpc_local_held(c->critical)||!pwrsc_writable(c->transaction,at,value))return 0;
#if defined(__aarch64__) || defined(__arm64__)
    *(volatile uint32_t*)(uintptr_t)at=value;paic_actual_order(0);return 1;
#else
    return 0;
#endif
}
static inline struct pwra_io pwra_physical_io(const struct paic_io *memory,struct pwra_context *context)
{return (struct pwra_io){memory,context,pwrmd_actual_translate,pwra_actual_read,pwra_actual_write};}
#endif
#endif
