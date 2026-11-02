/* Checked backend for the SAME power transaction. Default OFF in its new
 * pre-final-GCD parent scope. No caller-supplied permission boolean exists. The local
 * NS interval is derived from the original known client, complete provider
 * RAM, actual registered Device namespace/geometry and post-mask CPU evidence.
 * It is not an EL3/MPU/VMID grant and cannot start MSS or write SMEM/rails.
 * A physical candidate still needs its parent gate and exact host admission. */
#ifndef POLARIS_UEFI_WIFI_RSC_ACCESS_H
#define POLARIS_UEFI_WIFI_RSC_ACCESS_H
#ifndef EFI_XNU_WIFI_READ_ACCESS_CHECKPOINT
#define EFI_XNU_WIFI_READ_ACCESS_CHECKPOINT 0
#endif
#ifndef EFI_XNU_WIFI_READ_DB_CHECKPOINT
#define EFI_XNU_WIFI_READ_DB_CHECKPOINT 0
#endif
#ifndef EFI_XNU_WIFI_DB_WORD_CAPTURE
#define EFI_XNU_WIFI_DB_WORD_CAPTURE 0
#endif
#ifndef EFI_XNU_WIFI_CURRENT_WORD_READ
#define EFI_XNU_WIFI_CURRENT_WORD_READ 0
#endif
#include "uefi-wifi-power-critical.h"
#include "uefi-wifi-rsc-device.h"
#include "uefi-wifi-cmddb-prepared.h"
struct pwcp_result;
#if EFI_XNU_WIFI_POWER_TRANSACTION_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
#define PWRA_EVENTS (PWRSC_HISTORY+96u)
#if EFI_XNU_WIFI_DB_WORD_CAPTURE
#if !EFI_XNU_WIFI_CPU_LIVE_DIAGNOSTICS || (!EFI_XNU_WIFI_NORMAL_TO_MASKED_DB && !EFI_XNU_WIFI_CURRENT_WORD_READ) || (!EFI_XNU_WIFI_READ_DB_CHECKPOINT && !EFI_XNU_WIFI_CURRENT_WORD_READ) || !EFI_XNU_WIFI_PREPARED_POWER_AVAILABLE || !EFI_XNU_WIFI_ARC_READ_AVAILABLE
#error Word capture requires the complete normal-to-masked database diagnostic scope
#endif
/* Only the already NS/WB/same-PA validated Normal RAM page below uses a
 * word load. This is resident delivery/prefix evidence, not an IO lease. */
struct pwra_word_capture {
    uint32_t issued,returned,load_pending,compare_pending;
    uint32_t compared_bytes,failed_byte,last_valid,reserved;
    uint64_t pending_address,last_address,last_word;
};
_Static_assert(sizeof(struct pwra_word_capture)==56,"full word capture prefix");
#if defined(POLARIS_CMDDB_SOFTWARE_TEST)
static int pwra_test_word_load(uint64_t,uint64_t *);
#endif
#endif
struct pwra_event {
    struct pwrmd_event io;
    uint32_t operation,engine_event,native_before,native_after;
};
struct pwra_cmd_snapshot {
#if EFI_XNU_WIFI_DB_WORD_CAPTURE
    struct pwra_word_capture word;
#endif
    uint32_t attempted,complete,owner_bytes,table_bytes,global_bytes,bytes;
    uint32_t hash_count,hash_failed,page_issued[PWCD_PAGES],page_returned[PWCD_PAGES];
    uint64_t where[PWCD_PAGES],par[PWCD_PAGES];
    struct efi_loaded owner;uint8_t table[72],globals[72],hashes[5][32],raw[PWCD_DB_BYTES];
#if EFI_XNU_WIFI_PREPARED_POWER_AVAILABLE
    struct pgns_translation current_AT[PWCD_PAGES];
#endif
};
#if EFI_XNU_WIFI_DB_WORD_CAPTURE
_Static_assert(__builtin_offsetof(struct pwra_cmd_snapshot,raw)%8==0,"aligned Normal RAM record word store");
#endif
struct pwra_result {
    uint32_t attempted,error,unknown,outstanding,local_held,retired,acquired;
    uint32_t events,reads,writes,clock_calls,clock_returned,pre_reads,post_reads;
    uint64_t client,transaction,provider,critical,normal_RAM,masked_RAM,namespace_record;
    uint32_t saved[3],desired[3],mask,config,IRQ_enable,IRQ_status,tcs[8][4],command_status_OR[3];
    struct pwra_event history[PWRA_EVENTS];
    struct pwra_cmd_snapshot CmdDb[2];
#if EFI_XNU_WIFI_ARC_READ_AVAILABLE
    uint64_t read_transaction,write_transaction;
    uint32_t read_events,read_writes,read_retired,write_bound;
    struct pgcd_arch read_end;
#endif
};
struct pwra_io {
    const struct paic_io *memory;void *context;
    int (*translate)(void *,struct pwrmd_translation *);
    int (*read)(void *,uint64_t,uint32_t *);
    int (*write)(void *,uint64_t,uint32_t);
#if EFI_XNU_WIFI_PREPARED_POWER_AVAILABLE
    int (*RAM_translate)(void *,struct pgns_translation *);
#endif
};
struct pwra_context {
    struct pwra_io io;struct pgcd_context *core;
    struct pwrcl_result *provider;const struct pwrph_work *work;
    struct pwrpc_result *critical;struct pwrsc_transaction *transaction;
    const struct pwrmd_result *device;struct pwra_result *record;
    const struct pwcd_result *cmd;
#if EFI_XNU_WIFI_PREPARED_POWER_AVAILABLE
    const struct pwcp_result *prepared;
#endif
#if EFI_XNU_WIFI_ARC_READ_AVAILABLE
    struct pwrr_transaction *read;
    struct pwrsc_transaction *write;
#endif
};
enum pwra_error {PWRA_OK,PWRA_ARGUMENT,PWRA_SCOPE,PWRA_CLIENT,PWRA_SAVED,PWRA_CHANGED,
    PWRA_TRANSLATION,PWRA_IO,PWRA_TIME,PWRA_PREFIX,PWRA_HISTORY,PWRA_UNKNOWN_STATUS};
#if EFI_XNU_WIFI_READ_ACCESS_CHECKPOINT
static inline int pwra_reject_store(void *,uint64_t,uint32_t);
#endif
#if EFI_XNU_WIFI_ARC_READ_AVAILABLE
static inline int pwra_zero(const void *data,size_t bytes)
{const uint8_t *p=data;for(size_t k=0;k<bytes;k++)if(p[k])return 0;return 1;}
#endif
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
static inline int pwra_engine_writable(const struct pwra_context *c,uint64_t at,uint32_t value)
{
#if EFI_XNU_WIFI_ARC_READ_AVAILABLE
    if(c->read&&c->transaction==&c->read->io&&!c->record->write_bound)return pwrr_writable(c->read,at,value);
#endif
    return pwrsc_writable(c->transaction,at,value);
}
static inline int pwra_transfer(struct pwra_context *c,uint64_t at,uint32_t *value,unsigned write,unsigned engine)
{
    struct pwra_result *r=c->record;struct pwrsc_transaction *t=c->transaction;
    if(r->unknown||r->error||r->outstanding||r->retired||r->events==PWRA_EVENTS||!pwra_address(at)||(!write&&at==PWRSC_BASE+8)||
       (write&&(!r->acquired||!r->local_held||!engine||!pwra_engine_writable(c,at,*value))))return pwra_fail(c,PWRA_SCOPE,write!=0);
    unsigned read_engine=0;
#if EFI_XNU_WIFI_ARC_READ_AVAILABLE
    read_engine=c->read&&t==&c->read->io&&!r->write_bound;
#endif
    if(engine){
        if(!t->attempted||!t->outstanding||t->outstanding>t->events||t->events>PWRSC_HISTORY)return pwra_fail(c,PWRA_PREFIX,1);
#if EFI_XNU_WIFI_ARC_READ_AVAILABLE
        if(c->read&&!read_engine&&c->read->io.events+t->events>PWRSC_HISTORY)return pwra_fail(c,PWRA_HISTORY,1);
#endif
        const struct pwrsc_event *e=&t->history[t->outstanding-1];
#if EFI_XNU_WIFI_CURRENT_WORD_READ
        if(read_engine&&e->phase!=t->phase)return pwra_fail(c,PWRA_PREFIX,1);
#endif
        if(e->address!=at||e->operation!=(write?2u:1u)||!e->issued||!e->unknown||
           (write&&e->value!=*value)||t->active_mask!=r->mask)return pwra_fail(c,PWRA_PREFIX,1);
        for(unsigned k=0;k<3;k++){
            if(read_engine){if(t->saved_vote[k]||t->raised_vote[k]||t->address[k])return pwra_fail(c,PWRA_SAVED,1);}
            else if(t->saved_vote[k]!=r->saved[k]||t->raised_vote[k]!=(r->saved[k]>r->desired[k]?r->saved[k]:r->desired[k]))return pwra_fail(c,PWRA_SAVED,1);
        }
#if EFI_XNU_WIFI_ARC_READ_AVAILABLE
        if(c->read&&!read_engine){
            uint32_t saved[3],requested[3];
            if(!r->write_bound||!pwrr_plan((const void*)(uintptr_t)r->masked_RAM,c->prepared->resources[1],c->read,saved,requested))return pwra_fail(c,PWRA_SAVED,1);
            for(unsigned k=0;k<3;k++)if(saved[k]!=r->saved[k]||requested[k]!=r->desired[k])return pwra_fail(c,PWRA_SAVED,1);
        }
#endif
    }else if(write||!pwrmd_readable(at))return pwra_fail(c,PWRA_SCOPE,1);
    struct pwra_event *event=&r->history[r->events++];struct pwrmd_event *q=&event->io;
    q->address=at;q->value=write?*value:UINT32_MAX;event->operation=write?2u:1u;
    event->engine_event=engine?(t->outstanding|(read_engine?UINT32_C(0x80000000):0)):0;
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
#if EFI_XNU_WIFI_CURRENT_WORD_READ
            if(read_engine){
                /* A delivered RO snapshot is retained RAW, not interpreted
                 * as completion of a request that has not been issued (or
                 * has already been acknowledged). No bit is masked away.
                 * The independent full engine prefix still binds every
                 * initial/final sample and every NEW IRQ/DONE/idle/restore. */
                if(t->phase==0){
                    if(t->writes||t->triggers||t->completed||t->acknowledged||t->steps||
                       c->read->response_seen||c->read->valid||c->read->reserved)
                        return pwra_fail(c,PWRA_PREFIX,1);
                }else if(t->phase==7){
                    if(t->triggers!=3||t->completed!=3||t->acknowledged!=3||
                       c->read->response_seen!=7||c->read->valid||c->read->reserved)
                        return pwra_fail(c,PWRA_PREFIX,1);
                }else{
                    if(k||!(t->phase==2||t->phase==4||t->phase==6)||t->triggers!=t->phase/2||
                       t->completed+1!=t->triggers||t->acknowledged!=t->completed)
                        return pwra_fail(c,PWRA_PREFIX,1);
                    if(!pwrr_pending_status_known(q->value))return pwra_fail(c,PWRA_UNKNOWN_STATUS,1);
                }
            }else
#endif
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
#if EFI_XNU_WIFI_PREPARED_POWER_AVAILABLE
static inline int pwra_cmddb_prepared(struct pwra_context *c,unsigned slot)
{
    const struct pwcp_result *d=c->prepared;struct pwra_cmd_snapshot *s=&c->record->CmdDb[slot];
    if(slot>1||!d||pwcp_unsafe(d)||!d->stable||!d->complete||d->provider!=(uintptr_t)c->provider||
       d->core!=(uintptr_t)c->core||!c->io.RAM_translate||s->attempted)return pwra_fail(c,PWRA_SCOPE,1);
    const struct pwsp_result *prepared=(const void*)(uintptr_t)d->preparation;
    if(!prepared||!pgcd_in_self(&c->provider->core,(uintptr_t)prepared,sizeof(*prepared))||
       !prepared->complete||pwsp_unsafe(prepared)||!prepared->retired)return pwra_fail(c,PWRA_SCOPE,1);
#if EFI_XNU_WIFI_DB_WORD_CAPTURE
    if(!pwra_zero(&s->word,sizeof(s->word)))return pwra_fail(c,PWRA_PREFIX,1);
#endif
    s->attempted=1;c->record->outstanding=0x20000u|slot;paic_actual_order(0);
#if EFI_XNU_WIFI_DB_WORD_CAPTURE
    s->word.failed_byte=UINT32_MAX;
#endif
    const struct pwcp_source *prior=&d->source[2];struct pwrcl_result *p=c->provider;
    const struct paic_io *m=c->io.memory;uint32_t native;uint64_t ticks;
    if(!pwra_live(c,&native,&ticks)||!pwrcl_copy(m,p,c->work,&s->owner,d->owner_address,sizeof(s->owner),&s->owner_bytes)||
       !pgcd_equal(&s->owner,&prior->owner,sizeof(s->owner))||
       !pwrcl_copy(m,p,c->work,s->table,d->protocol,72,&s->table_bytes)||!pgcd_equal(s->table,prior->table,72)||
       !pwrcl_copy(m,p,c->work,s->globals,d->image+0x5158,72,&s->global_bytes)||!pgcd_equal(s->globals,prior->globals,72)||
       !pwrcl_owned(m,p,c->work,d->image,PWCDI_IMAGE_BYTES)||
       !pwcdi_verify((const void*)(uintptr_t)d->image,d->image,s->hashes,&s->hash_count,&s->hash_failed))return pwra_fail(c,PWRA_CHANGED,1);
    /* Preserve the existing FULL128KiB fresh comparisons before first store
     * and after full engine retirement. No earlier API status or preparation
     * boolean replaces these bytes. New NS/WB AT retains actual PAR restore.
     * A captured namespace descriptor is never labelled an original getter. */
    for(unsigned k=0;k<PWCD_PAGES;k++){
        uint64_t page=PWCD_UEFI_DB_BASE+4096u*k;struct pgcd_descriptor g;
        if(!pgns_descriptor(&d->namespace,page,&g)||g.type!=2||!(g.capabilities&8)||g.attributes!=8||
           (!polaris_efi_range_owned(c->work->map,c->work->bytes,c->work->stride,page,4096,0)&&
            !polaris_efi_range_owned(c->work->map,c->work->bytes,c->work->stride,page,4096,4))||
           !pwra_live(c,&native,&ticks))return pwra_fail(c,PWRA_SCOPE,1);
        struct pgns_translation *t=&s->current_AT[k];t->page=page;s->page_issued[k]=1;paic_actual_order(0);
        int returned=c->io.RAM_translate(c->io.context,t);s->page_returned[k]=returned?1:0;paic_actual_order(0);
        s->where[k]=t->page;s->par[k]=t->par;
        if(!returned||t->page!=page||t->issued!=1||t->returned!=1||t->saved!=t->restored||
           t->par!=(UINT64_C(0xff00000000000b80)|page))return pwra_fail(c,PWRA_TRANSLATION,1);
#if EFI_XNU_WIFI_DB_WORD_CAPTURE
        for(unsigned j=0;j<4096;j+=8){
            unsigned offset=4096*k+j;uint64_t word;struct pwra_word_capture *q=&s->word;
            q->issued++;q->load_pending=1;q->pending_address=page+j;
            /* The compiler memory clobber publishes the prefix before the
             * single aligned LDR. Existing per-page DSB/AT checks remain;
             * no new barrier per word, foreign call, or Device reader. */
#if defined(POLARIS_CMDDB_SOFTWARE_TEST)
            if(!pwra_test_word_load(page+j,&word))return pwra_fail(c,PWRA_IO,1);
#elif defined(__aarch64__) || defined(__arm64__)
            __asm__ volatile("ldr %0,[%1]":"=r"(word):"r"(page+j):"memory");
#else
            return pwra_fail(c,PWRA_IO,1);
#endif
            q->last_word=word;q->last_address=page+j;q->last_valid=1;
            q->returned++;q->load_pending=0;q->compare_pending=1;
            /* Keep baseline accesses byte-wide as before. Native object
             * representation compares all eight bytes without aliasing or
             * endian assumptions. An equal block needs just one aligned own
             * Normal RAM record store and one full byte-prefix update. */
            uint64_t expected;uint8_t *old=(uint8_t*)&expected;
            for(unsigned b=0;b<8;b++)old[b]=((const volatile uint8_t*)prepared->database[1])[offset+b];
            if(word==expected){
                __builtin_memcpy(__builtin_assume_aligned(s->raw+offset,8),&word,8);
                s->bytes=offset+8;q->compared_bytes=offset+8;q->compare_pending=0;continue;
            }
            /* Preserve the FIRST mismatching byte and the complete delivered
             * word; do not re-read the retained baseline sample on failure. */
            const uint8_t *bytes=(const uint8_t*)&word;
            for(unsigned b=0;b<8;b++){
                s->raw[offset+b]=bytes[b];s->bytes=offset+b+1;
                if(bytes[b]!=old[b]){
                    q->failed_byte=offset+b;return pwra_fail(c,PWRA_CHANGED,1);
                }
                q->compared_bytes=offset+b+1;
            }
            q->compare_pending=0;
        }
#else
        for(unsigned j=0;j<4096;j++){
            unsigned offset=4096*k+j;s->raw[offset]=PWCD_LOAD(page+j);s->bytes=offset+1;
            if(s->raw[offset]!=prepared->database[1][offset])return pwra_fail(c,PWRA_CHANGED,1);
        }
#endif
    }
    if(!pwra_live(c,&native,&ticks))return 0;s->complete=1;c->record->outstanding=0;paic_actual_order(0);return 1;
}
#endif
static inline int pwra_cmddb(struct pwra_context *c,unsigned slot)
{
    if(slot>1)return pwra_fail(c,PWRA_SCOPE,1);
#if EFI_XNU_WIFI_PREPARED_POWER_AVAILABLE
    if(c->prepared)return pwra_cmddb_prepared(c,slot);
#endif
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
static inline int pwra_prepare_checked(struct pwra_context *c,const struct pwra_io *io,struct pgcd_context *g,
    struct pwrcl_result *provider,const struct pwrph_work *w,struct pwrpc_result *critical,
    const struct pwcd_result *cmd,const struct pwrpb_baseline *normal,const struct pwrpb_baseline *masked,
    const struct pwrmd_result *device,struct pwrsc_transaction *tx,struct pwra_result *r,const struct pwcp_result *prepared,
    struct pwrr_transaction *read,struct pwrsc_transaction *writer)
{
    if(!r||r->attempted)return 0;r->attempted=1;
    if(!c||!io||!io->memory||!io->write||!g||!provider||!w||!critical||(!cmd&&!prepared)||(cmd&&prepared)||!normal||!masked||!device||!tx){r->error=PWRA_ARGUMENT;return 0;}
#if EFI_XNU_WIFI_READ_DB_CHECKPOINT
    /* This separate RAM observation cannot reach a masked RSC reader. */
    if(io->translate||io->read||io->write!=pwra_reject_store){r->error=PWRA_ARGUMENT;return 0;}
#else
    if(!io->translate||!io->read){r->error=PWRA_ARGUMENT;return 0;}
#endif
    *c=(struct pwra_context){*io,g,provider,w,critical,tx,device,r,cmd
#if EFI_XNU_WIFI_PREPARED_POWER_AVAILABLE
        ,prepared
#endif
#if EFI_XNU_WIFI_ARC_READ_AVAILABLE
        ,read,writer
#endif
    };
#if EFI_XNU_WIFI_ARC_READ_AVAILABLE
    if(read&&(!prepared||tx!=&read->io||!writer||writer==tx))return pwra_fail(c,PWRA_ARGUMENT,1);
    if(!read&&writer)return pwra_fail(c,PWRA_ARGUMENT,1);
#else
    if(read||writer)return pwra_fail(c,PWRA_ARGUMENT,1);
#endif
    const void *command=cmd;uint64_t command_bytes=sizeof(*cmd);const struct pwcd_resource *desired=cmd?cmd->resources[1]:0;
    int command_ready=cmd&&cmd->stable&&!cmd->error&&!cmd->unknown&&!cmd->outstanding&&cmd->owner_matches==1&&
        cmd->after.ticks<=critical->normal.cpu.ticks&&cmd->before.ticks>=g->record->before.cpu.ticks&&
        pgcd_equal(cmd->resources[0],cmd->resources[1],sizeof(cmd->resources[0]));
#if EFI_XNU_WIFI_PREPARED_POWER_AVAILABLE
    if(prepared){
        command=prepared;command_bytes=sizeof(*prepared);desired=prepared->resources[1];
        command_ready=prepared->complete&&prepared->stable&&!prepared->error&&!pwcp_unsafe(prepared)&&prepared->owner_matches==1&&
            prepared->provider==(uintptr_t)provider&&prepared->core==(uintptr_t)g&&
            prepared->bound_after.ticks<=critical->normal.cpu.ticks&&prepared->before.ticks>=g->record->before.cpu.ticks&&
            pgcd_equal(prepared->resources[0],prepared->resources[1],sizeof(prepared->resources[0]));
    }
#else
    if(prepared){r->error=PWRA_ARGUMENT;return 0;}
#endif
    r->client=(uintptr_t)provider->handle_output;r->provider=(uintptr_t)provider;r->critical=(uintptr_t)critical;r->transaction=(uintptr_t)tx;
    r->normal_RAM=(uintptr_t)normal;r->masked_RAM=(uintptr_t)masked;r->namespace_record=(uintptr_t)device;
    uint64_t tx_bytes=sizeof(*tx);unsigned object_count=9;
#if EFI_XNU_WIFI_ARC_READ_AVAILABLE
    if(read){tx_bytes=sizeof(*read);object_count=10;r->read_transaction=(uintptr_t)read;r->write_transaction=(uintptr_t)writer;}
#endif
    const void *objects[]={c,provider,critical,command,normal,masked,device,tx,r,writer};
    const uint64_t sizes[]={sizeof(*c),sizeof(*provider),sizeof(*critical),command_bytes,sizeof(*normal),sizeof(*masked),sizeof(*device),tx_bytes,sizeof(*r),sizeof(*writer)};
    for(unsigned k=0;k<object_count;k++)if(!pgcd_in_self(&provider->core,(uintptr_t)objects[k],sizes[k])||
       !pwrcl_owned(io->memory,provider,w,(uintptr_t)objects[k],(uint32_t)sizes[k]))return pwra_fail(c,PWRA_SCOPE,1);
    for(unsigned k=0;k<object_count;k++)for(unsigned j=0;j<k;j++)
        if(pwrcl_overlap((uintptr_t)objects[k],sizes[k],(uintptr_t)objects[j],sizes[j]))return pwra_fail(c,PWRA_SCOPE,1);
#if EFI_XNU_WIFI_ARC_READ_AVAILABLE
    if(read&&(!pwra_zero(read,sizeof(*read))||!pwra_zero(writer,sizeof(*writer))))return pwra_fail(c,PWRA_SCOPE,1);
#endif
    if(!provider->client_held||provider->client_returned||provider->retired||provider->unknown||provider->outstanding||provider->error||
       !provider->pools_complete[1]||provider->created.bytes!=88||!r->client||!pwrpc_local_held(critical)||
       !pwrpb_equal(normal,masked)||normal->before.daif||normal->before.group1!=1||masked->before.daif!=0xc0||masked->before.group1||
       !device->complete||device->error||device->unknown||device->outstanding||device->queries!=3||device->reads!=70||
       device->image!=provider->reader.image||device->core!=provider->core.core||device->self_base!=provider->core.self_base||
       device->self_bytes!=provider->core.self_bytes||device->after.ticks>critical->normal.cpu.ticks||
       !command_ready||(!read&&!pwrpb_plan(masked,desired,r->saved,r->desired)))return pwra_fail(c,PWRA_SCOPE,1);
    unsigned matches=0;const struct pwrcl_list *active=&masked->pool.list[0];
    for(unsigned k=0;k<active->count;k++)if(active->node[k].address==r->client&&
       pgcd_equal(active->node[k].raw,provider->created.raw,88))matches++;
    if(matches!=1)return pwra_fail(c,PWRA_CLIENT,1);
    for(unsigned k=0;k<4;k++)if(provider->created.queue_bytes[k]!=24||pwfi_le(provider->created.queue[k]+4,4))return pwra_fail(c,PWRA_CLIENT,1);
    r->mask=masked->active_mask;
    return pwra_cmddb(c,0);
}
#if EFI_XNU_WIFI_CURRENT_WORD_READ
static inline int pwra_observed_databases_valid(struct pwra_context *c,unsigned count);
#endif
static inline int pwra_acquire_checked(struct pwra_context *c,const struct pwra_io *io,struct pgcd_context *g,
    struct pwrcl_result *provider,const struct pwrph_work *w,struct pwrpc_result *critical,
    const struct pwcd_result *cmd,const struct pwrpb_baseline *normal,const struct pwrpb_baseline *masked,
    const struct pwrmd_result *device,struct pwrsc_transaction *tx,struct pwra_result *r,const struct pwcp_result *prepared,
    struct pwrr_transaction *read,struct pwrsc_transaction *writer)
{
    if(!pwra_prepare_checked(c,io,g,provider,w,critical,cmd,normal,masked,device,tx,r,prepared,read,writer)||
       !pwra_snapshot(c,0))return 0;
#if EFI_XNU_WIFI_CURRENT_WORD_READ
    if(!pwra_observed_databases_valid(c,1))return 0;
#endif
    r->acquired=r->local_held=1;paic_actual_order(0);return 1;
}
static inline int pwra_acquire_as(struct pwra_context *c,const struct pwra_io *io,struct pgcd_context *g,
    struct pwrcl_result *provider,const struct pwrph_work *w,struct pwrpc_result *critical,
    const struct pwcd_result *cmd,const struct pwrpb_baseline *normal,const struct pwrpb_baseline *masked,
    const struct pwrmd_result *device,struct pwrsc_transaction *tx,struct pwra_result *r,const struct pwcp_result *prepared)
{return pwra_acquire_checked(c,io,g,provider,w,critical,cmd,normal,masked,device,tx,r,prepared,0,0);}
static inline int pwra_acquire(struct pwra_context *c,const struct pwra_io *io,struct pgcd_context *g,
    struct pwrcl_result *provider,const struct pwrph_work *w,struct pwrpc_result *critical,
    const struct pwcd_result *cmd,const struct pwrpb_baseline *normal,const struct pwrpb_baseline *masked,
    const struct pwrmd_result *device,struct pwrsc_transaction *tx,struct pwra_result *r)
{return pwra_acquire_as(c,io,g,provider,w,critical,cmd,normal,masked,device,tx,r,0);}
#if EFI_XNU_WIFI_PREPARED_POWER_AVAILABLE
static inline int pwra_acquire_prepared(struct pwra_context *c,const struct pwra_io *io,struct pgcd_context *g,
    struct pwrcl_result *provider,const struct pwrph_work *w,struct pwrpc_result *critical,
    const struct pwcp_result *prepared,const struct pwrpb_baseline *normal,const struct pwrpb_baseline *masked,
    const struct pwrmd_result *device,struct pwrsc_transaction *tx,struct pwra_result *r)
{return pwra_acquire_as(c,io,g,provider,w,critical,0,normal,masked,device,tx,r,prepared);}
#endif
#if EFI_XNU_WIFI_ARC_READ_AVAILABLE
static inline int pwra_acquire_read(struct pwra_context *c,const struct pwra_io *io,struct pgcd_context *g,
    struct pwrcl_result *provider,const struct pwrph_work *w,struct pwrpc_result *critical,
    const struct pwcp_result *prepared,const struct pwrpb_baseline *normal,const struct pwrpb_baseline *masked,
    const struct pwrmd_result *device,struct pwrr_transaction *read,struct pwrsc_transaction *writer,struct pwra_result *r)
{if(!read)return 0;return pwra_acquire_checked(c,io,g,provider,w,critical,0,normal,masked,device,&read->io,r,prepared,read,writer);}
static inline int pwra_read_prefix(struct pwra_context *c)
{
    struct pwra_result *r=c->record;uint32_t native;uint64_t ticks;
    if(!c->read||!c->write||r->read_transaction!=(uintptr_t)c->read||r->write_transaction!=(uintptr_t)c->write||
       !pwrr_retired(c->read)||c->read->io.active_mask!=r->mask||
       !pwra_live(c,&native,&ticks)||c->read->io.started<c->critical->normal.cpu.ticks||
       c->read->io.last>ticks)return pwra_fail(c,PWRA_PREFIX,1);
    if(r->read_retired){
        if(r->read_events!=c->read->io.events||r->read_writes!=c->read->io.writes)return pwra_fail(c,PWRA_PREFIX,1);
    }else{
        r->read_events=c->read->io.events;r->read_writes=c->read->io.writes;
        r->read_end=c->critical->after;r->read_retired=1;
    }
    return 1;
}
static inline int pwra_bind_write(struct pwra_context *c)
{
    if(!c||!c->record||!c->read||!c->write||!c->prepared)return 0;
    struct pwra_result *r=c->record;
    if(r->write_bound||c->transaction!=&c->read->io||!r->acquired||!r->local_held||
       !pwra_read_prefix(c)||!pwra_zero(c->write,sizeof(*c->write))||
       !pwrr_plan((const void*)(uintptr_t)r->masked_RAM,c->prepared->resources[1],c->read,r->saved,r->desired))return pwra_fail(c,PWRA_SAVED,1);
    /* The READ prefix and its pointer/count/timestamp remain immutable.
     * Only this bounded transition selects the independently resident,
     * unused WRITE record. No source context or spent ticket is reopened. */
    c->transaction=c->write;r->transaction=(uintptr_t)c->write;r->write_bound=1;paic_actual_order(0);return 1;
}
static inline int pwra_engine_prefixes(const struct pwra_context *c)
{
    const struct pwra_result *r=c->record;unsigned read_seen=0,write_seen=0;
#if EFI_XNU_WIFI_CURRENT_WORD_READ
    uint32_t status_OR[3]={0};
#endif
    for(unsigned k=0;k<r->events;k++){
        const struct pwra_event *a=&r->history[k];
        if(!a->engine_event){if(a->operation!=1||!pwrmd_readable(a->io.address))return 0;continue;}
        unsigned is_read=a->engine_event>>31,index=a->engine_event&UINT32_C(0x7fffffff);
        const struct pwrsc_transaction *engine;
        if(is_read){
            if(!c->read||write_seen||index!=++read_seen) return 0;engine=&c->read->io;
        }else{
            if(index!=++write_seen|| (c->read&&read_seen!=c->read->io.events))return 0;engine=c->transaction;
        }
        if(!index||index>engine->events)return 0;const struct pwrsc_event *e=&engine->history[index-1];
        if(a->operation!=e->operation||a->io.address!=e->address||a->io.value!=e->value||
           a->io.before<e->before||a->io.after<a->io.before||a->io.after>e->after||
           a->native_before||a->native_after)return 0;
#if EFI_XNU_WIFI_CURRENT_WORD_READ
        if(is_read&&a->operation==1)for(unsigned j=0;j<3;j++)
            if(a->io.address==pwrsc_tcs(engine)+0x3c+20*j)status_OR[j]|=a->io.value;
#endif
    }
#if EFI_XNU_WIFI_CURRENT_WORD_READ
    if(c->read&&!pgcd_equal(status_OR,r->command_status_OR,sizeof(status_OR)))return 0;
#endif
    if(c->read&&read_seen!=c->read->io.events)return 0;
    return write_seen==(c->read&&!r->write_bound?0:c->transaction->events);
}
#endif
static inline int pwra_read(void *context,uint64_t at,uint32_t *value)
{struct pwra_context *c=context;return c&&c->record->acquired?pwra_transfer(c,at,value,0,1):0;}
static inline int pwra_write(void *context,uint64_t at,uint32_t value)
{struct pwra_context *c=context;return c&&c->record->acquired?pwra_transfer(c,at,&value,1,1):0;}
static inline int pwra_clock(void *context,uint64_t *ticks,uint64_t *frequency)
{
    struct pwra_context *c=context;uint32_t native;c->record->clock_calls++;
    if(!pwra_live(c,&native,ticks))return 0;
#if EFI_XNU_WIFI_ARC_READ_AVAILABLE
    if(c->read&&c->read->io.started&&(*ticks<c->read->io.started||*ticks-c->read->io.started>PWRSC_DEADLINE||
       (c->record->write_bound&&c->read->io.steps+c->transaction->steps>256)))return pwra_fail(c,PWRA_TIME,1);
#endif
    *frequency=c->critical->after.cpu.frequency;c->record->clock_returned++;return 1;
}
static inline void pwra_order(void *context){(void)context;paic_actual_order(0);}
static inline int pwra_retire(struct pwra_context *c)
{
    struct pwra_result *r=c->record;
    unsigned engine_ok=pwrsc_retired(c->transaction);uint32_t writes=c->transaction->writes;
#if EFI_XNU_WIFI_ARC_READ_AVAILABLE
    if(c->read){
        if(!pwra_read_prefix(c))return 0;
        engine_ok=r->write_bound?pwrsc_retired(c->transaction):pwra_zero(c->write,sizeof(*c->write));
        writes=r->read_writes+(r->write_bound?c->transaction->writes:0);
        if(r->write_bound){
            uint32_t saved[3],requested[3];
            if(!pwrr_plan((const void*)(uintptr_t)r->masked_RAM,c->prepared->resources[1],c->read,saved,requested))return pwra_fail(c,PWRA_SAVED,1);
            for(unsigned k=0;k<3;k++)if(saved[k]!=r->saved[k]||requested[k]!=r->desired[k]||
               c->transaction->saved_vote[k]!=saved[k]||c->transaction->raised_vote[k]!=(saved[k]>requested[k]?saved[k]:requested[k]))return pwra_fail(c,PWRA_SAVED,1);
        }
    }
    if(!pwra_engine_prefixes(c))return pwra_fail(c,PWRA_PREFIX,1);
#endif
    if(!r->acquired||!r->local_held||r->unknown||r->outstanding||r->error||!engine_ok||r->writes!=writes)
        return pwra_fail(c,PWRA_PREFIX,1);
    for(unsigned k=0;k<r->events;k++)if(r->history[k].io.issued!=1||r->history[k].io.returned!=1||r->history[k].io.unknown||
       !pwrmd_translation_valid(&r->history[k].io.translation))return pwra_fail(c,PWRA_PREFIX,1);
    if(!pwra_cmddb(c,1)||!pwra_snapshot(c,1))return 0;
#if EFI_XNU_WIFI_CURRENT_WORD_READ
    if(!pwra_observed_databases_valid(c,2))return 0;
#endif
    r->local_held=0;r->retired=1;paic_actual_order(0);return 1;
}
#if EFI_XNU_WIFI_READ_ACCESS_CHECKPOINT || EFI_XNU_WIFI_CURRENT_WORD_READ
static inline int pwra_observed_databases_valid(struct pwra_context *c
#if EFI_XNU_WIFI_CURRENT_WORD_READ
    ,unsigned count
#endif
    )
{
    struct pwra_result *r=c->record;
#if EFI_XNU_WIFI_CURRENT_WORD_READ
    if(count!=1&&count!=2)return pwra_fail(c,PWRA_PREFIX,1);
    for(unsigned slot=0;slot<count;slot++){
#else
    for(unsigned slot=0;slot<2;slot++){
#endif
        const struct pwra_cmd_snapshot *s=&r->CmdDb[slot];
        if(s->attempted!=1||s->complete!=1||s->bytes!=PWCD_DB_BYTES||s->hash_count!=5||s->hash_failed||
           s->owner_bytes!=sizeof(s->owner)||s->table_bytes!=72||s->global_bytes!=72||
           !pgcd_equal(s->raw,r->CmdDb[0].raw,PWCD_DB_BYTES)||
           !pgcd_equal(s->table,r->CmdDb[0].table,72)||!pgcd_equal(s->globals,r->CmdDb[0].globals,72)||
           !pgcd_equal(&s->owner,&r->CmdDb[0].owner,sizeof(s->owner)))return pwra_fail(c,PWRA_CHANGED,1);
        for(unsigned h=0;h<5;h++)if(!pgcd_equal(s->hashes[h],pwcdi_spans[h].hash,32))return pwra_fail(c,PWRA_CHANGED,1);
#if EFI_XNU_WIFI_DB_WORD_CAPTURE
        const struct pwra_word_capture *q=&s->word;
        if(q->issued!=PWCD_DB_BYTES/8||q->returned!=q->issued||q->load_pending||q->compare_pending||
           q->compared_bytes!=PWCD_DB_BYTES||q->failed_byte!=UINT32_MAX||q->last_valid!=1||q->reserved||
           q->pending_address!=PWCD_UEFI_DB_BASE+PWCD_DB_BYTES-8||q->last_address!=q->pending_address||
           !pgcd_equal(&q->last_word,s->raw+PWCD_DB_BYTES-8,8))return pwra_fail(c,PWRA_PREFIX,1);
#endif
        for(unsigned k=0;k<PWCD_PAGES;k++){
            const struct pgns_translation *t=&s->current_AT[k];uint64_t page=PWCD_UEFI_DB_BASE+4096u*k;
            if(s->page_issued[k]!=1||s->page_returned[k]!=1||s->where[k]!=page||
               t->page!=page||t->issued!=1||t->returned!=1||t->saved!=t->restored||
               s->par[k]!=t->par||t->par!=(UINT64_C(0xff00000000000b80)|page))return pwra_fail(c,PWRA_TRANSLATION,1);
        }
    }return 1;
}
#endif
#if EFI_XNU_WIFI_READ_ACCESS_CHECKPOINT
#if EFI_XNU_WIFI_READ_DB_CHECKPOINT
/* Close the second full RAM capture, not an RSC acquisition. acquired,
 * local_held and retired stay ZERO because that lifetime never opened. The
 * enclosing private caller still owns CPU/source/RAM/namespace retirement. */
static inline int pwra_observe_database_close(struct pwra_context *c)
{
    if(!c||!c->record||!c->read||!c->write||!c->provider||!c->device||!c->critical||!c->prepared)return 0;
    struct pwra_result *r=c->record;
    if(r->acquired||r->local_held||r->retired||r->error||r->unknown||r->outstanding||
       c->transaction!=&c->read->io||r->transaction!=(uintptr_t)&c->read->io||
       r->read_transaction!=(uintptr_t)c->read||r->write_transaction!=(uintptr_t)c->write||
       r->client!=(uintptr_t)c->provider->handle_output||r->namespace_record!=(uintptr_t)c->device||
       c->io.translate||c->io.read||c->io.write!=pwra_reject_store||
       r->write_bound||r->read_retired||r->read_events||r->read_writes||r->events||r->reads||r->writes||
       r->pre_reads||r->post_reads||r->clock_calls||r->clock_returned||
       !pwra_zero(c->read,sizeof(*c->read))||!pwra_zero(c->write,sizeof(*c->write)))return pwra_fail(c,PWRA_PREFIX,1);
    if(!pwra_cmddb(c,1)||!pwra_observed_databases_valid(c))return 0;
    if(r->acquired||r->local_held||r->retired||r->error||r->unknown||r->outstanding||
       r->events||r->reads||r->writes||r->pre_reads||r->post_reads||r->clock_calls||r->clock_returned||
       r->read_events||r->read_writes||r->read_retired||r->write_bound||
       !pwra_zero(r->history,sizeof(r->history))||!pwra_zero(r->saved,sizeof(r->saved))||
       !pwra_zero(r->desired,sizeof(r->desired))||r->config||r->IRQ_enable||r->IRQ_status||
       !pwra_zero(r->tcs,sizeof(r->tcs))||!pwra_zero(r->command_status_OR,sizeof(r->command_status_OR))||
       c->io.translate||c->io.read||c->io.write!=pwra_reject_store||
       r->client!=(uintptr_t)c->provider->handle_output||r->namespace_record!=(uintptr_t)c->device||
       r->transaction!=(uintptr_t)&c->read->io||r->read_transaction!=(uintptr_t)c->read||r->write_transaction!=(uintptr_t)c->write||
       !pwra_zero(c->read,sizeof(*c->read))||!pwra_zero(c->write,sizeof(*c->write)))return pwra_fail(c,PWRA_PREFIX,1);
    uint32_t native;uint64_t ticks;return pwra_live(c,&native,&ticks);
}
#endif
/* A distinct observation scope: no engine was started, so do not fabricate
 * READ completion. Both full current CmdDb captures and all checked geometry
 * reads still close inside the same masked interval before CPU restoration. */
static inline int pwra_retire_observation(struct pwra_context *c)
{
    if(!c||!c->record||!c->read||!c->write||!c->provider||!c->device||!c->critical||!c->prepared)return 0;
    struct pwra_result *r=c->record;
    if(!r->acquired||!r->local_held||r->retired||r->error||r->unknown||r->outstanding||
       c->transaction!=&c->read->io||r->transaction!=(uintptr_t)&c->read->io||
       r->read_transaction!=(uintptr_t)c->read||r->write_transaction!=(uintptr_t)c->write||
       r->client!=(uintptr_t)c->provider->handle_output||r->namespace_record!=(uintptr_t)c->device||
       r->write_bound||r->read_retired||r->read_events||r->read_writes||r->writes||r->clock_calls||r->clock_returned||
       r->events!=35||r->reads!=35||r->pre_reads!=35||r->post_reads||
       !pwra_zero(c->read,sizeof(*c->read))||!pwra_zero(c->write,sizeof(*c->write))||
       !pwra_engine_prefixes(c))return pwra_fail(c,PWRA_PREFIX,1);
    if(!pwra_cmddb(c,1)||!pwra_snapshot(c,1))return 0;
    if(r->events!=70||r->reads!=70||r->writes||r->post_reads!=35||
       r->client!=(uintptr_t)c->provider->handle_output||r->namespace_record!=(uintptr_t)c->device||
       r->read_transaction!=(uintptr_t)c->read||r->write_transaction!=(uintptr_t)c->write||
       !pwra_zero(c->read,sizeof(*c->read))||!pwra_zero(c->write,sizeof(*c->write))||
       !pwra_engine_prefixes(c))return pwra_fail(c,PWRA_PREFIX,1);
    if(!pwra_observed_databases_valid(c))return 0;
    for(unsigned k=0;k<r->events;k++)if(r->history[k].operation!=1||r->history[k].engine_event||
       r->history[k].native_before||r->history[k].native_after||r->history[k].io.issued!=1||
       r->history[k].io.returned!=1||r->history[k].io.unknown||
       !pwrmd_translation_valid(&r->history[k].io.translation))return pwra_fail(c,PWRA_PREFIX,1);
    r->local_held=0;r->retired=1;paic_actual_order(0);return 1;
}
/* Supplied instead of a physical writer. An accidental request fails sticky;
 * no MMIO store, IRQ ACK, fake engine result or authority boolean exists. */
static inline int pwra_reject_store(void *context,uint64_t at,uint32_t value)
{
    (void)at;(void)value;struct pwra_context *c=context;
    return c&&c->record?pwra_fail(c,PWRA_SCOPE,1):0;
}
#endif
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
       !pwrpc_local_held(c->critical)||!pwra_engine_writable(c,at,value))return 0;
#if defined(__aarch64__) || defined(__arm64__)
    *(volatile uint32_t*)(uintptr_t)at=value;paic_actual_order(0);return 1;
#else
    return 0;
#endif
}
static inline struct pwra_io pwra_physical_io(const struct paic_io *memory,struct pwra_context *context)
{return (struct pwra_io){memory,context,pwrmd_actual_translate,pwra_actual_read,pwra_actual_write
#if EFI_XNU_WIFI_PREPARED_POWER_AVAILABLE
    ,pgns_actual_translate
#endif
};}
#if EFI_XNU_WIFI_READ_ACCESS_CHECKPOINT
static inline struct pwra_io pwra_observation_io(const struct paic_io *memory,struct pwra_context *context)
{return (struct pwra_io){memory,context,
#if EFI_XNU_WIFI_READ_DB_CHECKPOINT
    0,0,
#else
    pwrmd_actual_translate,pwra_actual_read,
#endif
    pwra_reject_store,pgns_actual_translate};}
#endif
#endif
#endif
