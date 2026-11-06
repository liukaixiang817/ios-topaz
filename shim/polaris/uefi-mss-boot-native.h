/* Actual native MBA startup under the composed AOP/power/clock owner.
 * Existing independent staged/assigned MBA is the only image admitted.
 * READY means native RMB/PBL/MBA status observations, not modem auth or WLAN.
 * Default OFF/unregistered; failures retain CPU, resources and all records. */
#ifndef POLARIS_UEFI_MSS_BOOT_NATIVE_H
#define POLARIS_UEFI_MSS_BOOT_NATIVE_H
#ifndef EFI_XNU_MSS_BOOT_NATIVE_AVAILABLE
#define EFI_XNU_MSS_BOOT_NATIVE_AVAILABLE 0
#endif
#if EFI_XNU_MSS_BOOT_NATIVE_AVAILABLE
#if !EFI_XNU_MSS_AOP_NATIVE_AVAILABLE
#error Native MBA startup requires the actual AOP/power/clock composition
#endif
#include "uefi-mss-aop-native.h"
#include "../../tools/polaris-arm64-table-walk.h"
#include "uefi-mss-page-map.h"
#define PMBN_RECORDS (PMBA_EVENTS+PMSR_EVENTS)
struct pmbn_delivery {
    struct pmba_command command;struct pmrg_target target[2];
    struct pmni_arch opening;struct pmni_result native;
    uint32_t attempted,unknown,error,complete;uint8_t digest[32];
};
struct pmbn_walk {uint32_t read_error,reserved;struct pmpt_walk table;struct pmli_read source[2][4];struct pmni_arch after;};
struct pmbn_state {
    uint64_t aop,power,clocks,owner,records,opening;struct pmba_boot mba;
    uint32_t attempted,ready,unknown,error,pending,deliveries,complete,reserved;
    struct pmbn_walk translation;
#if EFI_XNU_MSS_PAGE_MAP_AVAILABLE
    struct pmbm_state mapping,pdc_mapping,restart_mapping;
#endif
    uint8_t records_digest[32],digest[32];
};
static inline int pmbn_fail(struct pmbn_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;if(s->power)pmpn_fail((void*)(uintptr_t)s->power,11);return PMBA_FAILED;}
static inline int pmbn_live(struct pmbn_state*s)
{
    if(!s||s->ready!=1||s->unknown||s->error||s->deliveries>PMBN_RECORDS)return 0;
#if EFI_XNU_MSS_PAGE_MAP_AVAILABLE
    if((s->mapping.complete&&!pmbm_current(&s->mapping))||
       (s->pdc_mapping.complete&&!pmbm_current(&s->pdc_mapping))||
       (s->restart_mapping.complete&&!pmbm_current(&s->restart_mapping)))return 0;
#endif
    struct pmpn_state*p=(void*)(uintptr_t)s->power;struct pmcn_state*c=(void*)(uintptr_t)s->clocks;
    struct pman_state*a=(void*)(uintptr_t)s->aop;
    const struct pmck_lifecycle*clock=(const void*)(uintptr_t)c->clocks;
    return s->opening==p->opening&&p->owner==s->owner&&c->power==s->power&&a->power==s->power&&a->clocks==s->clocks&&
        clock&&clock->epoch==s->opening&&clock->phase==2&&clock->held==63&&!clock->pending&&!clock->unknown&&!clock->error&&
        c->clock_calls==clock->events&&a->phase==1&&a->notify[0].complete==1&&!a->pending&&
        pmcn_live(c)&&pman_live(a)&&!p->pending&&!p->restored;
}
static inline int pmbn_child(struct pmbn_state*s,uint64_t at,uint64_t bytes)
{
    struct pmcn_state*c=(void*)(uintptr_t)s->clocks;struct pman_state*a=(void*)(uintptr_t)s->aop;
    return pmcn_child(c,at,bytes)&&pwea_disjoint(at,bytes,(uintptr_t)a,sizeof(*a))&&
        pwea_disjoint(at,bytes,a->records,sizeof(struct pman_delivery)*PMAN_RECORDS)&&
        pwea_disjoint(at,bytes,c->clocks,sizeof(struct pmck_lifecycle));
}
#if EFI_XNU_MSS_PAGE_MAP_AVAILABLE
struct pmbm_reader {struct pmbn_state*owner;struct pmbm_state*map;};
static inline int pmbm_read(void*context,unsigned pass,unsigned index,uint64_t at,uint64_t*value)
{
    struct pmbm_reader*c=context;struct pmbn_state*s=c->owner;struct pmbm_state*m=c->map;
    if(m!=&s->mapping&&m!=&s->pdc_mapping&&m!=&s->restart_mapping)return 0;
    if(pass>1||index>=4||!pmbn_live(s)){m->read_error=1;return 0;}
    struct pmpn_state*p=(void*)(uintptr_t)s->power;struct pmrg_map*g=(void*)(uintptr_t)p->namespace;
    struct pmli_ledger*l=(void*)(uintptr_t)g->images;struct pmli_read*q=&m->source[pass][index];
    if(!pmli_heap_excluded(&l->pass[1],at,8)){m->read_error=2;return 0;}
    if(!pmli_read_ram(l,q,at,8,1)){m->read_error=3;return 0;}
    if(!pmbn_live(s)){m->read_error=4;return 0;}*value=pwfi_le(q->raw,8);return 1;
}
static inline int pmbm_prepare(struct pmbn_state*s,struct pmbm_state*m,uint64_t base)
{
    struct pmpn_state*p=(void*)(uintptr_t)s->power;
    unsigned count=pmbm_pages(base);
    if(!count||(base==UINT64_C(0x4080000)?m!=&s->mapping:base==UINT64_C(0xb2e0000)?m!=&s->pdc_mapping:m!=&s->restart_mapping)||
       !pwmc_zero(m,sizeof(*m))||!pmbn_live(s))return 0;
    m->attempted=1;m->error=1;m->base=base;
    m->error=10;if(!pmpn_arch(p,&m->architecture)||!pgcd_equal(&p->architecture,&m->architecture,offsetof(struct pmni_arch,ticks)))return 0;
    unsigned ready=0;
    for(unsigned n=0;n<count;n++){
        uint64_t page=base+n*UINT64_C(0x100000);m->before[n].page=page;
        m->error=11+3*n;if(!pmpn_target(p,page,&m->target[n]))return 0;
        m->error=12+3*n;struct pmni_translation*t=&m->before[n];
        if(!pmni_translate(t)||t->page!=page||t->read_issued!=1||t->read_returned!=1||
           t->write_issued!=1||t->write_returned!=1||t->restore_issued!=1||t->restore_returned!=1||
           t->saved!=t->restored||t->read_par!=t->write_par)return 0;
        m->error=13+3*n;if(!pmbn_live(s))return 0;
        ready+=pmni_device_translation(&m->before[n],page);
    }
    /* Already valid firmware mappings need no table reads or mutation. */
    if(ready==count){m->error=0;m->complete=1;return 1;}
    m->error=2;if(ready)return 0;
    m->table=((uintptr_t)m->storage+4095)&~UINT64_C(4095);
    struct pmbm_reader reader={s,m};
    (void)pmpt_collect(&m->walk,m->architecture.ttbr0,m->architecture.tcr,base,pmbm_read,&reader);
    m->level=pmbm_hole(&m->walk,m->table);if(!m->level)return 0;
    m->error=3;
    if(m->level==2){
        if(!pmbn_child(s,m->table,4096)||!pwmc_zero((void*)(uintptr_t)m->table,4096))return 0;
        m->storage_AT.page=m->table;
        if(!pwmc_actual_translate(&m->storage_AT)||!pwmc_translation_valid(&m->storage_AT)||m->storage_AT.page!=m->table)return 0;
        uint64_t*t=(void*)(uintptr_t)m->table;for(unsigned n=0;n<512;n++)t[n]=pmbm_leaf(base,n);
        m->value=m->table|3;
    }else{
        /* The existing RAM reader qualified this exact writable WB L3 source
         * twice, outside loaded images. Its other511 entries remain untouched. */
        m->table=m->walk.descriptor[2]&UINT64_C(0x0000fffffffff000);
        m->value=base|PMBM_LEAF_FLAGS;
    }
    m->entry=m->walk.entry[m->level];
    if(!pmni_arch_read(&m->final_architecture)||!pmni_arch_same(&m->architecture,&m->final_architecture,m->architecture.ticks)||!pmbn_live(s))return 0;
    for(unsigned n=0;n<=m->level;n++)if(*(const volatile uint64_t*)(uintptr_t)m->walk.entry[n]!=m->walk.descriptor[n])return 0;
    /* Power effects already retain the exclusive CPU owner on any failure.
     * The map is permanent for this RAM-only parent lifetime, never undone. */
    m->error=4;if(!pmbm_publish(m))return 0;
    m->error=5;
    for(unsigned n=0;n<count;n++){
        m->after[n].page=m->before[n].page;
        if(!pmni_translate(&m->after[n])||!pmni_device_translation(&m->after[n],m->before[n].page))return 0;
    }
    if(!pmni_arch_read(&m->final_architecture)||!pmni_arch_same(&m->architecture,&m->final_architecture,m->architecture.ticks)||!pmbn_live(s))return 0;
    m->error=0;m->complete=1;if(!pmbm_current(m)){m->complete=0;m->error=6;return 0;}return 1;
}
#endif
static inline int pmbn_begin(struct pmbn_state*s,struct pmbn_delivery*r,struct pman_state*a)
{
    if(!s||!r||!a||!pwmc_zero(s,sizeof(*s)))return 0;s->attempted=1;
    if(!pman_live(a)||a->phase!=1||a->notify[0].complete!=1||a->pending)return 0;
    struct pmcn_state*c=(void*)(uintptr_t)a->clocks;struct pmpn_state*p=(void*)(uintptr_t)a->power;
    s->aop=(uintptr_t)a;s->clocks=(uintptr_t)c;s->power=(uintptr_t)p;s->owner=p->owner;s->opening=p->opening;
    uint64_t bytes=sizeof(*r)*PMBN_RECORDS;
    if(!pmcn_live(c)||!c->clocks||!pmbn_child(s,(uintptr_t)s,sizeof(*s))||!pmbn_child(s,(uintptr_t)r,bytes)||
       !pwea_disjoint((uintptr_t)s,sizeof(*s),(uintptr_t)r,bytes)||!pwmc_zero(r,bytes))return 0;
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;const struct pmsb_result*b=(const void*)(uintptr_t)o->mba;
    const struct pmsi_result*stage=(const void*)(uintptr_t)b->stage;
    uint8_t hash[32];pweh_digest(&a->notify[0],sizeof(a->notify[0]),hash);
    if(!pgcd_equal(hash,a->on_digest,32)||!pmsc_bound(o)||!pmrg_current((void*)(uintptr_t)p->namespace))return 0;
    s->records=(uintptr_t)r;s->ready=1;
#if EFI_XNU_MSS_PAGE_MAP_AVAILABLE
    if(!pmbm_prepare(s,&s->mapping,UINT64_C(0x4080000))||
       !pmbm_prepare(s,&s->pdc_mapping,UINT64_C(0xb2e0000))||
       !pmbm_prepare(s,&s->restart_mapping,UINT64_C(0xc2b0000))){pmbn_fail(s,4);return 0;}
#endif
    if(!pmbn_live(s)||pmba_begin(&s->mba,(const void*)(uintptr_t)c->clocks,&b->transaction,stage->asset[0].bytes,o->last)<0){pmbn_fail(s,1);return 0;}
    return 1;
}
static inline int pmbn_current(struct pmbn_state*s)
{
    if(!pmbn_live(s)||s->complete!=1||s->pending||s->mba.ready!=1||s->mba.phase!=4||s->mba.pending||s->mba.unknown||s->mba.error)return 0;
    uint8_t hash[32];pweh_digest(s,offsetof(struct pmbn_state,digest),hash);if(!pgcd_equal(hash,s->digest,32))return 0;
    pweh_digest((const void*)(uintptr_t)s->records,s->deliveries*sizeof(struct pmbn_delivery),hash);
    return pgcd_equal(hash,s->records_digest,32)&&pmbn_live(s);
}
static inline int pmbn_finish(struct pmbn_state*s)
{
    if(!pmbn_live(s)||s->complete||s->pending||s->mba.phase!=4||s->mba.ready!=1||s->mba.pending||s->mba.unknown||s->mba.error||
       s->mba.events+s->mba.reset.events!=s->deliveries)return 0;
    const struct pmbn_delivery*r=(const void*)(uintptr_t)s->records;uint8_t hash[32];
    for(unsigned n=0;n<s->deliveries;n++){
        pweh_digest(&r[n],offsetof(struct pmbn_delivery,digest),hash);
        if(r[n].complete!=1||r[n].unknown||r[n].error||!pgcd_equal(hash,r[n].digest,32))return 0;
    }
    pweh_digest(r,s->deliveries*sizeof(*r),s->records_digest);
    if(!pmbn_live(s))return 0;s->complete=1;pweh_digest(s,offsetof(struct pmbn_state,digest),s->digest);return 1;
}
/* Failure-only table evidence under the still-held CPU/resource owner. The
 * existing RAM reader checks BootServicesData, image exclusion and live WB
 * identity AT before reading each descriptor; never dereference a leaf PA. */
static inline int pmbn_table_read(void*context,unsigned pass,unsigned index,uint64_t at,uint64_t*value)
{
    struct pmbn_state*s=context;struct pmpn_state*p=(void*)(uintptr_t)s->power;
    if(pass>1||index>=4||!pmbn_live(s)){s->translation.read_error=1;return 0;}
    struct pmrg_map*g=(void*)(uintptr_t)p->namespace;struct pmli_ledger*l=(void*)(uintptr_t)g->images;
    struct pmli_read*q=&s->translation.source[pass][index];
    if(!pmli_heap_excluded(&l->pass[1],at,8)){s->translation.read_error=2;return 0;}
    if(!pmli_read_ram(l,q,at,8,1)){s->translation.read_error=3;return 0;}
    if(!pmbn_live(s)){s->translation.read_error=4;return 0;}
    *value=pwfi_le(q->raw,8);return 1;
}
static inline void pmbn_table_diagnostic(struct pmbn_state*s,const struct pmbn_delivery*r)
{
    const struct pmni_result*n=&r->native;const struct pmni_translation*t=&n->AT;
    if(s->deliveries!=1||s->mba.phase!=1||s->mba.step||!r->target[0].complete||
       !n->attempted||n->error!=3||n->issued||n->returned||
       (t->page!=UINT64_C(0x4080000)&&t->page!=UINT64_C(0x4180000))||!pmbn_live(s))return;
    (void)pmpt_collect(&s->translation.table,n->before.ttbr0,n->before.tcr,t->page,pmbn_table_read,s);
    if(!pmni_arch_read(&s->translation.after)||!pmni_arch_same(&n->before,&s->translation.after,n->before.ticks)){
        s->translation.table.error=5;s->translation.table.complete=0;
    }
}
static inline int pmbn_step(struct pmbn_state*s)
{
    if(!pmbn_live(s)||s->pending)return PMBA_FAILED;
    if(s->complete)return pmbn_current(s)?PMBA_READY:PMBA_FAILED;
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;struct pmba_command command;
    int result=pmba_next(&s->mba,o->last,&command);
    if(result==PMBA_WAIT)return result;
    if(result==PMBA_READY)return pmbn_finish(s)?PMBA_READY:pmbn_fail(s,2);
    if(result!=PMBA_IO||s->deliveries==PMBN_RECORDS)return pmbn_fail(s,2);
    struct pmbn_delivery*r=(struct pmbn_delivery*)(uintptr_t)s->records+s->deliveries;
    if(!pwmc_zero(r,sizeof(*r)))return pmbn_fail(s,2);
    r->command=command;r->attempted=r->unknown=1;s->pending=++s->deliveries;
    uint64_t address=command.phase==2?command.reset.address:command.address;
    unsigned kind=command.phase==2?command.reset.kind:command.kind;
    unsigned memory=kind==PMSR_READ||kind==PMSR_WRITE;struct pmpn_state*p=(void*)(uintptr_t)s->power;
    if((memory&&!pmpn_target(p,address&~UINT64_C(4095),&r->target[0]))||!pmpn_arch(p,&r->opening)||
       !pgcd_equal(&r->opening,&p->architecture,offsetof(struct pmni_arch,ticks)))goto fail;
    if(kind==PMSR_WRITE&&!pmsc_mark_effect(o,PMSC_REMOTE))goto fail;
    if(!pmni_mba(&s->mba,&r->command,&r->opening,&r->native)||
       (memory&&(!pmpn_target(p,address&~UINT64_C(4095),&r->target[1])||r->target[0].index!=r->target[1].index))||
       !pmbn_live(s)||!pgcd_equal(&command,&r->command,sizeof(command)))goto fail;
    result=pmba_complete(&s->mba,&r->command,o->last,1,r->native.value);if(result<0)goto fail;
    r->unknown=0;r->complete=1;pweh_digest(r,offsetof(struct pmbn_delivery,digest),r->digest);s->pending=0;
    if(result==PMBA_READY)return pmbn_finish(s)?PMBA_READY:pmbn_fail(s,2);return result;
fail:pmbn_table_diagnostic(s,r);r->error=3;return pmbn_fail(s,3);
}
#endif
#endif
