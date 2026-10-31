/* Read admission for the SAME bounded power caller, default OFF. The original
 * registered GCD provider and actual S1E1R/S1E1W translations must both agree
 * before an own RSC word is loaded. S1E1W is a translation, never a store.
 * No writer, IRQ ACK, provider submit, hardware lease or boot hook is exposed
 * here. These observations are necessary inputs, not CPU/EE/EL3 exclusivity. */
#ifndef POLARIS_UEFI_WIFI_RSC_DEVICE_H
#define POLARIS_UEFI_WIFI_RSC_DEVICE_H
#include "uefi-wifi-rsc-baseline.h"
#if EFI_XNU_WIFI_POWER_TRANSACTION_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
#define PWRMD_EVENTS 96u
struct pwrmd_translation {
    uint64_t page,saved,read_par,write_par,restored;
    uint32_t read_issued,read_returned,write_issued,write_returned,restore_issued,restore_returned;
};
struct pwrmd_event {
    uint64_t address,before,after;uint32_t value,issued,returned,unknown;
    struct pwrmd_translation translation;
};
struct pwrmd_result {
    uint32_t attempted,error,unknown,outstanding,complete,queries,reads,events;
    uint64_t image,core,self_base,self_bytes;
    struct paic_arch before,after;
    struct pgcd_observation GCD[3];
    uint32_t config[2],IRQ_enable[2],IRQ_status[2],tcs[2][8][4];
    struct pwrmd_event history[PWRMD_EVENTS];
};
struct pwrmd_io {
    const struct paic_io *memory;
    void *context;
    int (*translate)(void *,struct pwrmd_translation *);
    int (*read)(void *,uint64_t,uint32_t *);
};
enum pwrmd_error {PWRMD_OK,PWRMD_ARGUMENT,PWRMD_SOURCE,PWRMD_MAP,PWRMD_GCD,
    PWRMD_AT,PWRMD_READ,PWRMD_TIME,PWRMD_CHANGED,PWRMD_GEOMETRY,PWRMD_BUSY};
static const uint64_t pwrmd_pages[3]={0x179e0000,0x179e1000,0x179e2000};
static inline int pwrmd_fail(struct pwrmd_result *r,unsigned error,int unknown)
{if(!r->error)r->error=error;if(unknown)r->unknown=1;paic_actual_order(0);return 0;}
static inline int pwrmd_arch(const struct pwrmd_io *io,struct pwrcl_result *p,
    struct pgcd_context *g,struct pwrmd_result *r)
{
    const struct paic_arch *a=&r->before;
    if(!io->memory->arch(io->memory->context,&r->after)||!paic_arch_stable(a,&r->after)||
       r->after.ticks<g->record->before.cpu.ticks||r->after.ticks-g->record->before.cpu.ticks>PGCD_FRESH_TICKS||
       p->reader.image!=r->image||p->core.core!=r->core||p->core.self_base!=r->self_base||
       p->core.self_bytes!=r->self_bytes||!pwrph_context_ready(g))return pwrmd_fail(r,PWRMD_TIME,r->outstanding!=0);
    return 1;
}
static inline int pwrmd_exclude(const struct pwrph_work *w,uint64_t page)
{
    if(w->stride!=sizeof(struct efi_memory)||!w->bytes||w->bytes>sizeof(w->map)||w->bytes%w->stride)return 0;
    for(uint64_t k=0;k<w->bytes;k+=w->stride){const struct efi_memory *d=(const void*)(w->map+k);
        if(d->pages>UINT64_MAX/4096||d->physical>UINT64_MAX-d->pages*4096)return 0;
        if(d->physical<page+4096&&page<d->physical+d->pages*4096&&
           (d->type!=11||d->virtual_address||(d->attributes!=0&&d->attributes!=1)))return 0;
    }return 1; /* Absence is only exclusion; GCD registration is still required. */
}
static inline int pwrmd_namespace(const struct pwrmd_io *io,struct pwrcl_result *p,
    const struct pwrph_work *w,struct pgcd_context *g,struct pwrmd_result *r,unsigned k)
{
    struct pgcd_observation *q=&r->GCD[k];q->page=pwrmd_pages[k];q->status=UINT64_MAX;
    if(!pwrmd_exclude(w,q->page))return pwrmd_fail(r,PWRMD_MAP,0);
    if(!pwrmd_arch(io,p,g,r)||!pgcd_service_enter(g,&q->guard))return pwrmd_fail(r,PWRMD_GCD,pgcd_uncertain(g));
    q->before_ticks=q->guard.before.cpu.ticks;q->issued=q->unknown=1;r->outstanding=k+1;r->queries++;paic_actual_order(0);
    int returned=g->io.query(g->io.opaque,g->record->get_descriptor,q->page,&q->descriptor,&q->status);
    q->returned=returned?1:0;paic_actual_order(0);
    if(!pgcd_service_leave(g,&q->guard,returned))return pwrmd_fail(r,PWRMD_GCD,1);
    q->after_ticks=q->guard.after.cpu.ticks;q->unknown=0;r->outstanding=0;paic_actual_order(0);
    const struct pgcd_descriptor *d=&q->descriptor;
    if(q->status||d->type!=3||!(d->capabilities&1)||(d->attributes!=0&&d->attributes!=1)||
       d->base>q->page||!d->length||d->base>UINT64_MAX-d->length||d->base+d->length<q->page+4096)
        return pwrmd_fail(r,PWRMD_GCD,0);
    return 1;
}
static inline int pwrmd_readable(uint64_t at)
{
    if(at==UINT64_C(0x179e000c)||at==UINT64_C(0x179e0d00)||at==UINT64_C(0x179e0d04))return 1;
    if(at<UINT64_C(0x179e0d00)||at>=UINT64_C(0x179e0d00)+8*672||(at&3))return 0;
    unsigned offset=(unsigned)(at-UINT64_C(0x179e0d00))%672;
    return offset==0x10||offset==0x14||offset==0x18||offset==0x1c;
}
static inline int pwrmd_translation_valid(const struct pwrmd_translation *t)
{
    if(!t->read_issued||!t->read_returned||!t->write_issued||!t->write_returned||!t->restore_issued||!t->restore_returned||
       t->saved!=t->restored||t->read_par!=t->write_par)return 0;
    uint64_t par=t->read_par;
    return !(par&1)&&(par&UINT64_C(0x200))&&((par>>56)==0||(par>>56)==4)&&
        (par&UINT64_C(0x0000fffffffff000))==t->page;
}
static inline int pwrmd_load(const struct pwrmd_io *io,struct pwrcl_result *p,
    const struct pwrph_work *w,struct pgcd_context *g,struct pwrmd_result *r,uint64_t at,uint32_t *value)
{
    if(r->error||r->unknown||r->outstanding||r->events==PWRMD_EVENTS||!pwrmd_readable(at))return pwrmd_fail(r,PWRMD_ARGUMENT,0);
    unsigned k;uint64_t page=at&~UINT64_C(4095);for(k=0;k<3&&pwrmd_pages[k]!=page;k++){}
    if(k==3||!r->GCD[k].returned||r->GCD[k].status||!pwrmd_exclude(w,page))return pwrmd_fail(r,PWRMD_MAP,0);
    struct pwrmd_event *e=&r->history[r->events++];e->address=at;e->value=UINT32_MAX;e->translation.page=page;
    if(!pwrmd_arch(io,p,g,r))return 0;e->before=r->after.ticks;
    r->outstanding=UINT32_C(0x10000)|r->events;paic_actual_order(0);
    int returned=io->translate(io->context,&e->translation);paic_actual_order(0);
    if(!returned)return pwrmd_fail(r,PWRMD_AT,1);
    const struct pwrmd_translation *t=&e->translation;
    if(!t->read_issued||!t->read_returned||!t->write_issued||!t->write_returned||
       !t->restore_issued||!t->restore_returned||t->saved!=t->restored)return pwrmd_fail(r,PWRMD_AT,1);
    if(t->page!=page||!pwrmd_translation_valid(t)){r->outstanding=0;return pwrmd_fail(r,PWRMD_AT,0);}
    /* The actual architecture is re-read between translation and load. A
     * callback success or an old translation never authorizes the next load. */
    if(!pwrmd_arch(io,p,g,r))return 0;
    e->issued=e->unknown=1;r->reads++;paic_actual_order(0);
    returned=io->read(io->context,at,&e->value);e->returned=returned?1:0;paic_actual_order(0);
    if(!returned)return pwrmd_fail(r,PWRMD_READ,1);
    if(!pwrmd_arch(io,p,g,r))return 0;
    e->after=r->after.ticks;e->unknown=0;r->outstanding=0;*value=e->value;paic_actual_order(0);return 1;
}
static inline int pwrmd_collect(const struct pwrmd_io *io,struct pwrcl_result *p,
    const struct pwrph_work *w,struct pgcd_context *g,const struct pwrpb_baseline *b,struct pwrmd_result *r)
{
    if(!r||r->attempted)return 0;r->attempted=1;
    if(!io||!io->memory||!io->memory->arch||!io->memory->identity||!io->translate||!io->read||!p||!w||!g||!g->io.query||
       !b||!b->complete||b->error||!pwrph_context_ready(g)||!pgcd_in_self(g->record,(uintptr_t)r,sizeof(*r))||
       !p->reader.stable||p->reader.error||p->reader.unknown||p->reader.outstanding||p->reader.owner_matches!=1||
       p->core.core!=g->record->core||p->core.self_base!=g->record->self_base||p->core.self_bytes!=g->record->self_bytes||
       !pgcd_in_self(g->record,(uintptr_t)b,sizeof(*b))||!pwrcl_owned(io->memory,p,w,(uintptr_t)r,sizeof(*r))||
       !pwrcl_owned(io->memory,p,w,(uintptr_t)b,sizeof(*b))||
       pwrcl_overlap((uintptr_t)r,sizeof(*r),(uintptr_t)b,sizeof(*b))||
       pwrcl_overlap((uintptr_t)r,sizeof(*r),(uintptr_t)p,sizeof(*p)))return pwrmd_fail(r,PWRMD_ARGUMENT,0);
    unsigned active=(unsigned)pwfi_le(b->mode,4),matches=0;
    if(!active||active>8||b->active_mask!=(1u<<active)-1||b->HAL_runtime_bytes!=sizeof(b->HAL_runtime)||
       b->HAL_runtime[0]!=1||!pwfi_le(b->HAL_runtime+4,4)||pwfi_le(b->HAL_runtime+4,4)>16||
       pwfi_le(b->HAL_runtime+48+0x18,4)!=8||pwfi_le(b->HAL_runtime+48+0x1c,4)!=16||
       pwfi_le(b->drv_row,4)!=2||pwfi_le(b->drv_row+4,4)!=2||
       pwfi_le(b->drv_row+0x18,4)!=8||pwfi_le(b->drv_row+0x1c,4)!=16)return pwrmd_fail(r,PWRMD_SOURCE,0);
    for(unsigned k=0;k<16;k++){
        const uint8_t *entry=b->HAL_runtime+24*k;
        if(entry[0x14]==1&&pwfi_le(entry+0xc,4)==0x179c0000&&pwfi_le(entry+0x10,4)==2){
            if(k!=2)return pwrmd_fail(r,PWRMD_SOURCE,0);matches++;
        }
    }
    if(matches!=1)return pwrmd_fail(r,PWRMD_SOURCE,0);
    r->image=p->reader.image;r->core=p->core.core;r->self_base=p->core.self_base;r->self_bytes=p->core.self_bytes;
    if(!io->memory->arch(io->memory->context,&r->before)||!paic_arch_admitted(&r->before)||
       r->before.daif||r->before.group1!=1)return pwrmd_fail(r,PWRMD_SOURCE,0);
    for(unsigned k=0;k<3;k++)if(!pwrmd_namespace(io,p,w,g,r,k))return 0;
    for(unsigned pass=0;pass<2;pass++){
        if(!pwrmd_load(io,p,w,g,r,0x179e000c,&r->config[pass])||
           !pwrmd_load(io,p,w,g,r,0x179e0d00,&r->IRQ_enable[pass])||
           !pwrmd_load(io,p,w,g,r,0x179e0d04,&r->IRQ_status[pass]))return 0;
        /* Original6f58/700c read179c0000+(bank2<<16)+c, count[17:12]
         * and NCPT[31:27]. Use that source, not a guessed revision layout. */
        if(((r->config[pass]>>12)&63)!=8||(r->config[pass]>>27)!=16)return pwrmd_fail(r,PWRMD_GEOMETRY,0);
        if(r->IRQ_status[pass]||!(r->IRQ_enable[pass]&b->active_mask))return pwrmd_fail(r,PWRMD_BUSY,0);
        static const uint32_t offset[4]={0x10,0x14,0x18,0x1c};
        for(unsigned k=0;k<8;k++)for(unsigned j=0;j<4;j++)
            if(!pwrmd_load(io,p,w,g,r,UINT64_C(0x179e0d00)+672*k+offset[j],&r->tcs[pass][k][j]))return 0;
        for(unsigned k=0;k<8;k++)if(b->active_mask&(1u<<k))
            if((r->tcs[pass][k][1]&(1u<<24))||!(r->tcs[pass][k][2]&1)||r->tcs[pass][k][3])return pwrmd_fail(r,PWRMD_BUSY,0);
    }
    if(r->config[0]!=r->config[1]||r->IRQ_enable[0]!=r->IRQ_enable[1]||r->IRQ_status[0]!=r->IRQ_status[1]||
       !pgcd_equal(r->tcs[0],r->tcs[1],sizeof(r->tcs[0])))return pwrmd_fail(r,PWRMD_CHANGED,0);
    r->complete=1;return 1;
}
static inline int pwrmd_actual_translate(void *context,struct pwrmd_translation *t)
{
    (void)context;
#if defined(__aarch64__) || defined(__arm64__)
    uint64_t el;__asm__ volatile("mrs %0,currentel":"=r"(el));
    if(el!=4||!t||(t->page!=0x179e0000&&t->page!=0x179e1000&&t->page!=0x179e2000))return 0;
    __asm__ volatile("mrs %0,par_el1":"=r"(t->saved));
    t->read_issued=1;paic_actual_order(0);
    __asm__ volatile("at s1e1r,%1; isb; mrs %0,par_el1":"=r"(t->read_par):"r"(t->page):"memory");t->read_returned=1;
    t->write_issued=1;paic_actual_order(0);
    __asm__ volatile("at s1e1w,%1; isb; mrs %0,par_el1":"=r"(t->write_par):"r"(t->page):"memory");t->write_returned=1;
    t->restore_issued=1;paic_actual_order(0);
    __asm__ volatile("msr par_el1,%1; isb; mrs %0,par_el1":"=r"(t->restored):"r"(t->saved):"memory");t->restore_returned=1;return 1;
#else
    (void)t;return 0;
#endif
}
static inline int pwrmd_actual_read(void *context,uint64_t at,uint32_t *value)
{
    (void)context;if(!pwrmd_readable(at)||!value)return 0;
#if defined(__aarch64__) || defined(__arm64__)
    *value=*(const volatile uint32_t*)(uintptr_t)at;paic_actual_order(0);return 1;
#else
    return 0;
#endif
}
#endif
#endif
