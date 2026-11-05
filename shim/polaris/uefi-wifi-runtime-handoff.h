/* Complete-parent CPU0/XNU handoff. Never called by a mailbox command.
 * Native CPU0 keeps its C0/G1-off regime and never resumes original providers.
 * Default OFF until the actual loader, worker and post-CE exit are integrated. */
#ifndef POLARIS_UEFI_WIFI_RUNTIME_HANDOFF_H
#define POLARIS_UEFI_WIFI_RUNTIME_HANDOFF_H
#include "uefi-wifi-startup-parent.h"
#include "uefi-wifi-kernel-stage.h"
#include "uefi-xnu.h"
#include "../../tools/polaris-wifi-mailbox.h"
#if EFI_XNU_WIFI_RUNTIME_HANDOFF_AVAILABLE
#if !EFI_XNU_WIFI_STARTUP_PARENT_AVAILABLE
#error Runtime handoff requires the complete actual startup parent
#endif
#if defined(POLARIS_WIFI_RUNTIME_SOFTWARE_PEER)
static int pwkr_cache(uint64_t,uint64_t,unsigned);
static int64_t pwkr_cpu_on(uint64_t,uint64_t);
#else
static inline int pwkr_cache(uint64_t at,uint64_t bytes,unsigned clean)
{
    uint64_t ctr;__asm__ volatile("mrs %0,ctr_el0":"=r"(ctr));
    if((4u<<((ctr>>16)&15))!=64||!bytes||at>UINT64_MAX-bytes||clean>1)return 0;
    uint64_t end=at+bytes;if(end>UINT64_MAX-63)return 0;
    for(uint64_t p=at&~UINT64_C(63);p<end;p+=64){
        if(clean)__asm__ volatile("dc civac,%0"::"r"(p):"memory");
        else __asm__ volatile("dc ivac,%0"::"r"(p):"memory");
    }__asm__ volatile("dsb sy":::"memory");return 1;
}
static inline int64_t pwkr_cpu_on(uint64_t entry,uint64_t context)
{
    register uint64_t x0 __asm__("x0")=UINT64_C(0xc4000003),x1 __asm__("x1")=0x700,
        x2 __asm__("x2")=entry,x3 __asm__("x3")=context;
    __asm__ volatile("smc #0":"+r"(x0),"+r"(x1),"+r"(x2),"+r"(x3)::
        "x4","x5","x6","x7","x8","x9","x10","x11","x12","x13","x14","x15","x16","x17","cc","memory");
    return (int64_t)x0;
}
#endif
static inline int pwkr_fail(struct pmsc_owner*o,unsigned error)
{o->runtime.unknown=1;return pmsc_fail(o,error);}
static inline int pwkr_identity(uint64_t at,uint64_t bytes)
{
    if(!bytes||at>UINT64_MAX-bytes)return 0;
    uint64_t end=at+bytes;
    for(uint64_t page=at&~UINT64_C(4095);page<end;page+=4096){
        struct pwmc_translation t={.page=page};
        if(!pwmc_actual_translate(&t)||!pwmc_translation_valid(&t)||t.page!=page)return 0;
        if(page>UINT64_MAX-4096)return 0;
    }return 1;
}
static inline int pwkr_parent(struct pwns_parent*s)
{
    return s&&s->attempted==1&&s->phase==PWNS_READY&&!s->unknown&&!s->error&&
        pmwi_live(&s->wmi)&&s->wmi.client.phase==4&&pmhd_live(&s->data)&&pmnp_live(&s->nonce);
}
/* mailbox_va is the exact linked DATA symbol supplied by the candidate builder,
 * not an address from the other CPU. Only a whole initialized PW16KiB page
 * inside the already copied payload can be changed. */
static inline int pwkr_begin(struct pwns_parent*s,const struct pwks_image*k,
    struct polaris_efi_ap*ap,uint64_t entry,uint64_t stack,uint64_t stack_bytes,
    const struct polaris_plan*plan,uint64_t mailbox_va)
{
    if(!s||!k||!ap||!plan)return 0;struct pmsc_owner*o=&s->owner;
    struct pmsc_runtime*r=&o->runtime;
    if(o->phase!=2||!pwmc_zero(r,sizeof(*r))||!pwkr_parent(s)||!pmsc_bound(o))return 0;
    r->attempted=1;
    if(((uintptr_t)ap&127)||(entry&3)||(stack&127)||(stack_bytes&127))return pwkr_fail(o,10);
    const struct pweh_result*h=(const void*)(uintptr_t)o->retained;
    const struct pwea_native*e=h->input.early;
    const struct polaris_payload*p=(const void*)(uintptr_t)h->payload;
    if(!pmsi_image_range(e,&h->map,(uintptr_t)k,sizeof(*k))||
       !pmsi_image_range(e,&h->map,(uintptr_t)ap,sizeof(*ap))||
       !pmsi_image_range(e,&h->map,entry,4096)||!stack_bytes||stack_bytes>0x20000||
       !pmsi_image_range(e,&h->map,stack,stack_bytes)||
       !pwea_disjoint((uintptr_t)s,sizeof(*s),(uintptr_t)ap,sizeof(*ap))||
       !pwea_disjoint((uintptr_t)s,sizeof(*s),stack,stack_bytes)||
       !pwea_disjoint((uintptr_t)s,sizeof(*s),(uintptr_t)k,sizeof(*k))||
       !pwea_disjoint(stack,stack_bytes,(uintptr_t)ap,sizeof(*ap))||
       !pwea_disjoint(stack,stack_bytes,(uintptr_t)k,sizeof(*k))||
       !pwea_disjoint((uintptr_t)ap,sizeof(*ap),(uintptr_t)k,sizeof(*k))||
       !k->complete||k->unknown||k->error||k->completed!=k->segments||
       k->source!=h->payload||k->source_bytes!=h->input.logical_bytes||k->segments!=p->nsegs||
       k->base!=p->phys_base||k->virtual_base!=p->virt_base||k->entry!=p->entry_va||
       k->span!=p->kernel_end-p->virt_base||
       ap->entry!=k->base+k->entry-k->virtual_base||ap->entry!=plan->entry_pa||ap->args!=plan->args_pa||
       ap->stack!=stack+stack_bytes||ap->stage||ap->fault_esr||ap->fault_elr||ap->fault_far||ap->mpidr||
       ap->sctlr!=o->current.cpu.sctlr||ap->cpacr!=o->current.cpacr||
       mailbox_va<k->virtual_base||mailbox_va-k->virtual_base>k->span||
       PWMB_BYTES>k->span-(mailbox_va-k->virtual_base)||(mailbox_va&(PWMB_BYTES-1)))return pwkr_fail(o,10);
    uint64_t adt=k->base+k->span;
    if(adt>UINT64_MAX-p->adt_size||adt+p->adt_size>UINT64_MAX-(POLARIS_PAGE-1))return pwkr_fail(o,10);
    uint64_t args=(adt+p->adt_size+POLARIS_PAGE-1)&~(POLARIS_PAGE-1);
    if(args>UINT64_MAX-POLARIS_PAGE||args<k->base||args-k->base>p->mem_size||
       POLARIS_PAGE>p->mem_size-(args-k->base)||plan->adt_pa!=adt||plan->args_pa!=args||
       plan->top!=args+POLARIS_PAGE)return pwkr_fail(o,10);
    uint8_t hash[32];pweh_digest(p,sizeof(*p)+(uint64_t)k->segments*sizeof(p->segs[0]),hash);
    if(!pgcd_equal(hash,k->header_digest,32))return pwkr_fail(o,10);
    unsigned matches=0;
    for(unsigned n=0;n<k->segments;n++){
        const struct polaris_segment*q=&p->segs[n];
        if(mailbox_va>=q->vmaddr&&mailbox_va-q->vmaddr<=q->file_size&&
           PWMB_BYTES<=q->file_size-(mailbox_va-q->vmaddr))matches++;
    }
    uint64_t mailbox=k->base+mailbox_va-k->virtual_base;
    if(matches!=1||!pwkr_identity(entry,4096)||!pwkr_identity((uintptr_t)ap,sizeof(*ap))||
       !pwkr_identity(stack,stack_bytes)||!pwkr_identity(mailbox,PWMB_BYTES)||
       !pwkr_identity(plan->args_pa,POLARIS_PAGE)||!pmsc_live(o))return pwkr_fail(o,10);
    const volatile uint8_t*page=(const void*)(uintptr_t)mailbox;
    for(unsigned n=0;n<PWMB_BYTES;n++)if(page[n]!=(n==0?0x50:n==1?0x57:0))return pwkr_fail(o,10);
    struct pwmb_identity id={.epoch=o->opening};pgcd_copy(id.mac,s->wmi.client.mac,6);
    if(!pwmb_bootstrap_make(&id,r->bootstrap))return pwkr_fail(o,10);
    r->parent=(uintptr_t)s;r->copy=(uintptr_t)k;r->entry=entry;r->context=(uintptr_t)ap;
    r->stack=stack;r->stack_bytes=stack_bytes;r->mailbox=mailbox;r->started=o->last;
    pweh_digest(k,sizeof(*k),r->copy_digest);pweh_digest(ap,offsetof(struct polaris_efi_ap,stage),r->ap_digest);
    /* All seven peers must still be OFF immediately before our sole CPU_ON. */
    for(unsigned n=0;n<7;n++){
        struct pmsb_peer*q=&r->peer[n];q->target=(n+1)*0x100;
        if(!pmsc_live(o))return pwkr_fail(o,11);q->issued=1;
        uint8_t before[32],after[32];pmsc_seal(o,&q->raw,sizeof(q->raw),before);
        int ok=pmsc_affinity(q->target,&q->raw);pmsc_seal(o,&q->raw,sizeof(q->raw),after);
        if(ok!=1||q->raw!=1||!pgcd_equal(before,after,32)||!pmsc_live(o))return pwkr_fail(o,11);q->returned=1;
    }
    volatile uint8_t*dst=(void*)(uintptr_t)mailbox;
    for(unsigned n=0;n<PWMB_BYTES;n++)dst[n]=0;
    for(unsigned n=0;n<PWMB_LINE;n++)dst[PWMB_BOOTSTRAP_OFFSET+n]=r->bootstrap[n];
    if(!pwkr_cache(mailbox,PWMB_BYTES,1)||!pwkr_cache((uintptr_t)ap,sizeof(*ap),1)||
       !pwkr_cache(stack,stack_bytes,1)||!pwkr_cache(entry,4096,1)||!pwkr_parent(s)||!pmsc_bound(o))return pwkr_fail(o,12);
    /* Publish irreversibility before the secure call. No failure may clear it. */
    *(volatile uint32_t*)(uintptr_t)e->native_address=1;
    *(volatile uint32_t*)(uintptr_t)h->input.state=4;r->issued=1;o->phase=4;
    if(!pmsc_arch(o,&o->current,1)||!pmsc_bound(o))return pwkr_fail(o,12);
    uint8_t before[32],after[32];pmsc_seal(o,&r->result,sizeof(r->result),before);
    r->result=pwkr_cpu_on(entry,(uintptr_t)ap);pmsc_seal(o,&r->result,sizeof(r->result),after);
    if(!pgcd_equal(before,after,32))return pwkr_fail(o,13);r->returned=1;
    if(r->result||!pmsc_arch(o,&o->current,1)||!pmsc_bound(o))return pwkr_fail(o,13);
    return 1;
}
/* 1 waits for the actual AP, 2 starts persistent service, 0 retains UNKNOWN.
 * No sleep/firmware timer and no synthetic stage is supplied by this function. */
static inline int pwkr_poll(struct pwns_parent*s)
{
    if(!s)return 0;struct pmsc_owner*o=&s->owner;struct pmsc_runtime*r=&o->runtime;
    if(o->unknown||r->unknown||!pmsc_native(o)||r->returned!=1||r->result)return 0;
    struct polaris_efi_ap*ap=(void*)(uintptr_t)r->context;
    if(!pmsc_arch(o,&o->current,1)||!pwkr_cache((uintptr_t)ap,sizeof(*ap),0))return pwkr_fail(o,14);
    if(r->parent!=(uintptr_t)s)return pwkr_fail(o,14);
    uint8_t hash[32];pweh_digest((const void*)(uintptr_t)r->copy,sizeof(struct pwks_image),hash);
    if(!pgcd_equal(hash,r->copy_digest,32)||!pwkr_cache(r->mailbox+PWMB_BOOTSTRAP_OFFSET,PWMB_LINE,0))return pwkr_fail(o,14);
    const volatile uint8_t*b=(const void*)(uintptr_t)(r->mailbox+PWMB_BOOTSTRAP_OFFSET);
    for(unsigned n=0;n<PWMB_LINE;n++)if(b[n]!=r->bootstrap[n])return pwkr_fail(o,14);
    pweh_digest(ap,offsetof(struct polaris_efi_ap,stage),hash);
    if(!pgcd_equal(hash,r->ap_digest,32))return pwkr_fail(o,14);
    if(!ap->stage){if(r->complete||o->last<r->started||o->last-r->started>UINT64_C(19200000)*3)return pwkr_fail(o,14);return 1;}
    if(ap->stage!=1||(ap->mpidr&UINT64_C(0xffffff))!=0x700||ap->fault_esr||ap->fault_elr||ap->fault_far)return pwkr_fail(o,14);
    r->observed=1;r->complete=1;
    if(!pmsc_live(o)||!pwkr_parent(s))return pwkr_fail(o,14);return 2;
}
#endif
#endif
