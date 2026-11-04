/* Unconnected default-OFF native leaves for the own MSS clock/halt/reset
 * protocols. These check current CPU and Device translations, not ownership.
 * The real parent must first bind current GCD/source/resource lifetime, retain
 * all records, exclude competing CPUs/firmware/resetters and publish UNKNOWN.
 * No startup hook, GCD guess, SMEM allocation, power or handback is supplied.
 * These leaves never change interrupt masks and cannot make a hung bus return. */
#ifndef POLARIS_UEFI_MSS_MMIO_NATIVE_H
#define POLARIS_UEFI_MSS_MMIO_NATIVE_H
#ifndef EFI_XNU_MSS_NATIVE_IO_AVAILABLE
#define EFI_XNU_MSS_NATIVE_IO_AVAILABLE 0
#endif
#if EFI_XNU_MSS_NATIVE_IO_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
#include "../../tools/polaris-mss-clocks.h"
enum pmni_kind {PMNI_READ=1,PMNI_WRITE,PMNI_STORE_ORDER,PMNI_FULL_ORDER};
struct pmni_command {uint64_t address;uint32_t kind,value;};
struct pmni_arch {
    uint64_t el,mpidr,ttbr0,ttbr1,tcr,sctlr,mair,daif,sre,group1,cpacr,frequency,ticks;
};
struct pmni_translation {
    uint64_t page,saved,read_par,write_par,restored;
    uint32_t read_issued,read_returned,write_issued,write_returned,restore_issued,restore_returned;
};
struct pmni_result {
    struct pmni_command command;struct pmni_arch before,translated,after;
    struct pmni_translation AT;
    uint32_t attempted,unknown,error,issued,returned,value,complete,reserved;
};
#if defined(POLARIS_MSS_NATIVE_SOFTWARE_PEER)
static int pmni_arch_read(struct pmni_arch*);
static int pmni_translate(struct pmni_translation*);
static int pmni_raw(const struct pmni_command*,uint32_t*);
#else
static inline int pmni_arch_read(struct pmni_arch*a)
{
#if defined(__aarch64__) || defined(__arm64__)
    __asm__ volatile("mrs %0,currentel":"=r"(a->el)::"memory");if(a->el!=4)return 0;
    __asm__ volatile("mrs %0,mpidr_el1; mrs %1,ttbr0_el1; mrs %2,ttbr1_el1; mrs %3,tcr_el1"
        :"=r"(a->mpidr),"=r"(a->ttbr0),"=r"(a->ttbr1),"=r"(a->tcr)::"memory");
    __asm__ volatile("mrs %0,sctlr_el1; mrs %1,mair_el1; mrs %2,daif; mrs %3,icc_sre_el1"
        :"=r"(a->sctlr),"=r"(a->mair),"=r"(a->daif),"=r"(a->sre)::"memory");
    if(!(a->sre&1))return 0;
    __asm__ volatile("mrs %0,icc_igrpen1_el1; mrs %1,cpacr_el1; mrs %2,cntfrq_el0; isb; mrs %3,cntvct_el0"
        :"=r"(a->group1),"=r"(a->cpacr),"=r"(a->frequency),"=r"(a->ticks)::"memory");return 1;
#else
    (void)a;return 0;
#endif
}
static inline int pmni_translate(struct pmni_translation*t)
{
#if defined(__aarch64__) || defined(__arm64__)
    __asm__ volatile("mrs %0,par_el1":"=r"(t->saved)::"memory");
    t->read_issued=1;__asm__ volatile("at s1e1r,%1; isb; mrs %0,par_el1":"=r"(t->read_par):"r"(t->page):"memory");t->read_returned=1;
    t->write_issued=1;__asm__ volatile("at s1e1w,%1; isb; mrs %0,par_el1":"=r"(t->write_par):"r"(t->page):"memory");t->write_returned=1;
    t->restore_issued=1;__asm__ volatile("msr par_el1,%1; isb; mrs %0,par_el1":"=r"(t->restored):"r"(t->saved):"memory");t->restore_returned=1;return 1;
#else
    (void)t;return 0;
#endif
}
static inline int pmni_raw(const struct pmni_command*c,uint32_t*value)
{
#if defined(__aarch64__) || defined(__arm64__)
    if(c->kind==PMNI_READ)__asm__ volatile("ldr %w0,[%1]":"=r"(*value):"r"(c->address):"memory");
    else if(c->kind==PMNI_WRITE)__asm__ volatile("str %w0,[%1]"::"r"(c->value),"r"(c->address):"memory");
    else if(c->kind==PMNI_STORE_ORDER)__asm__ volatile("dsb st":::"memory");
    else if(c->kind==PMNI_FULL_ORDER)__asm__ volatile("dsb sy":::"memory");
    else return 0;return 1;
#else
    (void)c;(void)value;return 0;
#endif
}
#endif
static inline int pmni_fail(struct pmni_result*r,unsigned error)
{r->unknown=1;if(!r->error)r->error=error;return 0;}
static inline int pmni_arch_valid(const struct pmni_arch*a)
{
    return a->el==4&&!(a->mpidr&UINT64_C(0xff00ffffff))&&a->frequency==19200000&&a->ticks&&
        a->mair==UINT64_C(0xffbb4400)&&(a->sctlr&5)==5&&a->daif==0xc0&&a->group1==0&&
        (a->sre&1)&&((a->cpacr>>20)&3)==3;
}
static inline int pmni_arch_same(const struct pmni_arch*a,const struct pmni_arch*b,uint64_t minimum)
{
    return pmni_arch_valid(a)&&pmni_arch_valid(b)&&pmsr_equal(a,b,offsetof(struct pmni_arch,ticks))&&
        b->ticks>=a->ticks&&b->ticks>=minimum&&b->ticks-a->ticks<=PMCK_LIMIT;
}
static inline int pmni_allowed(const struct pmni_command*c)
{
    if(c->kind==PMNI_STORE_ORDER||c->kind==PMNI_FULL_ORDER)return !c->address&&!c->value;
    if(c->kind!=PMNI_READ&&c->kind!=PMNI_WRITE)return 0;
    if(c->kind==PMNI_READ&&c->value)return 0;
    for(unsigned n=0;n<PMCK_CLOCKS;n++){
        struct pmck_clock clock=pmck_clock(n);
        if(c->address==clock.enable||(c->kind==PMNI_READ&&clock.status&&c->address==clock.status))return 1;
    }
    if(c->address==PMSR_PDC)return 1;
    if(c->address==PMSR_ALT||c->address==PMSR_RESTART)return c->kind==PMNI_WRITE&&c->value<=1;
    for(unsigned port=0;port<3;port++){
        uint64_t base=pmh_base(port);
        if(c->address==base)return c->kind==PMNI_READ||c->value==1;
        if(c->address==base+4||c->address==base+8)return c->kind==PMNI_READ;
    }
    return c->address==PMS_DOORBELL&&c->kind==PMNI_WRITE&&(c->value==PMS_DOORBELL_MASK||!c->value);
}
/* Low-level access only; current parent qualification is deliberately NOT
 * replaced by a callback success, descriptor pointer or ready=true argument. */
static inline int pmni_access(const struct pmni_arch*opening,const struct pmni_command*command,struct pmni_result*r)
{
    if(!opening||!command||!r||!pmsr_disjoint(r,sizeof(*r),opening,sizeof(*opening))||
       !pmsr_disjoint(r,sizeof(*r),command,sizeof(*command))||!pms_zero(r,sizeof(*r)))return 0;
    r->attempted=1;r->command=*command;struct pmni_arch reference=*opening;
    if(!pmni_allowed(command)||!pmni_arch_read(&r->before)||!pmni_arch_same(&reference,&r->before,reference.ticks))return pmni_fail(r,1);
    r->unknown=1;
    if(command->kind==PMNI_READ||command->kind==PMNI_WRITE){
        r->AT.page=command->address&~UINT64_C(4095);
        if(!pmni_translate(&r->AT))return pmni_fail(r,2);
        const struct pmni_translation*t=&r->AT;uint64_t par=t->read_par;
        if(t->page!=(command->address&~UINT64_C(4095))||t->read_issued!=1||t->read_returned!=1||
           t->write_issued!=1||t->write_returned!=1||t->restore_issued!=1||t->restore_returned!=1||
           t->saved!=t->restored||par!=t->write_par||(par&1)||!(par&0x200)||
           ((par>>56)!=0&&(par>>56)!=4)||(par&UINT64_C(0x0000fffffffff000))!=t->page)return pmni_fail(r,3);
    }
    if(!pmsr_equal(opening,&reference,sizeof(reference))||!pmsr_equal(command,&r->command,sizeof(*command))||
       !pmni_arch_read(&r->translated)||!pmni_arch_same(&reference,&r->translated,r->before.ticks))return pmni_fail(r,4);
    r->issued=1;int returned=pmni_raw(&r->command,&r->value);r->returned=returned==1;
    if(returned!=1||!pmsr_equal(opening,&reference,sizeof(reference))||!pmsr_equal(command,&r->command,sizeof(*command))||
       !pmni_arch_read(&r->after)||!pmni_arch_same(&reference,&r->after,r->translated.ticks))return pmni_fail(r,5);
    r->unknown=0;r->complete=1;return 1;
}
static inline int pmni_clock(const struct pmck_lifecycle*c,const struct pmck_command*command,
    const struct pmni_arch*opening,struct pmni_result*r)
{
    if(!c||!command||!r||!pmsr_disjoint(c,sizeof(*c),r,sizeof(*r))||c->unknown||c->error||
       !c->pending||c->pending!=c->events||c->events>PMCK_EVENTS||
       !pmsr_equal(command,&c->event[c->events-1].command,sizeof(*command))||
       command->phase!=c->phase||command->clock!=c->clock||command->step!=c->step)return 0;
    struct pmni_command access={command->address,command->kind==PMCK_ORDER?PMNI_FULL_ORDER:command->kind,command->value};
    return pmni_access(opening,&access,r);
}
static inline int pmni_reset(const struct pmsd_shutdown*s,const struct pmsd_command*command,
    const struct pmni_arch*opening,struct pmni_result*r)
{
    if(!s||!command||!r||!pmsr_disjoint(s,sizeof(*s),r,sizeof(*r))||s->unknown||s->phase!=2||s->pending!=1||
       !pmsr_equal(command,&s->command,sizeof(*command))||!s->stop.complete||!s->stop.stop.ack_held||
       s->stop.halt.ports_held!=7||s->reset.unknown||s->reset.error||!s->reset.pending||
       s->reset.pending!=s->reset.events||s->reset.events>PMSR_EVENTS||
       !pmsr_equal(&command->command.reset,&s->reset.event[s->reset.events-1].command,sizeof(struct pmsr_command)))return 0;
    const struct pmsr_command*c=&command->command.reset;
    struct pmni_command access={c->address,c->kind,c->value};return pmni_access(opening,&access,r);
}
static inline int pmni_halt(const struct pmsd_shutdown*s,const struct pmsd_command*command,
    const struct pmni_arch*opening,struct pmni_result*r)
{
    if(!s||!command||!r||!pmsr_disjoint(s,sizeof(*s),r,sizeof(*r))||s->unknown||s->phase!=1||s->pending!=1||
       !pmsr_equal(command,&s->command,sizeof(*command))||s->stop.unknown||s->stop.phase!=2||s->stop.pending!=1||
       !s->stop.stop.ack_held||s->stop.halt.unknown||s->stop.halt.error||!s->stop.halt.pending||
       s->stop.halt.pending!=s->stop.halt.events||s->stop.halt.events>PMH_EVENTS||
       !pmsr_equal(&command->command.stop.command.halt,
           &s->stop.halt.event[s->stop.halt.events-1].command,sizeof(struct pmh_command)))return 0;
    const struct pmh_command*c=&command->command.stop.command.halt;
    struct pmni_command access={c->address,c->write?PMNI_WRITE:PMNI_READ,c->value};return pmni_access(opening,&access,r);
}
#endif
#endif
