/* Unconnected default-OFF native leaves for own MSS clocks/halt/reset and
 * MBA/metadata protocols. These check CPU and Device translations, not ownership.
 * The real parent must first bind current GCD/source/resource lifetime, retain
 * all records, exclude competing CPUs/firmware/resetters and publish UNKNOWN.
 * No startup hook, GCD guess, SMEM allocation, power or handback is supplied.
 * These leaves never change interrupt masks and cannot make a hung bus return. */
#ifndef POLARIS_UEFI_MSS_MMIO_NATIVE_H
#define POLARIS_UEFI_MSS_MMIO_NATIVE_H
#ifndef EFI_XNU_MSS_NATIVE_IO_AVAILABLE
#define EFI_XNU_MSS_NATIVE_IO_AVAILABLE 0
#endif
#ifndef EFI_XNU_MSS_RAIL_IO_AVAILABLE
#define EFI_XNU_MSS_RAIL_IO_AVAILABLE 0
#endif
#ifndef EFI_XNU_MSS_PROXY_IO_AVAILABLE
#define EFI_XNU_MSS_PROXY_IO_AVAILABLE 0
#endif
#ifndef EFI_XNU_MSS_AOP_IO_AVAILABLE
#define EFI_XNU_MSS_AOP_IO_AVAILABLE 0
#endif
#ifndef EFI_XNU_MSS_MODEM_IO_AVAILABLE
#define EFI_XNU_MSS_MODEM_IO_AVAILABLE 0
#endif
#ifndef EFI_XNU_MSS_RSC_STATE_AVAILABLE
#define EFI_XNU_MSS_RSC_STATE_AVAILABLE 0
#endif
#ifndef EFI_XNU_MSS_SFPB_IO_AVAILABLE
#define EFI_XNU_MSS_SFPB_IO_AVAILABLE 0
#endif
#ifndef EFI_XNU_MSS_CHANNEL_NATIVE_AVAILABLE
#define EFI_XNU_MSS_CHANNEL_NATIVE_AVAILABLE 0
#endif
#ifndef EFI_XNU_WIFI_SMMU_NATIVE_AVAILABLE
#define EFI_XNU_WIFI_SMMU_NATIVE_AVAILABLE 0
#endif
#ifndef EFI_XNU_WIFI_CE_NATIVE_AVAILABLE
#define EFI_XNU_WIFI_CE_NATIVE_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_CE_NATIVE_AVAILABLE
#include "../../tools/polaris-wifi-ce-init.h"
#endif
#if defined(EFI_XNU_WIFI_CE_TRANSPORT_AVAILABLE) && EFI_XNU_WIFI_CE_TRANSPORT_AVAILABLE
#include "../../tools/polaris-wifi-ce-ring.h"
#endif
#if EFI_XNU_WIFI_SMMU_NATIVE_AVAILABLE
#include "../../tools/polaris-wifi-smmu-route.h"
#endif
#if EFI_XNU_MSS_SFPB_IO_AVAILABLE && !EFI_XNU_MSS_NATIVE_IO_AVAILABLE
#error SFPB leaves require native MMIO and the separate current SMEM owner
#endif
#if EFI_XNU_MSS_MODEM_IO_AVAILABLE && !EFI_XNU_MSS_NATIVE_IO_AVAILABLE
#error MSS modem authentication requires the separate native MMIO leaves
#endif
#if EFI_XNU_MSS_AOP_IO_AVAILABLE && !EFI_XNU_MSS_NATIVE_IO_AVAILABLE
#error MSS AOP leaves require the separate native MMIO leaves
#endif
#if EFI_XNU_MSS_PROXY_IO_AVAILABLE && (!EFI_XNU_MSS_NATIVE_IO_AVAILABLE || !EFI_XNU_MSS_RAIL_IO_AVAILABLE)
#error MSS proxy leaves require the separate native MMIO and retained rail leaves
#endif
#if EFI_XNU_MSS_NATIVE_IO_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
#include "../../tools/polaris-mss-metadata.h"
#if EFI_XNU_MSS_MODEM_IO_AVAILABLE
#include "../../tools/polaris-mss-modem-auth.h"
#endif
#if EFI_XNU_MSS_RAIL_IO_AVAILABLE
#include "../../tools/polaris-mss-rail-request.h"
#endif
#if EFI_XNU_MSS_PROXY_IO_AVAILABLE
#include "../../tools/polaris-mss-proxy.h"
#endif
#if EFI_XNU_MSS_AOP_IO_AVAILABLE
#include "../../tools/polaris-mss-aop.h"
#endif
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
#if defined(EFI_XNU_WIFI_CE_TRANSPORT_AVAILABLE) && EFI_XNU_WIFI_CE_TRANSPORT_AVAILABLE
    if(pwcr_register(c->address,c->kind==PMNI_WRITE,c->value))return 1;
#endif
#if EFI_XNU_WIFI_CE_NATIVE_AVAILABLE
    if(pwce_register(c->address,c->kind==PMNI_WRITE))return 1;
#endif
#if EFI_XNU_WIFI_SMMU_NATIVE_AVAILABLE
    if(c->kind==PMNI_READ&&pwsu_readable(c->address))return 1;
#endif
#if EFI_XNU_MSS_SFPB_IO_AVAILABLE
    /* Own DT lock3 only. The typed lock owner below the parent decides when
     * acquisition/release is valid; this is merely the exact native leaf. */
    if(c->address==UINT64_C(0x1f43000))return c->kind==PMNI_READ||c->value<=1;
#endif
#if EFI_XNU_MSS_MODEM_IO_AVAILABLE
    if(c->address==0x4180018)return c->kind==PMNI_READ||c->value<=0x7800000;
    if(c->address==0x4180014)return c->kind==PMNI_WRITE&&(!c->value||
        (!(c->value&0xfffff)&&c->value>=0x80000000&&c->value<=0xf8800000));
    if(c->address==0x4180008)return c->kind==PMNI_WRITE&&(c->value==1||c->value==2);
#endif
#if EFI_XNU_MSS_AOP_IO_AVAILABLE
    /* APCS shares this address with SMP2P/GLINK; admit this exact AOP bit,
     * then let the other explicit profiles below inspect their own masks. */
    if(c->address==PMAQ_IRQ&&c->kind==PMNI_WRITE&&c->value==1)return 1;
    if(!(c->address&3)&&c->address>=PMAQ_BASE&&c->address<PMAQ_BASE+PMAQ_BYTES)
        return c->kind==PMNI_READ||c->address>=PMAQ_BASE+64;
#endif
#if EFI_XNU_MSS_PROXY_IO_AVAILABLE
    if(c->address==0x134004)return c->kind==PMNI_READ;
#endif
#if EFI_XNU_MSS_RAIL_IO_AVAILABLE
    /* Separate retained-request adapter below further restricts this to its
     * exact pending event and selected TCS. IRQ enable/type are never writes. */
#if EFI_XNU_MSS_RSC_STATE_AVAILABLE
    if(c->address==0x179e000c)return c->kind==PMNI_READ;
#endif
    if(c->kind==PMNI_READ&&pwrr_readable(c->address))return 1;
    if(c->address==PWRSC_BASE+8)return c->kind==PMNI_WRITE&&c->value&&
        c->value<=128&&!(c->value&(c->value-1));
    if(c->address>=PWRSC_BASE&&c->address<PWRSC_BASE+8*PWRSC_STRIDE&&!(c->address&3)){
        unsigned off=(unsigned)(c->address-PWRSC_BASE)%PWRSC_STRIDE;
        if(c->kind==PMNI_WRITE&&(off==0x10||off==0x14||off==0x1c||off==0x30||off==0x34||off==0x38))return 1;
    }
#endif
    for(unsigned n=0;n<PMCK_CLOCKS;n++){
        struct pmck_clock clock=pmck_clock(n);
        if(c->address==clock.enable||(c->kind==PMNI_READ&&clock.status&&c->address==clock.status))return 1;
    }
    if(c->address==PMSR_PDC)return 1;
    if(c->address==PMSR_ALT||c->address==PMSR_RESTART)return c->kind==PMNI_WRITE&&c->value<=1;
    if(c->address==UINT64_C(0x4080018)||c->address==UINT64_C(0x408003c))return 1;
    if(c->address==UINT64_C(0x4080400)||c->address==UINT64_C(0x4080404))return c->kind==PMNI_WRITE&&c->value==1;
    if(c->address==UINT64_C(0x4180000))return c->kind==PMNI_WRITE&&!(c->value&4095)&&c->value>=0x80000000&&c->value<=0xfff00000;
    if(c->address==UINT64_C(0x4180014)||c->address==UINT64_C(0x4180018))return c->kind==PMNI_WRITE&&!c->value;
    if(c->address==UINT64_C(0x4180040)||c->address==UINT64_C(0x4180004)||c->address==UINT64_C(0x418000c))return c->kind==PMNI_READ;
    if(c->address==UINT64_C(0x4180010))return c->kind==PMNI_WRITE&&!(c->value&4095)&&c->value>=0x80000000;
    if(c->address==UINT64_C(0x4180008))return c->kind==PMNI_WRITE&&c->value==1;
    for(unsigned port=0;port<3;port++){
        uint64_t base=pmh_base(port);
        if(c->address==base)return c->kind==PMNI_READ||c->value==1;
        if(c->address==base+4||c->address==base+8)return c->kind==PMNI_READ;
    }
#if EFI_XNU_MSS_CHANNEL_NATIVE_AVAILABLE
    if(c->address==PMS_DOORBELL&&c->kind==PMNI_WRITE&&c->value==0x1000)return 1;
#endif
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
static inline int pmni_mba(const struct pmba_boot*b,const struct pmba_command*c,
    const struct pmni_arch*opening,struct pmni_result*r)
{
    if(!b||!c||!r||!pmsr_disjoint(b,sizeof(*b),r,sizeof(*r))||b->unknown||b->error||b->pending!=1||
       !pmsr_equal(c,&b->command,sizeof(*c))||c->phase!=b->phase)return 0;
    struct pmni_command access={c->address,c->kind,c->value};
    if(b->phase==2){
        if(b->reset.unknown||b->reset.error||!b->reset.pending||b->reset.pending!=b->reset.events||
           b->reset.events>PMSR_EVENTS||!pmsr_equal(&c->reset,&b->reset.event[b->reset.events-1].command,sizeof(c->reset)))return 0;
        access=(struct pmni_command){c->reset.address,c->reset.kind,c->reset.value};
    }else if((b->phase!=1&&b->phase!=3)||!b->events||b->events>PMBA_EVENTS||
        !pmsr_equal(c,&b->event[b->events-1].command,sizeof(*c)))return 0;
    return pmni_access(opening,&access,r);
}
static inline int pmni_metadata(const struct pmmd_metadata*m,const struct pmmd_command*c,
    const struct pmni_arch*opening,struct pmni_result*r)
{
    if(!m||!c||!r||!pmsr_disjoint(m,sizeof(*m),r,sizeof(*r))||m->unknown||m->error||m->phase!=1||
       !m->pending||m->pending!=m->events||m->events>PMMD_EVENTS||
       !pmsr_equal(c,&m->event[m->events-1].command,sizeof(*c)))return 0;
    struct pmni_command access={c->address,c->kind,c->value};return pmni_access(opening,&access,r);
}
#if EFI_XNU_MSS_MODEM_IO_AVAILABLE
static inline int pmni_modem(const struct pmim_auth*m,const struct pmim_command*c,
    const struct pmni_arch*opening,struct pmni_result*r)
{
    if(!m||!c||!r||!pmsr_disjoint(m,sizeof(*m),r,sizeof(*r))||m->unknown||m->error||
       (m->phase!=2&&m->phase!=4)||!m->pending||m->pending!=m->events||m->events>PMIM_EVENTS||
       !pmsr_equal(c,&m->event[m->events-1].command,sizeof(*c))||c->step!=m->step||c->segment!=m->segment||
       c->kind<PMSR_READ||c->kind>PMSR_FULL_ORDER)return 0;
    struct pmni_command access={c->address,c->kind,c->value};return pmni_access(opening,&access,r);
}
#endif
#if EFI_XNU_MSS_RAIL_IO_AVAILABLE
static inline int pmni_rail(const struct pmrv_request*q,const struct pwrsc_event*e,
    const struct pmni_arch*opening,struct pmni_result*r)
{
    if(!q||!e||!r||!pmsr_disjoint(q,sizeof(*q),r,sizeof(*r))||!q->epoch||
       !pmrv_input(q->resource,q->write,q->value)||q->io.error||q->io.unknown||q->io.finished||
       !q->io.events||q->io.events>PWRSC_HISTORY||q->io.outstanding!=q->io.events||
       !pmsr_equal(e,&q->io.history[q->io.events-1],sizeof(*e))||e->issued!=1||e->returned||e->unknown!=1||
       e->phase!=q->io.phase||q->io.tcs>=8||!(q->io.active_mask&(1u<<q->io.tcs)))return 0;
    uint64_t t=pwrsc_tcs(&q->io);
    if(e->operation==2){if(!pmrv_writable(q,e->address,e->value))return 0;}
    else if(e->operation!=1||!pwrr_readable(e->address)||
        (e->address!=PWRSC_BASE&&e->address!=PWRSC_BASE+4&&(e->address<t||e->address>=t+PWRSC_STRIDE)))return 0;
    struct pmni_command access={e->address,e->operation==2?PMNI_WRITE:PMNI_READ,e->operation==2?e->value:0};
    return pmni_access(opening,&access,r);
}
#endif
#if EFI_XNU_MSS_PROXY_IO_AVAILABLE
static inline int pmni_proxy(const struct pmpx_lifecycle*p,const struct pmpx_command*c,
    const struct pmni_arch*opening,struct pmni_result*r)
{
    if(!p||!c||!r||!pmsr_disjoint(p,sizeof(*p),r,sizeof(*r))||p->unknown||p->error||
       !p->pending||p->pending!=p->events||p->events>PMPX_EVENTS||
       !pmsr_equal(c,&p->event[p->events-1].command,sizeof(*c))||c->step!=p->step||
       c->kind==PMPX_RAIL||c->kind<PMPX_READ||c->kind>PMPX_ORDER)return 0;
    struct pmni_command access={c->address,c->kind==PMPX_ORDER?PMNI_FULL_ORDER:c->kind,c->value};
    return pmni_access(opening,&access,r);
}
#endif
#if EFI_XNU_MSS_AOP_IO_AVAILABLE
static inline int pmni_aop(const struct pmaq_notify*q,const struct pmaq_command*c,
    const struct pmni_arch*opening,struct pmni_result*r)
{
    if(!q||!c||!r||!pmsr_disjoint(q,sizeof(*q),r,sizeof(*r))||q->unknown||q->error||q->complete||
       !q->pending||q->pending!=q->events||q->events>PMAQ_EVENTS||
       !pmsr_equal(c,&q->event[q->events-1].command,sizeof(*c))||c->step!=q->step||c->index!=q->index||
       c->kind<PMAQ_READ||c->kind>PMAQ_FULL_ORDER)return 0;
    if(c->kind==PMAQ_WRITE32){
        if(!pmaq_geometry(q->descriptor))return 0;
        uint64_t tx=PMAQ_BASE+q->descriptor[14];
        if(c->step==PMAQ_DOORBELL){if(c->address!=PMAQ_IRQ||c->value!=1)return 0;}
        else if(c->step==PMAQ_LENGTH){if(c->address!=tx||c->value!=96)return 0;}
        else if(c->step==PMAQ_WRITE||c->step==PMAQ_RESTORE){
            if(c->index>=24||c->address!=tx+4+4*c->index||
               c->value!=(c->step==PMAQ_WRITE?pmaq_word(q->on,c->index):q->saved[c->index]))return 0;
        }else return 0;
    }
    struct pmni_command access={c->address,c->kind==PMAQ_FULL_ORDER?PMNI_FULL_ORDER:c->kind,c->value};
    return pmni_access(opening,&access,r);
}
#endif
#endif
#endif
