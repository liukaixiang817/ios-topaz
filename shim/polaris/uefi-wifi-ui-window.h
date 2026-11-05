/* Serialized native UI window inside the continuously held Wi-Fi CPU owner.
 * C0/G1-off -> 3C0/G1-off -> C0/G1-off; never enables IRQ/FIQ or calls an
 * original provider. Existing keys/WLED/battery checks stay unchanged. This
 * validates CPU-local exclusion, not PMIC permissions or physical admission.
 */
#ifndef POLARIS_UEFI_WIFI_UI_WINDOW_H
#define POLARIS_UEFI_WIFI_UI_WINDOW_H
#include "uefi-mss-cpu-owner.h"
#if EFI_XNU_MSS_CPU_OWNER_AVAILABLE
enum pwnu_operation {PWNU_PREPARE=1,PWNU_POLL,PWNU_CLOSE,PWNU_SEAL};
struct pwnu_state {
    uint64_t owner,opening,turns,cookie;uint32_t sequence;
    uint32_t ready,closing,sealed,active,unknown,error,operation;
    struct pgcd_arch before,masked,after_service,restored;
    uint8_t owner_digest[32];
};
/* Fixed local implementation selected by the including loader, never a
 * function pointer or operation/address received from the other CPU. */
static int pwnu_service(unsigned,uint64_t,uint32_t);
#if defined(POLARIS_WIFI_UI_SOFTWARE_PEER)
static int pwnu_change_mask(uint64_t,uint64_t);
#else
static inline int pwnu_change_mask(uint64_t before,uint64_t after)
{
    if(!((before==0xc0&&after==0x3c0)||(before==0x3c0&&after==0xc0)))return 0;
    uint64_t el,sre,mask,group;
    __asm__ volatile("mrs %0,currentel":"=r"(el));if(el!=4)return 0;
    __asm__ volatile("mrs %0,ICC_SRE_EL1":"=r"(sre));if(!(sre&1))return 0;
    __asm__ volatile("mrs %0,daif; mrs %1,ICC_IGRPEN1_EL1":"=r"(mask),"=r"(group));
    if(mask!=before||group)return 0;
    __asm__ volatile("msr daif,%0; dsb sy; isb"::"r"(after):"memory");
    __asm__ volatile("mrs %0,daif; mrs %1,ICC_IGRPEN1_EL1":"=r"(mask),"=r"(group));
    return mask==after&&!group;
}
#endif
static inline int pwnu_fail(struct pwnu_state*s,unsigned error)
{if(s){s->unknown=1;if(!s->error)s->error=error;}return 0;}
static inline int pwnu_arch(const struct pgcd_arch*a,const struct pgcd_arch*b,uint64_t mask)
{
    const struct pwfc_arch*x=&a->cpu,*y=&b->cpu;
    return x->el==4&&!(x->mpidr&UINT64_C(0xff00ffffff))&&x->frequency==19200000&&
        x->el==y->el&&x->mpidr==y->mpidr&&x->ttbr0==y->ttbr0&&x->ttbr1==y->ttbr1&&
        x->tcr==y->tcr&&x->sctlr==y->sctlr&&x->mair==y->mair&&x->sre==y->sre&&
        x->frequency==y->frequency&&!x->group1&&!y->group1&&y->daif==mask&&
        y->ticks>=x->ticks&&a->cpacr==b->cpacr;
}
static inline int pwnu_owner_same(struct pwnu_state*s,struct pmsc_owner*o)
{
    uint8_t hash[32];pmsc_seal(o,0,0,hash);return pgcd_equal(hash,s->owner_digest,32);
}
/* 1 completed service, 2 close/restoration ready, 0 sticky retained refusal.
 * No recovery retries a failed mask or device command. Once service starts,
 * all errors keep the window held; the loader must enter UNKNOWN immediately.
 */
static inline int pwnu_run(struct pwnu_state*s,struct pmsc_owner*o,unsigned operation,
    uint64_t cookie,uint32_t sequence)
{
    if(!s||!o||s->unknown||s->error||s->active||s->sealed||operation<PWNU_PREPARE||operation>PWNU_SEAL)return 0;
    if(operation==PWNU_PREPARE){
        if(!pwmc_zero(s,sizeof(*s))||o->phase!=2||pmsc_native(o))return 0;
        const struct pweh_result*h=(const void*)(uintptr_t)o->retained;
        if(!h||!pmsi_image_range(h->input.early,&h->map,(uintptr_t)s,sizeof(*s))||
           !pwea_disjoint((uintptr_t)s,sizeof(*s),(uintptr_t)o,sizeof(*o)))return 0;
    }else if(!s->ready||s->owner!=(uintptr_t)o||s->opening!=o->opening||!pmsc_persistent(o))return 0;
    if((operation==PWNU_POLL&&s->closing)||(operation==PWNU_SEAL&&!s->closing)||
       ((operation==PWNU_SEAL)!=!!(cookie&&sequence))||
       (operation!=PWNU_SEAL&&(cookie||sequence)))return 0;
    if(!pmsc_bound(o)||!pmsc_live(o)||s->turns==UINT64_MAX)return pwnu_fail(s,1);
    s->owner=(uintptr_t)o;s->opening=o->opening;s->operation=operation;s->before=o->current;
    s->cookie=cookie;s->sequence=sequence;s->turns++;s->active=s->unknown=1;
    pmsc_seal(o,0,0,s->owner_digest);
    if(!pwnu_change_mask(0xc0,0x3c0)||!pwnu_owner_same(s,o)||
       !pgcd_actual_arch(0,&s->masked)||!pwnu_arch(&s->before,&s->masked,0x3c0))return pwnu_fail(s,2);
    int result=pwnu_service(operation,cookie,sequence);
    if((result!=1&&(operation!=PWNU_CLOSE||result!=2))||!pwnu_owner_same(s,o)||
       !pgcd_actual_arch(0,&s->after_service)||!pwnu_arch(&s->masked,&s->after_service,0x3c0))return pwnu_fail(s,3);
    if(!pwnu_change_mask(0x3c0,0xc0)||!pwnu_owner_same(s,o)||
       !pgcd_actual_arch(0,&s->restored)||!pwnu_arch(&s->after_service,&s->restored,0xc0)||
       !pmsc_bound(o)||!pmsc_live(o))return pwnu_fail(s,4);
    s->active=s->unknown=0;s->ready=1;
    if(operation==PWNU_CLOSE)s->closing=1;if(operation==PWNU_SEAL)s->sealed=1;
    return result;
}
#endif
#endif
