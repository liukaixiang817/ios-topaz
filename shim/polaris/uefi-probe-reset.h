/* Explicit host-requested FASTBOOT return for the original-service inventory
 * probe, before native ownership. Own DT restart_reason@146bf65c and existing
 * PM8998 PON marker only. No inactivity reset, watchdog or storage operation. */
#ifndef POLARIS_UEFI_PROBE_RESET_H
#define POLARIS_UEFI_PROBE_RESET_H
#include "uefi-apps-watchdog-readonly.h"
#include "uefi-reset.h"
#define PPR_REASON UINT64_C(0x146bf65c)
struct ppr_ops {
    void *context;
    int (*arch)(void *,struct pawr_arch *);
    int (*translate)(void *,unsigned,struct pawr_translation *);
    int (*read_reason)(void *,uint32_t *);
    int (*write_reason)(void *,uint32_t);
    void (*reset_system)(void *);
    struct polaris_efi_pon *pon;
};
struct ppr_result {
    unsigned prepared,attempted,error,reason_written;
    uint32_t before;
    struct pawr_arch opening;
    struct polaris_efi_reset_marker marker;
    unsigned reason_restored,pon_restored;
};
static inline int ppr_translation(const struct pawr_translation*t)
{
    uint64_t attr=t->par>>56;
    return t->saved==t->restored && !(t->par&1) && (t->par&0x200) &&
        (attr==0||attr==4||attr==0x44) &&
        (t->par&UINT64_C(0x0000fffffffff000))==(PPR_REASON&~UINT64_C(4095));
}
static inline int ppr_live(struct ppr_result*r,const struct ppr_ops*o)
{
    struct pawr_arch a={0};struct pawr_translation t={0};
    if(!o->arch(o->context,&a)||!pawr_arch_same(&r->opening,&a))return 0;
    for(unsigned write=0;write<2;write++)
        if(!o->translate(o->context,write,&t)||!ppr_translation(&t))return 0;
    return o->arch(o->context,&a)&&pawr_arch_same(&r->opening,&a);
}
static inline int ppr_prepare(struct ppr_result*r,const struct ppr_ops*o,unsigned mode)
{
    if(!r||r->attempted)return 0;
    r->prepared=0;
    if(mode!=2||!o||!o->arch||!o->translate||!o->read_reason||!o->write_reason||
       !o->reset_system||!o->pon||o->pon->revision!=0x10001||!o->pon->get||!o->pon->set)return 0;
    if(!o->arch(o->context,&r->opening)||!pawr_arch_valid(&r->opening)||!ppr_live(r,o))return 0;
    r->prepared=1;return 1;
}
static inline void ppr_restore(struct ppr_result*r,const struct ppr_ops*o)
{
    /* One bounded restoration attempt, never a retry of an unknown reset. */
    if(r->reason_written&&ppr_live(r,o))r->reason_restored=o->write_reason(o->context,r->before);
    uint8_t restored=0;
    r->pon_restored=!o->pon->set(0,3,r->marker.before,0xfe)&&
        !o->pon->get(0,3,&restored)&&(restored&0xfe)==(r->marker.before&0xfe);
}
static inline void ppr_execute(struct ppr_result*r,const struct ppr_ops*o,unsigned mode)
{
    /* The USB parser calls this only AFTER delivering its successful ACK.
     * A returned ACK alone never proves that the firmware actually reset. */
    if(!r||!r->prepared||!ppr_prepare(r,o,mode))return;
    r->attempted=1;r->prepared=0;
    if(!o->read_reason(o->context,&r->before)){r->error=1;return;}
    if(!polaris_efi_pon_marker(o->pon,2,&r->marker)){r->error=2;return;}
    if(!ppr_live(r,o)){r->error=3;ppr_restore(r,o);return;}
    r->reason_written=1;
    if(!o->write_reason(o->context,0x77665500u)){r->error=4;ppr_restore(r,o);return;}
    if(!ppr_live(r,o)){r->error=3;ppr_restore(r,o);return;}
    o->reset_system(o->context);
    r->error=5;ppr_restore(r,o); /* ResetSystem unexpectedly returned: HOLD. */
}
#endif
