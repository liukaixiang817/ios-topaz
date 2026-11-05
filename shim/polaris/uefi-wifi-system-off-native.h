/* Retained-memory terminal SYSTEM_OFF continuation. Default OFF and not a
 * loader/boot admission. No WLAN OFF, CE unpublish, power-vote restoration,
 * VMID handback, free, original provider or reset is performed here. */
#ifndef POLARIS_UEFI_WIFI_SYSTEM_OFF_NATIVE_H
#define POLARIS_UEFI_WIFI_SYSTEM_OFF_NATIVE_H
#ifndef EFI_XNU_WIFI_SYSTEM_OFF_NATIVE_AVAILABLE
#define EFI_XNU_WIFI_SYSTEM_OFF_NATIVE_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_SYSTEM_OFF_NATIVE_AVAILABLE
#include "uefi-wifi-worker-native.h"
#include "../../tools/polaris-wifi-system-off.h"
#if !EFI_XNU_WIFI_WORKER_NATIVE_AVAILABLE
#error Terminal SYSTEM_OFF requires the actual native worker
#endif
struct pwno_state {
    uint64_t worker,parent,owner,slot,opening;
    struct pwof_state policy;struct polaris_shutdown_status sample;
    struct pwof_command command;uint8_t worker_digest[32];int64_t raw;
    uint32_t ready,unknown,error,pending,off_issued,off_returned;
};
#if defined(POLARIS_WIFI_SYSTEM_OFF_SOFTWARE_PEER)
static int64_t pwno_smc(uint64_t,uint64_t);
#else
static inline int64_t pwno_smc(uint64_t function,uint64_t argument)
{
    register uint64_t x0 __asm__("x0")=function,x1 __asm__("x1")=argument,
        x2 __asm__("x2")=0,x3 __asm__("x3")=0;
    __asm__ volatile("smc #0":"+r"(x0),"+r"(x1),"+r"(x2),"+r"(x3)::
        "x4","x5","x6","x7","x8","x9","x10","x11","x12","x13","x14","x15","x16","x17","cc","memory");
    return (int64_t)x0;
}
#endif
static inline int pwno_fail(struct pwno_state*s,unsigned error)
{s->unknown=1;if(!s->error)s->error=error;return -1;}
static inline int pwno_live(struct pwno_state*s)
{
    if(!s||s->ready!=1||s->unknown||s->error||s->off_issued)return 0;
    struct pwwn_state*w=(void*)(uintptr_t)s->worker;struct pwns_parent*p=(void*)(uintptr_t)s->parent;
    uint8_t hash[32];
    if(w->retirement!=(uintptr_t)s||w->closing!=2||w->phase!=PWWN_CLOSED||
       w->unknown||w->error||!w->network.closed||w->mailbox.parent!=s->parent||
       (uintptr_t)&p->owner!=s->owner||p->owner.opening!=s->opening||!pmsc_persistent(&p->owner))return 0;
    pweh_digest(w,sizeof(*w),hash);
    return pgcd_equal(hash,s->worker_digest,32)&&pmsc_live(&p->owner);
}
static inline int pwno_read_status(struct pwno_state*s)
{
    if(!pwno_live(s)||!pwkr_cache(s->slot+128,128,0))return 0;
    const volatile uint8_t*p=(const void*)(uintptr_t)(s->slot+128);uint8_t*q=(void*)&s->sample;
    for(unsigned n=0;n<128;n++)q[n]=p[n];return pwno_live(s);
}
/* shutdown_va is the candidate's linked polaris_uefi_shutdown symbol, never
 * a mailbox-supplied address. Builder must also verify its writable section. */
static inline int pwno_begin(struct pwno_state*s,struct pwwn_state*w,uint64_t shutdown_va)
{
    if(!s||!w||!pwmb_zero(s,sizeof(*s))||!pwwn_live(w)||w->closing!=2||
       w->phase!=PWWN_CLOSED||!w->network.closed||w->retirement)return 0;
    struct pwns_parent*p=pwwn_parent(w);struct pmsc_owner*o=&p->owner;
    const struct pweh_result*h=(const void*)(uintptr_t)o->retained;
    const struct pwks_image*k=(const void*)(uintptr_t)o->runtime.copy;
    const struct polaris_payload*payload=(const void*)(uintptr_t)h->payload;
    if(pwkr_poll(p)!=2||!pmwi_child(&p->htc,(uintptr_t)s,sizeof(*s))||
       !pmsi_image_range(h->input.early,&h->map,(uintptr_t)s,sizeof(*s))||
       !pwea_disjoint((uintptr_t)s,sizeof(*s),(uintptr_t)p,sizeof(*p))||
       !pwea_disjoint((uintptr_t)s,sizeof(*s),(uintptr_t)w,sizeof(*w))||
       (shutdown_va&127)||shutdown_va<k->virtual_base||shutdown_va-k->virtual_base>k->span||
       sizeof(struct polaris_shutdown_slot)>k->span-(shutdown_va-k->virtual_base))return 0;
    const uint64_t at[]={o->runtime.copy,o->runtime.context,o->runtime.stack,o->retained,o->memory,o->mba,(uintptr_t)h->input.early};
    const uint64_t bytes[]={sizeof(*k),sizeof(struct polaris_efi_ap),o->runtime.stack_bytes,sizeof(*h),sizeof(struct pmmn_native),sizeof(struct pmsb_result),sizeof(struct pwea_native)};
    for(unsigned n=0;n<7;n++)if(!pwea_disjoint((uintptr_t)s,sizeof(*s),at[n],bytes[n]))return 0;
    uint8_t header[32];pweh_digest(payload,sizeof(*payload)+(uint64_t)k->segments*sizeof(payload->segs[0]),header);
    if(!pgcd_equal(header,k->header_digest,32))return 0;
    unsigned matches=0;
    for(unsigned n=0;n<k->segments;n++){
        const struct polaris_segment*q=&payload->segs[n];
        if(shutdown_va>=q->vmaddr&&shutdown_va-q->vmaddr<=q->vmsize&&
           sizeof(struct polaris_shutdown_slot)<=q->vmsize-(shutdown_va-q->vmaddr))matches++;
    }
    uint64_t slot=k->base+shutdown_va-k->virtual_base;
    if(matches!=1||!pwea_disjoint(slot,256,o->runtime.mailbox,PWMB_BYTES)||!pwkr_identity(slot,256)||
       !pwkr_cache(slot,128,0)||!pwmb_zero((const void*)(uintptr_t)slot,128)||!pwwn_live(w))return 0;
    s->worker=(uintptr_t)w;s->parent=(uintptr_t)p;s->owner=(uintptr_t)o;s->slot=slot;s->opening=o->opening;
    if(!pwof_begin(&s->policy,o->last,o->current.cpu.frequency))return pwno_fail(s,1);
    w->retirement=(uintptr_t)s;pweh_digest(w,sizeof(*w),s->worker_digest);s->ready=1;
    return pwno_live(s)?1:pwno_fail(s,1);
}
static inline void pwno_seal(const struct pwno_state*s,uint8_t hash[32])
{
    struct pwfi_sha256 h;pwfi_init(&h);const uint8_t*p=(const void*)s;
    for(unsigned n=0;n<sizeof(*s);n++){
        pwfi_byte(&h,n>=offsetof(struct pwno_state,raw)&&
            n<offsetof(struct pwno_state,raw)+sizeof(s->raw)?0:p[n]);
    }
    pwfi_final(&h,hash);
}
/*1 work/wait;negative sticky retained failure. No successful return exists. */
static inline int pwno_step(struct pwno_state*s)
{
    if(!s)return -1;if(!pwno_live(s)||s->pending)return pwno_fail(s,2);
    struct pmsc_owner*o=(void*)(uintptr_t)s->owner;
    int next=pwof_next(&s->policy,o->last,&s->command);
    if(next<0)return pwno_fail(s,3);if(!next)return 1;
    s->pending=1;const struct pwof_command*c=&s->command;int ok=0;s->raw=0;
    if(c->kind==PWOF_STATUS)ok=pwno_read_status(s);
    else if(c->kind==PWOF_PUBLISH){
        /* Host line is still untouched; publish sequence last. The kernel
         * owns a different128B line and may progress immediately afterwards. */
        if(pwno_live(s)&&pwkr_cache(s->slot,128,0)&&pwmb_zero((const void*)(uintptr_t)s->slot,128)){
            volatile struct polaris_shutdown_request*q=(void*)(uintptr_t)s->slot;
            q->cookie=s->policy.request.cookie;q->mode=2;
            __atomic_store_n(&q->sequence,1,__ATOMIC_RELEASE);
            ok=pwkr_cache(s->slot,128,1)&&pwno_live(s);
        }
    }else if(c->kind==PWOF_PSCI||c->kind==PWOF_POWER_OFF){
        if(c->phase>=PWOF_PEERS&&(!pwno_read_status(s)||
           !pwof_same(&s->sample,&s->policy.drained,sizeof(s->sample))))return pwno_fail(s,4);
        if(!pwno_live(s))return pwno_fail(s,4);
        uint8_t before[32],after[32],owner_before[32],owner_after[32];
        if(c->kind==PWOF_POWER_OFF){
            /* All memory/VMID/power ownership remains retained. Success is
             * terminal power-off, not a returned cleanup/handback grant. */
            s->off_issued=1;pwno_seal(s,before);pmsc_seal(o,0,0,owner_before);
            s->raw=pwno_smc(c->function,c->argument);
            pwno_seal(s,after);pmsc_seal(o,0,0,owner_after);
            s->off_returned=1;
            if(!pgcd_equal(before,after,32)||!pgcd_equal(owner_before,owner_after,32))return pwno_fail(s,5);
            (void)pwof_complete(&s->policy,c,o->last,1,s->raw,&s->sample);
            return pwno_fail(s,6);
        }
        pwno_seal(s,before);pmsc_seal(o,0,0,owner_before);
        s->raw=pwno_smc(c->function,c->argument);
        pwno_seal(s,after);pmsc_seal(o,0,0,owner_after);
        ok=pgcd_equal(before,after,32)&&pgcd_equal(owner_before,owner_after,32)&&pwno_live(s);
        if(ok&&c->phase==PWOF_PEERS)ok=pwno_read_status(s);
    }else return pwno_fail(s,4);
    if(!ok||!pwno_live(s))return pwno_fail(s,4);
    int done=pwof_complete(&s->policy,c,o->last,1,s->raw,&s->sample);
    if(done<0)return pwno_fail(s,7);s->pending=0;return 1;
}
#endif
#endif
