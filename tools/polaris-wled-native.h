/* Native display-workloop adapter. Caller owns the display lock; no separate
 * thread, PMIC access, allocation, reset or unverified frame acknowledgement.
 * The kernel profile includes these exact bytes as a private implementation
 * header. cache() MUST clean only native's line / invalidate only FW's line.
 */
#ifndef POLARIS_WLED_NATIVE_H
#define POLARIS_WLED_NATIVE_H
#include "polaris-wled-mailbox.h"
struct polaris_wled_native_adapter {
    struct polaris_wled_native state;
    struct polaris_wled_slot *slot;
    void (*cache)(void *,bool);
    uint64_t began_us;
    bool enabled;
};
static inline bool pwn_init(struct polaris_wled_native_adapter *a,
    struct polaris_wled_slot *slot,void (*cache)(void *,bool),bool enabled)
{
    if(!a||a->slot||a->cache||a->enabled||a->began_us||a->state.cookie||a->state.error)
        return false;
    if(!enabled)return true;
    if(!slot||!cache||((uintptr_t)slot&127))return false;
    const uint8_t *initial=(const uint8_t *)&slot->native;
    if(!pwm_zero(initial,sizeof(slot->native)))return false;
    a->slot=slot;a->cache=cache;a->enabled=true;
    /* Native BSS initialization precedes FW advertisement. This canonical
     * sequence-zero sentinel cannot request a device transition. */
    a->slot->native.on=1;
    a->cache(&a->slot->native,true);
    __atomic_store_n(&a->slot->native.cookie,PWM_NATIVE_START,__ATOMIC_RELEASE);
    a->cache(&a->slot->native,true);return true;
}
/* A boot advertisement uses READY-last, later acknowledgements SEQUENCE-last.
 * Always acquire then copy the entire independently owned128-byte line.
 * Never write FW's cacheline or use a partially copied acknowledgement. */
static inline bool pwn_exchange(struct polaris_wled_native_adapter *a,bool on,uint64_t now)
{
    if(!a||!a->enabled)return false;
    struct polaris_wled_native *n=&a->state;
    if(n->error)return false;
    if(!now||(a->began_us&&now<a->began_us))return pwm_native_fail(n,PWM_E_CLOCK);
    if(!a->began_us)a->began_us=now;
    a->cache(&a->slot->firmware,false);
    uint64_t ready=__atomic_load_n(&a->slot->firmware.ready,__ATOMIC_ACQUIRE);
    if(!ready&&!n->cookie) {
        if(now-a->began_us>=PWM_TIMEOUT_US)return pwm_native_fail(n,PWM_E_TIMEOUT);
        return false;
    }
    uint64_t sequence=__atomic_load_n(&a->slot->firmware.sequence,__ATOMIC_ACQUIRE);
    struct polaris_wled_ack ack;
    uint8_t *dst=(uint8_t *)&ack;
    const volatile uint8_t *src=(const volatile uint8_t *)&a->slot->firmware;
    for(unsigned i=0;i<sizeof(ack);i++)dst[i]=src[i];
    /* A publication may complete while this RAM copy runs. Defer that sample;
     * this is not a device-command retry and never consumes/ACKs partial data. */
    if(ack.ready!=ready||ack.sequence!=sequence)return false;
    if(ready!=PWM_READY)return pwm_native_fail(n,PWM_E_WIRE);
    if(!n->cookie) {
        if(!pwm_native_init(n,&ack,now))return pwm_native_fail(n,PWM_E_WIRE);
    } else {
        if(ack.cookie!=n->cookie||!pwm_zero(ack.reserved,sizeof(ack.reserved)))
            return pwm_native_fail(n,PWM_E_WIRE);
        if(ack.sequence!=n->acknowledged||(!n->inflight&&ack.error)) {
            if(!pwm_native_ack(n,&ack,now))return false;
        }
    }
    if(!pwm_native_tick(n,now)||!pwm_native_intent(n,on))return false;
    struct polaris_wled_request request;
    if(pwm_native_next(n,now,&request)) {
        /* Body first, clean, release sequence LAST, clean. Do not memcpy the
         * sequence first: a cache eviction could publish an unfinished body. */
        a->slot->native.cookie=request.cookie;
        a->slot->native.on=request.on;a->slot->native.frame=request.frame;
        for(unsigned i=0;i<sizeof(request.reserved);i++)a->slot->native.reserved[i]=0;
        a->cache(&a->slot->native,true);
        __atomic_store_n(&a->slot->native.sequence,request.sequence,__ATOMIC_RELEASE);
        a->cache(&a->slot->native,true);
    }
    return !n->error;
}
static inline bool pwn_needs_frame(const struct polaris_wled_native_adapter *a)
{
    return a&&a->enabled&&a->state.cookie&&!a->state.error&&a->state.desired_on&&
        !a->state.actual_on&&!a->state.inflight&&a->state.last_frame<=a->state.off_frame;
}
/* Invoke only after actual accepted panel writes and the caller's DSB, never
 * on swap submission, timer notification, busy/skipped surface or black fill. */
static inline bool pwn_presented(struct polaris_wled_native_adapter *a)
{
    if(!a||!a->enabled||!a->state.cookie||a->state.error)return false;
    if(a->state.last_frame==UINT64_MAX)return pwm_native_fail(&a->state,PWM_E_FRAME);
    return pwm_native_presented(&a->state,a->state.last_frame+1);
}
#endif
