/* Shared native/FW WLED protocol policy. OFFLINE: no mapping/cache operations,
 * PMIC writes or frame presentation. Runtime adapters must independently admit
 * both sides, copy an acquire-published line, validate every reserved byte and
 * clean ONLY their own line. A boolean/token supplied here is not hardware
 * evidence. Native presented() may be called ONLY after actual panel copy+DSB.
 */
#ifndef POLARIS_WLED_MAILBOX_H
#define POLARIS_WLED_MAILBOX_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define PWM_READY UINT64_C(0x50574c4544310001)
#define PWM_NATIVE_START UINT64_C(0x50574c4e00010001)
#define PWM_TIMEOUT_US UINT64_C(2000000)
#ifdef __cplusplus
#define PWM_EMPTY {}
#else
#define PWM_EMPTY {0}
#endif
enum {PWM_E_WIRE=128,PWM_E_SEQUENCE,PWM_E_FRAME,PWM_E_CLOCK,PWM_E_TIMEOUT,
      PWM_E_CAPACITY,PWM_E_BACKEND};
struct polaris_wled_request {
    uint64_t cookie,sequence,on,frame;
    uint8_t reserved[96];
} __attribute__((aligned(128)));
struct polaris_wled_ack {
    uint64_t cookie,sequence,on,error,completed_us,records,ready;
    uint8_t reserved[72];
} __attribute__((aligned(128)));
struct polaris_wled_slot {
    struct polaris_wled_request native;
    struct polaris_wled_ack firmware;
} __attribute__((aligned(128)));
struct polaris_wled_native {
    uint64_t cookie,sequence,acknowledged,last_frame,off_frame,sent_us,last_us;
    uint64_t firmware_us,records;
    unsigned error,frozen_polls;
    bool desired_on,actual_on,inflight,sent_on;
};
struct polaris_wled_firmware {
    uint64_t cookie,sequence,off_frame,last_frame,last_us,records;
    unsigned error;
    bool actual_on,pending,target_on,closing,capacity_stop;
};
static inline bool pwm_zero(const uint8_t *p,size_t bytes)
{for(size_t n=0;n<bytes;n++)if(p[n])return false;return true;}
static inline bool pwm_native_start_ready(const struct polaris_wled_request *r)
{
    return r&&r->cookie==PWM_NATIVE_START&&!r->sequence&&r->on==1&&!r->frame&&
        pwm_zero(r->reserved,sizeof(r->reserved));
}
static inline bool pwm_native_fail(struct polaris_wled_native *n,unsigned error)
{if(n&&!n->error)n->error=error;return false;}
static inline bool pwm_firmware_fail(struct polaris_wled_firmware *f,unsigned error)
{if(f&&!f->error)f->error=error;return false;}
static inline bool pwm_native_time(struct polaris_wled_native *n,uint64_t now)
{
    if(!now||now<n->last_us)return pwm_native_fail(n,PWM_E_CLOCK);
    if(now==n->last_us) {
        if(++n->frozen_polls>=4096)return pwm_native_fail(n,PWM_E_CLOCK);
    } else n->frozen_polls=0;
    n->last_us=now;return true;
}
static inline bool pwm_native_init(struct polaris_wled_native *n,
    const struct polaris_wled_ack *a,uint64_t now)
{
    if(!n||!a||n->cookie||n->error||n->frozen_polls||n->sequence||n->acknowledged||n->last_frame||
       n->off_frame||n->sent_us||n->last_us||n->firmware_us||n->records||
       n->desired_on||n->actual_on||n->inflight||
       n->sent_on||!a->cookie||a->sequence||a->on!=1||a->error||a->ready!=PWM_READY||
       !a->completed_us||!a->records||!pwm_zero(a->reserved,sizeof(a->reserved))||!now)
        return false;
    n->cookie=a->cookie;n->desired_on=n->actual_on=true;n->last_us=now;
    n->firmware_us=a->completed_us;n->records=a->records;return true;
}
/* Run under the same native lock as framebuffer state and presented(). A
 * rapid latest intent changes no already-published request. */
static inline bool pwm_native_intent(struct polaris_wled_native *n,bool on)
{
    if(!n||!n->cookie||n->error)return false;
    if(n->desired_on&&!on)n->off_frame=n->last_frame;
    n->desired_on=on;return true;
}
static inline bool pwm_native_presented(struct polaris_wled_native *n,uint64_t frame)
{
    if(!n||!n->cookie||n->error)return false;
    if(!frame||frame<=n->last_frame)return pwm_native_fail(n,PWM_E_FRAME);
    n->last_frame=frame;return true;
}
static inline bool pwm_native_next(struct polaris_wled_native *n,uint64_t now,
    struct polaris_wled_request *out)
{
    if(!n||!out||!n->cookie||n->error||!pwm_native_time(n,now))return false;
    if(n->inflight||n->desired_on==n->actual_on)return false;
    if(n->desired_on&&n->last_frame<=n->off_frame)return false;
    if(n->sequence==UINT64_MAX)return pwm_native_fail(n,PWM_E_SEQUENCE);
    struct polaris_wled_request r=PWM_EMPTY;
    r.cookie=n->cookie;r.sequence=++n->sequence;r.on=n->desired_on;r.frame=n->last_frame;
    n->sent_on=n->desired_on;n->inflight=true;n->sent_us=now;*out=r;return true;
}
static inline bool pwm_native_ack(struct polaris_wled_native *n,
    const struct polaris_wled_ack *a,uint64_t now)
{
    if(!n||!a||!n->cookie||n->error||!pwm_native_time(n,now))return false;
    if(n->inflight&&now-n->sent_us>=PWM_TIMEOUT_US)
        return pwm_native_fail(n,PWM_E_TIMEOUT);
    if(!n->inflight||a->cookie!=n->cookie||a->sequence!=n->sequence||
       a->ready!=PWM_READY||a->on>1||a->completed_us<=n->firmware_us||
       a->records<n->records||(!a->error&&a->records==n->records)||
       !pwm_zero(a->reserved,sizeof(a->reserved)))return pwm_native_fail(n,PWM_E_WIRE);
    if(a->error)return pwm_native_fail(n,a->error==PWM_E_CAPACITY?
        PWM_E_CAPACITY:PWM_E_BACKEND);
    if(a->on!=(uint64_t)n->sent_on)return pwm_native_fail(n,PWM_E_WIRE);
    n->actual_on=n->sent_on;n->acknowledged=a->sequence;n->inflight=false;
    n->firmware_us=a->completed_us;n->records=a->records;
    /* Even a frame copied while OFF was outstanding is insufficient: require
     * another actual presentation AFTER consuming the OFF acknowledgement. */
    if(!n->actual_on)n->off_frame=n->last_frame;
    return true;
}
static inline bool pwm_native_tick(struct polaris_wled_native *n,uint64_t now)
{
    if(!n||!n->cookie||n->error||!pwm_native_time(n,now))return false;
    if(n->inflight&&now-n->sent_us>=PWM_TIMEOUT_US)
        return pwm_native_fail(n,PWM_E_TIMEOUT);
    return true; /* Timeout never acknowledges or retries a request. */
}
/* Invoke only after the backend's actual initial saved-state validation and
 * archival. Like complete(), this policy cannot itself establish that fact. */
static inline bool pwm_firmware_init(struct polaris_wled_firmware *f,uint64_t cookie,
    uint64_t records,uint64_t now,struct polaris_wled_ack *out)
{
    if(!f||!out||!cookie||!records||!now||f->cookie||f->sequence||f->off_frame||
       f->last_frame||f->last_us||f->records||f->error||
       f->actual_on||f->pending||f->target_on||f->closing||f->capacity_stop)return false;
    struct polaris_wled_ack a=PWM_EMPTY;a.cookie=cookie;a.on=1;a.ready=PWM_READY;
    a.completed_us=now;a.records=records;
    f->cookie=cookie;f->actual_on=true;f->records=records;f->last_us=now;*out=a;return true;
}
static inline bool pwm_firmware_request(struct polaris_wled_firmware *f,
    const struct polaris_wled_request *r)
{
    if(!f||!r||!f->cookie||f->error||f->closing||f->capacity_stop)return false;
    if(f->pending||r->cookie!=f->cookie||f->sequence==UINT64_MAX||
       !r->sequence||r->sequence!=f->sequence+1||r->on>1||
       !pwm_zero(r->reserved,sizeof(r->reserved))||r->on==(uint64_t)f->actual_on)
        return pwm_firmware_fail(f,PWM_E_SEQUENCE);
    if(r->frame<f->last_frame||(r->on&&r->frame<=f->off_frame))
        return pwm_firmware_fail(f,PWM_E_FRAME);
    if(!r->on)f->off_frame=r->frame;
    f->sequence=r->sequence;f->last_frame=r->frame;f->target_on=r->on;
    f->pending=true;return true;
}
/* Adapter calls this ONLY after PWP acknowledgement, independent readback,
 * full raw archive and no uncertainty. It is not a PMIC completion emulator. */
static inline bool pwm_firmware_complete(struct polaris_wled_firmware *f,
    bool actual_on,bool verified,uint64_t records,uint64_t now,struct polaris_wled_ack *out)
{
    if(!f||!out||!f->cookie||f->error)return false;
    if(!f->pending||!verified||actual_on!=f->target_on||records<=f->records||
       !now||now<=f->last_us)
        return pwm_firmware_fail(f,PWM_E_BACKEND);
    struct polaris_wled_ack a=PWM_EMPTY;a.cookie=f->cookie;a.sequence=f->sequence;
    a.on=actual_on;a.completed_us=now;a.records=records;a.ready=PWM_READY;
    f->actual_on=actual_on;f->pending=false;f->last_us=now;f->records=records;
    *out=a;return true;
}
/* Capacity is a refusal, never an OFF success or a hardware-error clear. The
 * runtime sequencer has issued NO command for this pending OFF. Its separate
 * terminal restore/readback gate remains mandatory and has reserved space. */
static inline bool pwm_firmware_capacity(struct polaris_wled_firmware *f,
    uint64_t records,uint64_t now,struct polaris_wled_ack *out)
{
    if(!f||!out||!f->cookie||f->error||f->closing||f->capacity_stop||!f->pending||
       f->target_on||!f->actual_on||!records||records<f->records||
       !now||now<=f->last_us)return false;
    struct polaris_wled_ack a=PWM_EMPTY;a.cookie=f->cookie;a.sequence=f->sequence;
    a.on=1;a.error=PWM_E_CAPACITY;a.completed_us=now;a.records=records;a.ready=PWM_READY;
    f->capacity_stop=true;f->pending=false;f->last_us=now;*out=a;return true;
}
/* Terminal restoration is deliberately NOT a display ON acknowledgement and
 * has no fresh-frame bypass in the native request ABI. A runtime adapter must
 * still complete PWP restore+new readbacks and the separate shutdown gate. */
static inline bool pwm_firmware_close(struct polaris_wled_firmware *f)
{if(!f||!f->cookie)return false;f->closing=true;return !f->error;}
#if defined(__cplusplus)
static_assert(sizeof(polaris_wled_request)==128,"native request ownership");
static_assert(sizeof(polaris_wled_ack)==128,"firmware ack ownership");
static_assert(offsetof(polaris_wled_slot,firmware)==128,"independent cachelines");
static_assert(sizeof(polaris_wled_slot)==256,"bounded WLED mailbox ABI");
#else
_Static_assert(sizeof(struct polaris_wled_request)==128,"native request ownership");
_Static_assert(sizeof(struct polaris_wled_ack)==128,"firmware ack ownership");
_Static_assert(offsetof(struct polaris_wled_slot,firmware)==128,"independent cachelines");
_Static_assert(sizeof(struct polaris_wled_slot)==256,"bounded WLED mailbox ABI");
#endif
#undef PWM_EMPTY
#endif
