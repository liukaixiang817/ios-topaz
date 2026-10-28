/* Resident firmware physical-input channel, separate from USB touch. Only
 * the three fixed keys are representable; no address/keycode or host sender.
 * Producer and consumer own distinct128-byte cache lines. */
#ifndef POLARIS_UEFI_BUTTONS_H
#define POLARIS_UEFI_BUTTONS_H
#include <stdbool.h>
#include <stdint.h>
#define POLARIS_BUTTONS_READY UINT64_C(0x504f4c415249534b)
#define POLARIS_BUTTONS_EXPIRE_US UINT64_C(750000)
struct polaris_uefi_button_slot {
    volatile uint64_t request,pressed,sampled_us,hardware_error;
    uint8_t producer_padding[96];
    volatile uint64_t acknowledged,ready,error,events,current;
    uint8_t consumer_padding[88];
} __attribute__((aligned(128)));
struct polaris_button_consumer {
    uint64_t sequence,sampled_us,received_us;
    uint32_t pressed,error;
};
struct polaris_button_delivery {uint32_t changed,pressed;};
static inline bool polaris_button_wire_fault(struct polaris_button_consumer *s,
    struct polaris_button_delivery *out,unsigned error)
{
    out->changed=s->pressed;out->pressed=0;s->pressed=0;s->error=error;return false;
}
/* Caller validates all reserved bytes and reads one acquire-published request
 * under the one-producer/one-consumer, one-outstanding-snapshot contract. */
static inline bool polaris_button_wire_apply(struct polaris_button_consumer *s,
    uint64_t request,uint64_t pressed,uint64_t sampled_us,uint64_t hardware_error,
    bool reserved_zero,uint64_t now_us,struct polaris_button_delivery *out)
{
    *out=(struct polaris_button_delivery){0,0};
    if(s->error)return false;
    if(!now_us||(s->received_us&&now_us<=s->received_us)||request!=s->sequence+1||
       request>UINT32_MAX||pressed>7||!sampled_us||sampled_us<=s->sampled_us||
       !reserved_zero||(!s->sequence&&pressed)||hardware_error>8||
       (hardware_error&&pressed))return polaris_button_wire_fault(s,out,1);
    if(hardware_error)return polaris_button_wire_fault(s,out,2);
    out->changed=s->pressed^(uint32_t)pressed;out->pressed=(uint32_t)pressed;
    s->pressed=(uint32_t)pressed;s->sequence=request;s->sampled_us=sampled_us;s->received_us=now_us;
    return true;
}
static inline bool polaris_button_wire_expire(struct polaris_button_consumer *s,
    uint64_t now_us,struct polaris_button_delivery *out)
{
    *out=(struct polaris_button_delivery){0,0};
    if(s->error)return false;
    if(s->received_us&&(now_us<s->received_us||now_us-s->received_us>=POLARIS_BUTTONS_EXPIRE_US))
        return polaris_button_wire_fault(s,out,3);
    return true;
}
_Static_assert(sizeof(struct polaris_uefi_button_slot)==256,"physical button mailbox ABI");
_Static_assert(__builtin_offsetof(struct polaris_uefi_button_slot,acknowledged)==128,"button cache ownership");
#endif
