/* Three physical keys only. Pure policy; this header performs no MMIO and
 * does not imply that a native or firmware hardware backend is installed.
 * GPIO specifiers on the original PM8998 are ONE-based physical IDs:
 * pinctrl-spmi-gpio.c at MiCode c7cb50c1, of_xlate/gpio_idx, not Linux pin_idx.
 */
#ifndef POLARIS_BUTTONS_H
#define POLARIS_BUTTONS_H
#include <stdbool.h>
#include <stdint.h>
#define POLARIS_BUTTON_POWER 1u
#define POLARIS_BUTTON_VOLUME_UP 2u
#define POLARIS_BUTTON_VOLUME_DOWN 4u
#define POLARIS_BUTTON_MASK 7u
#define POLARIS_BUTTON_DEBOUNCE_US UINT64_C(15000)
struct polaris_button_filter {
    uint64_t last_us, since_us[3];
    uint32_t candidate, stable, seen_released, initialized, fault;
};
struct polaris_button_change {uint32_t changed, pressed;};
/* PON RT: bit0 KPDPWR, bit1 RESIN. GPIO6 RT: bit0 level, active-low.
 * Identity/input/pull/enable/ownership must be checked by the real backend
 * before these status bytes may be passed here. */
static inline uint32_t polaris_button_levels(uint8_t pon_rt,uint8_t gpio6_rt)
{
    return ((pon_rt&1)?POLARIS_BUTTON_POWER:0) |
        ((pon_rt&2)?POLARIS_BUTTON_VOLUME_DOWN:0) |
        ((gpio6_rt&1)?0:POLARIS_BUTTON_VOLUME_UP);
}
static inline bool polaris_button_sample(struct polaris_button_filter *s,
    uint64_t now_us,bool sample_valid,uint32_t bits,struct polaris_button_change *out)
{
    if(!s || !out)return false;
    *out=(struct polaris_button_change){0,0};
    if(s->fault)return false;
    if(!sample_valid || !now_us || (bits&~POLARIS_BUTTON_MASK) ||
        (s->initialized && now_us<=s->last_us)) {
        /* Release only states we actually delivered. Never invent a press or
         * resume after an ambiguous read/clock/owner failure. */
        out->changed=s->stable;out->pressed=0;
        s->stable=0;s->fault=1;return false;
    }
    s->last_us=now_us;
    if(!s->initialized) {
        s->initialized=1;s->candidate=bits;
        for(unsigned n=0;n<3;n++)s->since_us[n]=now_us;
        return true;
    }
    uint32_t before=s->stable;
    for(unsigned n=0;n<3;n++) {
        uint32_t mask=1u<<n;
        if((bits^s->candidate)&mask) {
            s->candidate^=mask;s->since_us[n]=now_us;
        }else if(now_us-s->since_us[n]>=POLARIS_BUTTON_DEBOUNCE_US) {
            if(!(bits&mask)) {
                s->seen_released|=mask;s->stable&=~mask;
            }else if(s->seen_released&mask)s->stable|=mask;
        }
    }
    out->changed=before^s->stable;out->pressed=s->stable;
    return true;
}
#endif
