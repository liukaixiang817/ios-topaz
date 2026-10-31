/* Parent-owned resident CPU0 adapter. No symbol lookup or hardware admission
 * occurs here. Before enabling, builder must bind/size/reserve the exact
 * polaris_uefi_battery symbol, establish that native BSS initialization has
 * completed, admit CNTVCT/CNTFRQ as a common domain, and admit the bus.
 * Poll on the existing resident service loop every 5 seconds. No extra CPU,
 * USB worker, boot service/getter/action, PMIC write or IRQ clearing. */
#ifndef POLARIS_BATTERY_PRODUCER_H
#define POLARIS_BATTERY_PRODUCER_H
#include "polaris-battery-readonly.h"
struct polaris_battery_producer {
    struct polaris_battery_bus bus;
    struct polaris_battery_sample *slot;
    void (*clean)(void *,unsigned);
    uint64_t sequence,last_poll_us;
    struct polaris_battery_transaction transaction;
    bool span_admitted,native_bss_complete,counter_domain_admitted;
};
static inline bool pbat_publish(struct polaris_battery_producer *p,
    const struct polaris_battery_sample *sample)
{
    if(!p||!sample||!p->span_admitted||!p->native_bss_complete||
       !p->counter_domain_admitted||!p->slot||!p->clean||
       ((uintptr_t)p->slot&127)||(p->sequence&1)||p->sequence>UINT64_MAX-2||
       sample->magic!=PBAT_MAGIC||sample->version!=PBAT_VERSION||sample->bytes!=sizeof(*sample)||
       !sample->cookie||sample->cookie!=p->bus.cookie||
       (sample->error&&sample->valid))return false;
    if(!p->sequence) {
        const volatile uint8_t *initial=(const volatile uint8_t *)p->slot;
        for(unsigned i=0;i<sizeof(*p->slot);i++)if(initial[i])return false;
    } else if(p->slot->sequence!=p->sequence||p->slot->magic!=PBAT_MAGIC||
        p->slot->cookie!=p->bus.cookie)return false;
    uint64_t odd=p->sequence+1,even=p->sequence+2;
    __atomic_store_n(&p->slot->sequence,odd,__ATOMIC_RELEASE);
    p->clean(p->slot,128);
    struct polaris_battery_sample s=*sample;s.sequence=odd;
    uint8_t *dst=(uint8_t *)p->slot;
    const uint8_t *src=(const uint8_t *)&s;
    for(unsigned i=0;i<sizeof(s);i++)dst[i]=src[i];
    p->clean(p->slot,sizeof(*p->slot));
    __atomic_store_n(&p->slot->sequence,even,__ATOMIC_RELEASE);
    p->clean(p->slot,128);p->sequence=even;return true;
}
static inline bool pbat_producer_poll(struct polaris_battery_producer *p)
{
    if(!p||!p->span_admitted||!p->native_bss_complete||!p->counter_domain_admitted||
       !p->bus.admitted||!p->bus.now_us)return false;
    uint64_t now=p->bus.now_us(p->bus.context);
    if(!now||now<p->last_poll_us)return pbat_fault(&p->bus,PBAT_E_CLOCK);
    if(!p->transaction.active) {
        if(p->last_poll_us&&now-p->last_poll_us<5000000)return true;
        p->last_poll_us=now;
        if(!pbat_transaction_begin(&p->bus,&p->transaction))
            return pbat_publish(p,&p->transaction.sample);
    }
    /* At most one PMIC command per service tick; caller gives critical WLED/
     * nativeONACK/reset work priority. Partial deadline survives all pauses. */
    if(!pbat_transaction_step(&p->bus,&p->transaction))return true;
    return pbat_publish(p,&p->transaction.sample);
}
#endif
