#ifndef POLARIS_LOG_BUDGET_H
#define POLARIS_LOG_BUDGET_H
#include <stdint.h>
#include <stdbool.h>

/* Fixed memory, no clock/locks/allocations or caller strings on the hot path.
 * Per selector: two successes; first four errors and powers of two thereafter.
 * Selectors outside the known range share a separate overflow bucket. The
 * counters saturate, so even a long-lived busy client cannot restart a flood.
 */
#define POLARIS_LOG_SELECTORS 256u
struct polaris_log_budget {
    uint32_t success[POLARIS_LOG_SELECTORS + 1];
    uint32_t error[POLARIS_LOG_SELECTORS + 1];
};
static inline uint32_t plog_tick(uint32_t *p)
{
    uint32_t n=__atomic_load_n(p,__ATOMIC_RELAXED);
    while (n!=UINT32_MAX) {
        if (__atomic_compare_exchange_n(p,&n,n+1,true,__ATOMIC_RELAXED,__ATOMIC_RELAXED)) {
            return n+1;
        }
    }
    return UINT32_MAX;
}
static inline bool
polaris_log_allow(struct polaris_log_budget *b, uint32_t selector, bool error)
{
    unsigned slot=selector<POLARIS_LOG_SELECTORS ? selector : POLARIS_LOG_SELECTORS;
    uint32_t n=plog_tick(error ? &b->error[slot] : &b->success[slot]);
    return error ? (n<=4 || (n && !(n & (n-1)))) : n<=2;
}
#endif
