/* First failing ORIGINAL live predicate, captured where it was evaluated.
 * No clock/register/owner re-read, callback, permission or retirement here. */
#ifndef POLARIS_WIFI_CPU_LIVE_DIAGNOSTICS_H
#define POLARIS_WIFI_CPU_LIVE_DIAGNOSTICS_H
#include <stdint.h>
enum pwrpc_live_reason {
    PWRPC_LIVE_NONE, PWRPC_LIVE_ARCH_CALLBACK, PWRPC_LIVE_EL,
    PWRPC_LIVE_MPIDR_LOCAL, PWRPC_LIVE_FREQUENCY, PWRPC_LIVE_EL_CHANGED,
    PWRPC_LIVE_MPIDR_CHANGED, PWRPC_LIVE_TTBR0, PWRPC_LIVE_TTBR1,
    PWRPC_LIVE_TCR, PWRPC_LIVE_SCTLR, PWRPC_LIVE_MAIR, PWRPC_LIVE_SRE,
    PWRPC_LIVE_DAIF, PWRPC_LIVE_GROUP1, PWRPC_LIVE_CPACR,
    PWRPC_LIVE_BEFORE_NORMAL, PWRPC_LIVE_NORMAL_AGE,
    PWRPC_LIVE_BEFORE_OPENING, PWRPC_LIVE_OPENING_AGE,
    PWRPC_LIVE_TPL, PWRPC_LIVE_BOOT, PWRPC_LIVE_TABLES,
    PWRPC_LIVE_TABLE_COUNT, PWRPC_LIVE_DS, PWRPC_LIVE_OWNER
};
struct pwrpc_live_diagnostic {
    uint32_t attempted,reason,call,masked;
    uint64_t opening_ticks,normal_ticks,failed_ticks;
    uint32_t arch_callback_ok,reserved;
};
_Static_assert(sizeof(struct pwrpc_live_diagnostic)==48,"complete first-live-failure record");
static inline int pwrpc_live_capture(struct pwrpc_live_diagnostic *d,unsigned reason,
    unsigned call,unsigned masked,uint64_t opening,uint64_t normal,
    uint64_t failed,unsigned arch_callback_ok)
{
    if(!d->attempted){
        d->reason=reason;d->call=call;d->masked=masked;
        d->opening_ticks=opening;d->normal_ticks=normal;d->failed_ticks=failed;
        d->arch_callback_ok=arch_callback_ok;d->attempted=1;
    }
    return 1; /* The ORIGINAL predicate failed; never an admission result. */
}
#endif
