/* Current event/timer DATA captured at the real incoming-contract caller.
 * This is never a future IRQ/owner/ABA lease or postrelease map qualification. */
#ifndef POLARIS_UEFI_WIFI_CACHE_TIMER_GRAPH_H
#define POLARIS_UEFI_WIFI_CACHE_TIMER_GRAPH_H
#include "uefi-wifi-cache-release.h"
#define PBHT_AT_MAX (2u*(PWMC_EVENT_MAX+PWMC_TIMER_MAX+1u))
#define PBHT_CLOCK_MAX (PBHT_AT_MAX+2u)
struct pbhi_result;
struct pbht_input {
    struct pbhr_live*caller;struct pbhr_result*witness;const struct pbhr_input*original;
    const struct pbhi_result*provider;const void*deferred;const void*timer;uint8_t service_seal[32];
};
struct pbht_result {
    struct pbht_input input;struct pbhr_live live_before;uint64_t opening,virtual_before;
    struct pwmc_event_path events;struct pwmc_timer_path timers;
    struct ppli_at AT[PBHT_AT_MAX];struct pbgi_clock clock[PBHT_CLOCK_MAX];
    uint32_t attempted,complete,unknown,error,AT_count,arch_issued,arch_returned,refusal_timer;
    uint8_t digest[32];
};
_Static_assert(sizeof(struct pbht_input)==80&&sizeof(struct pbht_result)==86616,"separate complete current timer graph input ABI");
_Static_assert(offsetof(struct pbht_result,events)==456&&offsetof(struct pbht_result,timers)==19000&&offsetof(struct pbht_result,AT)==27048&&offsetof(struct pbht_result,clock)==45080&&offsetof(struct pbht_result,digest)==86584,"independent graph input decoder offsets");
static inline void pbht_digest(const struct pbht_result*r,uint8_t out[32])
{ppli_sha(r,offsetof(struct pbht_result,digest),out);}
#endif
