/* OFFLINE eligibility component, not a clock controller or hardware admission.
 * Consume complete own-TSENS observations, never host supplied temperatures.
 * The proposed conservative experiment limits below are NOT OEM trip values.
 * A caller must still retain ownership/quiescence, bounded run/cooldown, idle,
 * shutdown restoration and sticky DMA/protocol failure rules. No native caller
 * exists yet. Changing values are a liveness witness, not sensor freshness.
 */
#ifndef POLARIS_THERMAL_ELIGIBILITY_H
#define POLARIS_THERMAL_ELIGIBILITY_H
#include "polaris-tsens-readonly.h"
#define PTE_MAX_AGE_US UINT64_C(500000)
#define PTE_CHANGE_AGE_US UINT64_C(5000000)
#define PTE_RECOVER_US UINT64_C(10000000)
enum { PTE_ALLOW=0,PTE_WARMUP,PTE_REJECTED,PTE_STALE,PTE_FROZEN,
       PTE_HOT,PTE_COOLDOWN,PTE_CLOCK,PTE_STOPPED };
struct polaris_thermal_eligibility {
    uint64_t last_now_us,ended_us,warm_since_us,changed_us[6],not_before_us;
    int32_t previous_mC[6],gold_mC,gpu_mC;
    uint32_t consecutive,last_error,hot,stopped,clock_fault;
};
static inline void pte_clear_observation(struct polaris_thermal_eligibility *s)
{
    s->ended_us=s->warm_since_us=0;s->consecutive=0;
    for(unsigned i=0;i<6;i++)s->changed_us[i]=0;
}
static inline bool pte_clock(struct polaris_thermal_eligibility *s,uint64_t now)
{
    if(!s || s->clock_fault || !now || now<s->last_now_us ||
       now>UINT64_MAX-PTE_RECOVER_US) {
        if(s)s->clock_fault=1;
        return false;
    }
    s->last_now_us=now;return true;
}
static inline bool pte_sample_valid(const struct polaris_tsens_sample *p,
    uint64_t now)
{
    if(!p || !p->began_us || p->began_us>p->ended_us || p->ended_us>now ||
       p->ended_us-p->began_us>1000 || now-p->ended_us>PTE_MAX_AGE_US)return false;
    int32_t gold=-40000,gpu=-40000;
    for(unsigned i=0;i<6;i++) {
        int32_t a=0,b=0;
        if(polaris_tsens_decode(p->raw[0][i],&a) ||
           polaris_tsens_decode(p->raw[1][i],&b))return false;
        if(a-b>2000 || b-a>2000 || p->temperature_mC[i]!=(a>b?a:b))return false;
        if(i<4 && p->temperature_mC[i]>gold)gold=p->temperature_mC[i];
        if(i>=4 && p->temperature_mC[i]>gpu)gpu=p->temperature_mC[i];
    }
    return p->max_gold_mC==gold && p->max_gpu_mC==gpu;
}
static inline bool pte_observe(struct polaris_thermal_eligibility *s,
    const struct polaris_tsens_sample *p,unsigned error,uint64_t now)
{
    if(!s || s->stopped || !pte_clock(s,now))return false;
    if(error || !pte_sample_valid(p,now) || (s->ended_us && p->ended_us<=s->ended_us)) {
        s->last_error=error?error:PTS_ARGUMENT;
        pte_clear_observation(s);s->not_before_us=now+PTE_RECOVER_US;return false;
    }
    if(s->ended_us && p->ended_us-s->ended_us>PTE_MAX_AGE_US)
        pte_clear_observation(s);
    bool previous=s->ended_us!=0;
    for(unsigned i=0;i<6;i++) {
        if(previous && p->temperature_mC[i]!=s->previous_mC[i])s->changed_us[i]=p->ended_us;
        s->previous_mC[i]=p->temperature_mC[i];
    }
    if(!s->consecutive)s->warm_since_us=p->ended_us;
    if(s->consecutive<3)s->consecutive++;
    s->ended_us=p->ended_us;s->gold_mC=p->max_gold_mC;s->gpu_mC=p->max_gpu_mC;s->last_error=0;
    if(s->gold_mC>=75000 || s->gpu_mC>=60000) {
        s->hot=1;s->not_before_us=now+PTE_RECOVER_US;
    } else if(s->hot && s->gold_mC<=70000 && s->gpu_mC<=55000 && now>=s->not_before_us)
        s->hot=0;
    return true;
}
static inline unsigned pte_verdict(struct polaris_thermal_eligibility *s,uint64_t now)
{
    if(!s)return PTE_REJECTED;
    if(s->stopped)return PTE_STOPPED;
    if(!pte_clock(s,now))return PTE_CLOCK;
    if(s->last_error)return PTE_REJECTED;
    if(!s->ended_us || s->consecutive<3 || s->ended_us-s->warm_since_us<500000)return PTE_WARMUP;
    if(now-s->ended_us>PTE_MAX_AGE_US)return PTE_STALE;
    if(s->hot)return PTE_HOT;
    if(now<s->not_before_us)return PTE_COOLDOWN;
    for(unsigned i=0;i<6;i++)
        if(!s->changed_us[i] || now-s->changed_us[i]>PTE_CHANGE_AGE_US)return PTE_FROZEN;
    return PTE_ALLOW;
}
static inline void pte_stop(struct polaris_thermal_eligibility *s)
{if(s){s->stopped=1;pte_clear_observation(s);}}
#endif
