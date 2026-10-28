/* Pure bounded experiment planner. Eligibility is produced from actual native
 * TSENS observations separately. Neither a plan nor a host ACK is an actual
 * request-state confirmation. Caller confirms only after the original HFI
 * ownership/quiescence/ACK/return/readback transaction has succeeded.
 * A thermal renewal cannot restart the120s hard budget. Only10s in a known
 * low request state opens a new budget. Original stock target and idle remain.
 */
#ifndef POLARIS_A630_THERMAL_PERFORMANCE_H
#define POLARIS_A630_THERMAL_PERFORMANCE_H
#include <stdint.h>
#include <stdbool.h>
#define A630_THERMAL_HIGH_NS UINT64_C(120000000000)
#define A630_THERMAL_COOL_NS UINT64_C(10000000000)
#define A630_THERMAL_IDLE_NS UINT64_C(250000000)
enum { AT_REQUEST=0,AT_UNCONFIRMED,AT_IDLE,AT_SENSOR,AT_HARD_LIMIT,AT_COOLING };
struct a630_thermal_state {
    uint64_t last_ns,cycle_since_ns,low_since_ns;
    uint32_t confirmed,high,cooling,reason,fault;
};
static inline bool a630_thermal_clock(struct a630_thermal_state *s,uint64_t now)
{
    if(!s || s->fault || !now || now<s->last_ns ||
       now>UINT64_MAX-A630_THERMAL_HIGH_NS) {
        if(s)s->fault=1;
        return false;
    }
    s->last_ns=now;return true;
}
static inline bool a630_thermal_confirm(struct a630_thermal_state *s,uint64_t now,
    uint32_t perf,uint32_t bus)
{
    if(!a630_thermal_clock(s,now))return false;
    if(!((perf==1 && bus==4)||(perf==4 && bus==8))){s->fault=1;return false;}
    bool high=perf==4;
    if(high) {
        /* A desired high request without a prior successful low observation
         * is never the beginning of an admitted experiment. */
        if(!s->confirmed || s->cooling){s->fault=1;return false;}
        if(!s->cycle_since_ns)s->cycle_since_ns=now;
        s->low_since_ns=0;
    } else if(!s->confirmed || s->high)s->low_since_ns=now;
    s->confirmed=1;s->high=high;return true;
}
static inline bool a630_thermal_plan(struct a630_thermal_state *s,uint64_t now,
    uint64_t activity,bool eligible,uint32_t *perf,uint32_t *bus)
{
    if(!perf || !bus || !a630_thermal_clock(s,now))return false;
    if(activity>now){s->fault=1;return false;}
    *perf=1;*bus=4;
    if(!s->confirmed){s->reason=AT_UNCONFIRMED;return true;}
    /* This is time in a confirmed-low request, not an idle/cooldown intent or
     * time since a failed transaction. Repeated low confirmations don't move it. */
    if(!s->high && s->low_since_ns && now-s->low_since_ns>=A630_THERMAL_COOL_NS) {
        s->cooling=0;s->cycle_since_ns=0;
    }
    if(s->cycle_since_ns && now-s->cycle_since_ns>=A630_THERMAL_HIGH_NS) {
        s->cooling=1;s->reason=AT_HARD_LIMIT;
    }
    if(s->cooling){s->reason=AT_COOLING;return true;}
    if(!eligible){s->reason=AT_SENSOR;return true;}
    if(!activity || now-activity>A630_THERMAL_IDLE_NS){s->reason=AT_IDLE;return true;}
    *perf=4;*bus=8;s->reason=AT_REQUEST;return true;
}
#endif
