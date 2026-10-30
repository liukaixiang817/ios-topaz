/* OFFLINE runtime sequencer component, deliberately NOT included by the EFI
 * image builder. No MMIO mapping, mailbox, image admission or reset operation.
 * Uses the unchanged fixed-address PWP writer. Caller supplies immutable,
 * exclusively owned RAM for EVERY raw observation; nothing wraps or overwrites.
 * Finite RAM is explicit: refuse a new OFF while still ON unless the whole
 * OFF/ON cycle AND terminal readbacks fit. Exhaustion does not clear a fault,
 * permit a write or prevent the already-reserved terminal ON restoration.
 */
#ifndef POLARIS_EFI_WLED_RUNTIME_H
#define POLARIS_EFI_WLED_RUNTIME_H
#include "uefi-wled-power.h"
#define PWR_MAX_RECORDS 65536u
#define PWR_OFF_RESERVE 32u
enum {PWR_E_ARGUMENT=96,PWR_E_REQUEST,PWR_E_ARCHIVE};
enum pwr_result {PWR_REFUSED,PWR_ACCEPTED,PWR_CAPACITY};
struct polaris_wled_runtime_record {
    struct polaris_wled_status_record raw;
    uint64_t sequence;
};
struct polaris_wled_runtime {
    struct polaris_wled_power *power;
    struct polaris_wled_runtime_record *records;
    uint32_t capacity,count,copied,error,final_first,final_last;
    bool pending,closing,exhausted,sealed;
};
static inline bool pwr_fail(struct polaris_wled_runtime *r,unsigned error)
{if(r&&!r->error)r->error=error;return false;}
static inline bool pwr_disjoint(const void *a,size_t an,const void *b,size_t bn)
{
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    return x&&y&&an<=UINTPTR_MAX-x&&bn<=UINTPTR_MAX-y&&
        (x+an<=y||y+bn<=x);
}
/* Copy failures and partial observations too. The active witness is not
 * retired here; a failed device transaction remains sticky in both objects. */
static inline bool pwr_archive(struct polaris_wled_runtime *r)
{
    struct polaris_wled_power *p=r->power;
    if(r->copied>p->witness.count||p->witness.count>PWS_RECORDS||
       r->count>r->capacity||p->witness.count-r->copied>r->capacity-r->count)
        return pwr_fail(r,PWR_E_ARCHIVE);
    while(r->copied<p->witness.count) {
        struct polaris_wled_runtime_record *dst=&r->records[r->count++];
        dst->raw=p->witness.record[r->copied++];dst->sequence=p->request;
    }
    return true;
}
static inline bool pwr_init(struct polaris_wled_runtime *r,
    struct polaris_wled_power *p,struct polaris_wled_runtime_record *records,
    uint32_t capacity)
{
    if(!r||!p||!records||capacity<64||capacity>PWR_MAX_RECORDS||
       (uintptr_t)records%_Alignof(struct polaris_wled_runtime_record))return false;
    size_t bytes=(size_t)capacity*sizeof(*records);
    if(!pwr_disjoint(records,bytes,r,sizeof(*r))||
       !pwr_disjoint(records,bytes,p,sizeof(*p))||
       !pwr_disjoint(r,sizeof(*r),p,sizeof(*p))||!p->bus||
       !pwr_disjoint(records,bytes,p->bus,sizeof(*p->bus))||
       !pwr_disjoint(r,sizeof(*r),p->bus,sizeof(*p->bus)))return false;
    if(r->power||r->records||r->capacity||r->count||r->copied||r->error||
       r->final_first||r->final_last||r->pending||r->closing||r->exhausted||r->sealed||
       p->error||p->witness.error||p->witness.count!=2||p->request||p->acknowledged||
       p->issued||p->completed||p->uncertain||p->phase!=PWP_ON||
       !p->actual_on||!p->desired_on||p->status_policy!=PWP_OEM_STATUS_WITNESS)
        return false;
    r->power=p;r->records=records;r->capacity=capacity;
    return pwr_archive(r);
}
/* Ordinary request admission. No same-state requests and no replacement of an
 * outstanding operation: coalescing belongs to the native display producer.
 * 10 OFF +12 ON +2 independent restored +4 final-gate reads =28 observations.
 * Reserve32 conservatively before OFF; faults stop earlier and retain partials.
 */
static inline enum pwr_result pwr_request(struct polaris_wled_runtime *r,
    uint64_t sequence,bool on)
{
    if(!r||!r->power||r->error||r->power->error||r->closing||r->sealed)
        return PWR_REFUSED;
    struct polaris_wled_power *p=r->power;
    if(r->pending||p->request==UINT64_MAX||sequence!=p->request+1||
       on==p->actual_on) {pwr_fail(r,PWR_E_REQUEST);return PWR_REFUSED;}
    if(!on&&(r->exhausted||r->count>r->capacity||
        r->capacity-r->count<PWR_OFF_RESERVE)) {
        r->exhausted=true;return PWR_CAPACITY; /* Zero writes, still ON. */
    }
    if(!pwp_request(p,sequence,on))return PWR_REFUSED;
    r->pending=true;return PWR_ACCEPTED;
}
/* Terminal shutdown/lease/raw-reset intent, NOT an ON frame or native SAFE.
 * It only asks the serialized poller to restore. No retry follows any error. */
static inline bool pwr_close(struct polaris_wled_runtime *r)
{
    if(!r||!r->power||r->error||r->power->error||r->sealed)return false;
    r->closing=true;return true;
}
static inline bool pwr_poll(struct polaris_wled_runtime *r)
{
    if(!r||!r->power||r->error||r->sealed)return false;
    struct polaris_wled_power *p=r->power;
    if(p->error)return false;
    if(!r->pending&&r->closing&&!p->actual_on) {
        if(p->request==UINT64_MAX||!pwp_request(p,p->request+1,true))
            return pwr_fail(r,PWR_E_REQUEST);
        r->pending=true;
    }
    if(!r->pending)return true; /* No idle bus traffic/witness consumption. */
    bool ok=pwp_poll(p);
    if(!pwr_archive(r)||!ok)return false;
    if(p->acknowledged==p->request) {
        if(p->actual_on) {
            ok=pwp_restored(p);
            if(!pwr_archive(r)||!ok)return false;
            /* ALL raw records already copied, only after successful ON and
             * independent readback. Keep time, lifetime ORs, counters and ALL
             * sticky errors. Never reinitialize the PWP object or its policy. */
            if(r->copied!=p->witness.count||p->witness.error||p->uncertain)
                return pwr_fail(r,PWR_E_ARCHIVE);
            for(unsigned n=0;n<PWS_RECORDS;n++)
                p->witness.record[n]=(struct polaris_wled_status_record){0};
            p->witness.count=0;r->copied=0;
        }
        r->pending=false;
    }
    return true;
}
/* One-shot terminal gate: two NEW complete readback pairs. Their exact raw
 * archive boundaries are retained for a future firmware-native receipt.
 * This does not send a receipt, reset a CPU, prove VFS/peer-off or grant SAFE.
 */
static inline bool pwr_seal(struct polaris_wled_runtime *r)
{
    if(!r||!r->power||r->error||!r->closing||r->pending||r->sealed||
       r->power->error||!r->power->actual_on)return false;
    for(unsigned n=0;n<2;n++) {
        uint32_t before=r->count;
        bool ok=pwp_restored(r->power);
        if(!pwr_archive(r)||!ok)return false;
        if(r->count-before!=2)return pwr_fail(r,PWR_E_ARCHIVE);
        if(!n)r->final_first=r->count;
        else r->final_last=r->count;
    }
    r->sealed=true;return true;
}
_Static_assert(sizeof(struct polaris_wled_runtime_record)==32,"bounded raw RAM entry");
#endif
