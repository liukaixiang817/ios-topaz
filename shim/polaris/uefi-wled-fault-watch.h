/* Bounded READ-only WLED FAULT/RT/enable timeline. Diagnostic only: it never
 * clears an earlier refusal, retries a writer, changes a PMIC register or
 * establishes health. Preserve BOTH fault reads, including disappearing bits.
 * Caller serializes the EE0 observer, owns the workspace and supplies time.
 */
#ifndef POLARIS_EFI_WLED_FAULT_WATCH_H
#define POLARIS_EFI_WLED_FAULT_WATCH_H
#include "uefi-wled-readonly.h"
#define PWF_SAMPLES 32u
#define PWF_INTERVAL_US UINT64_C(10000)
#define PWF_MAX_US UINT64_C(2000000)
struct polaris_wled_fault_sample {
    uint32_t began_us,ended_us;
    uint8_t first,after,rt,enable;
};
struct polaris_wled_fault_watch {
    struct polaris_wled_read_bus bus;
    struct polaris_wled_fault_sample samples[PWF_SAMPLES];
    struct polaris_wled_fault_sample partial;
    uint64_t started,previous,next;
    unsigned count,error,done,frozen,partial_valid;
    uint8_t fault_or,rt_or,enable_xor;
};
static inline void pwf_stop(struct polaris_wled_fault_watch *w,unsigned error)
{if(!w->error)w->error=error;w->done=1;}
static inline void polaris_wled_fault_watch_start(struct polaris_wled_fault_watch *w,
    const struct polaris_wled_read_bus *source,uint64_t (*clock_us)(void *))
{
    /* A distinct diagnostic reader. Original source->fault and power state
     * remain sticky and untouched. Do NOT pass this reader back to a writer. */
    if(!w||w->started||w->done)return;
    if(!source||!source->initialized||!clock_us||
       (source->fault&&source->fault!=PW_E_CHANGED)) {pwf_stop(w,PW_E_ARGUMENT);return;}
    w->bus=*source;w->bus.fault=0;w->bus.reads=0;
    w->bus.changed_byte_plus_one=0;w->bus.changed_first=w->bus.changed_after=0;
    w->bus.now_us=clock_us;
    w->started=clock_us(source->context);w->previous=w->started;w->next=w->started;
    if(!w->started)pwf_stop(w,PW_E_TIME);
}
static inline void polaris_wled_fault_watch_poll(struct polaris_wled_fault_watch *w)
{
    if(!w||w->done||!w->started)return;
    uint64_t now=w->bus.now_us(w->bus.context);
    if(now<w->previous||now-w->started>PWF_MAX_US) {pwf_stop(w,PW_E_TIME);return;}
    if(now==w->previous) {
        if(++w->frozen>=4096)pwf_stop(w,PW_E_TIME);
    } else w->frozen=0;
    w->previous=now;
    if(w->done||now<w->next)return;
    struct polaris_wled_fault_sample s={0};s.began_us=(uint32_t)(now-w->started);
    unsigned valid=0;
    bool ok=pw_read(&w->bus,0,8,&s.first,1);
    if(ok)valid|=1;
    /* Alternate the two middle reads to retain command-order witnesses.
     * No claim that the four values are simultaneous or a remote lock. */
    if(w->count&1) {
        ok=ok&&pw_read(&w->bus,0,0x46,&s.enable,1);if(ok)valid|=4;
        ok=ok&&pw_read(&w->bus,0,0x10,&s.rt,1);if(ok)valid|=2;
    } else {
        ok=ok&&pw_read(&w->bus,0,0x10,&s.rt,1);if(ok)valid|=2;
        ok=ok&&pw_read(&w->bus,0,0x46,&s.enable,1);if(ok)valid|=4;
    }
    ok=ok&&pw_read(&w->bus,0,8,&s.after,1);
    if(ok)valid|=8;
    w->partial=s;w->partial_valid=valid;
    /* Keep even an incomplete observation's fault bits. Partial raw words
     * never count as a complete sample or as clean hardware. */
    w->fault_or|=s.first|s.after;w->rt_or|=s.rt;
    if(!ok) {pwf_stop(w,w->bus.fault?w->bus.fault:PW_E_RESPONSE);return;}
    uint64_t end=w->bus.now_us(w->bus.context);
    if(end<now||end-w->started>PWF_MAX_US) {pwf_stop(w,PW_E_TIME);return;}
    s.ended_us=(uint32_t)(end-w->started);
    if(w->count)w->enable_xor|=s.enable^w->samples[0].enable;
    w->samples[w->count++]=s;
    if(w->count==PWF_SAMPLES){w->done=1;return;}
    w->previous=end;w->next=end+PWF_INTERVAL_US;
}
#endif
