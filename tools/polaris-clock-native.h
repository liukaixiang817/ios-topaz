/* Installed as bsd/dev/polaris_clock.h by profile0906. Included only by
 * polaris_touch.c: the existing resident thread is the sole consumer. */
#ifndef POLARIS_CLOCK_NATIVE_H
#define POLARIS_CLOCK_NATIVE_H
#include "polaris_clock_wire.h"
/* Firmware seeds this only after all payload segments have been copied and
 * zero-filled. Keep the slot file-backed, outside every BSS/common range, so
 * native BSS initialization cannot erase its before-CPU_ON boot cookie. */
struct polaris_clock_slot polaris_uefi_clock __attribute__((section("__DATA,__data")))={
    .firmware={.magic=PC_MAGIC}};
static bool pc_bound,pc_sealed;
static uint64_t pc_last_poll,pc_cookie,pc_sequence,pc_applied,pc_publish_revision;
/* A separate RAM backend for PE calendar resume. Values are atomics because
 * PEGetUTC may run concurrently with the serialized calendar writer. */
static uint64_t pc_ram_version,pc_ram_utc,pc_ram_ticks;
static uint64_t pc_counter(void)
{ uint64_t v;__asm__ volatile("isb\n\tmrs %0,cntvct_el0":"=r"(v)::"memory");return v; }
static uint64_t pc_frequency(void)
{ uint64_t v;__asm__ volatile("mrs %0,cntfrq_el0":"=r"(v));return v; }
static uint64_t pc_cache_line(void)
{
    uint64_t ctr;__asm__ volatile("mrs %0,ctr_el0":"=r"(ctr));
    return UINT64_C(4)<<((ctr>>16)&15);
}
static void pc_cache(uintptr_t address,bool clean)
{
    uint64_t line=pc_cache_line();
    /* 128B ownership units cannot share an actual cache line. */
    if(line>128 || !line)return;
    for(uintptr_t p=address&~(line-1);p<address+128;p+=line) {
        if(clean)__asm__ volatile("dc cvac,%0"::"r"(p):"memory");
        else __asm__ volatile("dc ivac,%0"::"r"(p):"memory");
    }
    __asm__ volatile("dsb sy":::"memory");
}
bool polaris_clock_ram_get(clock_sec_t *secs,clock_usec_t *usecs);
void polaris_clock_ram_set(clock_sec_t secs,clock_usec_t usecs);
void polaris_clock_poll(void);
void polaris_clock_seal(void);
bool polaris_clock_ram_get(clock_sec_t *secs,clock_usec_t *usecs)
{
    if(pc_frequency()!=PC_FREQUENCY)return false;
    for(unsigned attempt=0;attempt<3;attempt++) {
        uint64_t before=__atomic_load_n(&pc_ram_version,__ATOMIC_ACQUIRE);
        if(!before || (before&1))continue;
        uint64_t utc=__atomic_load_n(&pc_ram_utc,__ATOMIC_RELAXED);
        uint64_t ticks=__atomic_load_n(&pc_ram_ticks,__ATOMIC_RELAXED),now=pc_counter(),elapsed=0;
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        if(before!=__atomic_load_n(&pc_ram_version,__ATOMIC_RELAXED))continue;
        if(!pc_elapsed_us(ticks,now,&elapsed) || elapsed>=PC_MAX_UTC_US ||
           utc>=PC_MAX_UTC_US-elapsed)return false;
        utc+=elapsed;if(!pc_utc_valid(utc))return false;
        *secs=(clock_sec_t)(utc/1000000);*usecs=(clock_usec_t)(utc%1000000);return true;
    }
    return false;
}
void polaris_clock_ram_set(clock_sec_t secs,clock_usec_t usecs)
{
    /* Called by standard clock_set_calendar_microtime under settime_lock.
     * RAM only: deliberately no IOPlatformExpert RTC/NVRAM callback. */
    if((uint64_t)secs>=PC_MAX_UTC_US/1000000 || (uint64_t)usecs>=1000000 ||
       pc_frequency()!=PC_FREQUENCY)return;
    uint64_t utc=(uint64_t)secs*1000000+usecs;if(!pc_utc_valid(utc))return;
    uint64_t ram_revision=__atomic_load_n(&pc_ram_version,__ATOMIC_ACQUIRE);
    if((ram_revision&1) || ram_revision>UINT64_MAX-2 || !__atomic_compare_exchange_n(
       &pc_ram_version,&ram_revision,ram_revision+1,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))return;
    __atomic_store_n(&pc_ram_utc,utc,__ATOMIC_RELAXED);
    __atomic_store_n(&pc_ram_ticks,pc_counter(),__ATOMIC_RELAXED);
    __atomic_store_n(&pc_ram_version,ram_revision+2,__ATOMIC_RELEASE);
}
static void pc_publish(unsigned status,unsigned error,uint64_t utc,uint64_t ticks,uint64_t uncertainty)
{
    struct polaris_clock_status *s=&polaris_uefi_clock.kernel;
    __atomic_store_n(&s->revision,++pc_publish_revision,__ATOMIC_RELEASE);
    pc_cache((uintptr_t)s,true); /* Publish odd before changing payload in RAM. */
    s->magic=PC_MAGIC;s->cookie=pc_cookie;s->status=status;s->error=error;
    s->actual_utc_us=utc;s->actual_ticks=ticks;s->uncertainty_us=uncertainty;
    s->applied_count=pc_applied;s->frequency_hz=PC_FREQUENCY;
    __atomic_store_n(&s->sequence,pc_sequence,__ATOMIC_RELEASE);
    pc_cache((uintptr_t)s,true);
    __atomic_store_n(&s->revision,++pc_publish_revision,__ATOMIC_RELEASE);
    pc_cache((uintptr_t)s,true);
}
void polaris_clock_seal(void)
{
    /* Same resident thread, before reboot_kernel/VFS/CPU drain. No callback
     * or timer remains that could consume or publish after CPUs are sealed. */
    pc_sealed=true;
    if(pc_bound)pc_publish(PC_SEALED,PC_OK,0,pc_counter(),0);
}
void polaris_clock_poll(void)
{
    if(pc_sealed || pc_frequency()!=PC_FREQUENCY || pc_cache_line()>128)return;
    uint64_t now=pc_counter();if(!now)return;
    if(pc_last_poll && now<pc_last_poll) {
        pc_sealed=true;if(pc_bound)pc_publish(PC_SEALED,PC_BAD_COUNTER,0,now,0);return;
    }
    if(pc_last_poll && now-pc_last_poll<PC_FREQUENCY/10)return;
    pc_last_poll=now;
    if(!pc_bound && !polaris_ram_overlay_allowed())return;
    struct polaris_clock_request r;
    pc_cache((uintptr_t)&polaris_uefi_clock.firmware,false);
    uint64_t sequence=__atomic_load_n(&polaris_uefi_clock.firmware.sequence,__ATOMIC_ACQUIRE);
    memcpy(&r,&polaris_uefi_clock.firmware,sizeof(r));
    pc_cache((uintptr_t)&polaris_uefi_clock.firmware,false);
    if(sequence!=__atomic_load_n(&polaris_uefi_clock.firmware.sequence,__ATOMIC_ACQUIRE))return;
    if(!pc_bound) {
        if(r.magic!=PC_MAGIC || !r.cookie || r.sequence || r.utc_us || r.anchor_ticks ||
           r.uncertainty_us || r.frequency_hz!=PC_FREQUENCY || r.source!=PC_SOURCE_HOST_UTC)return;
        for(unsigned i=0;i<8;i++)if(r.reserved[i])return;
        pc_cookie=r.cookie;pc_bound=true;pc_publish(PC_READY,PC_OK,0,now,0);return;
    }
    if(r.sequence==pc_sequence)return;
    /* The producer can publish during the invalidation/copy above. Associate
     * admission with a counter sampled after that complete request, not the
     * earlier polling-budget timestamp. */
    now=pc_counter();
    uint64_t utc=0;unsigned error=pc_validate(&r,pc_cookie,pc_sequence,now,pc_frequency(),&utc);
    if(error) {
        if(r.sequence==pc_sequence+1 && pc_sequence<UINT32_MAX)pc_sequence=r.sequence;
        else pc_sealed=true;
        pc_publish(pc_sealed?PC_SEALED:PC_REJECTED,error,0,now,r.uncertainty_us);return;
    }
    /* Calendar adjustment only. Counter, mach_absolute_time and all device
     * age/freshness guards retain their original timebase and frequency. */
    clock_set_calendar_microtime((clock_sec_t)(utc/1000000),(clock_usec_t)(utc%1000000));
    clock_sec_t sec=0;clock_usec_t us=0;
    uint64_t before=pc_counter();clock_get_calendar_microtime(&sec,&us);uint64_t after=pc_counter();
    uint64_t actual=(uint64_t)sec*1000000+us,expected=0;
    error=pc_validate(&r,pc_cookie,pc_sequence,after,pc_frequency(),&expected);
    if(!error && (after<before || after-before>PC_FREQUENCY/100 ||
       !pc_utc_valid(actual) || pc_distance(actual,expected)>10000))error=PC_READBACK;
    pc_sequence=r.sequence;if(!error)pc_applied++;
    pc_publish(error?PC_REJECTED:PC_APPLIED,error,actual,before+(after-before)/2,r.uncertainty_us);
    printf("POLARIS CLOCK: host UTC seq=%llu status=%u error=%u uncertainty_us=%llu; RAM calendar only\n",
        pc_sequence,(unsigned)(error?PC_REJECTED:PC_APPLIED),error,r.uncertainty_us);
}
#endif
