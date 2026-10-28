/* Explicit bounded-kernel-core admission for a resident firmware USB server.
 * 0x100/0x700 are the phone's own DT small/big cores. 1/7 are their generic
 * QEMU affinity counterparts. Firmware CPU0 always remains reserved.
 * Default ABL boots keep the original physical/logical CPU0 requirement. */
#ifndef POLARIS_UEFI_CPU_H
#define POLARIS_UEFI_CPU_H
#include <stdint.h>
static inline int polaris_uefi_cpu_declared(uint32_t mode,uint32_t target,
    uint32_t count,uint32_t logical,uint32_t physical)
{
    if(mode!=1 || (target!=0x100 && target!=0x700 && target!=1 && target!=7) ||
        logical>=count || (count!=1 && count!=2 && count!=4)) return 0;
    if(count>1 && target!=0x700 && target!=7) return 0;
    uint32_t step=target==0x700?0x100:1;
    return physical==target-logical*step && physical!=0;
}
static inline int polaris_uefi_cpu_allowed(uint32_t mode,uint32_t target,
    uint32_t count,uint32_t logical,uint32_t physical,uint64_t actual)
{
    if(logical!=0 || !polaris_uefi_cpu_declared(mode,target,count,logical,physical))
        return 0;
    return physical==target && (actual&UINT64_C(0xffffff))==target;
}
/* The generic virt board declares PSCI HVC; the phone uses secure SMC.
 * Select only after the executing boot core matches its explicit trial.
 * Return -1 for an unbound caller, never probe the other conduit on failure. */
static inline int polaris_uefi_psci_conduit(uint32_t mode,uint32_t target,
    uint32_t count,uint64_t actual)
{
    if(!polaris_uefi_cpu_allowed(mode,target,count,0,target,actual)) return -1;
    return target==1 || target==7;
}
/* CPU_ON is a scheduler-thread operation: after the first peer comes online
 * the initiating thread may run on any declared XNU core. Accept only the
 * actual MPIDR of that bounded set; firmware CPU0 and foreign cores stay out.
 * Bootstrap/coordinator admission above remains strictly boot-core-only. */
static inline int polaris_uefi_psci_running_conduit(uint32_t mode,uint32_t target,
    uint32_t count,uint64_t actual)
{
    uint32_t physical=(uint32_t)(actual&UINT64_C(0xffffff));
    for(uint32_t logical=0;logical<4;logical++) {
        if(polaris_uefi_cpu_declared(mode,target,count,logical,physical))
            return target==1 || target==7;
    }
    return -1;
}
/* Read-only SD845 OSMv2 inventory. Source: this phone's own DT and MiCode
 * clk-cpu-osm.c c7cb50c18f812629b9620b2b8fa684bc40d82080. These pure helpers
 * never map/register-write, choose a performance state, or claim actual Hz. */
static inline int polaris_osm_ro_allowed(uint32_t flag,uint32_t mode,uint32_t target,
    uint32_t count,uint64_t actual,uint64_t midr,uint64_t timer,
    uint64_t dram_base,uint64_t dram_size,int compatible)
{
    return flag==1 && compatible==1 && target==0x700 && count==4 &&
        polaris_uefi_cpu_allowed(mode,target,count,0,target,actual) &&
        ((midr>>24)&0xff)==0x51 && ((midr>>4)&0xfff)==0x802 &&
        timer==19200000 && dram_base==UINT64_C(0x180000000) &&
        dram_size==UINT64_C(0xfc8a0000);
}
static inline uint64_t polaris_osm_lut_raw_hz(uint32_t word)
{
    return (word>>30)?UINT64_C(19200000)*(word&255):UINT64_C(300000000);
}
static inline uint64_t polaris_osm_lut_requested_hz(uint32_t word)
{
    uint32_t cores=(word>>16)&7;
    if(cores<1 || cores>4)return 0;
    uint64_t hz=polaris_osm_lut_raw_hz(word);
    return hz>=200000000 && hz<=3200000000 ? hz:0;
}
static inline uint32_t polaris_osm_lut_rows(const uint32_t *words)
{
    if(!words)return 0;
    for(uint32_t i=1;i<40;i++)
        if(polaris_osm_lut_raw_hz(words[i])==polaris_osm_lut_raw_hz(words[i-1]) &&
            ((words[i]>>16)&7)==((words[i-1]>>16)&7))return i;
    return 40;
}
static inline uint64_t polaris_osm_requested_hz(const uint32_t *words,uint32_t rows,uint32_t index)
{
    return words && rows && rows<=40 && index<rows ? polaris_osm_lut_requested_hz(words[index]):0;
}
/* Stock OSMv2 performance request, never PLL/voltage/thermal configuration.
 * Explicit RAM experiment only. Same clk_cpu_set_rate request/posted readback
 * as pinned MiCode c7cb50c1. Shared performance cluster only (CORE_DCVS=0).
 * A high request is bounded to30s, then10s at the saved request. */
struct polaris_cpu_perf_state {
    uint32_t lut[40], saved, target, current, fault, stopped;
    uint64_t high_since, cool_until, transitions;
};
struct polaris_cpu_perf_io {
    void *context;
    uint32_t (*read)(void *,uint32_t);
    void (*write_request)(void *,uint32_t);
    void (*barrier)(void *);
};
static inline int polaris_cpu_perf_init(struct polaris_cpu_perf_state *s,
    const uint32_t *lut,uint32_t enabled,uint32_t control,uint32_t saved)
{
    if(!s || !lut || enabled!=3 || control!=0 || saved!=0)return 0;
    uint32_t rows=polaris_osm_lut_rows(lut),target=0;uint64_t previous=0,best=0;
    if(rows!=27)return 0;
    for(uint32_t n=0;n<rows;n++) {
        uint32_t count=(lut[n]>>16)&7;uint64_t hz=polaris_osm_lut_requested_hz(lut[n]);
        if(!hz || hz<=previous || (n<=22?count!=4:count!=1))return 0;
        previous=hz;
        if(count==4 && hz<=UINT64_C(2649600000) && hz>best){best=hz;target=n;}
    }
    if(best!=UINT64_C(2649600000) || target!=22 ||
        polaris_osm_requested_hz(lut,rows,0)!=UINT64_C(825600000))return 0;
    for(uint32_t n=27;n<40;n++)if(lut[n]!=lut[26])return 0;
    for(uint32_t n=0;n<40;n++)s->lut[n]=lut[n];
    s->saved=saved;s->target=target;s->current=saved;s->fault=s->stopped=0;
    s->high_since=s->cool_until=s->transitions=0;return 1;
}
static inline int polaris_cpu_perf_same_table(struct polaris_cpu_perf_state *s,
    struct polaris_cpu_perf_io *io)
{
    if(io->read(io->context,0)!=3 || io->read(io->context,0xbc)!=0)return 0;
    for(uint32_t n=0;n<40;n++)if(io->read(io->context,0x110+n*32)!=s->lut[n])return 0;
    return 1;
}
static inline int polaris_cpu_perf_write(struct polaris_cpu_perf_state *s,
    struct polaris_cpu_perf_io *io,uint32_t target)
{
    if(target!=s->saved && target!=s->target){s->fault=4;return 0;}
    if(!polaris_cpu_perf_same_table(s,io)){s->fault=1;return 0;}
    uint32_t current=io->read(io->context,0x920);
    if(current!=s->current){s->fault=2;return 0;} /* Foreign requests are not overwritten. */
    if(current==target)return 1;
    io->write_request(io->context,target);io->barrier(io->context);
    (void)io->read(io->context,0); /* Posted-write readback, original driver sequence. */
    current=io->read(io->context,0x920);
    if(current!=target){s->fault=3;return 0;}
    s->current=current;++s->transitions;return 1;
}
static inline int polaris_cpu_perf_tick(struct polaris_cpu_perf_state *s,
    struct polaris_cpu_perf_io *io,uint64_t now,uint64_t activity)
{
    if(!s || !io || !io->read || !io->write_request || !io->barrier)return 0;
    if(s->stopped || s->fault)return 0;
    uint32_t desired=s->saved;
    if(s->high_since && (now<s->high_since || now-s->high_since>=UINT64_C(30000000000))) {
        s->cool_until=now+UINT64_C(10000000000);s->high_since=0;
    }
    if(now && activity && activity<=now && now-activity<=UINT64_C(250000000) && now>=s->cool_until) {
        desired=s->target;if(!s->high_since)s->high_since=now;
    } else if(now>=s->cool_until)s->high_since=0;
    /* Check the live request even without transitions; do not mask another owner. */
    if(io->read(io->context,0x920)!=s->current){s->fault=2;return 0;}
    return desired==s->current ? 1:polaris_cpu_perf_write(s,io,desired);
}
static inline int polaris_cpu_perf_stop(struct polaris_cpu_perf_state *s,
    struct polaris_cpu_perf_io *io)
{
    if(!s || !io || !io->read || !io->write_request || !io->barrier)return 0;
    s->stopped=1;
    /* Preserve a previous error, but still restore our known request if safe.
     * Refuse native reset if readback/ownership no longer proves restoration. */
    if(!polaris_cpu_perf_same_table(s,io))return 0;
    uint32_t current=io->read(io->context,0x920);
    if(current==s->saved){s->current=current;return 1;}
    if(current!=s->target || s->current!=s->target)return 0;
    return polaris_cpu_perf_write(s,io,s->saved);
}
#endif
