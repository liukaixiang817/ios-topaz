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
#endif
