/* Resident CPU0 PMI8998 telemetry, serialized with original keys/WLED.
 * Optional exact-DT/symbol admission comes from the payload builder. Nothing
 * touches this native BSS slot before the actual native WLED startup exchange.
 * No charger write, firmware getter, IRQ clear, retry or independent worker. */
#ifndef POLARIS_EFI_BATTERY_NATIVE_H
#define POLARIS_EFI_BATTERY_NATIVE_H
#if !EFI_XNU_BATTERY_AVAILABLE || !defined(EFI_XNU_WLED_NATIVE_RUNTIME)
#error "Battery adapter requires its explicit guarded native WLED session"
#endif
#include "../../tools/polaris-battery-producer.h"
#if defined(POLARIS_EFI_TEST_QEMU)
static void pb_runtime_poll(void)
{
    static unsigned noted;
    if(!noted&&load_state==4) {
        noted=1;report("BATTERY_SOFTWARE_PHYSICAL_READS_COMPILED_OUT=",1);
    }
    /* The separate software acquisition fixtures test the producer. The
     * whole-kernel terminal model must never read Qualcomm physical MMIO. */
}
#else
static struct polaris_battery_producer pbat_runtime;
static unsigned pbat_runtime_started,pbat_runtime_stopped,pbat_maps_reported;
static unsigned pbat_reports;
static uint64_t pbat_last_sequence;
static void pbat_runtime_clean(void *address,unsigned bytes)
{clean((uintptr_t)address,bytes);}
static int pbat_runtime_scope(uint64_t *frequency)
{
    uint64_t affinity,el,mask,group;
    __asm__ volatile("mrs %0,mpidr_el1":"=r"(affinity));
    __asm__ volatile("mrs %0,CurrentEL":"=r"(el));
    __asm__ volatile("mrs %0,DAIF":"=r"(mask));
    __asm__ volatile("mrs %0,ICC_IGRPEN1_EL1":"=r"(group));
    __asm__ volatile("mrs %0,cntfrq_el0":"=r"(*frequency));
    report("BATTERY_SCOPE_AFFINITY=",affinity);report("BATTERY_SCOPE_EL=",el);
    report("BATTERY_SCOPE_DAIF=",mask);report("BATTERY_SCOPE_GROUP=",group);
    report("BATTERY_SCOPE_COUNTER_HZ=",*frequency);
    return !(affinity&UINT64_C(0xff00ffffff))&&el==4&&(mask&0x3c0)==0x3c0&&!group&&
        *frequency==UINT64_C(19200000)&&cache_line()<=128&&128%cache_line()==0&&
        identity_range(0xc440000,0x1100)&&identity_range(0xc40a000,0x1000)&&
        identity_range(0xe600000,0x10000)&&
        identity_range(POLARIS_RAM_BASE+EFI_XNU_BATTERY_OFFSET,256);
}
static void pbat_runtime_record(void)
{
    struct polaris_battery_bus *b=&pbat_runtime.bus;
    if(b->initialized&&!pbat_maps_reported) {
        pbat_maps_reported=1;report("BATTERY_ARB_VERSION=",b->version);
        for(unsigned i=0;i<PBAT_BANKS;i++) {
            report("BATTERY_BANK_INDEX=",i);report("BATTERY_BANK_APID=",b->apid[i]);
            report("BATTERY_BANK_MAP=",b->map[i]);report("BATTERY_BANK_OWNER=",b->owner[i]);
        }
    }
    if(pbat_runtime.sequence==pbat_last_sequence)return;
    pbat_last_sequence=pbat_runtime.sequence;
    if(pbat_reports++>=16)return; /* Bounded boot evidence, not periodic spam. */
    const struct polaris_battery_sample *s=pbat_runtime.slot;
    report("BATTERY_SAMPLE_SEQUENCE=",s->sequence);report("BATTERY_SAMPLE_VALID=",s->valid);
    report("BATTERY_SAMPLE_ERROR=",s->error);report("BATTERY_SAMPLE_BEGAN_US=",s->began_us);
    report("BATTERY_SAMPLE_ENDED_US=",s->sampled_us);report("BATTERY_SAMPLE_READS=",s->reads);
    report("BATTERY_SAMPLE_SPAN_LIMIT_US=",s->span_limit_us);
    report("BATTERY_SAMPLE_SOC=",(uint64_t)(int64_t)s->soc_percent);
    report("BATTERY_SAMPLE_UV=",(uint64_t)(int64_t)s->voltage_uv);
    report("BATTERY_SAMPLE_UA=",(uint64_t)(int64_t)s->current_ua);
    report("BATTERY_SAMPLE_CENTI_C=",(uint64_t)(int64_t)s->temperature_centi_c);
    report("BATTERY_SAMPLE_EXTERNAL_CHARGING_FULL=",(s->external<<16)|(s->charging<<8)|s->full);
    for(unsigned i=0;i<sizeof(s->raw);i+=8) {
        uint64_t raw=0;for(unsigned j=0;j<8;j++)raw|=(uint64_t)s->raw[i+j]<<(8*j);
        report("BATTERY_SAMPLE_RAW_OFFSET=",i);report("BATTERY_SAMPLE_RAW=",raw);
    }
}
static void pb_runtime_poll(void)
{
    if(pbat_runtime_stopped||load_state!=4||cpu_status||!wln_advertised||
       wln_closing_mode||wln_exit_active||wln_lease_recovery||wln_runtime.sealed||
       wln_power.error||wln_power.uncertain||wln_runtime.error||wln_firmware.error||
       wln_runtime.pending||wln_firmware.pending)return;
    /* Native cannot post a second request until it has accepted the first
     * ACK, including its actual firmware timestamp. Require that exchange as
     * well as the shared architectural counter frequency before telemetry. */
    if(wln_firmware.sequence<2)return;
    volatile struct polaris_wled_slot *wled=wln_slot();
    invalidate((uintptr_t)&wled->native,128);
    uint64_t sequence=__atomic_load_n(&wled->native.sequence,__ATOMIC_ACQUIRE);
    if(sequence!=wln_firmware.sequence)return; /* Give new OFF/ON priority. */
    if(!pbat_runtime_started) {
        pbat_runtime_started=1;uint64_t hz=0;
        if(!pbat_runtime_scope(&hz)||EFI_XNU_BATTERY_SPAN_LIMIT_US!=500000u) {
            pbat_runtime_stopped=1;report("BATTERY_RUNTIME_SCOPE_REFUSED=",1);return;
        }
        struct polaris_battery_sample *slot=(void *)(uintptr_t)(POLARIS_RAM_BASE+EFI_XNU_BATTERY_OFFSET);
        invalidate((uintptr_t)slot,sizeof(*slot));
        const volatile uint8_t *initial=(const volatile uint8_t *)slot;
        for(unsigned i=0;i<sizeof(*slot);i++)if(initial[i]) {
            pbat_runtime_stopped=1;report("BATTERY_RUNTIME_NONZERO_BSS_REFUSED=",i+1);return;
        }
        pbat_runtime.slot=slot;pbat_runtime.clean=pbat_runtime_clean;
        pbat_runtime.span_admitted=pbat_runtime.native_bss_complete=true;
        pbat_runtime.counter_domain_admitted=true;
        pbat_runtime.bus=(struct polaris_battery_bus){.read=buttons_rd,
            .read_command=buttons_command,.now_us=buttons_us,.counter_hz=hz,
            .cookie=wln_cookie^UINT64_C(0x4241545445525931),.admitted=true,
            .span_limit_us=EFI_XNU_BATTERY_SPAN_LIMIT_US};
        if(!pbat_runtime.bus.cookie)pbat_runtime.bus.cookie=1;
        report("BATTERY_RUNTIME_ADMITTED=",1);
    }
    /* One actual PMIC command at most per call; the parent calls this only
     * after servicing WLED. A partial sample retains its original deadline. */
    (void)pbat_producer_poll(&pbat_runtime);pbat_runtime_record();
    if(pbat_runtime.bus.fault) {
        pbat_runtime_stopped=1;report("BATTERY_RUNTIME_STICKY_STOP=",pbat_runtime.bus.fault);
        report("BATTERY_RUNTIME_LAST_BANK=",pbat_runtime.bus.last_bank);
        report("BATTERY_RUNTIME_LAST_REG=",pbat_runtime.bus.last_reg);
        report("BATTERY_RUNTIME_LAST_STATUS=",pbat_runtime.bus.last_status);
        report("BATTERY_RUNTIME_LAST_POLLS=",pbat_runtime.bus.last_polls);
    }
}
#endif
#endif
