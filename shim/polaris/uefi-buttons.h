/* Included by the resident loader after its cache/identity helpers. Physical
 * reads remain on firmware CPU0, serialized between polled USB operations. */
#ifndef POLARIS_EFI_BUTTONS_H
#define POLARIS_EFI_BUTTONS_H
#include "../../tools/polaris-buttons.h"
#include "../../tools/polaris-uefi-buttons.h"
#include "uefi-buttons-spmi.h"
static uint64_t buttons_last_poll,buttons_last_publish;
static unsigned buttons_started,buttons_terminal;
#if defined(POLARIS_EFI_TEST_QEMU)
static unsigned buttons_qemu_passed;
#else
static struct polaris_button_filter buttons_filter;
static struct polaris_button_bus buttons_bus;
static uint32_t buttons_queue[16],buttons_head,buttons_count;
#endif
static uint64_t buttons_us(void *context)
{
    (void)context;uint64_t ticks,freq;
    __asm__ volatile("mrs %0,cntvct_el0":"=r"(ticks));
    __asm__ volatile("mrs %0,cntfrq_el0":"=r"(freq));
    if(!freq||freq>1000000000u)return 0;
    return ticks/freq*1000000u+(ticks%freq)*1000000u/freq;
}
#if !defined(POLARIS_EFI_TEST_QEMU)
static uint32_t buttons_rd(void *context,unsigned bank,uint32_t offset)
{
    (void)context;const uint64_t bases[]={0xc440000,0xc40a000,0xe600000};
    uint32_t value=*(volatile uint32_t *)(uintptr_t)(bases[bank]+offset);
    __asm__ volatile("dsb sy":::"memory");return value;
}
static void buttons_command(void *context,uint32_t offset,uint32_t value)
{
    (void)context;
    *(volatile uint32_t *)(uintptr_t)(UINT64_C(0xe600000)+offset)=value;
    __asm__ volatile("dsb sy":::"memory");
}
#endif
static volatile struct polaris_uefi_button_slot *buttons_slot(void)
{return (void *)(uintptr_t)(POLARIS_RAM_BASE+EFI_XNU_BUTTONS_OFFSET);}
static int buttons_publish(uint32_t pressed,uint64_t now,unsigned error)
{
    volatile struct polaris_uefi_button_slot *slot=buttons_slot();
    invalidate((uintptr_t)&slot->acknowledged,128);
    if(slot->ready!=POLARIS_BUTTONS_READY||slot->error||slot->acknowledged!=slot->request||
       slot->request>=UINT32_MAX||!now)return 0;
    slot->pressed=pressed;slot->sampled_us=now;slot->hardware_error=error;
    clean((uintptr_t)slot,128);
    __atomic_store_n(&slot->request,slot->request+1,__ATOMIC_RELEASE);
    clean((uintptr_t)slot,128);buttons_last_publish=now;return 1;
}
static void buttons_poll(void)
{
    if(!EFI_XNU_BUTTONS_AVAILABLE||load_state!=4||cpu_status||buttons_terminal)return;
    uint64_t now=buttons_us(0);
    if(!now||now<buttons_last_poll){buttons_terminal=1;return;}
    if(now-buttons_last_poll<10000)return;
    buttons_last_poll=now;
    volatile struct polaris_uefi_button_slot *slot=buttons_slot();
    invalidate((uintptr_t)&slot->acknowledged,128);
    if(slot->error){report("BUTTONS_KERNEL_STOP=",slot->error);buttons_terminal=1;return;}
    if(slot->ready!=POLARIS_BUTTONS_READY)return;
#if defined(POLARIS_EFI_TEST_QEMU)
    /* Actual native consumer fixture only, NEVER Qualcomm MMIO. */
    if(!buttons_started){buttons_started=1;buttons_publish(0,now,0);return;}
    static const unsigned states[]={1,3,7,6,4,0};static unsigned phase;
    if(now-buttons_last_publish<100000)return;
    if(phase<6&&buttons_publish(states[phase],now,0))phase++;
    else if(phase==6&&slot->request==7&&slot->acknowledged==7&&!slot->current&&slot->events==6){
        buttons_qemu_passed=1;phase++;
    }else if(phase>=7)buttons_publish(0,now,0);
#else
    if(!buttons_started) {
        uint64_t affinity,el,mask,group;
        __asm__ volatile("mrs %0,mpidr_el1":"=r"(affinity));
        __asm__ volatile("mrs %0,CurrentEL":"=r"(el));
        __asm__ volatile("mrs %0,DAIF":"=r"(mask));
        __asm__ volatile("mrs %0,ICC_IGRPEN1_EL1":"=r"(group));
        if((affinity&0xff00ffffffu)||el!=4||(mask&0x3c0)!=0x3c0||group||
           !identity_range(0xc440000,0x1100)||!identity_range(0xc40a000,0x1000)||
           !identity_range(0xe600000,0x10000)) {
            report("BUTTONS_FIRMWARE_OWNER_REFUSED=",1);
            buttons_bus.fault=PB_E_ARGUMENT;
        }else {
            buttons_bus=(struct polaris_button_bus){.read=buttons_rd,.read_command=buttons_command,.now_us=buttons_us};
            (void)pb_start(&buttons_bus);
        }
        buttons_started=1;
        report("BUTTONS_ARB_VERSION=",buttons_bus.version);
        report("BUTTONS_PON_APID=",buttons_bus.apid[0]);report("BUTTONS_GPIO6_APID=",buttons_bus.apid[1]);
        report("BUTTONS_PON_ID=",((unsigned)buttons_bus.pon_id[0]<<8)|buttons_bus.pon_id[1]);
        report("BUTTONS_GPIO_ID=",((unsigned)buttons_bus.gpio_id[0]<<8)|buttons_bus.gpio_id[1]);
        report("BUTTONS_GPIO_MODE_PULL_EN=",((unsigned)buttons_bus.gpio_config[0]<<16)|
            ((unsigned)buttons_bus.gpio_config[2]<<8)|buttons_bus.gpio_config[6]);
    }
    struct polaris_button_change change={0};uint8_t pon=0,gpio=0;
    bool valid=pb_levels(&buttons_bus,&pon,&gpio);
    if(valid&&!buttons_filter.initialized)report("BUTTONS_INITIAL_RT=",((unsigned)pon<<8)|gpio);
    if(!polaris_button_sample(&buttons_filter,now,valid,polaris_button_levels(pon,gpio),&change)) {
        /* Once the native consumer acknowledges, send one terminal release.
         * Until then its independent heartbeat deadline releases held keys. */
        unsigned error=buttons_bus.fault?buttons_bus.fault:PB_E_TIME;
        if(buttons_publish(0,now,error)) {
            report("BUTTONS_HARDWARE_STOP=",error);buttons_terminal=1;
        }
        return;
    }
    if(change.changed) {
        if(buttons_count==16) {
            buttons_bus.fault=PB_E_RESPONSE;return; /* sticky refusal, no lost edge */
        }
        buttons_queue[(buttons_head+buttons_count)%16]=change.pressed;buttons_count++;
        report("BUTTONS_PHYSICAL_CHANGED=",((uint64_t)change.changed<<32)|change.pressed);
    }
    if(buttons_count) {
        if(buttons_publish(buttons_queue[buttons_head],now,0)) {
            buttons_head=(buttons_head+1)%16;buttons_count--;
        }
    }else if(!slot->request||now-buttons_last_publish>=20000) {
        buttons_publish(buttons_filter.stable,now,0);
    }
#endif
}
#endif
