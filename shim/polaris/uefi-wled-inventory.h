/* A short pre-XNU diagnostic only. Never touches a PMIC write channel.
 * Current build mode compiles out CPU_ON and remains under resident USB.
 */
#ifndef POLARIS_EFI_WLED_INVENTORY_H
#define POLARIS_EFI_WLED_INVENTORY_H
#include "uefi-wled-readonly.h"
static unsigned wled_inventory_attempted;
#if defined(EFI_XNU_WLED_FAULT_WATCH)
#include "uefi-wled-fault-watch.h"
static struct polaris_wled_fault_watch wled_fault_watch;
static unsigned wled_fault_watch_reported,wled_fault_watch_source_error;
static void wled_fault_watch_poll(void)
{
    polaris_wled_fault_watch_poll(&wled_fault_watch);
    if(!wled_inventory_attempted||!wled_fault_watch.done||wled_fault_watch_reported)return;
    wled_fault_watch_reported=1;
    report("WH_VERSION=",1);report("WH_SOURCE_REFUSAL=",wled_fault_watch_source_error);
    report("WH_SAMPLES=",wled_fault_watch.count);report("WH_ERROR=",wled_fault_watch.error);
    report("WH_COMPLETE=",!wled_fault_watch.error&&wled_fault_watch.count==PWF_SAMPLES);
    report("WH_FAULT_OR=",wled_fault_watch.fault_or);report("WH_RT_OR=",wled_fault_watch.rt_or);
    report("WH_ENABLE_XOR=",wled_fault_watch.enable_xor);report("WH_READS=",wled_fault_watch.bus.reads);
    report("WH_PARTIAL_VALID=",wled_fault_watch.partial_valid);
    const struct polaris_wled_fault_sample *p=&wled_fault_watch.partial;
    report("WH_PARTIAL_WORD=",p->first|((uint32_t)p->after<<8)|((uint32_t)p->rt<<16)|((uint32_t)p->enable<<24));
    for(unsigned n=0;n<wled_fault_watch.count;n++) {
        char label[16]="WH_S00_AT=";label[4]=(char)('0'+n/10);label[5]=(char)('0'+n%10);
        const struct polaris_wled_fault_sample *s=&wled_fault_watch.samples[n];
        report(label,((uint64_t)s->began_us<<32)|s->ended_us);
        bytes_copy(label+7,"WORD=",6);
        report(label,s->first|((uint32_t)s->after<<8)|((uint32_t)s->rt<<16)|((uint32_t)s->enable<<24));
    }
    text("WH_WATCH_HOLD: READ_ONLY NO_WRITER_PERMISSION\r\n");
}
#endif
#if defined(POLARIS_EFI_TEST_QEMU)
struct wled_mock {uint32_t command,offset,commands,error;uint64_t clock;};
static struct wled_mock wled_mock_state;
#if defined(EFI_XNU_TEST_WLED_FAULT_PULSE)
static unsigned wled_mock_fault_pulses;
#endif
static uint32_t wled_mock_read(void *context,unsigned bank,uint32_t offset)
{
    struct wled_mock *s=context;
    if(bank==PW_CORE) {
        if(!offset)return 0x50000000;
        if(offset==0x900+7*4)return 0x3d800;
        if(offset==0x900+9*4)return 0x3d900;
        return 0;
    }
    if(bank==PW_CONFIG)return 0;
    if(bank!=PW_OBSERVER||offset<s->offset){s->error=1;return 2;}
    uint32_t local=offset-s->offset;
    if(local==8) {
#if defined(EFI_XNU_TEST_WLED_READ_FAILURE)
        if(s->commands==5)return 2;
#endif
        return s->error?2:1;
    }
    if(local!=0x18&&local!=0x1c){s->error=2;return 0;}
    uint32_t reg=(s->command>>4)&255,value=0;
    for(unsigned n=0;n<4;n++)value|=((reg+n+(local==0x1c?4:0))&255)<<(8*n);
#if defined(EFI_XNU_TEST_WLED_FAULT_PULSE)
    if(reg==8&&local==0x18)value=(value&~255u)|(wled_mock_fault_pulses&1);
#endif
    return value;
}
static void wled_mock_command(void *context,uint32_t offset,uint32_t value)
{
    struct wled_mock *s=context;
    if((offset!=7*0x80&&offset!=9*0x80)||(value>>27)!=1||(value&0x07fff008))s->error=3;
    s->command=value;s->offset=offset;s->commands++;
#if defined(EFI_XNU_TEST_WLED_FAULT_PULSE)
    if(((value>>4)&255)==8)wled_mock_fault_pulses++;
#endif
}
static uint64_t wled_mock_clock(void *context)
{return ++((struct wled_mock *)context)->clock;}
#endif
static uint64_t wled_pack(const uint8_t *bytes,unsigned count)
{
    uint64_t value=0;for(unsigned n=0;n<count;n++)value|=(uint64_t)bytes[n]<<(8*n);
    return value;
}
static unsigned wled_inventory_probe(void)
{
    if(wled_inventory_attempted)return PW_E_ARGUMENT;
    wled_inventory_attempted=1;
    struct polaris_wled_read_bus bus={0};struct polaris_wled_snapshot s={0};
#if defined(POLARIS_EFI_TEST_QEMU)
    bus.context=&wled_mock_state;bus.read=wled_mock_read;
    bus.read_command=wled_mock_command;bus.now_us=wled_mock_clock;
    report("WLED_MOCK_BACKEND=",1);
#else
    uint64_t affinity,el,mask,group;
    __asm__ volatile("mrs %0,mpidr_el1":"=r"(affinity));
    __asm__ volatile("mrs %0,CurrentEL":"=r"(el));
    __asm__ volatile("mrs %0,DAIF":"=r"(mask));
    __asm__ volatile("mrs %0,ICC_IGRPEN1_EL1":"=r"(group));
    if((affinity&0xff00ffffffu)||el!=4||(mask&0x3c0)!=0x3c0||group||
       !identity_range(0xc440000,0x1100)||!identity_range(0xc40a000,0x1000)||
       !identity_range(0xe600000,0x10000))return PW_E_ARGUMENT;
    bus.read=buttons_rd;bus.read_command=buttons_command;bus.now_us=buttons_us;
#endif
    bool valid=polaris_wled_inventory(&bus,&s);
#if defined(EFI_XNU_WLED_FAULT_WATCH)
    wled_fault_watch_source_error=bus.fault;
    polaris_wled_fault_watch_start(&wled_fault_watch,&bus,buttons_us);
#endif
    report("WLED_SNAPSHOT_FORMAT=",2);
    report("WLED_READONLY_VERSION=",bus.version);
    report("WLED_CTRL_APID_OWNER=",((uint64_t)bus.apid[0]<<32)|bus.owner[0]);
    report("WLED_SINK_APID_OWNER=",((uint64_t)bus.apid[1]<<32)|bus.owner[1]);
    report("WLED_CTRL_MAPPING=",bus.map[0]);report("WLED_SINK_MAPPING=",bus.map[1]);
    report("WLED_READ_COMMANDS=",bus.reads);
    if(!valid) {
        report("WLED_READ_FAILED_BANK_REG=",((uint64_t)bus.last_bank<<32)|bus.last_reg);
        report("WLED_READ_FAILED_STATUS_POLLS=",((uint64_t)bus.last_status<<32)|bus.last_polls);
        return bus.fault?bus.fault:PW_E_ARGUMENT;
    }
    report("WLED_CTRL_REVISION=",wled_pack(s.revision[0],8));
    report("WLED_SINK_REVISION=",wled_pack(s.revision[1],8));
    report("WLED_DISPLAY_READY_ENABLE=",wled_pack(s.ctrl,3));
    report("WLED_FAULT_RT=",wled_pack(s.faults,2));
    report("WLED_PSM_CONFIG=",wled_pack(s.psm,2));
    report("WLED_IRQ_ENABLE=",s.irq_enable);
    report("WLED_SINK_CONFIG=",wled_pack(s.sink,6));
    for(unsigned n=0;n<4;n++) {
        report("WLED_STRING_INDEX=",n);
        report("WLED_STRING_CONFIG=",wled_pack(s.string[n],7));
        report("WLED_STRING_LEVEL=",wled_pack(s.string[n]+7,2));
    }
    return 0;
}
#endif
