/* A short pre-XNU diagnostic only. Never touches a PMIC write channel.
 * Current build mode compiles out CPU_ON and remains under resident USB.
 */
#ifndef POLARIS_EFI_WLED_INVENTORY_H
#define POLARIS_EFI_WLED_INVENTORY_H
#include "uefi-wled-readonly.h"
static unsigned wled_inventory_attempted;
#if defined(POLARIS_EFI_TEST_QEMU)
struct wled_mock {uint32_t command,offset,commands,error;uint64_t clock;};
static struct wled_mock wled_mock_state;
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
    return value;
}
static void wled_mock_command(void *context,uint32_t offset,uint32_t value)
{
    struct wled_mock *s=context;
    if((offset!=7*0x80&&offset!=9*0x80)||(value>>27)!=1||(value&0x07fff008))s->error=3;
    s->command=value;s->offset=offset;s->commands++;
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
    report("WLED_SINK_CONFIG=",wled_pack(s.sink,6));
    for(unsigned n=0;n<4;n++) {
        report("WLED_STRING_INDEX=",n);
        report("WLED_STRING_CONFIG=",wled_pack(s.string[n],7));
        report("WLED_STRING_LEVEL=",wled_pack(s.string[n]+7,2));
    }
    return 0;
}
#endif
