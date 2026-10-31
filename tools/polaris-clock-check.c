/* Portable software validation of the exact clock metadata producer/consumer
 * math. No physical PMIC/USB/kernel-clock/RTC evidence is implied. */
#include "polaris-clock-uefi.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
struct model { uint64_t ticks,frequency;unsigned clean,invalidate;uintptr_t address;size_t bytes; };
static uint64_t ticks(void *p){struct model *m=p;return m->ticks+=192;}
static uint64_t frequency(void *p){return ((struct model *)p)->frequency;}
static void clean(void *p,uintptr_t address,size_t bytes)
{struct model *m=p;m->clean++;m->address=address;m->bytes=bytes;}
static void invalidate(void *p,uintptr_t address,size_t bytes)
{struct model *m=p;(void)address;(void)bytes;m->invalidate++;}
static unsigned checks;
#define CHECK(x) do { assert(x);checks++; } while(0)
static void native_ready(struct polaris_clock_slot *s,uint64_t cookie)
{
    s->kernel=(struct polaris_clock_status){.magic=PC_MAGIC,.cookie=cookie,
        .status=PC_READY,.frequency_hz=PC_FREQUENCY,.revision=2};
}
int main(void)
{
    struct polaris_clock_slot slot;struct pc_fw fw={0};struct model m={.ticks=PC_FREQUENCY,.frequency=PC_FREQUENCY};
    struct pc_fw_io io={ticks,frequency,clean,invalidate,&m};uint8_t out[60];size_t count=0;
    CHECK(!pc_fw_prepare(&fw,&slot,7,&io,false));
    CHECK(pc_fw_prepare(&fw,&slot,7,&io,true));
    CHECK(!pc_fw_prepare(&fw,&slot,7,&io,true));
    CHECK(m.bytes==256 && !slot.kernel.magic && slot.firmware.cookie==7);
    CHECK(!pc_fw_command(&fw,"oem utc-status",14,out,&count));
    native_ready(&slot,7);
    CHECK(pc_fw_command(&fw,"oem utc-status",14,out,&count) && count==60 && !memcmp(out,"PCLSTA01",8));
    CHECK(!pc_fw_command(&fw,"oem utc-probe:00000000",22,out,&count));
    CHECK(pc_fw_command(&fw,"oem utc-probe:00000001",22,out,&count) && count==60);
    uint64_t anchor=fw.rx+(fw.tx-fw.rx)/2;char command[64];
    snprintf(command,sizeof(command),"oem utc-set:%08x:%016llx:%016llx:%08x",1,
        (unsigned long long)(PC_MIN_UTC_US+1000000),(unsigned long long)anchor,12000);
    CHECK(strlen(command)==63);
    CHECK(pc_fw_command(&fw,command,63,out,&count) && count==0 && slot.firmware.sequence==1);
    CHECK(m.address==(uintptr_t)&slot.firmware && m.bytes==128 && slot.kernel.sequence==0);
    CHECK(!pc_fw_command(&fw,command,63,out,&count)); /* consumed probe, no replay */
    CHECK(!pc_fw_probe(&fw,2,out)); /* one outstanding */
    uint64_t utc=0;struct polaris_clock_request r=slot.firmware;
    CHECK(pc_validate(&r,7,0,anchor+PC_FREQUENCY,PC_FREQUENCY,&utc)==PC_OK && utc==r.utc_us+1000000);
    CHECK(pc_validate(&r,8,0,anchor,PC_FREQUENCY,&utc)==PC_BAD_WIRE);
    CHECK(pc_validate(&r,7,1,anchor,PC_FREQUENCY,&utc)==PC_BAD_SEQUENCE);
    r.source=2;CHECK(pc_validate(&r,7,0,anchor,PC_FREQUENCY,&utc)==PC_BAD_SOURCE);r.source=1;
    r.reserved[7]=1;CHECK(pc_validate(&r,7,0,anchor,PC_FREQUENCY,&utc)==PC_BAD_WIRE);r.reserved[7]=0;
    CHECK(pc_validate(&r,7,0,anchor-1,PC_FREQUENCY,&utc)==PC_BAD_COUNTER);
    CHECK(pc_validate(&r,7,0,anchor+PC_MAX_AGE_TICKS+1,PC_FREQUENCY,&utc)==PC_BAD_COUNTER);
    CHECK(pc_validate(&r,7,0,anchor,PC_FREQUENCY+1,&utc)==PC_BAD_COUNTER);
    r.uncertainty_us=PC_MAX_UNCERTAINTY_US+1;
    CHECK(pc_validate(&r,7,0,anchor,PC_FREQUENCY,&utc)==PC_BAD_UNCERTAINTY);
    r.uncertainty_us=1;r.utc_us=UINT64_MAX;
    CHECK(pc_validate(&r,7,0,anchor,PC_FREQUENCY,&utc)==PC_BAD_TIME);
    r.utc_us=PC_MAX_UTC_US-1;
    CHECK(pc_validate(&r,7,0,anchor+PC_FREQUENCY,PC_FREQUENCY,&utc)==PC_BAD_TIME);
    CHECK(!pc_elapsed_us(UINT64_MAX,0,&utc));
    CHECK(pc_elapsed_us(0,UINT64_MAX,&utc)); /* division-before-multiply */
    slot.kernel.sequence=1;slot.kernel.status=PC_APPLIED;slot.kernel.revision=4;
    CHECK(pc_fw_probe(&fw,2,out));
    anchor=fw.rx+(fw.tx-fw.rx)/2;
    CHECK(!pc_fw_set(&fw,2,PC_MIN_UTC_US,anchor+1,100));
    CHECK(!pc_fw_set(&fw,2,PC_MIN_UTC_US,anchor,100)); /* failed attempt consumed probe */
    CHECK(pc_fw_probe(&fw,2,out));m.ticks+=PC_MAX_AGE_TICKS+1;
    CHECK(!pc_fw_set(&fw,2,PC_MIN_UTC_US,fw.rx+(fw.tx-fw.rx)/2,100));
    slot.kernel.revision=5;CHECK(!pc_fw_status_wire(&fw,out));slot.kernel.revision=6;
    slot.kernel.reserved[4]=1;CHECK(!pc_fw_status_wire(&fw,out));slot.kernel.reserved[4]=0;
    slot.kernel.status=PC_SEALED;CHECK(!pc_fw_probe(&fw,2,out));
    CHECK(!pc_fw_command(&fw,"oem utc-set:ffffffff",20,out,&count));
    CHECK(!pc_fw_command(&fw,"oem rtc-write",13,out,&count));
    CHECK(!pc_fw_command(&fw,"oem utc-status:address",22,out,&count));
    printf("PASS %u clock-only software checks; no physical clock/USB/RTC operation\n",checks);
    return 0;
}
