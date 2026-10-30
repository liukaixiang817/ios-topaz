/* Explicit pre-XNU power trial: one OFF, two-second hold, one restored ON.
 * CPU_ON is compiled out. No general PMIC command is exposed to the host.
 * Native lock-screen integration is deliberately a separate admission step.
 */
#ifndef POLARIS_EFI_WLED_CYCLE_H
#define POLARIS_EFI_WLED_CYCLE_H
#include "uefi-wled-power.h"
#if defined(EFI_XNU_WLED_OEM_STATUS)
#include "uefi-wled-journal.h"
static struct polaris_wled_journal cycle_journal;
static uint8_t cycle_journal_wire[PWJ_LIMIT],cycle_reset_wire[PWJ_RECEIPT];
#endif
static struct polaris_wled_read_bus cycle_bus;
static struct polaris_wled_power cycle_power;
static unsigned cycle_started,cycle_stage,cycle_done;
static uint64_t cycle_off_us,cycle_on_us;
static uint32_t cycle_channel_error;
#if defined(POLARIS_EFI_TEST_QEMU)
static uint8_t cycle_mock_pmic[2][256];
static uint32_t cycle_mock_command,cycle_mock_offset;
#if defined(EFI_XNU_WLED_OEM_STATUS)
static unsigned cycle_mock_fault_reads,cycle_mock_rt_reads;
#endif
static void cycle_mock_init(void)
{
    const uint8_t a[8]={0,3,1,3,0x17,0x10,0,0},b[8]={1,1,0,1,0x17,0x11,0,0};
    const uint8_t sink[6]={0xf0,0x0f,0,0,0x4c,3},string[9]={0x80,2,8,0,0,0,0x80,0xff,7};
    bytes_copy(cycle_mock_pmic[0],a,8);bytes_copy(cycle_mock_pmic[1],b,8);
    cycle_mock_pmic[0][0x46]=0x80;cycle_mock_pmic[0][0x15]=2;
    cycle_mock_pmic[0][0x5a]=0x80;cycle_mock_pmic[0][0x5b]=0x84;
    bytes_copy(cycle_mock_pmic[1]+0x46,sink,6);
    for(unsigned n=0;n<4;n++)bytes_copy(cycle_mock_pmic[1]+0x50+0x10*n,string,9);
}
static uint32_t cycle_read(void *context,unsigned bank,uint32_t offset)
{
    (void)context;
    if(bank==PW_CORE) {
        if(!offset)return 0x50000000;
        if(offset==0x900+253*4)return 0x0103d800;
        if(offset==0x900+254*4)return 0x0103d900;
        return 0;
    }
    if(bank==PW_CONFIG)return 0;
    if(bank!=PW_OBSERVER||offset<cycle_mock_offset){cycle_channel_error=1;return 2;}
    unsigned local=offset-cycle_mock_offset;
    if(local==8)return cycle_channel_error?2:1;
    if(local!=0x18&&local!=0x1c){cycle_channel_error=2;return 0;}
    unsigned k=cycle_mock_offset==253*0x80?0:1,reg=(cycle_mock_command>>4)&255;
    uint32_t data=0;for(unsigned n=0;n<4;n++) {
        unsigned at=reg+n+(local==0x1c?4:0);
        if(at<256)data|=(uint32_t)cycle_mock_pmic[k][at]<<(8*n);
    }return data;
}
static void cycle_read_command(void *context,uint32_t offset,uint32_t command)
{
    (void)context;
    if((offset!=253*0x80&&offset!=254*0x80)||(command>>27)!=1||
       (command&0x07fff008))cycle_channel_error=3;
    cycle_mock_offset=offset;cycle_mock_command=command;
#if defined(EFI_XNU_WLED_OEM_STATUS)
    if(offset==253*0x80) {
        unsigned reg=(command>>4)&255;
        if(reg==8)cycle_mock_pmic[0][8]=(uint8_t)(++cycle_mock_fault_reads&1);
        if(reg==0x10)cycle_mock_pmic[0][0x10]=(uint8_t)(++cycle_mock_rt_reads&1);
#if defined(EFI_XNU_TEST_WLED_STATUS_AFTER_ISSUE)
        if(cycle_power.issued) {
            cycle_mock_pmic[0][8]=(uint8_t)EFI_XNU_TEST_WLED_STATUS_AFTER_ISSUE;
            cycle_mock_pmic[0][0x10]=(uint8_t)(EFI_XNU_TEST_WLED_STATUS_AFTER_ISSUE>>8);
        }
#endif
    }
#endif
}
#endif
static void cycle_issue(void *context,uint32_t offset,uint32_t command,uint32_t data)
{
    (void)context;
    if(offset!=0xfd0000||!((command==0x460&&(data==0||data==0x80))||
       (command==0x160&&data==2)||(command==0x141&&data==0x0202))) {
        cycle_channel_error=4;return;
    }
#if defined(POLARIS_EFI_TEST_QEMU)
    if(command==0x460)cycle_mock_pmic[0][0x46]=(uint8_t)data;
    else if(command==0x160)cycle_mock_pmic[0][0x15]&=~2u;
    else cycle_mock_pmic[0][0x15]|=2;
#else
    /* Own v5 RW window, different from observer stride. Only this exact APID
     * was admitted. Each WDATA/CMD store is completed before the next access. */
    *(volatile uint32_t *)(uintptr_t)(UINT64_C(0xc600000)+offset+0x10)=data;
    __asm__ volatile("dsb sy":::"memory");
    *(volatile uint32_t *)(uintptr_t)(UINT64_C(0xc600000)+offset)=command;
    __asm__ volatile("dsb sy":::"memory");
#endif
}
static uint32_t cycle_status(void *context,uint32_t offset)
{
    (void)context;
    if(cycle_channel_error||offset!=0xfd0008)return 2;
#if defined(POLARIS_EFI_TEST_QEMU)
#if defined(EFI_XNU_TEST_WLED_WRITE_TIMEOUT)
    if(cycle_power.issued==1)return 0; /* Actual command uncertain, no retry. */
#endif
    return 1;
#else
    uint32_t value=*(volatile uint32_t *)(uintptr_t)(UINT64_C(0xc600000)+offset);
    __asm__ volatile("dsb sy":::"memory");return value;
#endif
}
static void wled_cycle_begin(void)
{
    if(cycle_started)return;
    cycle_started=1;
#if defined(EFI_XNU_WLED_OEM_STATUS)
    cycle_journal.cookie=buttons_us(0)^UINT64_C(0x574c45444a320001);
    if(!cycle_journal.cookie)cycle_journal.cookie=1;
#endif
#if defined(POLARIS_EFI_TEST_QEMU)
    cycle_mock_init();report("WLED_POWER_MOCK_BACKEND=",1);
    cycle_bus.read=cycle_read;cycle_bus.read_command=cycle_read_command;
#else
    uint64_t affinity,el,mask,group,par;
    __asm__ volatile("mrs %0,mpidr_el1":"=r"(affinity));
    __asm__ volatile("mrs %0,CurrentEL":"=r"(el));
    __asm__ volatile("mrs %0,DAIF":"=r"(mask));
    __asm__ volatile("mrs %0,ICC_IGRPEN1_EL1":"=r"(group));
    __asm__ volatile("at s1e1w,%1; isb; mrs %0,par_el1":"=r"(par):
        "r"(UINT64_C(0xd5d0000)):"memory");
    if((affinity&0xff00ffffffu)||el!=4||(mask&0x3c0)!=0x3c0||group||
       (par&1)||(par&UINT64_C(0x0000fffffffff000))!=UINT64_C(0xd5d0000)||
       !identity_range(0xc440000,0x1100)||!identity_range(0xc40a000,0x1000)||
       !identity_range(0xe600000,0x10000)) {
        pwp_fail(&cycle_power,PWP_E_SCOPE);cycle_done=1;return;
    }
    cycle_bus.read=buttons_rd;cycle_bus.read_command=buttons_command;
#endif
    cycle_bus.now_us=buttons_us;
    cycle_power.issue=cycle_issue;cycle_power.status=cycle_status;
    struct polaris_wled_snapshot saved={0};
#if defined(EFI_XNU_WLED_OEM_STATUS)
    /* Independent entry, never a retry after the strict reader refused.
     * The first raw status is retained in saved; init checks every canonical
     * factory byte and two live snapshots. This is not a clean-health claim. */
    report("WLED_POWER_OEM_STATUS_POLICY=",1);
    bool initialized=pw_collect(&cycle_bus,&saved)&&
        pwp_init_oem_status(&cycle_power,&cycle_bus,&saved,false);
#else
    bool initialized=polaris_wled_inventory(&cycle_bus,&saved)&&
        pwp_init(&cycle_power,&cycle_bus,&saved,false);
#endif
    if(!initialized||
       !pwp_request(&cycle_power,1,false)) {
        if(!cycle_power.error)pwp_fail(&cycle_power,cycle_bus.fault);
        report("WLED_POWER_PREPARE_WRITES_ISSUED=",cycle_power.issued);
        report("WLED_POWER_CHANGED_BYTE=",((uint64_t)cycle_bus.changed_byte_plus_one<<32)|
            ((uint32_t)cycle_bus.changed_first<<8)|cycle_bus.changed_after);
        report("WLED_POWER_PREPARE_READS=",cycle_bus.reads);
        cycle_done=1;
    }
    if(!cycle_power.error) {
        report("WLED_POWER_INITIAL_VERSION=",cycle_bus.version);
        report("WLED_POWER_INITIAL_CTRL_MAP=",cycle_bus.map[0]);
        report("WLED_POWER_INITIAL_SINK_MAP=",cycle_bus.map[1]);
        report("WLED_POWER_INITIAL_CTRL_APID_OWNER=",((uint64_t)cycle_bus.apid[0]<<32)|cycle_bus.owner[0]);
        report("WLED_POWER_INITIAL_SINK_APID_OWNER=",((uint64_t)cycle_bus.apid[1]<<32)|cycle_bus.owner[1]);
        report("WLED_POWER_INITIAL_PSM=",(uint32_t)saved.psm[0]|((uint32_t)saved.psm[1]<<8));
        report("WLED_POWER_INITIAL_STATUS=",(uint32_t)saved.faults[0]|((uint32_t)saved.faults[1]<<8));
    }
}
#if defined(EFI_XNU_WLED_OEM_STATUS)
static void wled_cycle_status_report(void)
{
    const struct polaris_wled_status_witness *w=&cycle_power.witness;
    report("WLED_POWER_WITNESS_COUNT=",w->count);
    report("WLED_POWER_WITNESS_ERROR=",w->error);
    report("WLED_POWER_WITNESS_FAULT_OR=",w->fault_or);
    report("WLED_POWER_WITNESS_RT_OR=",w->rt_or);
    for(unsigned n=0;n<w->count&&n<PWS_RECORDS;n++) {
        char at[]="WLED_POWER_W00_AT=",word[]="WLED_POWER_W00_WORD=";
        at[12]=word[12]="0123456789ABCDEF"[(n>>4)&15];
        at[13]=word[13]="0123456789ABCDEF"[n&15];
        report(at,((w->record[n].began_us&UINT64_C(0xffffffff))<<32)|
            (w->record[n].ended_us&UINT64_C(0xffffffff)));
        report(word,(uint32_t)w->record[n].fault|((uint32_t)w->record[n].rt<<8)|
            ((uint32_t)w->record[n].valid<<16)|((uint32_t)w->record[n].expected<<24));
    }
}
#endif
static void wled_cycle_poll(void)
{
    if(!cycle_started||cycle_done)return;
    if(!pwp_poll(&cycle_power)) {
        report("WLED_POWER_CYCLE_ERROR=",cycle_power.error);
        report("WLED_POWER_CHANGED_BYTE=",((uint64_t)cycle_bus.changed_byte_plus_one<<32)|
            ((uint32_t)cycle_bus.changed_first<<8)|cycle_bus.changed_after);
        report("WLED_POWER_FAILED_BANK_REG=",((uint64_t)cycle_bus.last_bank<<32)|cycle_bus.last_reg);
        report("WLED_POWER_FAILED_STATUS_POLLS=",((uint64_t)cycle_bus.last_status<<32)|cycle_bus.last_polls);
        report("WLED_POWER_FAILED_READS=",cycle_bus.reads);
        report("WLED_POWER_UNCERTAIN=",cycle_power.uncertain);
        report("WLED_POWER_WRITES_ISSUED=",cycle_power.issued);
        report("WLED_POWER_WRITES_COMPLETED=",cycle_power.completed);
#if defined(EFI_XNU_WLED_OEM_STATUS)
        wled_cycle_status_report();
#endif
        cycle_done=1;return;
    }
    uint64_t now=buttons_us(0);
    if(!cycle_stage&&cycle_power.acknowledged==1) {
        cycle_off_us=now;cycle_stage=1;
        report("WLED_POWER_OFF_MODULE=",cycle_power.module);
        report("WLED_POWER_OFF_IRQ=",cycle_power.irq);
        report("WLED_POWER_OFF_US=",now);
    }else if(cycle_stage==1&&now>=cycle_off_us&&now-cycle_off_us>=2000000) {
        if(!pwp_request(&cycle_power,2,true)){cycle_done=1;return;}
        cycle_stage=2;
    }else if(cycle_stage==2&&cycle_power.acknowledged==2&&pwp_restored(&cycle_power)) {
        cycle_on_us=now;cycle_done=1;
        report("WLED_POWER_RESTORED_MODULE=",cycle_power.module);
        report("WLED_POWER_RESTORED_IRQ=",cycle_power.irq);
        report("WLED_POWER_RESTORED_US=",now);
        report("WLED_POWER_SOFTSTART_US=",cycle_power.previous_us-cycle_power.softstart_us);
        report("WLED_POWER_WRITES_ISSUED=",cycle_power.issued);
        report("WLED_POWER_WRITES_COMPLETED=",cycle_power.completed);
        report("WLED_POWER_CYCLE_ERROR=",0);
#if defined(EFI_XNU_WLED_OEM_STATUS)
        wled_cycle_status_report();
#endif
        text("WLED_POWER_CYCLE_HOLD: NO_CPU_ON SAVED_STATE_RESTORED\r\n");
    }
}
static int wled_cycle_reset_ready(void)
{
    /* Preflight refusal before the first write needs no PMIC recovery.
     * Every path after a write, including the RAM lease, requires readback. */
    return !cycle_started||!cycle_power.issued||pwp_restored(&cycle_power);
}
#if defined(EFI_XNU_WLED_OEM_STATUS)
static int wled_journal_capture(void *context,const uint8_t **data,uint64_t *bytes)
{
    (void)context;unsigned length=0;
    if(!cycle_started||!cycle_done||!data||!bytes||
       !pwj_packet(&cycle_journal,&cycle_power,cycle_journal_wire,sizeof(cycle_journal_wire),&length))return 0;
    *data=cycle_journal_wire;*bytes=length;return 1;
}
static int wled_reset_receipt(void *context,unsigned mode,const uint8_t **data,uint64_t *bytes)
{
    (void)context;
    if(data&&bytes&&!cycle_power.issued&&!cycle_power.completed&&!cycle_power.uncertain&&mode>=1&&mode<=2) {
        for(unsigned n=0;n<16;n++)cycle_reset_wire[n]=0;
        cycle_reset_wire[0]='W';cycle_reset_wire[1]='L';cycle_reset_wire[2]='R';cycle_reset_wire[3]='0';
        pwj_put(cycle_reset_wire+4,cycle_journal.cookie,8);
        cycle_reset_wire[12]=(uint8_t)mode;cycle_reset_wire[13]=(uint8_t)cycle_power.error;
        *data=cycle_reset_wire;*bytes=16;return 1;
    }
    if(!data||!bytes||!pwj_receipt(&cycle_journal,&cycle_power,mode,buttons_us(0),cycle_reset_wire))return 0;
    *data=cycle_reset_wire;*bytes=sizeof(cycle_reset_wire);return 1;
}
#endif
#endif
