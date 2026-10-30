/* Resident CPU0 runtime integration. Independent default-OFF physical scope
 * uses only the original, physically verified SPMI operations. The QEMU scope
 * retains an explicit SOFTWARE PMIC. Neither scope grants image admission. */
#ifndef POLARIS_EFI_WLED_NATIVE_H
#define POLARIS_EFI_WLED_NATIVE_H
#if !defined(EFI_XNU_SHUTDOWN_BRIDGE) || !EFI_XNU_BUTTONS_AVAILABLE || \
    (defined(EFI_XNU_WLED_NATIVE_RUNTIME_TEST)==defined(EFI_XNU_WLED_NATIVE_RUNTIME_PHYSICAL))
#error "Native WLED requires exactly one independent runtime scope and native drain/keys"
#endif
#if defined(EFI_XNU_WLED_NATIVE_RUNTIME_TEST) != defined(POLARIS_EFI_TEST_QEMU)
#error "SOFTWARE and physical PMIC runtime scopes cannot substitute for one another"
#endif
#if defined(EFI_XNU_WLED_NATIVE_RUNTIME_PHYSICAL) && \
    (defined(EFI_XNU_WLED_NATIVE_FAULT) || defined(EFI_XNU_WLED_NATIVE_LIFECYCLE) || defined(EFI_XNU_WLED_NATIVE_START_REFUSAL) || defined(EFI_XNU_WLED_NATIVE_EXIT_TEST))
#error "Physical runtime forbids software fault/lifecycle injection"
#endif
#if defined(EFI_XNU_WLED_NATIVE_FAULT) && (EFI_XNU_WLED_NATIVE_FAULT<1 || EFI_XNU_WLED_NATIVE_FAULT>8)
#error "Unknown explicit SOFTWARE PMIC fault"
#endif
#if defined(EFI_XNU_WLED_NATIVE_LIFECYCLE) && (EFI_XNU_WLED_NATIVE_LIFECYCLE<1 || EFI_XNU_WLED_NATIVE_LIFECYCLE>4 || defined(EFI_XNU_WLED_NATIVE_FAULT))
#error "Unknown/mixed SOFTWARE runtime lifecycle fixture"
#endif
#if defined(EFI_XNU_WLED_NATIVE_START_REFUSAL) && \
    (EFI_XNU_WLED_NATIVE_START_REFUSAL<1 || EFI_XNU_WLED_NATIVE_START_REFUSAL>3 || \
     defined(EFI_XNU_WLED_NATIVE_FAULT) || defined(EFI_XNU_WLED_NATIVE_LIFECYCLE))
#error "Prestart refusal must be a separate SOFTWARE scope"
#endif
#if defined(EFI_XNU_WLED_NATIVE_EXIT_TEST) && \
    (EFI_XNU_WLED_NATIVE_EXIT_TEST<1 || EFI_XNU_WLED_NATIVE_EXIT_TEST>2 || \
     defined(EFI_XNU_WLED_NATIVE_FAULT) || defined(EFI_XNU_WLED_NATIVE_LIFECYCLE) || \
     defined(EFI_XNU_WLED_NATIVE_START_REFUSAL))
#error "Atomic exit fixture must be an independent SOFTWARE scope"
#endif
#include "uefi-wled-runtime.h"
#include "uefi-wled-journal.h"
#include "../../tools/polaris-wled-mailbox.h"
#define WLN_RECORDS 8192u
#if defined(EFI_XNU_WLED_NATIVE_LIFECYCLE) && EFI_XNU_WLED_NATIVE_LIFECYCLE==1
#define WLN_CAPACITY 64u
#else
#define WLN_CAPACITY WLN_RECORDS
#endif
static struct polaris_wled_read_bus wln_bus;
static struct polaris_wled_power wln_power;
static struct polaris_wled_runtime wln_runtime;
static struct polaris_wled_firmware wln_firmware;
static struct polaris_wled_runtime_record wln_archive[WLN_RECORDS];
static uint64_t wln_cookie,wln_last_poll;
static unsigned wln_started,wln_advertised,wln_closing_mode,wln_error_reported;
static unsigned wln_cpu_on_issued,wln_zero_receipt_issued;
static uint64_t wln_zero_receipt_us;
static uint8_t wln_zero_receipt[40];
static uint32_t wln_backend_error;
#if defined(EFI_XNU_WLED_NATIVE_RUNTIME_TEST)
static uint8_t wln_pmic[2][256];
static uint32_t wln_read_offset,wln_read_command_value;
static unsigned wln_mock_fault_reads,wln_mock_rt_reads;
#endif
static uint32_t wln_crc=~0u,wln_crc_count;
static uint8_t wln_receipt[60],wln_page[80+32*28+4],wln_snapshot_header[80];
static unsigned wln_snapshot_sequence,wln_snapshot_count;
static unsigned wln_archive_owned;
static uint64_t wln_native_cookie;
static uint32_t wln_native_sequence;
static unsigned wln_receipt_issued,wln_lease_recovery;
static unsigned wln_exit_attempt,wln_exit_active,wln_exit_aborted,wln_exit_finished,wln_actual_reset_entered,wln_reset_retryable;
static uint32_t wln_exit_sealed_count;
static uint8_t wln_exit_footer[212],wln_exit_receipt[60];
#if defined(EFI_XNU_WLED_NATIVE_LIFECYCLE) || defined(EFI_XNU_WLED_NATIVE_EXIT_TEST)
static unsigned wln_test_reset_observed;
#endif
static volatile struct polaris_wled_slot *wln_slot(void)
{return (void *)(uintptr_t)(POLARIS_RAM_BASE+EFI_XNU_WLED_OFFSET);}
/* Called only during pre-handoff admission with the just-validated map. Self
 * PE containment and loader ownership are separate from identity translation.
 * Do not call new BootServices operations after the IRQ/native handoff. */
static int wln_image_owned(const struct efi_loaded *image)
{
    uint64_t begin=(uintptr_t)wln_archive,bytes=sizeof(wln_archive),base=image?(uintptr_t)image->base:0;
#if defined(EFI_XNU_WLED_NATIVE_RUNTIME_PHYSICAL)
    /* EDK2 CoreLoadPeImage: EFI_BOOT_SERVICE_DRIVER uses precisely3/4,
     * whereas the QEMU EFI_APPLICATION uses1/2. No runtime/free pages. */
    const uint32_t code_type=3,data_type=4;
#else
    const uint32_t code_type=1,data_type=2;
#endif
    if(!image||!base||!image->bytes||base>UINT64_MAX-image->bytes||begin<base||
       bytes>image->bytes||begin-base>image->bytes-bytes||image->code_type!=code_type||image->data_type!=data_type||
       overlap(begin,bytes,POLARIS_RAM_BASE,POLARIS_RAM_SIZE))return 0;
    for(uint64_t page=begin&~UINT64_C(4095);page<begin+bytes;page+=4096) {
        if(!polaris_efi_range_owned(map_snapshot.data,map_snapshot.bytes,map_snapshot.stride,page,4096,code_type)&&
           !polaris_efi_range_owned(map_snapshot.data,map_snapshot.bytes,map_snapshot.stride,page,4096,data_type))
            return 0;
    }
    wln_archive_owned=1;report("WLED_NATIVE_ARCHIVE_OWNED=",1);return 1;
}
static void wln_encode_record(uint8_t raw[28],const struct polaris_wled_runtime_record *r)
{pwj_record(raw,&r->raw);pwj_put(raw+20,r->sequence,8);}
static void wln_sync_history(void)
{
    uint8_t raw[28];
    while(wln_crc_count<wln_runtime.count) {
        wln_encode_record(raw,&wln_archive[wln_crc_count++]);
        wln_crc=pwj_crc_step(wln_crc,raw,sizeof(raw));
    }
}
static void wln_publish(const struct polaris_wled_ack *ack,bool first)
{
    volatile struct polaris_wled_ack *to=&wln_slot()->firmware;
    to->cookie=ack->cookie;to->on=ack->on;to->error=ack->error;
    to->completed_us=ack->completed_us;to->records=ack->records;
    for(unsigned n=0;n<sizeof(to->reserved);n++)to->reserved[n]=0;
    if(first) {
        to->sequence=0;clean((uintptr_t)to,128);
        __atomic_store_n(&to->ready,PWM_READY,__ATOMIC_RELEASE);
    } else {
        clean((uintptr_t)to,128);
        uint64_t sequence=ack->sequence;
#if defined(EFI_XNU_WLED_NATIVE_LIFECYCLE) && EFI_XNU_WLED_NATIVE_LIFECYCLE==2
        /* Explicit stale publication fault, not a product acknowledgement.
         * The native producer must not accept OFF or invent an ON frame. */
        if(sequence==1&&!ack->error&&!ack->on)sequence=0;
#endif
        __atomic_store_n(&to->sequence,sequence,__ATOMIC_RELEASE);
    }
    clean((uintptr_t)to,128);
}
#if defined(EFI_XNU_WLED_NATIVE_RUNTIME_TEST)
static void wln_mock_init(void)
{
    const uint8_t a[8]={0,3,1,3,0x17,0x10,0,0},b[8]={1,1,0,1,0x17,0x11,0,0};
    const uint8_t sink[6]={0xf0,0x0f,0,0,0x4c,3},string[9]={0x80,2,8,0,0,0,0x80,0xff,7};
    bytes_copy(wln_pmic[0],a,8);bytes_copy(wln_pmic[1],b,8);
    wln_pmic[0][0x46]=0x80;wln_pmic[0][0x15]=2;
    wln_pmic[0][0x5a]=0x80;wln_pmic[0][0x5b]=0x84;
#if defined(EFI_XNU_WLED_NATIVE_START_REFUSAL) && EFI_XNU_WLED_NATIVE_START_REFUSAL==2
    wln_pmic[0][0x5a]^=1; /* Actual SOFTWARE PMIC saved configuration differs. */
#endif
    bytes_copy(wln_pmic[1]+0x46,sink,6);
    for(unsigned n=0;n<4;n++)bytes_copy(wln_pmic[1]+0x50+n*16,string,9);
}
static uint32_t wln_read(void *context,unsigned bank,uint32_t offset)
{
    (void)context;
    if(bank==PW_CORE) {
        if(!offset)return 0x50000000;
        return offset==0x900+253*4?0x0103d800:offset==0x900+254*4?0x0103d900:0;
    }
    if(bank==PW_CONFIG) {
#if defined(EFI_XNU_WLED_NATIVE_START_REFUSAL) && EFI_XNU_WLED_NATIVE_START_REFUSAL==1
        return 1; /* Actual SOFTWARE owner, not an internal-error overwrite. */
#else
        return 0;
#endif
    }
    if(bank!=PW_OBSERVER||offset<wln_read_offset){wln_backend_error=1;return 2;}
    unsigned local=offset-wln_read_offset;
    if(local==8)return wln_backend_error?2:1;
    if(local!=0x18&&local!=0x1c){wln_backend_error=2;return 0;}
    unsigned bank_id=wln_read_offset==253*0x80?0:1,reg=(wln_read_command_value>>4)&255;
    uint32_t out=0;
    for(unsigned n=0;n<4;n++) {
        unsigned at=reg+n+(local==0x1c?4:0);
        if(at<256)out|=(uint32_t)wln_pmic[bank_id][at]<<(8*n);
    }return out;
}
static void wln_read_command(void *context,uint32_t offset,uint32_t command)
{
    (void)context;
    if((offset!=253*0x80&&offset!=254*0x80)||(command>>27)!=1||(command&0x07fff008))
        wln_backend_error=3;
    wln_read_offset=offset;wln_read_command_value=command;
    if(offset==253*0x80) {
        unsigned reg=(command>>4)&255;
        if(reg==8)wln_pmic[0][8]=(uint8_t)(++wln_mock_fault_reads&1);
        if(reg==0x10)wln_pmic[0][0x10]=(uint8_t)(++wln_mock_rt_reads&1);
#if defined(EFI_XNU_WLED_NATIVE_FAULT) && EFI_XNU_WLED_NATIVE_FAULT>=2 && EFI_XNU_WLED_NATIVE_FAULT<=7
        if(wln_power.issued) {
            const unsigned masks[6]={2,4,8,2,4,8};
            unsigned fault=EFI_XNU_WLED_NATIVE_FAULT-2;
            if(reg==(fault<3?8u:0x10u))wln_pmic[0][reg]|=(uint8_t)masks[fault];
        }
#endif
    }
}
static void wln_issue(void *context,uint32_t offset,uint32_t command,uint32_t data)
{
    (void)context;
    if(offset!=0xfd0000||!((command==0x460&&(data==0||data==0x80))||
       (command==0x160&&data==2)||(command==0x141&&data==0x0202))){wln_backend_error=4;return;}
    if(command==0x460)wln_pmic[0][0x46]=(uint8_t)data;
    else if(command==0x160)wln_pmic[0][0x15]&=~2u;
    else wln_pmic[0][0x15]|=2;
}
static uint32_t wln_status(void *context,uint32_t offset)
{
    (void)context;
    if(wln_backend_error||offset!=0xfd0008)return 2;
#if defined(EFI_XNU_WLED_NATIVE_FAULT) && EFI_XNU_WLED_NATIVE_FAULT==1
    if(wln_power.issued)return 0; /* Actual unknown completion; never retried. */
#endif
    return 1;
}
#else
/* Exact original v5 channel and commands used by the completed optical test.
 * No caller-selected register, permission change, retry or PMIC fault clear. */
static void wln_issue(void *context,uint32_t offset,uint32_t command,uint32_t data)
{
    (void)context;
    if(offset!=0xfd0000||!((command==0x460&&(data==0||data==0x80))||
       (command==0x160&&data==2)||(command==0x141&&data==0x0202))) {
        wln_backend_error=4;return;
    }
    *(volatile uint32_t *)(uintptr_t)(UINT64_C(0xc600000)+offset+0x10)=data;
    __asm__ volatile("dsb sy":::"memory");
    *(volatile uint32_t *)(uintptr_t)(UINT64_C(0xc600000)+offset)=command;
    __asm__ volatile("dsb sy":::"memory");
}
static uint32_t wln_status(void *context,uint32_t offset)
{
    (void)context;if(wln_backend_error||offset!=0xfd0008)return 2;
    uint32_t value=*(volatile uint32_t *)(uintptr_t)(UINT64_C(0xc600000)+offset);
    __asm__ volatile("dsb sy":::"memory");return value;
}
static int wln_physical_scope(void)
{
    uint64_t affinity,el,mask,group,par;
    __asm__ volatile("mrs %0,mpidr_el1":"=r"(affinity));
    __asm__ volatile("mrs %0,CurrentEL":"=r"(el));
    __asm__ volatile("mrs %0,DAIF":"=r"(mask));
    __asm__ volatile("mrs %0,ICC_IGRPEN1_EL1":"=r"(group));
    __asm__ volatile("at s1e1w,%1; isb; mrs %0,par_el1":"=r"(par):
        "r"(UINT64_C(0xd5d0000)):"memory");
    report("WLED_NATIVE_SCOPE_AFFINITY=",affinity);report("WLED_NATIVE_SCOPE_EL=",el);
    report("WLED_NATIVE_SCOPE_DAIF=",mask);report("WLED_NATIVE_SCOPE_GROUP=",group);
    report("WLED_NATIVE_SCOPE_WRITE_PAR=",par);
    int core=identity_range(0xc440000,0x1100),config=identity_range(0xc40a000,0x1000);
    int observer=identity_range(0xe600000,0x10000);
    report("WLED_NATIVE_SCOPE_CORE_IDENTITY=",core);report("WLED_NATIVE_SCOPE_CONFIG_IDENTITY=",config);
    report("WLED_NATIVE_SCOPE_OBSERVER_IDENTITY=",observer);
    return !(affinity&0xff00ffffffu)&&el==4&&(mask&0x3c0)==0x3c0&&!group&&
        !(par&1)&&(par&UINT64_C(0x0000fffffffff000))==UINT64_C(0xd5d0000)&&core&&config&&observer;
}
#endif
static uint64_t wln_bus_now(void *context)
{
#if defined(EFI_XNU_WLED_NATIVE_FAULT) && EFI_XNU_WLED_NATIVE_FAULT==8
    static unsigned injected;
    if(wln_power.issued&&!injected) {
        injected=1;
        report("WLED_NATIVE_CLOCK_PREVIOUS=",wln_power.previous_us);
        report("WLED_NATIVE_CLOCK_INJECTED=",wln_power.previous_us-1);
        return wln_power.previous_us-1; /* One explicit input fault; sticky. */
    }
#endif
    return buttons_us(context);
}
static int wln_begin(void)
{
    if(wln_started)return 0;wln_started=1;
    if(!wln_archive_owned||cache_line()<16||cache_line()>128||128%cache_line()||
       !identity_range((uintptr_t)wln_archive,sizeof(wln_archive)))return 0;
    /* No unjournaled status read or firmware getter. The unchanged PWP
     * initializer verifies and records both live full snapshots. */
    struct polaris_wled_snapshot expected={0};
    const uint8_t a[8]={0,3,1,3,0x17,0x10,0,0},b[8]={1,1,0,1,0x17,0x11,0,0};
    const uint8_t sink[6]={0xf0,0x0f,0,0,0x4c,3},string[9]={0x80,2,8,0,0,0,0x80,0xff,7};
    bytes_copy(expected.revision[0],a,8);bytes_copy(expected.revision[1],b,8);
    expected.ctrl[2]=0x80;expected.irq_enable=2;expected.psm[0]=0x80;expected.psm[1]=0x84;
    bytes_copy(expected.sink,sink,6);
    for(unsigned n=0;n<4;n++)bytes_copy(expected.string[n],string,9);
#if defined(EFI_XNU_WLED_NATIVE_RUNTIME_TEST)
    wln_mock_init();wln_bus.read=wln_read;wln_bus.read_command=wln_read_command;
#else
    if(!wln_physical_scope()){pwp_fail(&wln_power,PWP_E_SCOPE);return 0;}
    wln_bus.read=buttons_rd;wln_bus.read_command=buttons_command;
#endif
    wln_bus.now_us=wln_bus_now;
    wln_power.issue=wln_issue;wln_power.status=wln_status;
    wln_cookie=buttons_us(0)^UINT64_C(0x574c454452330001);
    if(!wln_cookie||wln_cookie==PWM_NATIVE_START)wln_cookie=1;
    if(!pwp_init_oem_status(&wln_power,&wln_bus,&expected,false)) {
        /* Diagnostic copy of a refused initializer, not runtime admission or
         * an error clear. CPU_ON remains refused and no WRITE can be issued. */
        wln_runtime.power=&wln_power;wln_runtime.records=wln_archive;wln_runtime.capacity=WLN_RECORDS;
        (void)pwr_archive(&wln_runtime);wln_sync_history();return 0;
    }
    if(!pwr_init(&wln_runtime,&wln_power,wln_archive,WLN_CAPACITY))return 0;
    wln_sync_history();
#if defined(EFI_XNU_WLED_NATIVE_RUNTIME_TEST)
    report("WLED_NATIVE_SOFTWARE_PMIC=",1);
#else
    report("WLED_NATIVE_PHYSICAL_PMIC=",1);
#endif
    report("WLED_NATIVE_ARCHIVE_ADDRESS=",(uintptr_t)wln_archive);
    report("WLED_NATIVE_ARCHIVE_CAPACITY=",WLN_CAPACITY);
    return 1;
}
static int wln_close(unsigned mode)
{
    if(!wln_started||mode<1||mode>2||wln_power.error||wln_runtime.error||wln_firmware.error)return 0;
    if(wln_closing_mode)return wln_closing_mode==mode;
    if(wln_advertised&&!pwm_firmware_close(&wln_firmware))return 0;
    if(!pwr_close(&wln_runtime))return 0;
    wln_closing_mode=mode;return 1;
}
static void wln_poll(void)
{
    if(!wln_started||load_state!=4||cpu_status||wln_runtime.sealed)return;
    uint64_t now=buttons_us(0);
    if(!now||now<wln_last_poll){pwr_fail(&wln_runtime,PWP_E_CLOCK);return;}
    if(now-wln_last_poll<10000)return;wln_last_poll=now;
    volatile struct polaris_wled_slot *slot=wln_slot();
    struct polaris_wled_ack ack={0};
    if(!wln_advertised) {
        invalidate((uintptr_t)&slot->native,128);
        uint64_t cookie=__atomic_load_n(&slot->native.cookie,__ATOMIC_ACQUIRE);
        if(!cookie)return;
        struct polaris_wled_request request;bytes_copy(&request,(const void *)&slot->native,sizeof(request));
        if(request.cookie!=cookie)return;
        if(!pwm_native_start_ready(&request)||
           !pwm_firmware_init(&wln_firmware,wln_cookie,wln_runtime.count,now,&ack)) {
            pwm_firmware_fail(&wln_firmware,PWM_E_WIRE);return;
        }
        wln_publish(&ack,true);wln_advertised=1;return;
    }
    if(wln_power.error||wln_runtime.error||wln_firmware.error) {
        if(!wln_error_reported) {
            wln_error_reported=1;wln_sync_history();
            ack=(struct polaris_wled_ack){.cookie=wln_cookie,.sequence=wln_firmware.sequence,
                .on=wln_power.actual_on,.error=wln_power.error?wln_power.error:
                    wln_runtime.error?wln_runtime.error:wln_firmware.error,
                .completed_us=now,.records=wln_runtime.count,.ready=PWM_READY};
            wln_publish(&ack,false);report("WLED_NATIVE_STOPPED=",ack.error);
        }return;
    }
    if(!wln_closing_mode&&!wln_firmware.pending) {
        invalidate((uintptr_t)&slot->native,128);
        uint64_t seq=__atomic_load_n(&slot->native.sequence,__ATOMIC_ACQUIRE);
        if(seq!=wln_firmware.sequence) {
            struct polaris_wled_request request;bytes_copy(&request,(const void *)&slot->native,sizeof(request));
            if(request.sequence!=seq)return;
            if(!pwm_firmware_request(&wln_firmware,&request))return;
            enum pwr_result accepted=pwr_request(&wln_runtime,seq,request.on);
            if(accepted==PWR_CAPACITY) {
                if(pwm_firmware_capacity(&wln_firmware,wln_runtime.count,now,&ack))wln_publish(&ack,false);
                return;
            }
            if(accepted!=PWR_ACCEPTED){pwm_firmware_fail(&wln_firmware,PWM_E_BACKEND);return;}
        }
    }
    bool ok=pwr_poll(&wln_runtime);wln_sync_history();
    if(!ok)return;
    if(wln_firmware.pending&&!wln_runtime.pending) {
        if(pwm_firmware_complete(&wln_firmware,wln_power.actual_on,
           !wln_power.error&&!wln_power.uncertain,wln_runtime.count,buttons_us(0),&ack))
            wln_publish(&ack,false);
    }
}
/* Prefix is immutable: later records may append while host reads pages. */
static int wln_capture_page(void *context,uint32_t page,const uint8_t **data,uint64_t *bytes)
{
    (void)context;if(!data||!bytes||!wln_started||!wln_runtime.count)return 0;
    if(!page) {
        if(wln_snapshot_sequence==UINT32_MAX)return 0;
        wln_sync_history();wln_snapshot_count=wln_runtime.count;wln_snapshot_sequence++;
        bytes_zero(wln_snapshot_header,sizeof(wln_snapshot_header));
        bytes_copy(wln_snapshot_header,"WLRPAGE3",8);pwj_put(wln_snapshot_header+8,wln_cookie,8);
        pwj_put(wln_snapshot_header+16,wln_snapshot_sequence,4);pwj_put(wln_snapshot_header+20,wln_snapshot_count,4);
        pwj_put(wln_snapshot_header+30,28,2);pwj_put(wln_snapshot_header+32,~wln_crc,4);
        pwj_put(wln_snapshot_header+36,wln_power.error,4);pwj_put(wln_snapshot_header+40,wln_firmware.error,4);
        pwj_put(wln_snapshot_header+44,wln_runtime.error,4);pwj_put(wln_snapshot_header+48,wln_power.issued,4);
        pwj_put(wln_snapshot_header+52,wln_power.completed,4);pwj_put(wln_snapshot_header+56,wln_power.request,8);
        pwj_put(wln_snapshot_header+64,wln_power.acknowledged,8);
        wln_snapshot_header[72]=wln_power.module;wln_snapshot_header[73]=wln_power.irq;
        wln_snapshot_header[74]=(uint8_t)(pwj_flags(&wln_power)|(wln_closing_mode?8:0)|(wln_runtime.sealed?16:0));
        wln_snapshot_header[75]=wln_power.witness.fault_or;wln_snapshot_header[76]=wln_power.witness.rt_or;
    }
    if(!wln_snapshot_sequence||page>=((wln_snapshot_count+31)/32))return 0;
    unsigned offset=page*32,count=wln_snapshot_count-offset;if(count>32)count=32;
    bytes_copy(wln_page,wln_snapshot_header,80);pwj_put(wln_page+24,offset,4);pwj_put(wln_page+28,count,2);
    for(unsigned n=0;n<count;n++)wln_encode_record(wln_page+80+n*28,&wln_archive[offset+n]);
    unsigned length=80+count*28+4;pwj_put(wln_page+length-4,~pwj_crc_step(~0u,wln_page,length-4),4);
    *data=wln_page;*bytes=length;return 1;
}
/* The caller must first prove actual native VFS/GPU/CPU drain. This function
 * contributes only WLED restoration, never native SAFE or UFS durability. */
static int wln_reset_ready(uint64_t native_cookie,uint32_t native_sequence,unsigned mode)
{
    if(!native_cookie||!native_sequence||wln_closing_mode!=mode||wln_firmware.error||
       wln_power.error||wln_runtime.error||wln_runtime.pending||!wln_power.actual_on||
       wln_power.uncertain||wln_receipt_issued)return 0;
    if(!wln_runtime.sealed) {
        if(!pwr_seal(&wln_runtime))return 0;
        wln_sync_history();wln_native_cookie=native_cookie;wln_native_sequence=native_sequence;
    }
    return wln_native_cookie==native_cookie&&wln_native_sequence==native_sequence;
}
/* Independent pre-CPU_ON recovery. This is never native drain or restored
 * WLED proof: it proves only that neither native nor a PMIC writer ran. */
static int wln_zero_ready(unsigned mode)
{
    return mode==2&&!wln_cpu_on_issued&&!polaris_efi_ap_state.stage&&
        !wln_power.issued&&!wln_power.completed&&!wln_power.uncertain;
}
static int wln_zero_receipt_make(unsigned mode,const uint8_t **data,uint64_t *bytes)
{
    if(!data||!bytes||!wln_zero_ready(mode)||wln_zero_receipt_issued)return 0;
    uint64_t now=buttons_us(0);if(!now)return 0;
    if(!wln_cookie){wln_cookie=now^UINT64_C(0x574c454452330001);if(!wln_cookie)wln_cookie=1;}
    bytes_zero(wln_zero_receipt,sizeof(wln_zero_receipt));bytes_copy(wln_zero_receipt,"WLZ4",4);
    pwj_put(wln_zero_receipt+4,mode,4);pwj_put(wln_zero_receipt+8,wln_cookie,8);
    pwj_put(wln_zero_receipt+16,now,8);pwj_put(wln_zero_receipt+24,wln_power.error,4);
    pwj_put(wln_zero_receipt+28,wln_runtime.error,4);
    /* bytes32..35 are the actual CPU-issued/APstage/WRITE/uncertain zero flags. */
    pwj_put(wln_zero_receipt+36,~pwj_crc_step(~0u,wln_zero_receipt,36),4);
    wln_zero_receipt_us=now;wln_zero_receipt_issued=1;
    *data=wln_zero_receipt;*bytes=sizeof(wln_zero_receipt);return 1;
}
static int wln_reset_receipt(void *context,unsigned mode,const uint8_t **data,uint64_t *bytes)
{
    (void)context;
    if(wln_zero_ready(mode))return wln_zero_receipt_make(mode,data,bytes);
    if(!data||!bytes||!wln_runtime.sealed||wln_closing_mode!=mode||wln_receipt_issued||
       wln_power.error||wln_runtime.error||wln_firmware.error||!wln_native_cookie||
       wln_runtime.count!=wln_runtime.final_last||wln_runtime.final_last!=wln_runtime.final_first+2)
        return 0;
    uint64_t now=buttons_us(0),last=wln_archive[wln_runtime.count-1].raw.ended_us;
    if(now<last||now-last>PWS_MAX_CHECK_US)return 0;
    bytes_zero(wln_receipt,sizeof(wln_receipt));bytes_copy(wln_receipt,"WLR3",4);
    pwj_put(wln_receipt+4,wln_cookie,8);pwj_put(wln_receipt+12,wln_native_cookie,8);
    pwj_put(wln_receipt+20,mode,4);pwj_put(wln_receipt+24,wln_native_sequence,4);
    pwj_put(wln_receipt+28,wln_runtime.count,4);pwj_put(wln_receipt+32,wln_runtime.final_first,4);
    pwj_put(wln_receipt+36,wln_runtime.final_last,4);pwj_put(wln_receipt+40,~wln_crc,4);
    pwj_put(wln_receipt+44,wln_power.request,8);pwj_put(wln_receipt+56,1,4);
    uint32_t crc=pwj_crc_step(~0u,wln_receipt,52);crc=pwj_crc_step(crc,wln_receipt+56,4);
    pwj_put(wln_receipt+52,~crc,4);wln_receipt_issued=1;
    *data=wln_receipt;*bytes=sizeof(wln_receipt);return 1;
}
/* At most ONE explicit recovery after a known USB/late-reset refusal. Both
 * operations after seal are READ ONLY. The host must first capture a NEW full
 * prefix; old cookie/count/CRC or a replayed command cannot admit recovery. */
static int wln_exit_begin(void *context,int recover,uint64_t cookie,uint32_t count,uint32_t crc,
    const uint8_t **data,uint64_t *bytes)
{
    if(!data||!bytes||!wln_cpu_on_issued||!wln_started||wln_zero_ready(2)||
       wln_actual_reset_entered||wln_exit_active||wln_exit_attempt>=2||
       recover!=(int)(wln_exit_attempt==1)||
       (recover&&!wln_exit_aborted)||wln_power.error||wln_runtime.error||wln_firmware.error||
       wln_power.uncertain||wln_closing_mode!=2||wln_runtime.pending||!wln_power.actual_on||
       wln_runtime.count>WLN_CAPACITY-(recover?2u:8u)||cookie!=wln_cookie||count!=wln_runtime.count)return 0;
    wln_sync_history();if(crc!=~wln_crc)return 0;
    if(!recover) {
        if(wln_runtime.sealed||wln_receipt_issued||!prepare_reset(context,2))return 0;
    } else {
        const uint8_t *native_data=0;uint64_t native_bytes=0;
        if(!wln_runtime.sealed||!shutdown_reset_ready(context,2)||
           !shutdown_status(context,&native_data,&native_bytes)||native_bytes!=128)return 0;
        const struct polaris_shutdown_status *native=(const void *)native_data;
        if(native->cookie!=wln_native_cookie||native->sequence!=wln_native_sequence||native->mode!=2)return 0;
    }
    if(recover&&!runtime_arm_reset(2))return 0;
    unsigned added=wln_runtime.count-count;
    if(added!=(recover?0u:4u))return 0;
    const uint8_t *page=0;uint64_t page_bytes=0;
    if(!wln_capture_page(context,0,&page,&page_bytes)||page_bytes<84)return 0;
    bytes_copy(wln_exit_footer,page,80);bytes_copy(wln_exit_footer,"WLEXIT05",8);
    pwj_put(wln_exit_footer+24,count,4);pwj_put(wln_exit_footer+28,added,2);
    pwj_put(wln_exit_footer+80,wln_native_cookie,8);
    pwj_put(wln_exit_footer+88,wln_native_sequence,4);pwj_put(wln_exit_footer+92,2,4);
    for(unsigned n=0;n<added;n++)wln_encode_record(wln_exit_footer+96+n*28,&wln_archive[count+n]);
    unsigned length=100+added*28;
    pwj_put(wln_exit_footer+length-4,~pwj_crc_step(~0u,wln_exit_footer,length-4),4);
    wln_exit_attempt++;wln_exit_active=1;wln_exit_aborted=0;wln_exit_finished=0;
    wln_exit_sealed_count=wln_runtime.count;
    *data=wln_exit_footer;*bytes=length;return 1;
}
static int wln_exit_finish(void *context,const uint8_t **data,uint64_t *bytes)
{
    (void)context;
    if(!data||!bytes||!wln_exit_active||wln_exit_finished||wln_actual_reset_entered||
       wln_power.error||wln_runtime.error||wln_firmware.error||wln_power.uncertain||
       !wln_runtime.sealed||wln_runtime.count!=wln_exit_sealed_count||
       wln_runtime.count>WLN_CAPACITY-2||!shutdown_reset_ready(context,2))return 0;
    /* Footer USB delivery completed. Take and ARCHIVE a NEW actual full pair;
     * do not refresh a timestamp, retry a WRITE, retire history or clear error. */
    unsigned before=wln_runtime.count;
    bool restored=pwp_restored(&wln_power);
    if(!pwr_archive(&wln_runtime)||!restored)return 0;
    wln_sync_history();if(wln_runtime.count!=before+2)return 0;
    uint64_t now=buttons_us(0),last=wln_archive[wln_runtime.count-1].raw.ended_us;
    if(now<last||now-last>PWS_MAX_CHECK_US)return 0;
    bytes_copy(wln_exit_receipt,"WLR5",4);pwj_put(wln_exit_receipt+4,wln_cookie,8);
    pwj_put(wln_exit_receipt+12,wln_runtime.count,4);pwj_put(wln_exit_receipt+16,~wln_crc,4);
    for(unsigned n=0;n<2;n++)pwj_record(wln_exit_receipt+20+n*20,&wln_archive[before+n].raw);
    wln_receipt_issued=1;wln_exit_finished=1;
    *data=wln_exit_receipt;*bytes=sizeof(wln_exit_receipt);return 1;
}
static void wln_exit_abort(void *context,unsigned cause)
{
    (void)context;
    if(!wln_actual_reset_entered&&wln_exit_active) {
        wln_exit_active=0;
        int unarmed=runtime_unarm_reset();
        wln_exit_aborted=unarmed&&((cause==1)||(cause==2&&wln_reset_retryable));
        report("WLED_NATIVE_EXIT_DELIVERY_REFUSED=",((uint64_t)cause<<32)|wln_exit_attempt);
    }
}
static int wln_final_fresh(unsigned mode)
{
    if(wln_zero_ready(mode)) {
        uint64_t now=buttons_us(0);
        return wln_zero_receipt_issued&&now>=wln_zero_receipt_us&&now-wln_zero_receipt_us<=PWS_MAX_CHECK_US;
    }
    if(wln_exit_attempt&&(!wln_exit_active||!wln_exit_finished))return 0;
    if(!wln_runtime.sealed||!wln_receipt_issued||wln_closing_mode!=mode||
       wln_power.error||wln_runtime.error||wln_firmware.error||!wln_runtime.count)return 0;
    uint64_t now=buttons_us(0),last=wln_archive[wln_runtime.count-1].raw.ended_us;
    return now>=last&&now-last<=PWS_MAX_CHECK_US;
}
#endif
