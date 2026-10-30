/* Resident iOS loader with volatile kernel writes. No block-I/O write,
 * file-write or NVRAM API. Fixed disk payloads are read before handoff.
 * The kernel receives only an explicitly owned bank. Firmware stays on CPU0;
 * kernel MMU/GIC work executes on the one declared, separately started core. */
#include "uefi-xnu.h"
#include "uefi-reset.h"
#include "uefi-boot-options.h"
#include "uefi-ram-lease.h"
#include "uefi-memory.h"
#include "runtime-marker.h"
#include "uefi-xnu-config.h" /* exact payload bytes/CRC, symbol offsets, board */
#if defined(EFI_XNU_OWNED_TEST) && (!defined(POLARIS_EFI_TEST_QEMU) || !defined(EFI_XNU_RAM_DRAIN_TEST) || !defined(EFI_XNU_SHUTDOWN_BRIDGE))
#error "Owned-file durability test requires the isolated QEMU native shutdown bridge"
#endif
#if defined(EFI_XNU_PHYSICAL_MARKER) && (defined(POLARIS_EFI_TEST_QEMU) || !defined(EFI_XNU_SHUTDOWN_BRIDGE))
#error "Physical marker requires its own native shutdown bridge and physical platform"
#endif
#if defined(EFI_XNU_OWNED_TEST) || defined(EFI_XNU_PHYSICAL_MARKER)
#define EFI_XNU_DURABLE_GUARD 1
#endif
#if defined(EFI_XNU_TEST_OMIT_OWNED_GUARD) && (!defined(POLARIS_EFI_TEST_QEMU) || !defined(EFI_XNU_OWNED_TEST))
#error "Guard omission is exclusively an isolated emulator refusal test"
#endif
#if defined(EFI_XNU_RAM_DRAIN_TEST)
#if !defined(POLARIS_EFI_TEST_QEMU)
#error "Native RAM drain experiment is emulator-only until independently verified"
#endif
#endif
#if defined(EFI_XNU_SHUTDOWN_BRIDGE)
#include "runtime-quiesce.h"
#endif
#if defined(EFI_XNU_DISK_GUID)
#include "uefi-file.h"
#endif
struct video {uint64_t base,display,stride,width,height,depth;};
struct args {uint16_t revision,version;uint64_t va,pa,size,top;struct video video;
    uint32_t machine;uint64_t tree;uint32_t tree_bytes;char cmdline[608];uint64_t flags,actual;};
_Static_assert(sizeof(struct args)==736,"XNU boot args ABI");
static struct efi_system *system_table;
static efi_handle driver_image;
static uint8_t log_buffer[32768];static uint64_t log_bytes;
static struct {uint64_t magic,bytes,stride,version;uint8_t data[65536];} map_snapshot;
static uint64_t map_bytes;
static struct polaris_efi_boot_options boot_inventory;
static struct polaris_gop *gop;
#if !defined(POLARIS_EFI_TEST_QEMU)
static struct polaris_efi_pon *reset_pon;
#endif
static struct polaris_plan plan;
static uint8_t *payload,*log_snapshot;
static uint64_t received,payload_count;
static uint32_t load_state;
static struct polaris_efi_ram_lease ram_lease;
static int64_t cpu_status;
static uint8_t ap_stack[131072] __attribute__((aligned(128)));
struct polaris_efi_ap polaris_efi_ap_state __attribute__((aligned(128)));
static void bytes_copy(void *dest,const void *source,uint64_t n)
{uint8_t *d=dest;const uint8_t *s=source;for(uint64_t i=0;i<n;i++)d[i]=s[i];}
static void bytes_zero(void *dest,uint64_t n)
{uint8_t *d=dest;for(uint64_t i=0;i<n;i++)d[i]=0;}
static void text(const char *s)
{
    uint16_t wide[128];unsigned at=0;
    while(*s){
        if(log_bytes<sizeof(log_buffer))log_buffer[log_bytes++]=(uint8_t)*s;
        if(at<127)wide[at++]=(uint8_t)*s;s++;
    }
    wide[at]=0;
    if(load_state<4 && system_table&&system_table->out)system_table->out->string(system_table->out,wide);
}
static void report(const char *name,uint64_t value)
{
    char buf[19]={'0','x'};for(unsigned i=0;i<16;i++)buf[2+i]="0123456789abcdef"[(value>>(60-i*4))&15];
    buf[18]=0;text(name);text(buf);text("\r\n");
}
static int overlap(uint64_t a,uint64_t n,uint64_t b,uint64_t z)
{return n&&z&&a<b+z&&b<a+n;}
static int identity(uint64_t address)
{
    uint64_t par;__asm__ volatile("at s1e1r,%1; isb; mrs %0,par_el1":"=r"(par):"r"(address):"memory");
    return !(par&1) && (par&UINT64_C(0x0000fffffffff000))==(address&~UINT64_C(4095));
}
static int identity_range(uint64_t address,uint64_t bytes)
{
    if(!bytes||address>UINT64_MAX-bytes)return 0;
    uint64_t end=address+bytes;
    for(uint64_t p=address&~UINT64_C(4095);p<end;p+=4096)if(!identity(p))return 0;
    return 1;
}
static uint64_t cache_line(void)
{uint64_t c;__asm__ volatile("mrs %0,ctr_el0":"=r"(c));return UINT64_C(4)<<((c>>16)&15);}
static void clean(uint64_t address,uint64_t bytes)
{
    uint64_t line=cache_line();for(uint64_t p=address&~(line-1);p<address+bytes;p+=line)__asm__ volatile("dc cvac,%0"::"r"(p):"memory");
    __asm__ volatile("dsb sy":::"memory");
}
static void invalidate(uint64_t address,uint64_t bytes)
{
    uint64_t line=cache_line();for(uint64_t p=address&~(line-1);p<address+bytes;p+=line)__asm__ volatile("dc ivac,%0"::"r"(p):"memory");
    __asm__ volatile("dsb sy":::"memory");
}
#if EFI_XNU_BUTTONS_AVAILABLE
#include "uefi-buttons.h"
#endif
#if defined(EFI_XNU_WLED_INVENTORY_ONLY)
#if !EFI_XNU_BUTTONS_AVAILABLE || defined(EFI_XNU_DURABLE_GUARD)
#error "WLED inventory requires original key observer and RAM-only pre-XNU hold"
#endif
#include "uefi-wled-inventory.h"
#endif
#if defined(EFI_XNU_WLED_POWER_CYCLE_ONLY)
#if !EFI_XNU_BUTTONS_AVAILABLE || defined(EFI_XNU_DURABLE_GUARD) || defined(EFI_XNU_WLED_INVENTORY_ONLY)
#error "WLED cycle requires its separate RAM-only pre-XNU scope"
#endif
#include "uefi-wled-cycle.h"
#endif
static int64_t psci(uint64_t function,uint64_t a,uint64_t b,uint64_t c)
{
    register uint64_t x0 __asm__("x0")=function,x1 __asm__("x1")=a,x2 __asm__("x2")=b,x3 __asm__("x3")=c;
#if defined(POLARIS_EFI_TEST_QEMU)
    __asm__ volatile("hvc #0":"+r"(x0),"+r"(x1),"+r"(x2),"+r"(x3)::"x4","x5","x6","x7","x8","x9","x10","x11","x12","x13","x14","x15","x16","x17","cc","memory");
#else
    __asm__ volatile("smc #0":"+r"(x0),"+r"(x1),"+r"(x2),"+r"(x3)::"x4","x5","x6","x7","x8","x9","x10","x11","x12","x13","x14","x15","x16","x17","cc","memory");
#endif
    return (int64_t)x0;
}
static int token(const char *cmd,const char *expected)
{
    unsigned n=0,key=0,found=0;while(expected[n]){if(expected[n]=='=')key=n+1;n++;}
    if(!key)return 0;
    for(unsigned i=0;i<608&&cmd[i];){
        unsigned j=0;while(i+j<608&&cmd[i+j]&&cmd[i+j]!=' ')j++;
        unsigned k=0;while(k<key&&k<j&&cmd[i+k]==expected[k])k++;
        if(k==key){
            if(j!=n)return 0;
            while(k<n&&cmd[i+k]==expected[k])k++;
            if(k!=n||++found!=1)return 0;
        }
        i+=j;if(i<608&&cmd[i]==' ')i++;
    }return found==1;
}
static int begin(void *context,uint64_t count)
{
    (void)context;if(load_state>=4||count!=EFI_XNU_PAYLOAD_BYTES||count>POLARIS_PAYLOAD_LIMIT)return 0;
    received=0;payload_count=count;load_state=1;return 1;
}
static int write_payload(void *context,uint64_t offset,const uint8_t *data,uint64_t count)
{
    (void)context;if(load_state!=1||offset!=received||offset>payload_count||count>payload_count-offset)return 0;
    bytes_copy(payload+offset,data,count);received+=count;return 1;
}
static int finish(void *context)
{
    (void)context;load_state=0;
    if(received!=payload_count||polaris_efi_crc32(payload,payload_count)!=EFI_XNU_PAYLOAD_CRC32)return 0;
    const char *error=polaris_payload_check(payload,payload_count,(uintptr_t)payload,&plan);
    if(error){text(error);text("\r\n");return 0;}
    const struct polaris_payload *p=(const void*)payload;
    const char *required[]={EFI_XNU_CPUS_TOKEN,"ufsrw=0","sweetlog=0","polarisramcow=1","polarisusb=0","polarisdebug=0","polarisuefi=1",EFI_XNU_BOOT_CPU_TOKEN};
    for(unsigned i=0;i<sizeof(required)/sizeof(required[0]);i++)if(!token(p->cmdline,required[i]))return 0;
    if(EFI_XNU_INPUT_AVAILABLE&&!token(p->cmdline,"polarisinput=1"))return 0;
    if(EFI_XNU_LOG_OFFSET>p->kernel_end-p->virt_base || EFI_XNU_LOG_SIZE>p->kernel_end-p->virt_base-EFI_XNU_LOG_OFFSET ||
       EFI_XNU_LOG_TOTAL_OFFSET>p->kernel_end-p->virt_base-8)return 0;
    load_state=2;report("RAM_PAYLOAD_VALID=",1);return 1;
}
#if defined(EFI_XNU_DISK_GUID)
static int disk_payload(void)
{
    static const uint8_t guid[16]=EFI_XNU_DISK_GUID;
    static const uint16_t name[]=EFI_XNU_DISK_PATH;
    static struct polaris_efi_disk_result r;
    int ok=polaris_efi_read_disk(system_table->boot,guid,EFI_XNU_DISK_START,EFI_XNU_DISK_BLOCKS,
                               name,payload,EFI_XNU_PAYLOAD_BYTES,&r);
    report("DISK_FS_COUNT=",r.filesystems);report("DISK_ESP_MATCHES=",r.matches);
    report("DISK_READ_STATUS=",r.status);report("DISK_READ_BYTES=",r.bytes);report("DISK_FILES_CLOSED=",r.closed);
    if(r.matches==1&&r.path_bytes){
        text("DISK_ESP_PATH=");
        for(uint64_t i=0;i<r.path_bytes;i++){
            char b[3]={"0123456789abcdef"[r.path[i]>>4],"0123456789abcdef"[r.path[i]&15],0};text(b);
        }text("\r\n");
    }
    if(!ok||!begin(0,EFI_XNU_PAYLOAD_BYTES))return 0;
    received=EFI_XNU_PAYLOAD_BYTES;return finish(0);
}
#endif
static int prepare_boot(void *context)
{
    (void)context;if(load_state!=2)return 0;
    int64_t affinity=psci(UINT64_C(0xc4000004),EFI_XNU_CPU,0,0);report("AP_AFFINITY=",(uint64_t)affinity);
    if(affinity!=1)return 0; /* Never seize a core already owned by firmware. */
    uint64_t sre;__asm__ volatile("mrs %0,ICC_SRE_EL1":"=r"(sre));report("EFI_GIC_SRE=",sre);
    if(!(sre&1))return 0;
    if(!identity((uintptr_t)polaris_efi_ap_entry)||!identity((uintptr_t)&polaris_efi_ap_state)||
       !identity((uintptr_t)ap_stack+sizeof(ap_stack)-16))return 0;
    const struct polaris_payload *p=(const void*)payload;
    /* Admit every translation before the first destination write. The PE's
     * own identity mapping does not imply that all upper-bank pages map 1:1. */
    if(!identity_range((uintptr_t)payload,payload_count)||
       !identity_range(plan.adt_pa,plan.top-plan.adt_pa))return 0;
    for(uint32_t i=0;i<p->nsegs;i++){
        const struct polaris_segment *s=&p->segs[i];
        if(!identity_range(p->phys_base+s->vmaddr-p->virt_base,s->vmsize))return 0;
    }
    for(uint32_t i=0;i<p->nsegs;i++){
        const struct polaris_segment *s=&p->segs[i];uint64_t dest=p->phys_base+s->vmaddr-p->virt_base;
        bytes_copy((void*)(uintptr_t)dest,payload+s->file_off,s->file_size);
        bytes_zero((void*)(uintptr_t)(dest+s->file_size),s->vmsize-s->file_size);clean(dest,s->vmsize);
    }
    bytes_copy((void*)(uintptr_t)plan.adt_pa,payload+p->adt_off,p->adt_size);
    bytes_zero((void*)(uintptr_t)plan.args_pa,POLARIS_PAGE);struct args *a=(void*)(uintptr_t)plan.args_pa;
    a->revision=2;a->version=2;a->va=p->virt_base;a->pa=p->phys_base;a->size=p->mem_size;a->top=plan.top;
    if(gop&&gop->mode&&gop->mode->info){
        struct polaris_gop_mode *m=gop->mode;struct polaris_gop_info *i=m->info;
        a->video=(struct video){m->base,1,(uint64_t)i->stride*4,i->width,i->height,32};
    }
#if defined(POLARIS_EFI_TEST_QEMU)
    a->video=(struct video){UINT64_C(0x9d400000),1,4320,1080,2160,32};
#endif
    a->tree=p->virt_base+plan.adt_pa-p->phys_base;a->tree_bytes=(uint32_t)p->adt_size;
    bytes_copy(a->cmdline,p->cmdline,sizeof(a->cmdline));a->actual=p->mem_size;
    clean(plan.adt_pa,plan.top-plan.adt_pa);
    struct polaris_efi_ap *ap=&polaris_efi_ap_state;bytes_zero(ap,sizeof(*ap));
    ap->entry=plan.entry_pa;ap->args=plan.args_pa;ap->stack=(uintptr_t)ap_stack+sizeof(ap_stack);
    __asm__ volatile("mrs %0,sctlr_el1":"=r"(ap->sctlr));__asm__ volatile("mrs %0,cpacr_el1":"=r"(ap->cpacr));
    clean((uintptr_t)ap,sizeof(*ap));clean((uintptr_t)ap_stack,sizeof(ap_stack));
    clean((uintptr_t)polaris_efi_ap_entry,4096);load_state=3;report("KERNEL_PREPARED_ENTRY=",plan.entry_pa);return 1;
}
static void boot_kernel(void *context)
{
    (void)context;if(load_state!=3)return;
    report("KERNEL_PSCI_TARGET=",EFI_XNU_CPU);load_state=4;
    uint64_t now;__asm__ volatile("mrs %0,cntvct_el0":"=r"(now));
    ram_lease=(struct polaris_efi_ram_lease){.last=now,.active=1};
#if defined(EFI_XNU_DURABLE_GUARD)
    /* Must precede CPU_ON: that CPU may submit an owned WRITE immediately. */
    ram_lease.active=0;
    struct args *args=(void*)(uintptr_t)plan.args_pa;
    bool physical=false;
#if defined(EFI_XNU_PHYSICAL_MARKER)
    physical=true;
#endif
#if !defined(EFI_XNU_TEST_OMIT_OWNED_GUARD)
    if(!polaris_marker_append_guard(args->cmdline,sizeof(args->cmdline),physical)){
        load_state=3;report("DURABLE_GUARD_REFUSED=",1);return;
    }
#endif
    clean(plan.args_pa,sizeof(*args));report("DURABLE_RESET_GUARD_ARMED=",physical?1:2);
#endif
    /* IRQ ownership moves to XNU. USB's controller API is polled; no firmware
     * UFS/file operation or GOP BLT is allowed while the kernel owns devices. */
    __asm__ volatile("msr daifset,#15; dsb sy; isb":::"memory");
    /* Firmware USB helpers may restore IRQ masks internally. Disable this
     * firmware core's Group1 interface too; XNU's separate core is unaffected.
     * Same architectural handoff as the pinned resident-loader reference. */
    __asm__ volatile("msr ICC_IGRPEN1_EL1,%0; isb"::"r"(UINT64_C(0)):"memory");
    uint64_t group1;__asm__ volatile("mrs %0,ICC_IGRPEN1_EL1":"=r"(group1));report("EFI_IRQ_GROUP1=",group1);
#if EFI_XNU_BUTTONS_AVAILABLE
    if(!buttons_prepare()) {
        /* No XNU core has run. Keep the controlled polled USB service and
         * ordinary RAM reset available; don't spend an iOS boot on refusal. */
        load_state=3;report("BUTTONS_PRESTART_REFUSED=",1);return;
    }
#endif
#if defined(EFI_XNU_WLED_POWER_CYCLE_ONLY)
    load_state=3;
    wled_cycle_begin();
    report("WLED_POWER_PREPARE_ERROR=",cycle_power.error);
    report("WLED_KERNEL_AP_STAGE=",polaris_efi_ap_state.stage);
    report("WLED_AP_STAGE_ADDRESS=",(uintptr_t)&polaris_efi_ap_state.stage);
    text("WLED_POWER_CYCLE_ARMED: NO_CPU_ON\r\n");
#elif defined(EFI_XNU_WLED_INVENTORY_ONLY)
    /* Compile out CPU_ON entirely. Success and failure both remain in this
     * controlled pre-kernel RAM hold; raw FASTBOOT and RAM lease still work. */
    load_state=3;
    report("WLED_READONLY_RESULT=",wled_inventory_probe());
    report("WLED_KERNEL_AP_STAGE=",polaris_efi_ap_state.stage);
    report("WLED_AP_STAGE_ADDRESS=",(uintptr_t)&polaris_efi_ap_state.stage);
    text("WLED_INVENTORY_HOLD: NO_CPU_ON NO_PMIC_WRITE\r\n");
#else
    cpu_status=psci(UINT64_C(0xc4000003),EFI_XNU_CPU,(uintptr_t)polaris_efi_ap_entry,(uintptr_t)&polaris_efi_ap_state);
    report("KERNEL_PSCI_STATUS=",(uint64_t)cpu_status);
#endif
}
static int running(void *context){(void)context;return load_state>=4;}
static int boot_options(void *context,const uint8_t **data,uint64_t *bytes)
{
    (void)context;if(boot_inventory.used<32||boot_inventory.used>sizeof(boot_inventory.data))return 0;
    *data=boot_inventory.data;*bytes=boot_inventory.used;return 1;
}
static int input_status(void *context,struct polaris_uefi_input_status *out)
{
    (void)context;if(!EFI_XNU_INPUT_AVAILABLE||load_state<4||cpu_status||!out)return 0;
    volatile struct polaris_uefi_input_slot *slot=(void*)(uintptr_t)(POLARIS_RAM_BASE+EFI_XNU_INPUT_OFFSET);
    invalidate((uintptr_t)&slot->acknowledged,128);
    *out=(struct polaris_uefi_input_status){slot->ready==POLARIS_INPUT_READY,
        (uint32_t)slot->request,(uint32_t)slot->acknowledged,(uint32_t)slot->error};return 1;
}
static int touch(void *context,unsigned down,unsigned x,unsigned y)
{
    struct polaris_uefi_input_status s;
    if(!polaris_uefi_input_valid(down,x,y)||!input_status(context,&s)||!s.ready||
       s.request!=s.acknowledged||s.request==UINT32_MAX)return 0;
    volatile struct polaris_uefi_input_slot *slot=(void*)(uintptr_t)(POLARIS_RAM_BASE+EFI_XNU_INPUT_OFFSET);
    slot->x=x;slot->y=y;slot->down=down;clean((uintptr_t)slot,128);
    slot->request=(uint64_t)s.request+1;clean((uintptr_t)slot,128);return 1;
}
static const char *state(void *context)
{
    (void)context;if(load_state>=4){
        invalidate((uintptr_t)&polaris_efi_ap_state,sizeof(polaris_efi_ap_state));
        if(cpu_status)return "CPU_ON-refused";
        if(polaris_efi_ap_state.stage==2)return "AP-early-fault";
        if(polaris_efi_ap_state.stage==3)return "AP-wrong-EL";
        return polaris_efi_ap_state.stage==1?"kernel-entered":"AP-start-pending";
    }return load_state==3?"prepared":load_state==2?"validated":load_state==1?"receiving":"waiting-payload";
}
static int logs(void *context,const uint8_t **data,uint64_t *count)
{
    (void)context;uint64_t at=log_bytes;bytes_copy(log_snapshot,log_buffer,at);
    if(load_state>=4 && !cpu_status){
        uint64_t total_pa=POLARIS_RAM_BASE+EFI_XNU_LOG_TOTAL_OFFSET;
        invalidate(total_pa,8);uint64_t total=*(const volatile uint64_t*)(uintptr_t)total_pa;
        uint64_t bytes=total;if(bytes>EFI_XNU_LOG_SIZE)bytes=EFI_XNU_LOG_SIZE;
        uint64_t begin=total-bytes,ring=POLARIS_RAM_BASE+EFI_XNU_LOG_OFFSET;
#if EFI_XNU_BUTTONS_AVAILABLE
        for(uint64_t offset=0;offset<EFI_XNU_LOG_SIZE;offset+=16384){
            buttons_poll();invalidate(ring+offset,16384);
        }
#else
        invalidate(ring,EFI_XNU_LOG_SIZE);
#endif
        static const char label[]="\n--- live XNU RAM console (bounded snapshot) ---\n";
        bytes_copy(log_snapshot+at,label,sizeof(label)-1);at+=sizeof(label)-1;
        for(uint64_t i=0;i<bytes;i++){
#if EFI_XNU_BUTTONS_AVAILABLE
            if(!(i&4095))buttons_poll();
#endif
            log_snapshot[at+i]=((const volatile uint8_t*)(uintptr_t)ring)[(begin+i)%EFI_XNU_LOG_SIZE];
        }
        at+=bytes;
    }
    *data=log_snapshot;*count=at;return at>0;
}
#if defined(EFI_XNU_SHUTDOWN_BRIDGE)
static struct polaris_shutdown_status shutdown_snapshot;
static int shutdown_status(void *context,const uint8_t **data,uint64_t *bytes)
{
    (void)context;if(load_state<4||cpu_status||!data||!bytes)return 0;
    volatile struct polaris_shutdown_slot *slot=(void*)(uintptr_t)(POLARIS_RAM_BASE+EFI_XNU_SHUTDOWN_OFFSET);
    invalidate((uintptr_t)&slot->kernel,sizeof(slot->kernel));
    bytes_copy(&shutdown_snapshot,(const void*)&slot->kernel,sizeof(shutdown_snapshot));
    *data=(const void*)&shutdown_snapshot;*bytes=sizeof(shutdown_snapshot);return 1;
}
static int shutdown_begin(void *context,unsigned mode)
{
    const uint8_t *data;uint64_t bytes;
    if((mode!=1&&mode!=2)||!shutdown_status(context,&data,&bytes))return 0;
    const struct polaris_shutdown_status *s=(const void*)data;
    if(!s->cookie||s->error)return 0;
#if defined(EFI_XNU_DURABLE_GUARD)
    if(s->flushed_epoch>s->write_epoch)return 0;
#else
    if(s->write_epoch||s->flushed_epoch)return 0;
#endif
    volatile struct polaris_shutdown_slot *slot=(void*)(uintptr_t)(POLARIS_RAM_BASE+EFI_XNU_SHUTDOWN_OFFSET);
    if(slot->firmware.sequence){
        return slot->firmware.sequence==1&&slot->firmware.cookie==s->cookie&&slot->firmware.mode==mode&&
            s->phase>=POLARIS_Q_RUNNING&&s->phase<=POLARIS_Q_SEALED;
    }
    if(s->phase!=POLARIS_Q_RUNNING||s->sequence||s->mode)return 0;
#if defined(EFI_XNU_DURABLE_GUARD)
    if(s->capabilities)return 0;
#else
    if(s->capabilities!=POLARIS_Q_RAM_CONFIG)return 0;
#endif
    bytes_zero((void*)&slot->firmware,sizeof(slot->firmware));
    slot->firmware.cookie=s->cookie;slot->firmware.mode=mode;
    __atomic_store_n(&slot->firmware.sequence,1,__ATOMIC_RELEASE);
    clean((uintptr_t)&slot->firmware,sizeof(slot->firmware));return 1;
}
static int shutdown_reset_ready(void *context,unsigned mode)
{
    const uint8_t *data;uint64_t bytes;
    if((mode!=1&&mode!=2)||!shutdown_status(context,&data,&bytes))return 0;
    volatile struct polaris_shutdown_slot *slot=(void*)(uintptr_t)(POLARIS_RAM_BASE+EFI_XNU_SHUTDOWN_OFFSET);
    const struct polaris_shutdown_status *s=(const void*)data;
#if defined(EFI_XNU_DURABLE_GUARD)
    return slot->firmware.mode==mode&&polaris_q_reset_ready(s,slot->firmware.cookie,
        slot->firmware.sequence,mode);
#else
    /* RAM-only approval is deliberately distinct from durable SAFE. */
    return polaris_q_ram_drained(s,slot->firmware.cookie,slot->firmware.sequence,mode)&&
        slot->firmware.mode==mode&&!polaris_q_reset_ready(s,slot->firmware.cookie,slot->firmware.sequence,mode);
#endif
}
#endif
static int prepare_reset(void *context,unsigned mode)
{
    (void)context;if(mode!=1&&mode!=2)return 0;
#if defined(EFI_XNU_WLED_POWER_CYCLE_ONLY)
    if(!wled_cycle_reset_ready())return 0;
#endif
#if defined(EFI_XNU_DURABLE_GUARD)
    if(load_state>=4&&!shutdown_reset_ready(context,mode))return 0;
#endif
    if(!system_table->runtime||!system_table->runtime->reset_system)return 0;
#if !defined(POLARIS_EFI_TEST_QEMU)
    /* Own phone's live DT restart_reason@65c within imem@146bf000. Vendor
     * msm-poweroff.c uses77665500 for bootloader,77665501 for normal reset.
     * This is a volatile reset marker, never a partition/NVRAM file write. */
    if(!identity(UINT64_C(0x146bf65c)))return 0;
    static const efi_guid pon_guid={0x97044b58,0xfea4,0x4ad0,{0x9d,0x0b,0xe4,0x17,0xd6,0x0f,0x11,0xa1}};
    reset_pon=0;
    efi_status s=system_table->boot->locate_protocol(&pon_guid,0,(void**)&reset_pon);
    if(s||!reset_pon||reset_pon->revision!=0x10001||!reset_pon->get||!reset_pon->set){
        reset_pon=0;if(mode==2)return 0;
    }
#endif
    return 1;
}
static void reset(void *context,unsigned mode)
{
    (void)context;
#if !defined(POLARIS_EFI_TEST_QEMU)
    volatile uint32_t *reason=(void*)(uintptr_t)UINT64_C(0x146bf65c);
    uint32_t before=*reason;
    struct polaris_efi_reset_marker marker={0};
    if(reset_pon){
        int valid=polaris_efi_pon_marker(reset_pon,mode,&marker);
        report("RESET_PON_STATUS=",marker.status);report("RESET_PON_BEFORE=",marker.before);
        report("RESET_PON_AFTER=",marker.after);
        if(!valid){report("RESET_PON_RESTORE=",marker.restore_status);return;}
    }else if(mode==2)return;
    uint32_t value=mode==2?0x77665500u:0x77665501u;*reason=value;
    __asm__ volatile("dsb sy":::"memory");if(*reason!=value){
        report("RESET_MARKER_FAILED=",*reason);
        if(reset_pon)report("RESET_PON_RESTORE=",reset_pon->set(0,3,marker.before,0xfe));
        *reason=before;__asm__ volatile("dsb sy":::"memory");return;
    }
#else
    (void)mode;
#endif
    report("RESET_REQUESTED=",mode);system_table->runtime->reset_system(0,0,0,0);
    report("RESET_RETURNED=",1);
#if !defined(POLARIS_EFI_TEST_QEMU)
    if(reset_pon)report("RESET_PON_RESTORE=",reset_pon->set(0,3,marker.before,0xfe));
    *reason=before;__asm__ volatile("dsb sy":::"memory");
#endif
}
static efi_status admission(void)
{
    uint64_t el,mpidr,sp;__asm__ volatile("mrs %0,CurrentEL":"=r"(el));__asm__ volatile("mrs %0,mpidr_el1":"=r"(mpidr));
    __asm__ volatile("mov %0,sp":"=r"(sp));report("EFI_EL=",el);report("EFI_MPIDR=",mpidr);
    report("EFI_CODE_IDENTITY=",identity((uintptr_t)admission));report("EFI_STACK_IDENTITY=",identity(sp));
    if(el!=4||(mpidr&UINT64_C(0xffffff))!=0||!identity((uintptr_t)admission)||!identity(sp))return EFI_ERROR|3;
    report("EFI_BOOT_OPTIONS_CAPTURE=",polaris_efi_boot_options_capture(system_table->runtime,&boot_inventory));
    struct efi_loaded *image=0;static const efi_guid loaded={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
    efi_status s=system_table->boot->handle_protocol(driver_image,&loaded,(void**)&image);
    report("EFI_LOADED_IMAGE=",s);if(image){report("EFI_IMAGE_BASE=",(uintptr_t)image->base);report("EFI_IMAGE_BYTES=",image->bytes);}
    if((s&EFI_ERROR)||!image||overlap((uintptr_t)image->base,image->bytes,POLARIS_RAM_BASE,POLARIS_RAM_SIZE)||
       overlap(sp,16,POLARIS_RAM_BASE,POLARIS_RAM_SIZE))return EFI_ERROR|3;
    uint64_t size=sizeof(map_snapshot.data),key=0,stride=0;uint32_t version=0;
    s=system_table->boot->get_map(&size,map_snapshot.data,&key,&stride,&version);struct polaris_efi_memory check;
    report("EFI_MAP_STATUS=",s);report("EFI_MAP_BYTES=",size);report("EFI_MAP_STRIDE=",stride);
    if((s&EFI_ERROR)||!polaris_efi_memory_check(map_snapshot.data,size,sizeof(map_snapshot.data),stride,&check))return EFI_ERROR|3;
    if(!polaris_efi_range_owned(map_snapshot.data,size,stride,POLARIS_RAM_BASE,POLARIS_RAM_SIZE,7))return EFI_ERROR|9;
    map_snapshot.magic=UINT64_C(0x3150414d49464550);map_snapshot.bytes=size;map_snapshot.stride=stride;map_snapshot.version=version;map_bytes=32+size;
    uint64_t address=POLARIS_RAM_BASE;s=system_table->boot->allocate_pages(2,2,POLARIS_RAM_SIZE/4096,&address);
    if((s&EFI_ERROR)||address!=POLARIS_RAM_BASE)return EFI_ERROR|9;report("XNU_BANK_CLAIMED=",address);
    /* Re-read the map after claiming: success alone is not an ownership map.
     * Refuse gaps, runtime pages or a page still reported as free/firmware. */
    size=sizeof(map_snapshot.data);
    s=system_table->boot->get_map(&size,map_snapshot.data,&key,&stride,&version);
    if((s&EFI_ERROR)||!polaris_efi_memory_check(map_snapshot.data,size,sizeof(map_snapshot.data),stride,&check))return EFI_ERROR|3;
    if(!polaris_efi_range_owned(map_snapshot.data,size,stride,POLARIS_RAM_BASE,POLARIS_RAM_SIZE,2))return EFI_ERROR|9;
    report("XNU_BANK_OWNERSHIP=",1);
    map_snapshot.bytes=size;map_snapshot.stride=stride;map_snapshot.version=version;map_bytes=32+size;
#if defined(POLARIS_EFI_TEST_QEMU)
    /* virt has no physical panel reservation. Claim the synthetic panel RAM
     * explicitly so subsequent firmware allocations cannot alias its pixels. */
    address=UINT64_C(0x9d400000);s=system_table->boot->allocate_pages(2,2,0x2400000/4096,&address);
    if((s&EFI_ERROR)||address!=UINT64_C(0x9d400000))return EFI_ERROR|9;
#endif
    address=POLARIS_RAM_BASE-1;s=system_table->boot->allocate_pages(1,2,(EFI_XNU_PAYLOAD_BYTES+4095)/4096,&address);
    if((s&EFI_ERROR)||address<UINT64_C(0x80000000)||address+EFI_XNU_PAYLOAD_BYTES>POLARIS_RAM_BASE)return EFI_ERROR|9;
    payload=(void*)(uintptr_t)address;
    s=system_table->boot->allocate_pool(2,32768+128+EFI_XNU_LOG_SIZE,(void**)&log_snapshot);if(s&EFI_ERROR)return s;
    static const efi_guid graphics={0x9042a9de,0x23dc,0x4a38,{0x96,0xfb,0x7a,0xde,0xd0,0x80,0x51,0x6a}};
    s=system_table->boot->locate_protocol(&graphics,0,(void**)&gop);
#if !defined(POLARIS_EFI_TEST_QEMU)
    if((s&EFI_ERROR)||!gop||!gop->mode||!gop->mode->info)return EFI_ERROR|3;
    struct polaris_gop_mode *m=gop->mode;struct polaris_gop_info *i=m->info;
    if(m->base!=UINT64_C(0x9d400000)||i->width!=1080||i->height!=2160||i->stride!=1080||i->format>1||m->bytes<UINT64_C(9331200))return EFI_ERROR|3;
#endif
    return 0;
}
static void disk_autoboot(void *context)
{
#if defined(EFI_XNU_DISK_GUID)
    if(load_state==2&&prepare_boot(context))boot_kernel(context);
#else
    (void)context;
#endif
}
static void host_activity(void *context)
{
#if defined(EFI_XNU_DURABLE_GUARD)
    if(load_state>=4)return;
#endif
    (void)context;uint64_t now;__asm__ volatile("mrs %0,cntvct_el0":"=r"(now));
    polaris_efi_ram_lease_activity(&ram_lease,now);
}
static void idle_guard(void *context)
{
#if defined(EFI_XNU_WLED_FAULT_WATCH)
    wled_fault_watch_poll();
#endif
#if defined(EFI_XNU_WLED_POWER_CYCLE_ONLY)
    wled_cycle_poll();
#endif
#if EFI_XNU_BUTTONS_AVAILABLE
    buttons_poll();
#endif
#if defined(EFI_XNU_DURABLE_GUARD)
    if(load_state>=4)return;
#endif
    uint64_t now,frequency;__asm__ volatile("mrs %0,cntvct_el0":"=r"(now));
    __asm__ volatile("mrs %0,cntfrq_el0":"=r"(frequency));
    if(polaris_efi_ram_lease_expired(&ram_lease,now,frequency)){
        report("RAM_HOST_LEASE_EXPIRED=",POLARIS_RAM_LEASE_SECONDS);
        if(prepare_reset(context,2))reset(context,2);
    }
}
static struct polaris_usb_control controls={.begin=begin,.write=write_payload,.finish=finish,
    .prepare_boot=prepare_boot,.boot=boot_kernel,.prepare_reset=prepare_reset,.reset=reset,
    .state=state,.logs=logs,.running=running,.touch=touch,.input_status=input_status,.boot_options=boot_options,
#if defined(EFI_XNU_SHUTDOWN_BRIDGE)
    .shutdown_status=shutdown_status,.shutdown_begin=shutdown_begin,.shutdown_reset_ready=shutdown_reset_ready,
#endif
    .autoboot=disk_autoboot,.idle_guard=idle_guard,.host_activity=host_activity};
#if defined(POLARIS_EFI_TEST_QEMU)
struct file {
    uint64_t revision;
    efi_status (*open)(struct file *,struct file **,const uint16_t *,uint64_t,uint64_t);
    efi_status (*close)(struct file *);void *remove;
    efi_status (*read)(struct file *,uint64_t *,void *);
};
struct fs {uint64_t revision;efi_status (*open)(struct fs *,struct file **);};
static int test_file_payload(void)
{
#if defined(EFI_XNU_DISK_GUID)
    return disk_payload();
#else
    static const efi_guid loaded={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
    static const efi_guid filesystem={0x964e5b22,0x6459,0x11d2,{0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b}};
    static const uint16_t name[]={'\\','P','A','Y','L','O','A','D','.','B','I','N',0};
    struct efi_loaded *image=0;struct fs *volume=0;struct file *root=0,*file=0;
    if(system_table->boot->handle_protocol(driver_image,&loaded,(void**)&image)&EFI_ERROR)return 0;
    if(!image||system_table->boot->handle_protocol(image->device,&filesystem,(void**)&volume)&EFI_ERROR)return 0;
    if(!volume||volume->open(volume,&root)&EFI_ERROR)return 0;
    efi_status s=root->open(root,&file,name,1,0);root->close(root);if(s&EFI_ERROR)return 0;
    uint64_t size=EFI_XNU_PAYLOAD_BYTES;if(!begin(0,size)){file->close(file);return 0;}
    s=file->read(file,&size,payload);uint8_t byte;uint64_t extra=1;
    efi_status tail=file->read(file,&extra,&byte);file->close(file);
    if((s&EFI_ERROR)||(tail&EFI_ERROR)||size!=EFI_XNU_PAYLOAD_BYTES||extra)return 0;
    received=size;return finish(0);
#endif
}
static void test_uart_text(const char *message)
{
    volatile uint32_t *uart=(void*)(uintptr_t)UINT64_C(0x9000000);
    while(*message){while(uart[6]&(1u<<5))__asm__ volatile("yield");uart[0]=(uint8_t)*message++;}
}
#if defined(EFI_XNU_RAM_DRAIN_TEST)
static void test_ram_drain(int stress_done,unsigned contact_phase)
{
    static uint64_t cookie;static unsigned sent,finished;
    if(finished||!stress_done||contact_phase!=3)return;
    volatile struct polaris_shutdown_slot *slot=(void*)(uintptr_t)(POLARIS_RAM_BASE+EFI_XNU_SHUTDOWN_OFFSET);
    struct polaris_shutdown_status s;
    invalidate((uintptr_t)&slot->kernel,sizeof(slot->kernel));
    bytes_copy(&s,(const void*)&slot->kernel,sizeof(s));
#if defined(EFI_XNU_OWNED_TEST)
    static unsigned protected;
    if(!protected){
        if(ram_lease.active||prepare_reset(0,1)||prepare_reset(0,2)){
            finished=1;test_uart_text("\nQEMU_OWNED_RESET_PROTECTION_FAILED=1\n");return;
        }
        protected=1;test_uart_text("\nQEMU_OWNED_RAW_AND_LEASE_DISABLED=1\n");
    }
#if defined(EFI_XNU_TEST_OMIT_OWNED_GUARD)
    if(!s.cookie&&s.phase==POLARIS_Q_OFF&&!s.write_epoch&&!s.flushed_epoch&&!s.capabilities){
        finished=1;test_uart_text("\nQEMU_OWNED_GUARD_ABSENT_REFUSED=1\n");
    }
    return;
#endif
    if(s.phase==POLARIS_Q_FAILED){
        if(s.cookie&&s.error&&!s.capabilities&&!ram_lease.active&&
           !shutdown_reset_ready(0,1)&&!shutdown_reset_ready(0,2)&&
           !prepare_reset(0,1)&&!prepare_reset(0,2)){
            finished=1;test_uart_text("\nQEMU_OWNED_REFUSED=1\n");
        }
        return;
    }
    if(!sent){
        if(!s.cookie||s.phase!=POLARIS_Q_RUNNING||s.error||s.sequence||s.mode||
           s.flushed_epoch||s.write_epoch!=1||s.capabilities)return;
        cookie=s.cookie;
        if(EFI_XNU_RAM_DRAIN_TEST==2){
            bytes_zero((void*)&slot->firmware,sizeof(slot->firmware));
            slot->firmware.cookie=cookie^UINT64_C(2);slot->firmware.mode=2;
            __atomic_store_n(&slot->firmware.sequence,1,__ATOMIC_RELEASE);
            clean((uintptr_t)&slot->firmware,sizeof(slot->firmware));
        }else if(!shutdown_begin(0,2))return;
        sent=1;test_uart_text("\nQEMU_OWNED_DRAIN_REQUESTED=1\n");
    }else if(s.cookie==cookie&&s.write_epoch==1&&s.flushed_epoch==1&&
             polaris_q_reset_ready(&s,cookie,1,2)&&shutdown_reset_ready(0,2)&&
             !shutdown_reset_ready(0,1)&&prepare_reset(0,2)&&!prepare_reset(0,1)&&!ram_lease.active){
        finished=1;test_uart_text("\nQEMU_OWNED_DURABLE_SAFE=1\n");
    }
#else
    if(!sent){
        if(!s.cookie||s.phase!=POLARIS_Q_RUNNING||s.error||s.sequence||s.mode||
           s.write_epoch||s.flushed_epoch||s.capabilities!=POLARIS_Q_RAM_CONFIG)return;
        cookie=s.cookie;
        if(EFI_XNU_RAM_DRAIN_TEST!=2){
            if(!shutdown_begin(0,2))return;
        }else{
            /* Only this emulator fault injection bypasses the common sender. */
            bytes_zero((void*)&slot->firmware,sizeof(slot->firmware));
            slot->firmware.cookie=cookie^UINT64_C(2);slot->firmware.mode=2;
            __atomic_store_n(&slot->firmware.sequence,1,__ATOMIC_RELEASE);
            clean((uintptr_t)&slot->firmware,sizeof(slot->firmware));
        }
        sent=1;test_uart_text("\nQEMU_RAM_DRAIN_REQUESTED=1\n");
    }else if(EFI_XNU_RAM_DRAIN_TEST==1&&polaris_q_ram_drained(&s,cookie,1,2)&&
             !polaris_q_reset_ready(&s,cookie,1,2)&&shutdown_reset_ready(0,2)&&!shutdown_reset_ready(0,1)){
        finished=1;test_uart_text("\nQEMU_RAM_DRAINED=1\n");
    }else if(s.phase==POLARIS_Q_FAILED){
        finished=1;
        if(s.cookie==cookie&&s.sequence==1&&s.mode==2&&s.error&&
           s.capabilities==POLARIS_Q_RAM_CONFIG&&!shutdown_reset_ready(0,2)&&
           !shutdown_reset_ready(0,1)&&!polaris_q_ram_drained(&s,cookie,1,2)){
            test_uart_text("\nQEMU_RAM_RESET_REFUSED=1\n");
        }
        if(EFI_XNU_RAM_DRAIN_TEST==3&&s.cookie==cookie&&s.sequence==1&&s.mode==2&&
           s.error&&s.capabilities==POLARIS_Q_RAM_CONFIG&&!shutdown_reset_ready(0,2)&&
           !shutdown_reset_ready(0,1)&&!polaris_q_ram_drained(&s,cookie,1,2)){
            test_uart_text("\nQEMU_RAM_PEER_OFF_REFUSED=1\n");return;
        }
        test_uart_text(EFI_XNU_RAM_DRAIN_TEST==2&&s.cookie==cookie&&s.error&&
            s.capabilities==POLARIS_Q_RAM_CONFIG?"\nQEMU_RAM_DRAIN_STALE_REFUSED=1\n":
            "\nQEMU_RAM_DRAIN_FAILED=1\n");
    }
#endif
}
#endif
static void test_monitor(void)
{
    uint64_t position=0,last=0;unsigned contact_phase=0;
#if EFI_XNU_BUTTONS_AVAILABLE
    unsigned keys_reported=0;
#endif
#if defined(EFI_XNU_WLED_POWER_CYCLE_ONLY)
    unsigned cycle_reset_checked=0,cycle_final_checked=0;
#endif
#if defined(EFI_XNU_RAM_DRAIN_TEST)
    int stress_done=0;
#endif
    volatile uint32_t *uart=(void*)(uintptr_t)UINT64_C(0x9000000);
    for(;;){
        uint64_t now;__asm__ volatile("mrs %0,cntvct_el0":"=r"(now));
#if defined(EFI_XNU_WLED_FAULT_WATCH)
        wled_fault_watch_poll();
#endif
#if defined(EFI_XNU_WLED_POWER_CYCLE_ONLY)
        wled_cycle_poll();
        if(cycle_stage==1&&!cycle_reset_checked) {
            cycle_reset_checked=1;
            report("WLED_POWER_OFF_RESET_REFUSED=",!prepare_reset(0,1)&&!prepare_reset(0,2));
        }
        if(cycle_done&&!cycle_final_checked) {
            cycle_final_checked=1;
            report("WLED_POWER_FINAL_RESET_ALLOWED=",prepare_reset(0,1)&&prepare_reset(0,2));
            report("WLED_POWER_FINAL_ERROR=",cycle_power.error);
            report("WLED_POWER_FINAL_UNCERTAIN=",cycle_power.uncertain);
            text("WLED_POWER_MODEL_HOLD: NO_CPU_ON\r\n");
        }
#endif
#if EFI_XNU_BUTTONS_AVAILABLE
        buttons_poll();
#endif
        if(now-last<6250000){__asm__ volatile("yield");continue;}last=now;
#if EFI_XNU_BUTTONS_AVAILABLE
        if(buttons_qemu_passed&&!keys_reported){
            test_uart_text("\nQEMU_PHYSICAL_KEY_CONSUMER=1\n");keys_reported=1;
        }
#endif
        const uint8_t *data;uint64_t bytes;
        if(logs(0,&data,&bytes)&&bytes>position){
            for(uint64_t i=position;i<bytes;i++){while(uart[6]&(1u<<5))__asm__ volatile("yield");uart[0]=data[i];}
#if defined(EFI_XNU_RAM_DRAIN_TEST)
            static const char marker[]="SMP STRESS all4 PASS";
            for(uint64_t i=0;i+sizeof(marker)-1<=bytes&&!stress_done;i++){
                unsigned j=0;while(j<sizeof(marker)-1&&data[i+j]==(uint8_t)marker[j])j++;
                if(j==sizeof(marker)-1)stress_done=1;
            }
#endif
            position=bytes;
        }
        struct polaris_uefi_input_status s;
        if(input_status(0,&s)&&s.ready&&!s.error){
            if(contact_phase==0&&s.request==0&&s.acknowledged==0&&touch(0,1,540,1080))contact_phase=1;
            else if(contact_phase==1&&s.request==1&&s.acknowledged==1&&touch(0,0,540,1080))contact_phase=2;
            else if(contact_phase==2&&s.request==2&&s.acknowledged==2){
                test_uart_text("\nQEMU_INPUT_BRIDGE=1\n");
                contact_phase=3;
            }
        }
#if defined(EFI_XNU_RAM_DRAIN_TEST)
#if EFI_XNU_BUTTONS_AVAILABLE
        /* Shutdown must not cut the real six-edge native fixture short. */
        test_ram_drain(stress_done&&buttons_qemu_passed,contact_phase);
#else
        test_ram_drain(stress_done,contact_phase);
#endif
#endif
    }
}
#endif
/* The RAM chain wrapper exercises the actual installed EFI application. It
 * never claims the kernel bank; the selected application owns admission.
 * Refuse a PE allocation overlapping that bank before calling StartImage. */
#if defined(POLARIS_EFI_CHAIN_APP)
static efi_status chain_disk_application(void)
{
    static const uint8_t guid[16]=EFI_XNU_DISK_GUID;
    static const uint16_t name[]=EFI_XNU_CHAIN_PATH;
    static struct polaris_efi_disk_result result;static uint8_t path[4352];
    uint8_t *source=0;efi_handle child=0;struct efi_boot *bs=system_table->boot;
    efi_status s=bs->allocate_pool(2,EFI_XNU_CHAIN_BYTES,(void**)&source);if(s||!source)return s?s:EFI_ERROR|9;
    int ok=polaris_efi_read_disk(bs,guid,EFI_XNU_DISK_START,EFI_XNU_DISK_BLOCKS,name,
                                source,EFI_XNU_CHAIN_BYTES,&result);
    report("CHAIN_READ_STATUS=",result.status);report("CHAIN_FILES_CLOSED=",result.closed);
    if(!ok||polaris_efi_crc32(source,EFI_XNU_CHAIN_BYTES)!=EFI_XNU_CHAIN_CRC32||
       !polaris_efi_file_path(&result,name,path,sizeof(path))){bs->free_pool(source);return EFI_ERROR|3;}
    s=bs->load_image(0,driver_image,path,source,EFI_XNU_CHAIN_BYTES,&child);
    efi_status closed=bs->free_pool(source);report("CHAIN_LOAD_IMAGE=",s);if(s||closed||!child)return s?s:closed?closed:EFI_ERROR|3;
    static const efi_guid loaded={0x5b1b31a1,0x9562,0x11d2,{0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b}};
    struct efi_loaded *image=0;s=bs->handle_protocol(child,&loaded,(void**)&image);
    if(s||!image||image->code_type!=1||overlap((uintptr_t)image->base,image->bytes,POLARIS_RAM_BASE,POLARIS_RAM_SIZE))return EFI_ERROR|3;
    report("CHAIN_IMAGE_BASE=",(uintptr_t)image->base);
    uint64_t size=sizeof(map_snapshot.data),key=0,stride=0;uint32_t version=0;struct polaris_efi_memory check;
    s=bs->get_map(&size,map_snapshot.data,&key,&stride,&version);
    if(s||!polaris_efi_memory_check(map_snapshot.data,size,sizeof(map_snapshot.data),stride,&check)||
       !polaris_efi_range_owned(map_snapshot.data,size,stride,POLARIS_RAM_BASE,POLARIS_RAM_SIZE,7))return EFI_ERROR|9;
    report("CHAIN_APP_START=",1);return bs->start_image(child,0,0);
}
#endif
#if !defined(POLARIS_EFI_TEST_QEMU)
static const char *rescue_state(void *context){(void)context;return "admission-refused";}
static int rescue_logs(void *context,const uint8_t **data,uint64_t *bytes)
{(void)context;*data=log_buffer;*bytes=log_bytes;return log_bytes>0;}
static void rescue_service(void)
{
    struct polaris_usb_control rescue={.prepare_reset=prepare_reset,.reset=reset,.state=rescue_state,.logs=rescue_logs};
    report("RESCUE_USB_RESULT=",polaris_efi_usb_serve_control(system_table,log_buffer,&log_bytes,0,0,report,&rescue));
    /* A refused admission never starts the kernel. If even the USB protocol
     * cannot initialize, use the already-proven PON FASTBOOT reset directly. */
    if(prepare_reset(0,2))reset(0,2);
}
#endif
static void ready(void *event,void *context)
{
    (void)event;(void)context;system_table->boot->restore_tpl(4);
    text("POLARIS UEFI XNU: RAM-only resident bridge\r\n");system_table->boot->watchdog(0,0,0,0);
#if defined(POLARIS_EFI_CHAIN_APP)
    efi_status chain=chain_disk_application();report("CHAIN_APP_RETURN=",chain);
#if !defined(POLARIS_EFI_TEST_QEMU)
    rescue_service();
#endif
    for(;;)system_table->boot->stall(1000000);
#endif
    efi_status s=admission();report("XNU_ADMISSION=",s);
#if defined(POLARIS_EFI_TEST_QEMU)
    if(!(s&EFI_ERROR)){
        int valid=test_file_payload();report("QEMU_PAYLOAD_VALID=",valid);
        if(valid&&prepare_boot(0)){boot_kernel(0);test_monitor();}
    }
#else
    if(!(s&EFI_ERROR)){
#if defined(EFI_XNU_DISK_GUID)
        report("DISK_PAYLOAD_VALID=",disk_payload());
#endif
        report("USB_BRIDGE_RESULT=",polaris_efi_usb_serve_control(system_table,log_buffer,&log_bytes,(void*)&map_snapshot,map_bytes,report,&controls));
        if(prepare_reset(0,2))reset(0,2);
    }else rescue_service();
#endif
    for(;;)system_table->boot->stall(1000000);
}
efi_status EfiMain(efi_handle image,struct efi_system *st)
{
    if(!st||st->hdr.signature!=UINT64_C(0x5453595320494249)||!st->boot||st->boot->hdr.size<376)return EFI_ERROR|2;
    system_table=st;driver_image=image;void *event=0;
#if defined(POLARIS_EFI_TEST_QEMU) || defined(POLARIS_EFI_APPLICATION)
    (void)event;(void)controls;ready(0,0);
#endif
    static const efi_guid group={0x7ce88fb3,0x4bd7,0x4679,{0x87,0xa8,0xa8,0xd8,0xde,0xe5,0x0d,0x2b}};
    efi_status s=st->boot->create_event_ex(0x200,8,ready,0,&group,&event);
    if(s&EFI_ERROR)ready(0,0);return s;
}
