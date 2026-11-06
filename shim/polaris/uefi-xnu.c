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
#ifndef EFI_XNU_WIFI_NATIVE_RUNTIME_AVAILABLE
#define EFI_XNU_WIFI_NATIVE_RUNTIME_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_NATIVE_RUNTIME_AVAILABLE
#if !EFI_XNU_WIFI_NATIVE_MEMORY_AVAILABLE || !EFI_XNU_WIFI_WORKER_NATIVE_AVAILABLE || !EFI_XNU_WIFI_NONCE_POOL_AVAILABLE
#error "Native radio runtime requires independent memory, worker and candidate nonce inputs"
#endif
#if !defined(EFI_XNU_WIFI_MAILBOX_VA) || !defined(EFI_XNU_WIFI_COUNTRY) || EFI_XNU_WIFI_COUNTRY != 36 || EFI_XNU_CPU != 0x700
#error "Native radio runtime requires the linked mailbox symbol, explicit AU profile and CPU700"
#endif
#if !EFI_XNU_WIFI_UI_NATIVE_AVAILABLE
#error "Native radio runtime requires serialized keys/display and terminal restoration"
#endif
#if !EFI_XNU_WIFI_SYSTEM_OFF_NATIVE_AVAILABLE || !defined(EFI_XNU_WIFI_SHUTDOWN_VA) || !EFI_XNU_SHUTDOWN_BRIDGE
#error "Native radio runtime requires its terminal continuation and linked kernel shutdown slot"
#endif
#endif
#ifndef EFI_XNU_WIFI_NATIVE_MEMORY_AVAILABLE
#define EFI_XNU_WIFI_NATIVE_MEMORY_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_NATIVE_MEMORY_AVAILABLE
#if !EFI_XNU_MSS_MBA_SHARE_AVAILABLE || !EFI_XNU_WIFI_NV_NATIVE_AVAILABLE || !EFI_XNU_WIFI_CE_MEMORY_AVAILABLE
#error "Native radio memory requires the actual independent MSS, fresh NV and DMA producers"
#endif
#endif
#ifndef EFI_XNU_WIFI_NONCE_POOL_AVAILABLE
#define EFI_XNU_WIFI_NONCE_POOL_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_NONCE_POOL_AVAILABLE
#if !EFI_XNU_MSS_MBA_SHARE_AVAILABLE
#error "Nonce input requires the actual independent MSS staging parent"
#endif
#include "uefi-wifi-image-nonce-pool.h" /* private per-candidate generated input */
#endif
#if defined(_WIN32) && EFI_XNU_MSS_PAYLOAD_FIRMWARE_AVAILABLE
/* Keep resident zero-initialized storage virtual. The UEFI linker merges
 * ordinary .bss into .data before .rdata, otherwise serializing the zeros. */
#pragma clang section bss=".mssbss"
#endif
#ifndef EFI_XNU_WIFI_EARLY_MEMORY_AVAILABLE
#define EFI_XNU_WIFI_EARLY_MEMORY_AVAILABLE 0
#endif
#ifndef EFI_XNU_MSS_MEMORY_AVAILABLE
#define EFI_XNU_MSS_MEMORY_AVAILABLE 0
#endif
#ifndef EFI_XNU_MSS_STAGING_AVAILABLE
#define EFI_XNU_MSS_STAGING_AVAILABLE 0
#endif
#ifndef EFI_XNU_MSS_MBA_SHARE_AVAILABLE
#define EFI_XNU_MSS_MBA_SHARE_AVAILABLE 0
#endif
#if EFI_XNU_MSS_MBA_SHARE_AVAILABLE && !EFI_XNU_MSS_STAGING_AVAILABLE
#error "MBA assignment requires the actual staging parent"
#endif
#if EFI_XNU_MSS_STAGING_AVAILABLE && !EFI_XNU_MSS_MEMORY_AVAILABLE
#error "MSS staging requires actual MSS allocations"
#endif
#if EFI_XNU_MSS_MEMORY_AVAILABLE && !EFI_XNU_WIFI_EARLY_MEMORY_AVAILABLE
#error "MSS memory requires the actual early memory parent"
#endif
#if EFI_XNU_WIFI_EARLY_MEMORY_AVAILABLE && (!EFI_XNU_WIFI_FOUR_VRM_AVAILABLE || !EFI_XNU_WIFI_TERMINAL_GOP_DIAGNOSTICS || !EFI_XNU_AUDIO_CLOCK_GCD_QUERY_AVAILABLE || !EFI_XNU_GCD_MMIO_QUERY_AVAILABLE || !EFI_XNU_WIFI_RESOURCES_AVAILABLE || EFI_XNU_WIFI_CPU_RO_ADMISSION || defined(POLARIS_EFI_TEST_QEMU))
#error "Early WiFi memory needs its own qualified physical incoming-UEFI profile"
#endif
#if EFI_XNU_WIFI_REMOTE_MEMORY_AVAILABLE && (!EFI_XNU_WIFI_FOUR_VRM_AVAILABLE || !EFI_XNU_AUDIO_CLOCK_GCD_QUERY_AVAILABLE || !EFI_XNU_GCD_MMIO_QUERY_AVAILABLE || !EFI_XNU_WIFI_RESOURCES_AVAILABLE || EFI_XNU_WIFI_CPU_RO_ADMISSION || defined(POLARIS_EFI_TEST_QEMU))
#error "Incoming parent map evidence requires the complete physical WiFi source scope"
#endif
#if EFI_XNU_WIFI_REMOTE_MEMORY_AVAILABLE
#define POLARIS_WIFI_PARENT_IMAGE_LEDGER 1
#define POLARIS_WIFI_PARENT_GCD_BOOTSTRAP 1
#define POLARIS_WIFI_CURRENT_GRAPH_INPUT 1
#define POLARIS_WIFI_CURRENT_TIMER_INPUT 1
#endif
#if defined(EFI_XNU_WLED_NATIVE_RUNTIME_TEST) || defined(EFI_XNU_WLED_NATIVE_RUNTIME_PHYSICAL)
#define EFI_XNU_WLED_NATIVE_RUNTIME 1
#endif
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
#if EFI_XNU_WIFI_CPU_RO_ADMISSION
static uint8_t log_buffer[1048576];static uint64_t log_bytes;
static volatile uint32_t log_overflow;
#elif EFI_XNU_WIFI_REMOTE_MEMORY_AVAILABLE
static uint8_t log_buffer[58720256];static uint64_t log_bytes;
static volatile uint32_t log_overflow;
#elif EFI_XNU_MSS_STAGING_AVAILABLE
static uint8_t log_buffer[13631488];static uint64_t log_bytes;
static volatile uint32_t log_overflow;
#elif EFI_XNU_MSS_MEMORY_AVAILABLE
static uint8_t log_buffer[12582912];static uint64_t log_bytes;
static volatile uint32_t log_overflow;
#elif EFI_XNU_WIFI_EARLY_MEMORY_AVAILABLE
static uint8_t log_buffer[11534336];static uint64_t log_bytes;
static volatile uint32_t log_overflow;
#elif EFI_XNU_WIFI_FOUR_VRM_AVAILABLE
static uint8_t log_buffer[10747904];static uint64_t log_bytes;
static volatile uint32_t log_overflow;
#elif EFI_XNU_WIFI_PREPARED_POWER_AVAILABLE
static uint8_t log_buffer[10485760];static uint64_t log_bytes;
static volatile uint32_t log_overflow;
#elif EFI_XNU_WIFI_POWER_TRANSACTION_AVAILABLE
static uint8_t log_buffer[8388608];static uint64_t log_bytes;
static volatile uint32_t log_overflow;
#elif EFI_XNU_WIFI_RPMH_CLIENT_AVAILABLE
static uint8_t log_buffer[2097152];static uint64_t log_bytes;
static volatile uint32_t log_overflow;
#elif EFI_XNU_WIFI_NPA_READONLY_AVAILABLE
static uint8_t log_buffer[1572864];static uint64_t log_bytes;
static volatile uint32_t log_overflow;
#elif EFI_XNU_GCD_MMIO_QUERY_AVAILABLE
static uint8_t log_buffer[262144];static uint64_t log_bytes;
static volatile uint32_t log_overflow;
#elif EFI_XNU_WIFI_RESOURCES_AVAILABLE
static uint8_t log_buffer[131072];static uint64_t log_bytes;
static volatile uint32_t log_overflow;
#else
static uint8_t log_buffer[32768];static uint64_t log_bytes;
#endif
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
#if (EFI_XNU_WIFI_POWER_TRANSACTION_AVAILABLE || EFI_XNU_WIFI_CPU_RO_ADMISSION) && !defined(POLARIS_EFI_TEST_QEMU)
static int new_original_unknown(void);
#endif
static struct polaris_efi_ram_lease ram_lease;
static int64_t cpu_status;
#if EFI_XNU_WIFI_NATIVE_RUNTIME_AVAILABLE
static uint32_t wifi_native_boot_phase;
#if EFI_XNU_WIFI_TERMINAL_GOP_DIAGNOSTICS
static void wifi_native_startup_gop_evidence(void);
#endif
#endif
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
#if EFI_XNU_WIFI_RESOURCES_AVAILABLE
        else log_overflow=1;
#endif
        if(at<127)wide[at++]=(uint8_t)*s;s++;
    }
    wide[at]=0;
    if(load_state<4 && system_table&&system_table->out
#if EFI_XNU_WIFI_NATIVE_RUNTIME_AVAILABLE
        &&!wifi_native_boot_phase /* Native staging/UI diagnostics are RAM-only. */
#endif
#if (EFI_XNU_WIFI_POWER_TRANSACTION_AVAILABLE || EFI_XNU_WIFI_CPU_RO_ADMISSION) && !defined(POLARIS_EFI_TEST_QEMU)
        &&!new_original_unknown()
#endif
    )system_table->out->string(system_table->out,wide);
}
static void report(const char *name,uint64_t value)
{
    char buf[19]={'0','x'};for(unsigned i=0;i<16;i++)buf[2+i]="0123456789abcdef"[(value>>(60-i*4))&15];
    buf[18]=0;text(name);text(buf);text("\r\n");
}
#if EFI_XNU_WIFI_RESOURCES_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
/* New bulk witnesses stay in RAM. They never enter OutputString and cannot
 * consume a WLED terminal-receipt/200ms interval. Reserve each append in full;
 * overflow is sticky and logs() explicitly reports an incomplete prefix. */
static void ram_text(const char *s)
{
    uint64_t n=0;while(s[n])n++;
    if(log_bytes>sizeof(log_buffer)||n>sizeof(log_buffer)-log_bytes){log_overflow=1;return;}
    bytes_copy(log_buffer+log_bytes,s,n);log_bytes+=n;
}
static void ram_report(const char *name,uint64_t value)
{
    char buf[19]={'0','x'};for(unsigned i=0;i<16;i++)buf[2+i]="0123456789abcdef"[(value>>(60-i*4))&15];
    buf[18]=0;ram_text(name);ram_text(buf);ram_text("\r\n");
}
static void ram_hex(const uint8_t *raw,uint64_t bytes)
{
    if(bytes>UINT64_MAX/3||log_bytes>sizeof(log_buffer)||bytes*2+2*((bytes+63)/64)>sizeof(log_buffer)-log_bytes){log_overflow=1;return;}
    for(uint64_t n=0;n<bytes;n++){
        log_buffer[log_bytes++]="0123456789abcdef"[raw[n]>>4];
        log_buffer[log_bytes++]="0123456789abcdef"[raw[n]&15];
        if((n&63)==63||n+1==bytes){log_buffer[log_bytes++]='\r';log_buffer[log_bytes++]='\n';}
    }
}
#endif
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
#if EFI_XNU_HOST_UTC_AVAILABLE
#include "../../tools/polaris-clock-uefi.h"
static struct pc_fw host_utc_context;
static uint64_t host_utc_counter(void *context)
{ (void)context;uint64_t n;__asm__ volatile("isb; mrs %0,cntvct_el0":"=r"(n)::"memory");return n; }
static uint64_t host_utc_frequency(void *context)
{ (void)context;uint64_t n;__asm__ volatile("mrs %0,cntfrq_el0":"=r"(n));return n; }
static void host_utc_clean(void *context,uintptr_t address,size_t bytes)
{ (void)context;clean(address,bytes); }
static void host_utc_invalidate(void *context,uintptr_t address,size_t bytes)
{ (void)context;invalidate(address,bytes); }
static int host_utc_prepare(void)
{
    const struct pc_fw_io io={host_utc_counter,host_utc_frequency,host_utc_clean,host_utc_invalidate,0};
    uint64_t address=POLARIS_RAM_BASE+EFI_XNU_HOST_UTC_OFFSET;
    if(cache_line()>128 || !identity_range(address,256))return 0;
    return pc_fw_prepare(&host_utc_context,(void*)(uintptr_t)address,
        host_utc_counter(0)|UINT64_C(1),&io,true);
}
static int host_utc_command(void *context,const uint8_t *command,uint64_t bytes,uint8_t out[60],uint64_t *count)
{
    (void)context;*count=0;
    if(load_state!=4 || cpu_status)return 0;
    invalidate((uintptr_t)&polaris_efi_ap_state,sizeof(polaris_efi_ap_state));
    if(polaris_efi_ap_state.stage!=1)return 0;
    size_t result=0;int ok=pc_fw_command(&host_utc_context,(const char*)command,(size_t)bytes,out,&result);
    *count=result;return ok;
}
#endif
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
#if defined(EFI_XNU_WLED_NATIVE_RUNTIME)
#if defined(EFI_XNU_WLED_POWER_CYCLE_ONLY) || defined(EFI_XNU_WLED_INVENTORY_ONLY) || defined(EFI_XNU_DURABLE_GUARD)
#error "Runtime WLED must not reuse pre-XNU or durable-write admission"
#endif
static int prepare_reset(void *,unsigned);
static int runtime_arm_reset(unsigned);
static int runtime_unarm_reset(void);
static int cache_reset_protocol(void);
static int shutdown_reset_ready(void *,unsigned);
static int shutdown_status(void *,const uint8_t **,uint64_t *);
#include "uefi-wled-native.h"
#endif
#if EFI_XNU_BATTERY_AVAILABLE
#include "uefi-battery-native.h"
#endif
#if EFI_XNU_WIFI_CACHE_AVAILABLE
#if !defined(EFI_XNU_WLED_NATIVE_RUNTIME)
#error "Firmware image cache inspection requires its guarded native runtime scope"
#endif
#if !defined(POLARIS_EFI_TEST_QEMU)
#include "uefi-wifi-cache-readonly.h"
#if EFI_XNU_WIFI_FIRSTREAD_AVAILABLE
#include "uefi-wifi-firstread.h"
#endif
#if EFI_XNU_WIFI_NORMAL_NC_FIRSTREAD_AVAILABLE
#include "uefi-wifi-firstread-normal-nc.h"
#endif
#if EFI_XNU_WIFI_RESOURCES_AVAILABLE
#include "uefi-wifi-resources-readonly.h"
#endif
#endif
#endif
#if EFI_XNU_AUDIO_I2C_CACHE_AVAILABLE
#if !defined(EFI_XNU_WLED_NATIVE_RUNTIME)
#error "Audio image cache inspection requires guarded native runtime"
#endif
#if !defined(POLARIS_EFI_TEST_QEMU)
#include "uefi-audio-i2c-cache.h"
#endif
#endif
#if EFI_XNU_AUDIO_CLOCK_GCD_QUERY_AVAILABLE
#if !EFI_XNU_GCD_MMIO_QUERY_AVAILABLE || !EFI_XNU_WIFI_RESOURCES_AVAILABLE || !EFI_XNU_AUDIO_CLOCK_QUERY_AVAILABLE
#error "NEW GCD/Clock requires its exact combined original-resource scope"
#endif
#if !defined(POLARIS_EFI_TEST_QEMU)
/* Outer include gate removes every new physical/query/FP body from QEMU. */
#include "uefi-gcd-mmio-readonly.h"
#if EFI_XNU_WIFI_EARLY_MEMORY_AVAILABLE
#include "uefi-wifi-retained-memory.h"
static struct pwea_native early_wifi_memory;
static uint8_t early_wifi_digest[32];
static struct pweh_result retained_wifi_memory;
#if EFI_XNU_MSS_MEMORY_AVAILABLE
#include "uefi-mss-memory.h"
static struct pmmn_native mss_memory;
static uint8_t mss_memory_digest[32];
static uint32_t mss_retained_attempted,mss_retained_ok;
#if EFI_XNU_MSS_STAGING_AVAILABLE
#include "uefi-mss-stage.h"
#include "uefi-mss-firmware-binding.h"
static struct pmsi_result mss_stage;
#if EFI_XNU_MSS_MBA_SHARE_AVAILABLE
#include "uefi-mss-mba-share.h"
static struct pmsb_result mss_mba_share;
#if EFI_XNU_WIFI_NATIVE_MEMORY_AVAILABLE
#include "uefi-wifi-nv-native.h"
#include "uefi-wifi-ce-memory-native.h"
#include "uefi-wifi-kernel-stage.h"
#include "own-nv-plan.h" /* private generated GPT geometry; no NV contents */
static struct pnnv_state wifi_native_nv;
static struct pcdm_state wifi_native_ce_memory,wifi_native_htt_memory;
static struct pwks_image wifi_native_kernel_copy;
static uint32_t wifi_native_memory_stage;
#endif
#endif
#endif
#endif
#endif
#if EFI_XNU_WIFI_REMOTE_MEMORY_AVAILABLE
#if !EFI_XNU_WIFI_FOUR_VRM_AVAILABLE || EFI_XNU_WIFI_CPU_RO_ADMISSION
#error "Incoming parent map evidence requires the new physical full WiFi parent scope"
#endif
#include "uefi-wifi-remote-memory.h"
#include "uefi-wifi-current-map.h"
#include "uefi-wifi-gcd-bootstrap.h"
#include "uefi-wifi-current-graph.h"
#include "uefi-wifi-current-provider.h"
#include "uefi-wifi-current-events.h"
#include "uefi-wifi-cache-allocation.h"
#include "uefi-wifi-cache-release.h"
#include "uefi-wifi-cache-dispatch.h"
static struct pwmc_parent_map incoming_parent_maps[2];
static struct pwmc_parent_map pbgi_cache_call;
static struct pbgi_result pbgi_seed;
static struct pbha_result pbha_handles;
static struct pbhr_result pbhr_handles;
static struct pbhd_result pbhd_handles;
static struct pbhd_timer_result pbhd_timer_handles;
static struct pbhi_result pbhi_handles;
static struct pbht_result pbht_handles;
static uint64_t pbgi_cache_opening;
static struct pcmp_payload current_payload_binding;
static struct pcmp_result current_private_maps[PCMP_PARENT_CONTEXTS][2];
static struct pcmg_result current_private_graphs[PCMP_PARENT_CONTEXTS][2];
static struct pcmi_result current_private_providers[PCMP_PARENT_CONTEXTS][2];
static struct pcmt_result current_private_timers[PCMP_PARENT_CONTEXTS][2];
static struct pcme_result current_private_events[PCMP_PARENT_CONTEXTS][2];
static struct pcmp_route_fault current_private_fault;
static struct pgcd_io current_private_original_io;
#endif
#include "uefi-audio-clock-gcd-query.h"
#if EFI_XNU_WIFI_REMOTE_MEMORY_AVAILABLE
#if !EFI_XNU_WIFI_CMDDB_STAGED_RO_AVAILABLE || !EFI_XNU_WIFI_RPMH_CLIENT_AVAILABLE
#error "Parent map dispatch requires its exact four preparation and one client constructors"
#endif
static const struct pcmp_route current_private_routes[PCMP_PARENT_CONTEXTS]={
    {&pgcd_resident_context,&pgcd_record,&pgcd_ticket,current_private_maps[0],PCMP_QUERY_PAIR,0},
    {&pwsp_record.phase[0].context,&pwsp_record.phase[0].core,&pwsp_record.phase[0].ticket,current_private_maps[1],PCMP_PREPARATION_PAIR,0},
    {&pwsp_record.phase[1].context,&pwsp_record.phase[1].core,&pwsp_record.phase[1].ticket,current_private_maps[2],PCMP_PREPARATION_PAIR,0},
    {&pwsp_record.phase[2].context,&pwsp_record.phase[2].core,&pwsp_record.phase[2].ticket,current_private_maps[3],PCMP_PREPARATION_PAIR,0},
    {&pwsp_record.phase[3].context,&pwsp_record.phase[3].core,&pwsp_record.phase[3].ticket,current_private_maps[4],PCMP_PREPARATION_PAIR,0},
    {&pwrcl_early_context,&pwrcl_record.core,&pwrcl_record.core_ticket,current_private_maps[5],PCMP_CLIENT_OPEN,0}
};
static int current_private_unknown(void)
{
    if(current_private_fault.unknown)return 1;
    for(unsigned n=0;n<PCMP_PARENT_CONTEXTS;n++)for(unsigned k=0;k<2;k++)
        if(current_private_maps[n][k].unknown||current_private_graphs[n][k].unknown||current_private_providers[n][k].unknown||
           current_private_timers[n][k].unknown||current_private_events[n][k].unknown)return 1;
    return 0;
}
#endif
#if EFI_XNU_WIFI_TERMINAL_GOP_DIAGNOSTICS
#if !EFI_XNU_WIFI_READ_DB_CHECKPOINT && !EFI_XNU_WIFI_CURRENT_WORD_READ
#error "Terminal GOP evidence requires its distinct masked database diagnostic"
#endif
#include "uefi-wifi-terminal-gop.h"
struct terminal_gop_result {
    struct pwtg_result pixels;struct pgcd_fp_guard map_FP;
    struct pwtg_arch map_before,map_after;
    uint64_t map_function;uint32_t map_issued,map_returned,uncertain;
};
static struct terminal_gop_result terminal_gop;
#if EFI_XNU_WIFI_EARLY_MEMORY_AVAILABLE
/* Independent incoming GOP binding: early allocation precedes prepare_boot,
 * where the later power diagnostic obtains its own fresh map and binding. */
static struct pwtg_result early_wifi_gop;
static void early_wifi_gop_raw(void)
{
    ram_report("EARLY_WIFI_GOP_RAW_V1_BYTES=",sizeof(early_wifi_gop));
    ram_text("EARLY_WIFI_GOP_RAW_V1_BEGIN\r\n");ram_hex((const void*)&early_wifi_gop,sizeof(early_wifi_gop));
    ram_text("EARLY_WIFI_GOP_RAW_V1_END\r\n");
}
static int early_wifi_gop_bind(const struct efi_loaded*image,uint64_t key)
{
    struct pwtg_result*r=&early_wifi_gop;
    if(r->attempted||!key||!image||!pgcd_record.self_bound||
       pgcd_record.self_base!=(uintptr_t)image->base||pgcd_record.self_bytes!=image->bytes||
       !map_snapshot.bytes||map_snapshot.bytes>sizeof(r->map))return 0;
    r->map_key=key;r->map_bytes=map_snapshot.bytes;r->map_stride=map_snapshot.stride;r->map_version=map_snapshot.version;
    bytes_copy(r->map,map_snapshot.data,map_snapshot.bytes);
    return pwtg_arm(r,(uintptr_t)gop,(uintptr_t)&wln_cpu_on_issued,(uintptr_t)image->base,image->bytes);
}
static void early_wifi_gop_evidence(void)
{
    struct pwtg_result*r=&early_wifi_gop;const struct pwea_memory*m=&early_wifi_memory.memory;
    if(r->native_address!=(uintptr_t)&wln_cpu_on_issued||r->self_base!=pgcd_record.self_base||
       r->self_bytes!=pgcd_record.self_bytes||r->headers.address[0]!=(uintptr_t)gop){
        (void)pwtg_fail(r,PWTG_ARGUMENT);early_wifi_gop_raw();return;
    }
    pwtg_line(r,0,"EARLY HOLD",early_wifi_memory.attempted,early_wifi_memory.error);
    pwtg_line(r,1,"MEM CALL E",m->calls,m->error);
    pwtg_line(r,2,"CLAIM0 S LO",(uint32_t)(m->claim[0].status>>32),(uint32_t)m->claim[0].status);
    pwtg_line(r,3,"CLAIM1 S LO",(uint32_t)(m->claim[1].status>>32),(uint32_t)m->claim[1].status);
    for(unsigned n=0;n<5;n++){
        const struct pwea_native_call*c=&early_wifi_memory.call[n];
        pwtg_line(r,4+n,"CALL IR CU",(c->issued<<24)|(c->returned<<16)|(c->complete<<8)|c->unknown,
            (c->fp.saved<<24)|(c->fp.restored<<16)|(c->source[0].complete<<8)|c->source[1].complete);
    }
    for(unsigned n=0;n<3;n++)pwtg_line(r,9+n,"MAP S LO",(uint32_t)(m->map[n].map.status>>32),(uint32_t)m->map[n].map.status);
    pwtg_line(r,12,"AT0 AT1",early_wifi_memory.translated[0],early_wifi_memory.translated[1]);
    pwtg_line(r,13,"MSA BASE",(uint32_t)(m->claim[0].requested>>32),(uint32_t)m->claim[0].requested);
    pwtg_line(r,14,"RMTFS BASE",(uint32_t)(m->claim[1].requested>>32),(uint32_t)m->claim[1].requested);
    pwtg_line(r,15,"NO RADIO",m->claim[0].retained,m->claim[1].retained);
    (void)pwtg_draw(r);early_wifi_gop_raw();
}
#if EFI_XNU_WIFI_NATIVE_MEMORY_AVAILABLE
/* These producers run before prepare_boot arms terminal_gop. Their terminal
 * evidence must use the already admitted early GOP, with all original draw
 * guards intact. Cached counters only; no service, retry or cleanup here. */
static void wifi_native_memory_gop_evidence(void)
{
    struct pwtg_result*r=&early_wifi_gop;
    if(wln_cpu_on_issued||r->native_address!=(uintptr_t)&wln_cpu_on_issued||
       r->self_base!=pgcd_record.self_base||r->self_bytes!=pgcd_record.self_bytes||
       r->headers.address[0]!=(uintptr_t)gop){
        (void)pwtg_fail(r,PWTG_ARGUMENT);early_wifi_gop_raw();return;
    }
    if(wifi_native_nv.inputs.error==2){
        const struct pnv_result*v=&wifi_native_nv.inputs;
        const struct pnv_device*d=0;
        if(v->selection_stage<=5&&v->selection_index<PNV_PARTS)d=&v->part[v->selection_index];
        else if(v->selection_stage>=6&&v->selection_stage<=9&&v->selection_index<PNV_DISKS)d=&v->disk[v->selection_index];
        pwtg_line(r,0,"NV SELECT HOLD",wifi_native_memory_stage,load_state);
        pwtg_line(r,1,"NV ERROR CALL",wifi_native_nv.error,wifi_native_nv.calls);
        pwtg_line(r,2,"NV PEND DONE",wifi_native_nv.pending,wifi_native_nv.complete);
        pwtg_line(r,3,"NV INPUT E U",v->error,v->unknown);
        pwtg_line(r,4,"SELECT STEP IDX",v->selection_stage,v->selection_index);
        pwtg_line(r,5,"PROTO STATUS",(uint32_t)v->selection_status,(uint32_t)(v->selection_status>>32));
        pwtg_line(r,6,"HANDLES READS",(uint32_t)v->handle_count,v->reads);
        pwtg_line(r,7,"PART MATCH 0 1",v->part[0].matches,v->part[1].matches);
        pwtg_line(r,8,"PART MATCH 2 3",v->part[2].matches,v->part[3].matches);
        pwtg_line(r,9,"DISK MATCH 0 1",v->disk[0].matches,v->disk[1].matches);
        pwtg_line(r,10,"MEDIA REV BLOCK",d?(uint32_t)d->protocol.revision:0,d?d->media.block:0);
        pwtg_line(r,11,"MEDIA LAST",d?(uint32_t)d->media.last:0,d?(uint32_t)(d->media.last>>32):0);
        pwtg_line(r,12,"ALIGN FLAGS",d?d->media.align:0,d?((uint32_t)d->media.removable<<24)|((uint32_t)d->media.present<<16)|((uint32_t)d->media.logical<<8)|d->media.readonly:0);
        pwtg_line(r,13,"NV AT0 AT1",wifi_native_nv.translated[0],wifi_native_nv.translated[1]);
        pwtg_line(r,14,"CE HTT ERROR",wifi_native_ce_memory.error,wifi_native_htt_memory.error);
        pwtg_line(r,15,"NO RADIO",wln_cpu_on_issued,0);
        (void)pwtg_draw(r);early_wifi_gop_raw();return;
    }
    pwtg_line(r,0,"NATIVE MEM HOLD",wifi_native_memory_stage,load_state);
    pwtg_line(r,1,"NV ERROR CALL",wifi_native_nv.error,wifi_native_nv.calls);
    pwtg_line(r,2,"NV PEND DONE",wifi_native_nv.pending,wifi_native_nv.complete);
    pwtg_line(r,3,"NV AT0 AT1",wifi_native_nv.translated[0],wifi_native_nv.translated[1]);
    pwtg_line(r,4,"NV INPUT E U",wifi_native_nv.inputs.error,wifi_native_nv.inputs.unknown);
    pwtg_line(r,5,"NV UNKNOWN",wifi_native_nv.unknown,wifi_native_nv.allocated);
    pwtg_line(r,6,"CE ERROR CALL",wifi_native_ce_memory.error,wifi_native_ce_memory.calls);
    pwtg_line(r,7,"CE PEND DONE",wifi_native_ce_memory.pending,wifi_native_ce_memory.complete);
    pwtg_line(r,8,"HTT ERROR CALL",wifi_native_htt_memory.error,wifi_native_htt_memory.calls);
    pwtg_line(r,9,"HTT PEND DONE",wifi_native_htt_memory.pending,wifi_native_htt_memory.complete);
    for(unsigned n=0;n<PNNV_CALLS;n++){
        const struct pwea_native_call*c=&wifi_native_nv.call[n];
        pwtg_line(r,10+n,"NV CALL IR CU",(c->issued<<24)|(c->returned<<16)|(c->complete<<8)|c->unknown,
            (c->fp.saved<<24)|(c->fp.restored<<16)|(c->source[0].complete<<8)|c->source[1].complete);
    }
    pwtg_line(r,15,"NO RADIO",wln_cpu_on_issued,0);
    (void)pwtg_draw(r);early_wifi_gop_raw();
}
#endif
#if EFI_XNU_MSS_MEMORY_AVAILABLE
#include "uefi-mss-memory-diagnostic.h"
static void mss_memory_gop_evidence(void)
{
    struct pwtg_result*r=&early_wifi_gop;const struct pmme_memory*m=&mss_memory.memory;
    if(r->native_address!=(uintptr_t)&wln_cpu_on_issued||r->self_base!=pgcd_record.self_base||
       r->self_bytes!=pgcd_record.self_bytes||r->headers.address[0]!=(uintptr_t)gop){
        (void)pwtg_fail(r,PWTG_ARGUMENT);early_wifi_gop_raw();return;
    }
    pwtg_line(r,0,"MSS HOLD",mss_memory.attempted,mss_memory.error);
    pwtg_line(r,1,"MEM CALL E",m->calls,m->error);
    for(unsigned n=0;n<3;n++)pwtg_line(r,2+n,"CLAIM S LO",(uint32_t)(m->claim[n].status>>32),(uint32_t)m->claim[n].status);
    for(unsigned n=0;n<7;n++){
        const struct pwea_native_call*c=&mss_memory.call[n];
        pwtg_line(r,5+n,"CALL IR CU",(c->issued<<24)|(c->returned<<16)|(c->complete<<8)|c->unknown,
            (c->fp.saved<<24)|(c->fp.restored<<16)|(c->source[0].complete<<8)|c->source[1].complete);
    }
    pwtg_line(r,12,"MODEM BASE",(uint32_t)(m->claim[0].requested>>32),(uint32_t)m->claim[0].requested);
    pwtg_line(r,13,"MBA BASE",(uint32_t)(m->claim[1].requested>>32),(uint32_t)m->claim[1].requested);
    pwtg_line(r,14,"MDT BASE",(uint32_t)(m->claim[2].requested>>32),(uint32_t)m->claim[2].requested);
    pwtg_line(r,15,"RETAINED",mss_retained_attempted,mss_retained_ok);
    if(m->error==PWEA_DELTA){
        struct pmmd_difference d={0};pmmd_capture(m,&d);
        pwtg_line(r,0,"MSS DELTA",d.reason,d.direction);
        pwtg_line(r,1,"CALL KIND",m->calls,d.kind);
        pwtg_line(r,2,"DIFF BYTE INDEX",d.byte,(d.old_index<<16)|d.new_index);
        pwtg_line(r,3,"DIFF ADDRESS",(uint32_t)(d.address>>32),(uint32_t)d.address);
        pwtg_line(r,4,"BEFORE AFTER T",d.before.type,d.after.type);
        pwtg_line(r,5,"BEFORE BASE",(uint32_t)(d.before.physical>>32),(uint32_t)d.before.physical);
        pwtg_line(r,6,"AFTER BASE",(uint32_t)(d.after.physical>>32),(uint32_t)d.after.physical);
        pwtg_line(r,7,"BEFORE PAGES",(uint32_t)(d.before.pages>>32),(uint32_t)d.before.pages);
        pwtg_line(r,8,"AFTER PAGES",(uint32_t)(d.after.pages>>32),(uint32_t)d.after.pages);
        pwtg_line(r,9,"BEFORE ATTR",(uint32_t)(d.before.attributes>>32),(uint32_t)d.before.attributes);
        pwtg_line(r,10,"AFTER ATTR",(uint32_t)(d.after.attributes>>32),(uint32_t)d.after.attributes);
        pwtg_line(r,11,"BEFORE VIRT",(uint32_t)(d.before.virtual_address>>32),(uint32_t)d.before.virtual_address);
        pwtg_line(r,12,"AFTER VIRT",(uint32_t)(d.after.virtual_address>>32),(uint32_t)d.after.virtual_address);
        pwtg_line(r,13,"DIFF RAW WORD",d.old_word,d.new_word);
        uint64_t base=d.kind<PMME_CLAIMS?m->claim[d.kind].requested:0;
        uint64_t bytes=d.kind<PMME_CLAIMS?m->claim[d.kind].bytes:0;
        pwtg_line(r,14,"CLAIM BASE",(uint32_t)(base>>32),(uint32_t)base);
        pwtg_line(r,15,"CLAIM BYTES",(uint32_t)(bytes>>32),(uint32_t)bytes);
    }
#if EFI_XNU_MSS_STAGING_AVAILABLE
    if(mss_stage.unknown){
        pwtg_line(r,0,"STAGE HOLD",mss_stage.attempted,mss_stage.error);
        pwtg_line(r,1,"PAGE ASSET",mss_stage.pages,mss_stage.assets_complete);
        pwtg_line(r,12,"SOURCE PAGE",mss_stage.source_pages[0],mss_stage.source_pages[1]);
    }
#if EFI_XNU_MSS_MBA_SHARE_AVAILABLE
    if(mss_mba_share.unknown){
        pwtg_line(r,0,"MBA SHARE",mss_mba_share.assignment_issued,mss_mba_share.error);
        pwtg_line(r,1,"ROUND ERROR",mss_mba_share.transaction.rounds,mss_mba_share.transaction.error);
        const struct pwmt_transaction*t=&mss_mba_share.transaction;
        pwtg_line(r,2,"TX STEP EVENTS",t->step,t->events);
        pwtg_line(r,3,"TX OPEN TICKS",(uint32_t)(t->opening>>32),(uint32_t)t->opening);
        pwtg_line(r,4,"TX LAST TICKS",(uint32_t)(t->last>>32),(uint32_t)t->last);
        pwtg_line(r,5,"CHECK DETAIL",mss_mba_share.reserved,mss_mba_share.assignment_returned_zero);
        uint64_t entry=mss_mba_share.entry.cpu.ticks,checked=mss_mba_share.assigned.cpu.ticks;
        pwtg_line(r,6,"ENTRY TICKS",(uint32_t)(entry>>32),(uint32_t)entry);
        pwtg_line(r,7,"CHECK TICKS",(uint32_t)(checked>>32),(uint32_t)checked);
        for(unsigned n=0;n<7;n++){
            const struct pmsb_peer*p=&mss_mba_share.peer[1][n];
            pwtg_line(r,8+n,"POST PEER IR RAW",(n<<16)|(p->issued<<8)|p->returned,(uint32_t)p->raw);
        }
        if(mss_mba_share.error==7&&t->error==PWMT_TIME&&t->events<PWMT_EVENTS){
            uint64_t ticks=mss_mba_share.step[t->events].cpu.ticks;
            pwtg_line(r,7,"TX CHECK TICKS",(uint32_t)(ticks>>32),(uint32_t)ticks);
            uint64_t delta=ticks>=t->opening?ticks-t->opening:UINT64_MAX;
            pwtg_line(r,6,"TX DELTA TICKS",(uint32_t)(delta>>32),(uint32_t)delta);
        }
        pwtg_line(r,15,"MASK RESTORE",mss_mba_share.cpu_held,mss_mba_share.restore_issued);
    }
#endif
#endif
    (void)pwtg_draw(r);early_wifi_gop_raw();
}
#endif
#endif
static void terminal_gop_raw(void)
{
    ram_report("WIFI_TERMINAL_GOP_RAW_V1_BYTES=",sizeof(terminal_gop));
    ram_text("WIFI_TERMINAL_GOP_RAW_V1_BEGIN\r\n");ram_hex((const void*)&terminal_gop,sizeof(terminal_gop));
    ram_text("WIFI_TERMINAL_GOP_RAW_V1_END\r\n");
}
/* Separate normal admission, before ANY Wi-Fi private context opens. The
 * original GetMap is the only foreign call. Keep its raw FP/architecture
 * evidence; an uncertain return is still terminal, never a clean refusal. */
static int terminal_gop_arm(void)
{
    struct pwtg_result*r=&terminal_gop.pixels;
    if(r->attempted||terminal_gop.map_issued)return pwtg_fail(r,PWTG_REENTRY);
    if(wln_cpu_on_issued)return pwtg_fail(r,PWTG_NATIVE);
    if(!pgcd_record.self_bound||!pwtg_arch_read(&terminal_gop.map_before)||!pwtg_normal(&terminal_gop.map_before)||
       !pgcd_actual_fp_save(0,&terminal_gop.map_FP))return pwtg_fail(r,PWTG_ARCH);
    r->map_bytes=sizeof(r->map);
    terminal_gop.map_function=(uintptr_t)system_table->boot->get_map;
    terminal_gop.map_issued=1;
    r->map_status=system_table->boot->get_map(&r->map_bytes,r->map,&r->map_key,&r->map_stride,&r->map_version);
    terminal_gop.map_returned=1;
    int fp_ok=pgcd_actual_fp_restore(0,&terminal_gop.map_FP);
    if(!fp_ok||!terminal_gop.map_FP.saved||!terminal_gop.map_FP.restored||
       !pwtg_arch_read(&terminal_gop.map_after)||!pwtg_same_arch(&terminal_gop.map_before,&terminal_gop.map_after,0)){
        terminal_gop.uncertain=1;return pwtg_fail(r,PWTG_ARCH);
    }
    return pwtg_arm(r,(uintptr_t)gop,(uintptr_t)&wln_cpu_on_issued,pgcd_record.self_base,pgcd_record.self_bytes);
}
static void terminal_gop_evidence(void)
{
    struct pwtg_result*r=&terminal_gop.pixels;
    if(r->native_address!=(uintptr_t)&wln_cpu_on_issued||r->self_base!=pgcd_record.self_base||
       r->self_bytes!=pgcd_record.self_bytes||r->headers.address[0]!=(uintptr_t)gop){
        (void)pwtg_fail(r,PWTG_ARGUMENT);terminal_gop_raw();return;
    }
#if EFI_XNU_WIFI_EARLY_MEMORY_AVAILABLE
    if(retained_wifi_memory.unknown){
        const struct pweh_result*h=&retained_wifi_memory;
        pwtg_line(r,0,"RETAIN HOLD",h->attempted,h->error);
        pwtg_line(r,1,"MAP IR",h->issued,h->returned);
        pwtg_line(r,2,"MAP S LO",(uint32_t)(h->map.map.status>>32),(uint32_t)h->map.map.status);
        pwtg_line(r,3,"FP S R",h->fp.saved,h->fp.restored);
        pwtg_line(r,4,"CORE PRE",h->source[0].pages,h->source[0].complete);
        pwtg_line(r,5,"CORE POST",h->source[1].pages,h->source[1].complete);
        pwtg_line(r,6,"AT0 AT1",h->translated[0],h->translated[1]);
        (void)pwtg_draw(r);terminal_gop_raw();return;
    }
#endif
    /* Numeric resident observations, never an inference from an unused zero.
     * The attempted/issued masks beside the errors distinguish UNOBSERVED. */
#if EFI_XNU_WIFI_CPU_LIVE_DIAGNOSTICS
    const struct pwrpc_live_diagnostic*d=&pwrpt_record.CPU.live_failure;
#if EFI_XNU_WIFI_CURRENT_WORD_READ
    /* Projection of resident issued/returned evidence only. No observer,
     * clock, register or firmware call is made after the original failure. */
    const struct pwra_result*a=&pwrpt_record.access;
    const struct pwra_event*e=a->events&&a->events<=PWRA_EVENTS?&a->history[a->events-1]:0;
#if EFI_XNU_WIFI_FOUR_VRM_AVAILABLE
    pwtg_line(r,0,"V9 HOLD",pwrpt_record.attempted,pwrpt_record.phase);
#elif EFI_XNU_WIFI_CURRENT_WORD_VOTE
#if EFI_XNU_WIFI_CURRENT_WORD_VOTE_LATCHED
    pwtg_line(r,0,"V8 HOLD",pwrpt_record.attempted,pwrpt_record.phase);
#else
    pwtg_line(r,0,"V7 HOLD",pwrpt_record.attempted,pwrpt_record.phase);
#endif
#else
    pwtg_line(r,0,"V6 HOLD",pwrpt_record.attempted,pwrpt_record.phase);
#endif
    pwtg_line(r,1,"BODY CPU",pwrpt_record.error,pwrpt_record.CPU.error);
    pwtg_line(r,2,"WHY CALL",d->reason,d->call);
    pwtg_line(r,3,"MASK ARCH OK",d->masked,d->arch_callback_ok);
#if EFI_XNU_WIFI_FOUR_VRM_AVAILABLE
    pwtg_line(r,4,"TCS IRQ EN",pwrpt_record.VRM.read.io.tcs,pwrpt_record.VRM.read.io.IRQ_enable);
#elif EFI_XNU_WIFI_CURRENT_WORD_VOTE_LATCHED
    pwtg_line(r,4,"TCS IRQ EN",pwrpt_record.transaction.tcs,pwrpt_record.transaction.IRQ_enable);
#else
    pwtg_line(r,4,"OPEN HI LO",(uint32_t)(d->opening_ticks>>32),(uint32_t)d->opening_ticks);
#endif
    if(d->reason)pwtg_line(r,5,"FAIL HI LO",(uint32_t)(d->failed_ticks>>32),(uint32_t)d->failed_ticks);
    else pwtg_line(r,5,"IO VALUE OR0",e?e->io.value:0,a->command_status_OR[0]);
    pwtg_line(r,6,"ACC A E",a->attempted,a->error);
    pwtg_line(r,7,"ACC U OUT",a->unknown,a->outstanding);
    pwtg_line(r,8,"IO OP FLAGS",e?e->operation:0,e?(e->io.issued|(e->io.returned<<8)|(e->io.unknown<<16)):0);
    pwtg_line(r,9,"IO ADDR L H",e?(uint32_t)e->io.address:0,e?(uint32_t)(e->io.address>>32):0);
#if EFI_XNU_WIFI_FOUR_VRM_AVAILABLE
    pwtg_line(r,10,"VRM READ WRITE",pwrpt_record.VRM.read.io.phase,pwrpt_record.VRM.write.io.phase);
    pwtg_line(r,11,"VRM TR DONE",pwrpt_record.VRM.write.io.triggers,pwrpt_record.VRM.write.io.completed);
#elif EFI_XNU_WIFI_CURRENT_WORD_VOTE
    pwtg_line(r,10,"READ WRITE PH",pwrpt_record.read.io.phase,pwrpt_record.transaction.phase);
    pwtg_line(r,11,"WRITE TR DONE",pwrpt_record.transaction.triggers,pwrpt_record.transaction.completed);
#else
    pwtg_line(r,10,"READ PH STEP",pwrpt_record.read.io.phase,pwrpt_record.read.io.steps);
    pwtg_line(r,11,"READ TR DONE",pwrpt_record.read.io.triggers,pwrpt_record.read.io.completed);
#endif
    pwtg_line(r,12,"DB0 BYTE WR",a->CmdDb[0].bytes,a->CmdDb[0].word.returned);
    pwtg_line(r,13,"DB1 BYTE WR",a->CmdDb[1].bytes,a->CmdDb[1].word.returned);
    pwtg_line(r,14,"CPU H R",pwrpt_record.CPU.local_mask_held,pwrpt_record.CPU.local_restored);
#if EFI_XNU_WIFI_FOUR_VRM_AVAILABLE
    pwtg_line(r,15,"VRM R W ERR",pwrpt_record.VRM.read.io.error,pwrpt_record.VRM.write.io.error);
#elif EFI_XNU_WIFI_CURRENT_WORD_VOTE
    pwtg_line(r,15,"WRITE E U",pwrpt_record.transaction.error,pwrpt_record.transaction.unknown);
#else
    pwtg_line(r,15,"READ E U",pwrpt_record.read.io.error,pwrpt_record.read.io.unknown);
#endif
#else
#if EFI_XNU_WIFI_DB_WORD_CAPTURE
    pwtg_line(r,0,"V3 HOLD",pwrpt_record.attempted,pwrpt_record.phase);
#else
    pwtg_line(r,0,"V2 HOLD",pwrpt_record.attempted,pwrpt_record.phase);
#endif
    pwtg_line(r,1,"BODY CPU",pwrpt_record.error,pwrpt_record.CPU.error);
    pwtg_line(r,2,"WHY CALL",d->reason,d->call);
    pwtg_line(r,3,"MASK ARCH OK",d->masked,d->arch_callback_ok);
    pwtg_line(r,4,"OPEN HI LO",(uint32_t)(d->opening_ticks>>32),(uint32_t)d->opening_ticks);
    pwtg_line(r,5,"NORM HI LO",(uint32_t)(d->normal_ticks>>32),(uint32_t)d->normal_ticks);
    pwtg_line(r,6,"FAIL HI LO",(uint32_t)(d->failed_ticks>>32),(uint32_t)d->failed_ticks);
    pwtg_line(r,7,"LIMIT TICKS",0,PGCD_FRESH_TICKS);
    pwtg_line(r,8,"ACC A E",pwrpt_record.access.attempted,pwrpt_record.access.error);
    pwtg_line(r,9,"ACC U OUT",pwrpt_record.access.unknown,pwrpt_record.access.outstanding);
    pwtg_line(r,10,"DB0 A BYTES",pwrpt_record.access.CmdDb[0].attempted,pwrpt_record.access.CmdDb[0].bytes);
    pwtg_line(r,11,"DB1 A BYTES",pwrpt_record.access.CmdDb[1].attempted,pwrpt_record.access.CmdDb[1].bytes);
#if EFI_XNU_WIFI_DB_WORD_CAPTURE
    pwtg_line(r,12,"DB0 WORD I R",pwrpt_record.access.CmdDb[0].word.issued,pwrpt_record.access.CmdDb[0].word.returned);
    pwtg_line(r,13,"DB1 WORD I R",pwrpt_record.access.CmdDb[1].word.issued,pwrpt_record.access.CmdDb[1].word.returned);
#else
    pwtg_line(r,12,"DB0 H FAIL",pwrpt_record.access.CmdDb[0].hash_count,pwrpt_record.access.CmdDb[0].hash_failed);
    pwtg_line(r,13,"DB1 H FAIL",pwrpt_record.access.CmdDb[1].hash_count,pwrpt_record.access.CmdDb[1].hash_failed);
#endif
    pwtg_line(r,14,"CPU H R",pwrpt_record.CPU.local_mask_held,pwrpt_record.CPU.local_restored);
    pwtg_line(r,15,"NOT WIFI",pwrpt_record.read.io.attempted,pwrpt_record.transaction.attempted);
#endif
#else
    pwtg_line(r,0,"V1 HOLD",pwrpt_record.attempted,pwrpt_record.phase);
    pwtg_line(r,1,"BODY E U",pwrpt_record.error,pwrpt_record.unknown);
    pwtg_line(r,2,"CLIENT E OUT",pwrcl_record.error,pwrcl_record.outstanding);
    pwtg_line(r,3,"CPU E OUT",pwrpt_record.CPU.error,pwrpt_record.CPU.outstanding);
    pwtg_line(r,4,"CPU N M",pwrpt_record.CPU.affinity_issued,pwrpt_record.CPU.masked_issued);
    pwtg_line(r,5,"CPU H R",pwrpt_record.CPU.local_mask_held,pwrpt_record.CPU.local_restored);
    pwtg_line(r,6,"ACC A E",pwrpt_record.access.attempted,pwrpt_record.access.error);
    pwtg_line(r,7,"ACC U OUT",pwrpt_record.access.unknown,pwrpt_record.access.outstanding);
#if EFI_XNU_WIFI_PRE_MASK_ARGUMENTS
    pwtg_line(r,8,"ARG A E",pwrpt_record.arguments.attempted,pwrpt_record.arguments.error);
    pwtg_line(r,9,"ARG U OUT",pwrpt_record.arguments.unknown,pwrpt_record.arguments.outstanding);
    pwtg_line(r,10,"ARG O P",pwrpt_record.arguments.objects,pwrpt_record.arguments.pages);
    pwtg_line(r,11,"ARG FAIL",pwrpt_record.arguments.failed_object,pwrpt_record.arguments.failed_page);
#else
    pwtg_line(r,8,"DB0 A BYTES",pwrpt_record.access.CmdDb[0].attempted,pwrpt_record.access.CmdDb[0].bytes);
    pwtg_line(r,9,"DB1 A BYTES",pwrpt_record.access.CmdDb[1].attempted,pwrpt_record.access.CmdDb[1].bytes);
    pwtg_line(r,10,"DB0 H FAIL",pwrpt_record.access.CmdDb[0].hash_count,pwrpt_record.access.CmdDb[0].hash_failed);
    pwtg_line(r,11,"DB1 H FAIL",pwrpt_record.access.CmdDb[1].hash_count,pwrpt_record.access.CmdDb[1].hash_failed);
#endif
    pwtg_line(r,12,"ACC R W",pwrpt_record.access.reads,pwrpt_record.access.writes);
    pwtg_line(r,13,"CORE E PH",pwrcl_record.core.error,pwrcl_record.core.phase);
    pwtg_line(r,14,"GOP A MAP U",r->armed,terminal_gop.uncertain);
    pwtg_line(r,15,"NOT WIFI",pwrpt_record.read.io.attempted,pwrpt_record.transaction.attempted);
#endif
    (void)pwtg_draw(r);terminal_gop_raw();
}
#endif
static int original_service_unknown;
static int new_original_unknown(void)
{return pwcq_parent_unsafe()||original_service_unknown||(pgcd_resident_context.record&&pgcd_uncertain(&pgcd_resident_context))||pacgq_preboot_record.uncertain||pacgq_preboot_record.outstanding||pacgq_ticket.outstanding
#if EFI_XNU_WIFI_REMOTE_MEMORY_AVAILABLE
    ||incoming_parent_maps[0].unknown||incoming_parent_maps[1].unknown||ppli_record.unknown||
      current_payload_binding.unknown||current_private_unknown()||pbgi_cache_call.unknown||pbgi_seed.unknown||pbha_handles.unknown||pbhr_handles.unknown||pbhd_handles.unknown||pbhd_timer_handles.unknown||pbhi_handles.unknown||pbht_handles.unknown
#endif
#if EFI_XNU_WIFI_EARLY_MEMORY_AVAILABLE
    ||early_wifi_memory.unknown||early_wifi_memory.memory.unknown||retained_wifi_memory.unknown
#endif
#if EFI_XNU_MSS_MEMORY_AVAILABLE
    ||mss_memory.unknown||mss_memory.memory.unknown||(mss_retained_attempted&&!mss_retained_ok)
#endif
#if EFI_XNU_MSS_STAGING_AVAILABLE
    ||mss_stage.unknown
#endif
#if EFI_XNU_MSS_MBA_SHARE_AVAILABLE
    ||mss_mba_share.unknown||mss_mba_share.cpu_held
#endif
#if EFI_XNU_WIFI_TERMINAL_GOP_DIAGNOSTICS
    ||terminal_gop.uncertain
#endif
#if EFI_XNU_WIFI_NPA_READONLY_AVAILABLE
    ||pwnpa_unknown()
#endif
#if EFI_XNU_WIFI_RPMH_READONLY_AVAILABLE
    ||pwrph_unknown()
#endif
#if EFI_XNU_WIFI_RPMH_CLIENT_AVAILABLE
    ||pwrcl_unsafe()
#endif
#if EFI_XNU_WIFI_CPU_RO_ADMISSION
    ||log_overflow
#endif
#if EFI_XNU_WIFI_POWER_TRANSACTION_AVAILABLE
    ||pwrpt_parent_unsafe()||log_overflow
#endif
    ;}
#if EFI_XNU_WIFI_POWER_TRANSACTION_AVAILABLE || EFI_XNU_WIFI_CPU_RO_ADMISSION
/* A held/UNKNOWN power interval must never return to UsbFn transmit/poll,
 * BootServices Stall, Console, PON or native handoff. Those opaque original
 * services may touch the same resource provider. Preserve all resident raw
 * records and appended evidence; only local instructions execute afterwards.
 * There is deliberately no cleanup, response ACK or automatic reset here. */
static struct {uint64_t daif_before,group_before,daif_after,group_after;} power_hold_raw;
__attribute__((noreturn)) static void power_unknown_hold(void)
{
    __asm__ volatile("mrs %0,daif; mrs %1,ICC_IGRPEN1_EL1":"=r"(power_hold_raw.daif_before),"=r"(power_hold_raw.group_before));
    /* A pre-mask UNKNOWN can still have original interrupts enabled. Do not
     * let WFE dispatch a foreign IRQ handler while quarantined. This terminal
     * local mask is retained, never described as a successful restoration. */
    __asm__ volatile("msr daifset,#15; msr ICC_IGRPEN1_EL1,xzr; dsb sy; isb":::"memory");
    __asm__ volatile("mrs %0,daif; mrs %1,ICC_IGRPEN1_EL1":"=r"(power_hold_raw.daif_after),"=r"(power_hold_raw.group_after));
    ram_text("WIFI_POWER_UNKNOWN_HOLD_RAW_V1_BEGIN\r\n");ram_hex((const void*)&power_hold_raw,sizeof(power_hold_raw));
    ram_text("WIFI_POWER_UNKNOWN_HOLD_RAW_V1_END\r\n");
#if EFI_XNU_WIFI_TERMINAL_GOP_DIAGNOSTICS
    /* Remains terminal even if this local draw fails or is partial. No
     * foreign method, cleanup, response or CPU/private restoration follows. */
#if EFI_XNU_WIFI_EARLY_MEMORY_AVAILABLE
#if EFI_XNU_WIFI_NATIVE_MEMORY_AVAILABLE
    if(wifi_native_memory_stage>=1&&wifi_native_memory_stage<=4)wifi_native_memory_gop_evidence();
    else
#endif
#if EFI_XNU_MSS_MEMORY_AVAILABLE
#if EFI_XNU_MSS_STAGING_AVAILABLE
#if EFI_XNU_MSS_MBA_SHARE_AVAILABLE
    if(mss_mba_share.unknown||mss_mba_share.cpu_held)mss_memory_gop_evidence();
    else
#endif
    if(mss_stage.unknown)mss_memory_gop_evidence();
    else
#endif
    if(mss_memory.unknown||mss_memory.memory.unknown||(mss_retained_attempted&&!mss_retained_ok))mss_memory_gop_evidence();
    else
#endif
    if(early_wifi_memory.unknown||early_wifi_memory.memory.unknown)early_wifi_gop_evidence();
    else
#endif
#if EFI_XNU_WIFI_NATIVE_RUNTIME_AVAILABLE
    if(wifi_native_boot_phase>=4&&!wln_cpu_on_issued)wifi_native_startup_gop_evidence();
    else
#endif
    terminal_gop_evidence();
#endif
    for(;;)__asm__ volatile("wfe":::"memory");
}
#if EFI_XNU_WIFI_REMOTE_MEMORY_AVAILABLE
static void ppli_parent_raw(void)
{
    ram_report("PARENT_LOADED_IMAGES_RAW_V1_BYTES=",sizeof(ppli_record));
    ram_text("PARENT_LOADED_IMAGES_RAW_V1_BEGIN\r\n");ram_hex((const uint8_t*)&ppli_record,sizeof(ppli_record));
    ram_text("PARENT_LOADED_IMAGES_RAW_V1_END\r\n");
}
__attribute__((noreturn)) static void ppli_parent_stop(void)
{
    ppli_record.unknown=1;original_service_unknown=1;ppli_parent_raw();power_unknown_hold();
}
static void pbgi_parent_raw(void)
{
    ram_report("GCD_INPUT_PRODUCER_CACHE_OPENING=",pbgi_cache_opening);
    ram_report("GCD_INPUT_PRODUCER_CALL_RAW_V1_BYTES=",sizeof(pbgi_cache_call));
    ram_text("GCD_INPUT_PRODUCER_CALL_RAW_V1_BEGIN\r\n");ram_hex((const uint8_t*)&pbgi_cache_call,sizeof(pbgi_cache_call));
    ram_text("GCD_INPUT_PRODUCER_CALL_RAW_V1_END\r\n");
    ram_report("GCD_INPUT_PRODUCER_RAW_V1_BYTES=",sizeof(pbgi_seed));
    ram_text("GCD_INPUT_PRODUCER_RAW_V1_BEGIN\r\n");ram_hex((const uint8_t*)&pbgi_seed,sizeof(pbgi_seed));
    ram_text("GCD_INPUT_PRODUCER_RAW_V1_END\r\n");
}
__attribute__((noreturn)) static void pbgi_parent_stop(void)
{original_service_unknown=1;pbgi_seed.unknown=1;pbgi_parent_raw();ppli_parent_stop();}
static void pbha_parent_raw(void)
{
    ram_report("CACHE_HANDLE_ALLOCATION_RAW_V1_BYTES=",sizeof(pbha_handles));
    ram_text("CACHE_HANDLE_ALLOCATION_RAW_V1_BEGIN\r\n");ram_hex((const uint8_t*)&pbha_handles,sizeof(pbha_handles));
    ram_text("CACHE_HANDLE_ALLOCATION_RAW_V1_END\r\n");
}
__attribute__((noreturn)) static void pbha_parent_stop(void)
{original_service_unknown=1;pbha_handles.unknown=1;pbha_parent_raw();pbgi_parent_raw();ppli_parent_stop();}
static void pbhr_parent_raw(void)
{
    ram_report("CACHE_HANDLE_RELEASE_CALL_RAW_V1_BYTES=",sizeof(pbhr_handles));
    ram_text("CACHE_HANDLE_RELEASE_CALL_RAW_V1_BEGIN\r\n");ram_hex((const uint8_t*)&pbhr_handles,sizeof(pbhr_handles));
    ram_text("CACHE_HANDLE_RELEASE_CALL_RAW_V1_END\r\n");
}
static void pbhd_parent_raw(void)
{
    ram_report("CACHE_HANDLE_DISPATCH_RAW_V1_BYTES=",sizeof(pbhd_handles));
    ram_text("CACHE_HANDLE_DISPATCH_RAW_V1_BEGIN\r\n");ram_hex((const uint8_t*)&pbhd_handles,sizeof(pbhd_handles));
    ram_text("CACHE_HANDLE_DISPATCH_RAW_V1_END\r\n");
    ram_report("CACHE_HANDLE_TIMER_GRAPH_INPUT_RAW_V1_BYTES=",sizeof(pbht_handles));
    ram_text("CACHE_HANDLE_TIMER_GRAPH_INPUT_RAW_V1_BEGIN\r\n");ram_hex((const uint8_t*)&pbht_handles,sizeof(pbht_handles));
    ram_text("\r\nCACHE_HANDLE_TIMER_GRAPH_INPUT_RAW_V1_END\r\n");
    ram_report("CACHE_HANDLE_PROVIDER_INPUT_RAW_V1_BYTES=",sizeof(pbhi_handles));
    ram_text("CACHE_HANDLE_PROVIDER_INPUT_RAW_V1_BEGIN\r\n");ram_hex((const uint8_t*)&pbhi_handles,sizeof(pbhi_handles));
    ram_text("\r\nCACHE_HANDLE_PROVIDER_INPUT_RAW_V1_END\r\n");
    ram_report("CACHE_HANDLE_TIMER_RAW_V1_BYTES=",sizeof(pbhd_timer_handles));
    ram_text("CACHE_HANDLE_TIMER_RAW_V1_BEGIN\r\n");ram_hex((const uint8_t*)&pbhd_timer_handles,sizeof(pbhd_timer_handles));
    ram_text("CACHE_HANDLE_TIMER_RAW_V1_END\r\n");
}
static int pbhd_parent_leaf(struct pbhr_live*live,struct pbhr_result*witness,const struct pbhr_input*input,const uint8_t seal[32],uint64_t*closing_ticks)
{
    if(!closing_ticks||witness!=&pbhr_handles||!pbhd_call(&pbhd_handles,&pbhd_timer_handles,&pbhi_handles,&pbht_handles,live,witness,input,seal))return 0;
    if(!pbhi_handles.arch_returned||pbhi_handles.arch_returned>PBHI_CLOCK_MAX||
       pbhi_handles.arch_returned!=pbhi_handles.arch_issued||!pbhi_handles.closed||!pbhi_handles.complete||pbhi_handles.unknown||pbht_handles.unknown)return 0;
    *closing_ticks=pbhi_handles.clock[pbhi_handles.arch_returned-1].raw.cpu.ticks;return 1;
}
__attribute__((noreturn)) static void pbhr_parent_stop(void)
{original_service_unknown=1;pbhr_handles.unknown=1;pbhd_parent_raw();pbhr_parent_raw();pbha_parent_raw();pbgi_parent_raw();ppli_parent_stop();}
static uint64_t pbhr_parent_release(struct efi_boot*bs,struct pwfc_result*r,struct pwfc_workspace*w,void*handles)
{
    if(bs!=system_table->boot||r!=&pwfc_record||w!=&pwfc_work||(uintptr_t)handles!=r->handles||
       pbhr_handles.attempted||!pbha_handles.complete||pbha_handles.unknown)pbhr_parent_stop();
    const struct pbhr_input input={.allocation=&pbha_handles,.seed=&pbgi_seed,.images=&ppli_record,
        .system=system_table,.image=(const void*)(uintptr_t)pgcd_record.self_owner_address,.native=&wln_cpu_on_issued,
        .opening=pbgi_cache_opening,.io=pbgi_cache_call.io,.page=ppli_actual_page,.release=pbhr_actual_release};
    if(!pbhr_call_guarded(&pbhr_handles,&input,pbhd_parent_leaf))pbhr_parent_stop();return pbhr_handles.api.status;
}
static int pbgi_parent_cache_map(struct efi_boot*bs,struct pwfc_result*r,struct pwfc_workspace*w)
{
    if(bs!=system_table->boot||r!=&pwfc_record||w!=&pwfc_work||pbgi_cache_call.attempted||load_state!=2||
       !pgcd_record.self_bound||!r->before.ticks)pbgi_parent_stop();
    pbgi_cache_opening=r->before.ticks;
    const struct pwmc_parent_input input={.system=system_table,.image=(const void*)(uintptr_t)pgcd_record.self_owner_address,
        .native_flag=&wln_cpu_on_issued,.output=w->map,.capacity=sizeof(w->map),.image_handle=(uintptr_t)driver_image,
        .phase=4,.bank=POLARIS_RAM_BASE,.bank_bytes=POLARIS_RAM_SIZE,.payload=(uintptr_t)payload,.payload_bytes=payload_count,
        .log_snapshot=(uintptr_t)log_snapshot,.log_snapshot_bytes=sizeof(log_buffer)+128+EFI_XNU_LOG_SIZE};
    const struct pgcd_io io={.system=system_table,.arch=pgcd_actual_arch,.map=pgcd_actual_map,
        .identity=pwfc_actual_identity,.query=pgcd_actual_query,.fp_save=pgcd_actual_fp_save,
        .fp_restore=pgcd_actual_fp_restore,.order=pwfc_actual_order};
    if(!pwmc_parent_map_call_window(&pbgi_cache_call,&input,&io,pbgi_cache_opening))pbgi_parent_stop();
    r->map_status=pbgi_cache_call.map.status;r->map_key[1]=pbgi_cache_call.map.key;
    r->map_bytes=pbgi_cache_call.map.bytes;r->map_stride=pbgi_cache_call.map.stride;return 1;
}
static void pbgi_parent_capture(struct pwfc_result*r,struct pwfc_workspace*w)
{
    if(r!=&pwfc_record||w!=&pwfc_work||r->map_key[1]!=pbgi_cache_call.map.key||r->map_bytes!=pbgi_cache_call.map.bytes||
       r->map_stride!=pbgi_cache_call.map.stride||!pgcd_equal(w->map,pbgi_cache_call.data,r->map_bytes))pbgi_parent_stop();
    const struct pbgi_input input={.call=&pbgi_cache_call,.native=&wln_cpu_on_issued,.opening=pbgi_cache_opening,.io=pbgi_cache_call.io};
    if(!pbgi_capture(&pbgi_seed,&input,ppli_actual_page))pbgi_parent_stop();
    const struct pbha_input allocation={.seed=&pbgi_seed,.images=&ppli_record,.handles=r->handles,.count=r->handle_count,.page=ppli_actual_page};
    if(!pbha_capture(&pbha_handles,&allocation))pbha_parent_stop();
}
static void current_private_raw(unsigned index,unsigned slot)
{
    ram_report("CURRENT_PARENT_MAP_CONTEXT=",index);ram_report("CURRENT_PARENT_MAP_SLOT=",slot);
    ram_report("CURRENT_PARENT_MAP_RAW_V2_BYTES=",sizeof(current_private_maps[index][slot]));
    ram_text("CURRENT_PARENT_MAP_RAW_V2_BEGIN\r\n");ram_hex((const uint8_t*)&current_private_maps[index][slot],sizeof(current_private_maps[index][slot]));
    ram_text("CURRENT_PARENT_MAP_RAW_V2_END\r\n");
    ram_report("CURRENT_PARENT_GRAPH_INPUT_RAW_V3_BYTES=",sizeof(current_private_graphs[index][slot]));
    ram_text("CURRENT_PARENT_GRAPH_INPUT_RAW_V3_BEGIN\r\n");
    ram_hex((const uint8_t*)&current_private_graphs[index][slot],sizeof(current_private_graphs[index][slot]));
    ram_text("CURRENT_PARENT_GRAPH_INPUT_RAW_V3_END\r\n");
    ram_report("CURRENT_PARENT_PROVIDER_INPUT_RAW_V1_BYTES=",sizeof(current_private_providers[index][slot]));
    ram_text("CURRENT_PARENT_PROVIDER_INPUT_RAW_V1_BEGIN\r\n");
    ram_hex((const uint8_t*)&current_private_providers[index][slot],sizeof(current_private_providers[index][slot]));
    ram_text("CURRENT_PARENT_PROVIDER_INPUT_RAW_V1_END\r\n");
    ram_report("CURRENT_PARENT_TIMER_DEFERRED_INPUT_RAW_V1_BYTES=",sizeof(current_private_timers[index][slot]));
    ram_text("CURRENT_PARENT_TIMER_DEFERRED_INPUT_RAW_V1_BEGIN\r\n");
    ram_hex((const uint8_t*)&current_private_timers[index][slot],sizeof(current_private_timers[index][slot]));
    ram_text("CURRENT_PARENT_TIMER_DEFERRED_INPUT_RAW_V1_END\r\n");
    ram_report("CURRENT_PARENT_EVENT_TIMER_GRAPH_INPUT_RAW_V2_BYTES=",sizeof(current_private_events[index][slot]));
    ram_text("CURRENT_PARENT_EVENT_TIMER_GRAPH_INPUT_RAW_V2_BEGIN\r\n");
    ram_hex((const uint8_t*)&current_private_events[index][slot],sizeof(current_private_events[index][slot]));
    ram_text("CURRENT_PARENT_EVENT_TIMER_GRAPH_INPUT_RAW_V2_END\r\n");
}
static const struct pcmt_result*pcmi_parent_timer(struct pcmi_live*caller)
{return pcmt_route_capture(current_private_routes,PCMP_PARENT_CONTEXTS,current_private_timers,
    current_private_providers,current_private_graphs,caller);}
static int pcmp_parent_graph(struct pcmp_live*parent,int(*read_page)(struct ppli_at*))
{return pcmg_route_capture(current_private_routes,PCMP_PARENT_CONTEXTS,current_private_graphs,parent,read_page)&&
    pcmi_route_capture(current_private_routes,PCMP_PARENT_CONTEXTS,current_private_providers,current_private_graphs,parent,read_page)&&
    pcme_route_capture(current_private_routes,PCMP_PARENT_CONTEXTS,current_private_events,current_private_graphs,
        current_private_providers,current_private_timers,parent,read_page);}
static int pgcd_parent_map_minimum(const struct pgcd_context*c,unsigned slot,uint64_t*out)
{return pcme_route_minimum(current_private_routes,PCMP_PARENT_CONTEXTS,current_private_graphs,current_private_providers,
    current_private_timers,current_private_events,c,slot,out);}
__attribute__((noreturn)) static void current_private_stop(void)
{
    original_service_unknown=1;current_private_fault.attempted=current_private_fault.unknown=1;
    ram_report("CURRENT_PARENT_MAP_DISPATCH_RAW_V1_BYTES=",sizeof(current_private_fault));
    ram_text("CURRENT_PARENT_MAP_DISPATCH_RAW_V1_BEGIN\r\n");ram_hex((const uint8_t*)&current_private_fault,sizeof(current_private_fault));
    ram_text("CURRENT_PARENT_MAP_DISPATCH_RAW_V1_END\r\n");
    for(unsigned n=0;n<PCMP_PARENT_CONTEXTS;n++)for(unsigned k=0;k<2;k++)
        if(current_private_maps[n][k].attempted||current_private_maps[n][k].unknown||
           current_private_graphs[n][k].attempted||current_private_graphs[n][k].unknown||
           current_private_providers[n][k].attempted||current_private_providers[n][k].unknown||
           current_private_timers[n][k].attempted||current_private_timers[n][k].unknown||
           current_private_events[n][k].attempted||current_private_events[n][k].unknown)current_private_raw(n,k);
    ram_report("CURRENT_PARENT_PAYLOAD_RAW_V1_BYTES=",sizeof(current_payload_binding));
    ram_text("CURRENT_PARENT_PAYLOAD_RAW_V1_BEGIN\r\n");ram_hex((const uint8_t*)&current_payload_binding,sizeof(current_payload_binding));
    ram_text("CURRENT_PARENT_PAYLOAD_RAW_V1_END\r\n");power_unknown_hold();
}
static int current_private_map(void*opaque,struct efi_system*system,struct pgcd_map*map,void*data)
{
    const struct pcmp_route*routes=current_private_routes;
    unsigned index=UINT32_MAX,slot=UINT32_MAX;
    int selected=pcmp_select(routes,PCMP_PARENT_CONTEXTS,map,data,&index,&slot);
    if(!selected||current_private_fault.unknown||opaque!=current_private_original_io.opaque||system!=system_table||
       !pcmp_in_self(&pgcd_record.self_owner,(const void*)(uintptr_t)pgcd_record.self_owner_address,sizeof(struct efi_loaded))||
       routes[index].context->io.map!=current_private_map){
        current_private_fault=(struct pcmp_route_fault){(uintptr_t)opaque,(uintptr_t)system,(uintptr_t)map,(uintptr_t)data,1,1,index,slot};
        current_private_stop();
    }
    const struct pcmp_input input={.image=(const void*)(uintptr_t)pgcd_record.self_owner_address,
        .images=&ppli_record,.payload_binding=&current_payload_binding,.native_flag=&wln_cpu_on_issued,.load_state=&load_state,
        .payload_slot=&payload,.log_slot=&log_snapshot,.received=&received,.payload_count=&payload_count,.plan=&plan,
        .image_handle=(uintptr_t)driver_image,.bank=POLARIS_RAM_BASE,.bank_bytes=POLARIS_RAM_SIZE,
        .log_bytes=sizeof(log_buffer)+128+EFI_XNU_LOG_SIZE};
    if(!pcmp_route_read(&routes[index],slot,&input,&current_private_original_io,map,data,ppli_actual_page)){
        current_private_fault=(struct pcmp_route_fault){(uintptr_t)opaque,(uintptr_t)system,(uintptr_t)map,(uintptr_t)data,1,1,index,slot};
        current_private_stop();
    }
    current_private_raw(index,slot);return 1;
}
#endif
#endif
#if EFI_XNU_WIFI_CPU_RO_ADMISSION
_Static_assert(sizeof(log_buffer)>=2*(PWCQ_RAW_BYTES+sizeof(pacgq_preboot_record)+sizeof(pacgq_preboot_i2c)+sizeof(pgcd_record))+65536,
    "complete CPU RO and original source reports fit without truncation");
#endif
#if EFI_XNU_WIFI_POWER_TRANSACTION_AVAILABLE
#if EFI_XNU_WIFI_PREPARED_POWER_AVAILABLE
#if EFI_XNU_WIFI_ARC_READ_AVAILABLE
#if EFI_XNU_WIFI_PRE_MASK_ARGUMENTS
#if EFI_XNU_WIFI_FOUR_VRM_AVAILABLE
_Static_assert(sizeof(struct pwrpt_result)==2072064,"complete four VRM body raw ABI");
#elif EFI_XNU_WIFI_DB_WORD_CAPTURE
_Static_assert(sizeof(struct pwrpt_result)==1969216,"complete word capture body raw ABI");
#elif EFI_XNU_WIFI_CPU_LIVE_DIAGNOSTICS
_Static_assert(sizeof(struct pwrpt_result)==1969104,"complete original body plus live failure raw ABI");
#else
_Static_assert(sizeof(struct pwrpt_result)==1969056,"complete normal pre-mask argument body raw ABI");
#endif
_Static_assert(sizeof(struct pwrpa_result)==25216,"complete argument and page prefix raw ABI");
#elif EFI_XNU_WIFI_ARC_READ_WORK_ADMISSION
_Static_assert(sizeof(struct pwrpt_result)==1943840,"complete current ARC READ/work body raw ABI");
#else
_Static_assert(sizeof(struct pwrpt_result)==1941984,"complete current ARC READ body raw ABI");
#endif
#if EFI_XNU_WIFI_DB_WORD_CAPTURE
_Static_assert(sizeof(struct pwra_result)==402048,"complete word capture access raw ABI");
#else
_Static_assert(sizeof(struct pwra_result)==401936,"complete current ARC READ access raw ABI");
#endif
#else
_Static_assert(sizeof(struct pwrpt_result)==1892336,"complete prepared power body raw ABI");
_Static_assert(sizeof(struct pwra_result)==401800,"complete prepared access raw ABI");
#endif
#elif EFI_XNU_WIFI_GCD_NAMESPACE_RO_AVAILABLE
_Static_assert(sizeof(struct pwrpt_result)==1235200+2*sizeof(struct pgns_result)+66*sizeof(struct pgns_target),"complete bounded namespace power RAW_V2 ABI");
#else
_Static_assert(sizeof(struct pwrpt_result)==1235200,"complete power raw ABI");
#endif
#if !EFI_XNU_WIFI_PREPARED_POWER_AVAILABLE
_Static_assert(sizeof(struct pwra_result)==399240,"complete checked access raw ABI");
#endif
#if EFI_XNU_WIFI_CPU_LIVE_DIAGNOSTICS
_Static_assert(sizeof(struct pwrpc_result)==10096,"complete CPU-local plus first live failure raw ABI");
#else
_Static_assert(sizeof(struct pwrpc_result)==10048,"complete CPU-local raw ABI");
#endif
/* Includes both complete client/path records, NPA/RPMh, current Clock/I2C/GCD
 * records and 1MiB for earlier firmware evidence/labels. Native 4MiB ring is
 * stored separately in the already sizeof(log_buffer)-based snapshot. */
#if EFI_XNU_WIFI_PREPARED_POWER_AVAILABLE
_Static_assert(sizeof(log_buffer)>=2*(sizeof(pwsp_record)+sizeof(pwrpt_record)+sizeof(pwrcl_record)+sizeof(pwnpa_record)+
    sizeof(pwrph_record)+sizeof(pacgq_preboot_record)+sizeof(pacgq_preboot_i2c)+sizeof(pgcd_record))+
#if EFI_XNU_WIFI_TERMINAL_GOP_DIAGNOSTICS
    4*sizeof(terminal_gop)+
#endif
#if EFI_XNU_WIFI_REMOTE_MEMORY_AVAILABLE
    3*(sizeof(incoming_parent_maps)+sizeof(ppli_record)+sizeof(current_private_maps)+sizeof(current_payload_binding)+sizeof(pbgi_cache_call)+sizeof(pbgi_seed)+sizeof(pbha_handles)+sizeof(pbhr_handles)+sizeof(pbhd_handles)+sizeof(pbhd_timer_handles)+sizeof(pbhi_handles)+sizeof(pbht_handles))+
    5*(sizeof(current_private_graphs)+sizeof(current_private_providers)+sizeof(current_private_timers)+sizeof(current_private_events))+
#endif
#if EFI_XNU_WIFI_EARLY_MEMORY_AVAILABLE
    2*sizeof(early_wifi_memory)+4*sizeof(early_wifi_gop)+2*sizeof(retained_wifi_memory)+
#endif
#if EFI_XNU_MSS_MEMORY_AVAILABLE
    2*sizeof(mss_memory)+
#endif
#if EFI_XNU_MSS_STAGING_AVAILABLE
    2*sizeof(mss_stage)+
#endif
#if EFI_XNU_MSS_MBA_SHARE_AVAILABLE
    2*PMSB_RAW_BYTES+
#endif
    1048576,
    "complete preparation/client/power/source raw must fit without truncation");
#elif EFI_XNU_WIFI_CMDDB_STAGED_RO_AVAILABLE
_Static_assert(sizeof(log_buffer)>=2*(sizeof(pwsp_record)+sizeof(pwnpa_record)+
    sizeof(pwrph_record)+sizeof(pacgq_preboot_record)+sizeof(pacgq_preboot_i2c)+sizeof(pgcd_record))+1048576,
    "complete staged RO/source raw records must fit without truncation");
#else
_Static_assert(sizeof(log_buffer)>=2*(PWBD_RAW_BYTES+sizeof(pwrpt_record)+sizeof(pwrcl_record)+sizeof(pwnpa_record)+
    sizeof(pwrph_record)+sizeof(pacgq_preboot_record)+sizeof(pacgq_preboot_i2c)+sizeof(pgcd_record))+1048576,
    "complete power/source raw records must fit without truncation");
#endif
#endif
#endif
#elif EFI_XNU_AUDIO_CLOCK_QUERY_AVAILABLE
#if !defined(POLARIS_EFI_TEST_QEMU)
#include "uefi-audio-clock-query.h"
#endif
#endif
#if EFI_XNU_WIFI_RESOURCES_AVAILABLE || EFI_XNU_AUDIO_CLOCK_QUERY_AVAILABLE || EFI_XNU_AUDIO_CLOCK_QUERY_CAMERA_READONLY || EFI_XNU_AUDIO_CLOCK_QUERY_MSS_READONLY
#if !EFI_XNU_WIFI_RESOURCES_AVAILABLE || !EFI_XNU_AUDIO_CLOCK_QUERY_AVAILABLE || !EFI_XNU_AUDIO_CLOCK_QUERY_CAMERA_READONLY || !EFI_XNU_AUDIO_CLOCK_QUERY_MSS_READONLY || !EFI_XNU_AUDIO_I2C_CACHE_AVAILABLE || !EFI_XNU_WIFI_NORMAL_NC_FIRSTREAD_AVAILABLE || !EFI_XNU_WIFI_CACHE_AVAILABLE
#error "Resource/Clock scope requires exact combined original caches, NC and GCC readonly clock baseline"
#endif
#endif
#if EFI_XNU_WIFI_NORMAL_NC_FIRSTREAD_AVAILABLE && EFI_XNU_WIFI_FIRSTREAD_AVAILABLE
#error "Normal-NC and original Device-only firstread are mutually exclusive"
#endif
#if EFI_XNU_WIFI_NORMAL_NC_FIRSTREAD_AVAILABLE && !EFI_XNU_WIFI_CACHE_AVAILABLE
#error "Normal-NC first-read requires its exact original firmware cache witness"
#endif
#if EFI_XNU_WIFI_FIRSTREAD_AVAILABLE && !EFI_XNU_WIFI_CACHE_AVAILABLE
#error "CPU0 first-read requires its exact original firmware cache witness"
#endif
#if EFI_XNU_WIFI_NATIVE_RUNTIME_AVAILABLE
#include "uefi-wifi-worker-native.h"
#include "uefi-wifi-system-off-native.h"
static struct pwns_parent wifi_native_parent;
#if EFI_XNU_WIFI_TERMINAL_GOP_DIAGNOSTICS
/* Failure-only projection of resident startup records. Use the already armed
 * early GOP before CPU_ON; never poll a provider or draw after CPU_ON here. */
static void wifi_native_startup_gop_evidence(void)
{
    struct pwtg_result*r=&early_wifi_gop;const struct pwns_parent*s=&wifi_native_parent;
    const struct pmsc_owner*o=&s->owner;
    if(wln_cpu_on_issued||wifi_native_boot_phase<4||
       r->native_address!=(uintptr_t)&wln_cpu_on_issued||r->self_base!=pgcd_record.self_base||
       r->self_bytes!=pgcd_record.self_bytes||r->headers.address[0]!=(uintptr_t)gop){
        (void)pwtg_fail(r,PWTG_ARGUMENT);early_wifi_gop_raw();return;
    }
    pwtg_line(r,0,"NATIVE HOLD",wifi_native_boot_phase,s->error);
    pwtg_line(r,1,"PARENT PH FLAGS",s->phase,s->attempted|(s->unknown<<8));
    pwtg_line(r,2,"OWNER ERR PHASE",o->error,o->phase);
    pwtg_line(r,3,"OWNER HELD MASK",o->held,o->mask_issued);
    pwtg_line(r,4,"OWNER LAST TICK",(uint32_t)(o->last>>32),(uint32_t)o->last);
    pwtg_line(r,5,"OWNER ENTRY TICK",(uint32_t)(o->entry.cpu.ticks>>32),(uint32_t)o->entry.cpu.ticks);
    pwtg_line(r,6,"OWNER CHECKS",o->checkpoints,o->live_checks);
    pwtg_line(r,7,"IMAGES MAP ERR",s->images.error,s->map.error);
    pwtg_line(r,8,"RPMH CMDDB ERR",s->rpmh.error,s->cmddb.error);
    pwtg_line(r,9,"RSC POWER ERR",s->rsc.error,s->power.error);
    pwtg_line(r,10,"CLOCK AOP ERR",s->clocks.error,s->aop.error);
    pwtg_line(r,11,"BOOT AUTH ERR",s->boot.error,s->auth.error);
    pwtg_line(r,12,"SMEM RMTFS ERR",s->smem.error,s->rmtfs.error);
    pwtg_line(r,13,"WLAN SMMU ERR",s->wlan.error,s->smmu.error);
    pwtg_line(r,14,"CE WMI ERR",s->ce.error,s->wmi.error);
    pwtg_line(r,15,"HTT NONCE ERR",s->htt.error,s->nonce.error);
    if(s->images.error==2){
        const struct pmli_failure*f=&s->images.failure;
        pwtg_line(r,7,"IMAGE WHY BYTES",f->reason,(uint32_t)f->bytes);
        pwtg_line(r,8,"IMAGE READ ADDR",(uint32_t)(f->address>>32),(uint32_t)f->address);
        pwtg_line(r,9,"IMAGE READ SLOT",(uint32_t)(f->record_offset>>32),(uint32_t)f->record_offset);
        pwtg_line(r,10,"MAP TYPE MATCH",f->type,f->matches);
        pwtg_line(r,11,"MAP ATTR",(uint32_t)(f->attributes>>32),(uint32_t)f->attributes);
        pwtg_line(r,12,"MAP BASE",(uint32_t)(f->base>>32),(uint32_t)f->base);
        pwtg_line(r,13,"MAP PAGES",(uint32_t)(f->pages>>32),(uint32_t)f->pages);
        pwtg_line(r,14,"IMAGE COUNTS",s->images.pass[0].protocols,s->images.pass[0].images);
        pwtg_line(r,15,"IMAGE PASS2",s->images.pass[1].protocols,s->images.pass[1].images);
    }
    if(s->cmddb.error==5){
        const struct pmdc_failure*f=&s->cmddb.failure;
        pwtg_line(r,7,"CMDDB WHY SLOT",f->reason,f->slot);
        pwtg_line(r,8,"CMDDB PAGE ADDR",(uint32_t)(f->address>>32),(uint32_t)f->address);
        pwtg_line(r,9,"EFI TYPE MATCH",f->map_type,f->map_matches);
        pwtg_line(r,10,"EFI CAP",(uint32_t)(f->map_attributes>>32),(uint32_t)f->map_attributes);
        pwtg_line(r,11,"GCD TYPE CAPS",f->gcd_type,(uint32_t)f->gcd_capabilities);
        pwtg_line(r,12,"GCD ATTR",(uint32_t)(f->gcd_attributes>>32),(uint32_t)f->gcd_attributes);
        pwtg_line(r,13,"TARGET PAR",(uint32_t)(f->par>>32),(uint32_t)f->par);
        pwtg_line(r,14,"CMDDB READS",s->cmddb.pass[0].reads,s->cmddb.pass[1].reads);
        pwtg_line(r,15,"CMDDB PAGES",s->cmddb.pass[0].pages,s->cmddb.pass[1].pages);
    }
    if(s->aop.error==4&&s->aop.pending&&s->aop.pending<=PMAN_RECORDS&&
       s->aop.pending==s->aop.deliveries&&s->aop.records==(uintptr_t)s->aop_records&&
       s->aop.phase>=1&&s->aop.phase<=2){
        const struct pman_delivery*d=&s->aop_records[s->aop.pending-1];
        const struct pmaq_notify*q=&s->aop.notify[s->aop.phase-1];
        pwtg_line(r,0,"AOP HOLD",wifi_native_boot_phase,s->phase);
        pwtg_line(r,1,"AOP WHY EVENT",d->reserved,s->aop.deliveries);
        pwtg_line(r,2,"AOP STEP INDEX",d->command.step,d->command.index);
        pwtg_line(r,3,"AOP KIND ERROR",d->command.kind,d->native.error);
        pwtg_line(r,4,"AOP ADDRESS",(uint32_t)(d->command.address>>32),(uint32_t)d->command.address);
        pwtg_line(r,5,"AOP TARGETS",d->target[0].complete,d->target[1].complete);
        pwtg_line(r,6,"AOP PAR",(uint32_t)(d->native.AT.read_par>>32),(uint32_t)d->native.AT.read_par);
        pwtg_line(r,7,"AOP PROTO ERROR",q->error,q->step);
        if(q->error==5){
            static const char labels[8][16]={"AOP DESC 00 01","AOP DESC 02 03","AOP DESC 04 05","AOP DESC 06 07",
                "AOP DESC 08 09","AOP DESC 10 11","AOP DESC 12 13","AOP DESC 14 15"};
            for(unsigned n=0;n<8;n++)pwtg_line(r,8+n,labels[n],q->descriptor[2*n],q->descriptor[2*n+1]);
        }else{
            pwtg_line(r,8,"AOP IO VALUE",d->native.issued|(d->native.returned<<8),d->native.value);
            pwtg_line(r,9,"AOP PENDING",q->pending,q->events);
            pwtg_line(r,10,"AOP GCD TYPE CAP",0,0);pwtg_line(r,11,"AOP GCD ATTR",0,0);

            uint64_t page=d->command.address&~UINT64_C(4095);
            if(s->map.pass[1].nodes<=PMRG_NODES)for(unsigned n=0;n<s->map.pass[1].nodes;n++){
                const uint8_t*v=s->map.pass[1].node[n].raw;uint64_t base=pwfi_le(v+24,8),end=pwfi_le(v+32,8);
                if(base>page||end<page||end-page<4095)continue;
                uint64_t attr=pwfi_le(v+48,8);
                pwtg_line(r,10,"AOP GCD TYPE CAP",(uint32_t)pwfi_le(v+56,4),(uint32_t)pwfi_le(v+40,8));
                pwtg_line(r,11,"AOP GCD ATTR",(uint32_t)(attr>>32),(uint32_t)attr);
                break;
            }
            const struct pwea_map*m=&retained_wifi_memory.map;unsigned type=0,matches=0;uint64_t attr=0;
            if(o->retained==(uintptr_t)&retained_wifi_memory&&m->map.stride>=sizeof(struct efi_memory)&&
               !(m->map.stride&7)&&m->map.bytes<=sizeof(m->data)&&!(m->map.bytes%m->map.stride)){
                for(uint64_t off=0;off<m->map.bytes;off+=m->map.stride){
                    const struct efi_memory*v=(const void*)(m->data+off);
                    if(page>=v->physical&&(page-v->physical)/4096<v->pages){
                        if(!matches){type=v->type;attr=v->attributes;}matches++;
                    }
                }
            }
            pwtg_line(r,12,"AOP EFI TYPE N",type,matches);
            pwtg_line(r,13,"AOP EFI ATTR",(uint32_t)(attr>>32),(uint32_t)attr);
            pwtg_line(r,14,"AOP OPEN TICK",(uint32_t)(q->opening>>32),(uint32_t)q->opening);
            pwtg_line(r,15,"OWNER LAST TICK",(uint32_t)(o->last>>32),(uint32_t)o->last);
        }
    }
    /* Failure-only supply/checkpoint evidence. Read embedded resident records;
     * no power request, provider, retry, timer or hardware observation here. */
    if(s->power.error==6){
        const struct pmpn_state*p=&s->power;const struct pmsp_lifecycle*v=&s->supply;
        pwtg_line(r,0,"PWR HOLD",wifi_native_boot_phase,s->phase);
        pwtg_line(r,1,"PWR ERR CALLS",p->error,p->supply_calls);
        pwtg_line(r,2,"SUP ERR PHASE",v->error,v->phase);
        pwtg_line(r,3,"SUP INDEX EVENTS",v->index,v->events);
        pwtg_line(r,4,"SUP PEND REQUEST",v->pending,p->requests);
        pwtg_line(r,5,"SUP TRANS TICK",(uint32_t)(v->transition>>32),(uint32_t)v->transition);
        pwtg_line(r,6,"SUP LAST TICK",(uint32_t)(v->last>>32),(uint32_t)v->last);
        pwtg_line(r,7,"OWNER LAST TICK",(uint32_t)(o->last>>32),(uint32_t)o->last);
        pwtg_line(r,8,"CHECKS PHASE",p->checkpoints,p->supply_phase);
        pwtg_line(r,9,"CHECK STATUS",0,0);pwtg_line(r,10,"CHECK RPMH DB",0,0);pwtg_line(r,11,"CHECK DB PAGES",0,0);
        if(p->checkpoints&&p->checkpoints<=PMPN_CHECKPOINTS){
            const struct pmpn_checkpoint*c=&p->checkpoint[p->checkpoints-1];
            pwtg_line(r,9,"CHECK STATUS",c->attempted,c->complete);
            pwtg_line(r,10,"CHECK RPMH DB",c->rpmh.reads,c->cmddb.reads);
            pwtg_line(r,11,"CHECK DB PAGES",c->cmddb.pages,c->cmddb.complete);
        }
        pwtg_line(r,12,"REQ VALID ERROR",0,0);pwtg_line(r,13,"REQ PH EVENTS",0,0);
        pwtg_line(r,14,"REQ RES RESPONSE",0,0);pwtg_line(r,15,"REQ AGE TICKS",0,0);
        if(p->records==(uintptr_t)s->power_records&&p->pending&&p->pending<=PMPN_REQUESTS&&p->pending==p->requests){
            const struct pmrv_request*q=&s->power_records[p->pending-1].request;
            pwtg_line(r,12,"REQ VALID ERROR",q->valid,q->io.error);
            pwtg_line(r,13,"REQ PH EVENTS",q->io.phase,q->io.events);
            pwtg_line(r,14,"REQ RES RESPONSE",q->resource,q->response);
            uint64_t age=q->io.last>=q->io.started?q->io.last-q->io.started:UINT64_MAX;
            pwtg_line(r,15,"REQ AGE TICKS",(uint32_t)(age>>32),(uint32_t)age);
        }
    }
    (void)pwtg_draw(r);early_wifi_gop_raw();
}
#endif
static struct pwwn_state wifi_native_worker;
static struct pwno_state wifi_native_terminal;
static uint32_t wifi_native_prepared;
#include "uefi-wifi-ui-window.h"
static struct pwnu_state wifi_native_ui;
static uint64_t wifi_native_ui_last;
static int wifi_native_ui_healthy(void)
{return !buttons_terminal&&!wln_power.error&&!wln_power.uncertain&&!wln_runtime.error&&!wln_firmware.error&&!log_overflow;}
static int pwnu_service(unsigned operation,uint64_t cookie,uint32_t sequence)
{
    if(operation==PWNU_PREPARE)return buttons_prepare()&&wln_begin()&&wifi_native_ui_healthy();
    if(operation==PWNU_SEAL)return wifi_native_ui_healthy()&&wln_reset_ready(cookie,sequence,2);
    if(operation==PWNU_CLOSE&&!wln_close(2))return 0;
    buttons_poll();wln_poll();
#if EFI_XNU_BATTERY_AVAILABLE
    if(operation==PWNU_POLL)pb_runtime_poll();
#endif
    if(!wifi_native_ui_healthy())return 0;
    return operation==PWNU_CLOSE&&wln_runtime.closing&&!wln_runtime.pending&&
        !wln_firmware.pending&&wln_power.actual_on?2:1;
}
static int pwno_ui_ready(const struct polaris_shutdown_status*status)
{
    return status&&status->phase==POLARIS_Q_SEALED&&status->mode==2&&
        pwnu_run(&wifi_native_ui,&wifi_native_parent.owner,PWNU_SEAL,status->cookie,status->sequence)==1;
}
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
#if EFI_XNU_WIFI_REMOTE_MEMORY_AVAILABLE
    if(!pcmp_payload_bind(&current_payload_binding,payload,payload_count,&plan))current_private_stop();
#endif
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
#if EFI_XNU_WIFI_NATIVE_RUNTIME_AVAILABLE
    if(wifi_native_prepared||wifi_native_boot_phase)return 0;
#endif
#if EFI_XNU_WIFI_REMOTE_MEMORY_AVAILABLE
    if(!ppli_bind(&ppli_record,&wln_cpu_on_issued,(uintptr_t)driver_image))ppli_parent_stop();
#endif
#if EFI_XNU_WIFI_TERMINAL_GOP_DIAGNOSTICS && !defined(POLARIS_EFI_TEST_QEMU)
    if(!terminal_gop_arm()){
        terminal_gop_raw();
        if(terminal_gop.uncertain){original_service_unknown=1;power_unknown_hold();}
        /* No private/CPU/access work has started. Missing display provenance
         * safely refuses this diagnostic instead of running another opaque
         * power test. Reentry cannot open a second admission. */
        return 0;
    }
#endif
#if EFI_XNU_WIFI_EARLY_MEMORY_AVAILABLE && !EFI_XNU_WIFI_NATIVE_RUNTIME_AVAILABLE
    const struct pweh_input retained_input={.early=&early_wifi_memory,.digest=early_wifi_digest,
        .payload_slot=&payload,.log_slot=&log_snapshot,.state=&load_state,.received=&received,.count=&payload_count,
        .logical_bytes=EFI_XNU_PAYLOAD_BYTES,.log_bytes=sizeof(log_buffer)+128+EFI_XNU_LOG_SIZE};
    int retained_ok=pweh_run(&retained_wifi_memory,&retained_input);
    ram_report("RETAINED_WIFI_MEMORY_ACCEPTED=",retained_ok);
    ram_report("RETAINED_WIFI_MEMORY_RAW_V1_BYTES=",sizeof(retained_wifi_memory));
    ram_text("RETAINED_WIFI_MEMORY_RAW_V1_BEGIN\r\n");ram_hex((const void*)&retained_wifi_memory,sizeof(retained_wifi_memory));
    ram_text("RETAINED_WIFI_MEMORY_RAW_V1_END\r\n");
    if(!retained_ok){original_service_unknown=1;power_unknown_hold();}
#if EFI_XNU_WIFI_NONCE_POOL_AVAILABLE
    /* Keep this candidate's input in the linked image and check it before
     * any new staging/assignment. The later native producer still performs
     * its own fresh source translation and single-owner consumption. This
     * input check neither starts WLAN nor authorizes replaying the image. */
    uint8_t nonce_hash[32];
    pweh_digest(polaris_wifi_image_nonces,POLARIS_WIFI_IMAGE_NONCE_BYTES,nonce_hash);
    int nonce_input_ok=pgcd_equal(nonce_hash,polaris_wifi_image_nonce_sha256,32);
    ram_report("WIFI_HOST_NONCE_INPUT_ACCEPTED=",nonce_input_ok);
    if(!nonce_input_ok){original_service_unknown=1;power_unknown_hold();}
#endif
#if EFI_XNU_MSS_MEMORY_AVAILABLE
    mss_retained_attempted=1;
    mss_retained_ok=pmmn_retained(&mss_memory,mss_memory_digest,&retained_wifi_memory);
    ram_report("RETAINED_MSS_MEMORY_ACCEPTED=",mss_retained_ok);
    if(!mss_retained_ok){original_service_unknown=1;power_unknown_hold();}
#if EFI_XNU_MSS_STAGING_AVAILABLE
#if EFI_XNU_MSS_PAYLOAD_FIRMWARE_AVAILABLE
    const uint8_t*mss_firmware_source=payload+EFI_XNU_MSS_FIRMWARE_OFFSET;
#else
    const uint8_t*mss_firmware_source=pmsf_blob;
#endif
    int stage_ok=pmsi_stage(&mss_stage,&mss_memory,mss_memory_digest,&retained_wifi_memory,
        mss_firmware_source,PMSF_BLOB_BYTES,pmsf_assets,PMSF_ASSETS);
    ram_report("MSS_STAGE_ACCEPTED=",stage_ok);
    ram_report("MSS_STAGE_RAW_V1_BYTES=",sizeof(mss_stage));
    ram_text("MSS_STAGE_RAW_V1_BEGIN\r\n");ram_hex((const void*)&mss_stage,sizeof(mss_stage));
    ram_text("MSS_STAGE_RAW_V1_END\r\n");
    if(!stage_ok){original_service_unknown=1;power_unknown_hold();}
#if EFI_XNU_MSS_MBA_SHARE_AVAILABLE
    int mba_share_ok=pmsb_share(&mss_mba_share,&mss_stage);
    ram_report("MSS_MBA_SHARE_ACCEPTED=",mba_share_ok);
    ram_report("MSS_MBA_SHARE_RAW_V1_BYTES=",PMSB_RAW_BYTES);
    ram_text("MSS_MBA_SHARE_RAW_V1_BEGIN\r\n");ram_hex((const void*)&mss_mba_share,PMSB_RAW_BYTES);
    ram_text("MSS_MBA_SHARE_RAW_V1_END\r\n");
    if(!mba_share_ok){original_service_unknown=1;power_unknown_hold();}
#endif
#endif
#endif
#endif
#if EFI_XNU_WIFI_CACHE_AVAILABLE
#if defined(POLARIS_EFI_TEST_QEMU)
    static unsigned wifi_cache_software_reported;
    if(!wifi_cache_software_reported){
        wifi_cache_software_reported=1;
        report("WIFI_CACHE_SOFTWARE_PHYSICAL_IMAGE_INSPECTION_COMPILED_OUT=",1);
#if EFI_XNU_WIFI_FIRSTREAD_AVAILABLE
        report("WIFI_FIRSTREAD_SOFTWARE_PHYSICAL_SMEM_READ_COMPILED_OUT=",1);
#endif
#if EFI_XNU_WIFI_NORMAL_NC_FIRSTREAD_AVAILABLE
        report("WIFI_NORMAL_NC_FIRSTREAD_SOFTWARE_PHYSICAL_SMEM_READ_COMPILED_OUT=",1);
#endif
#if EFI_XNU_WIFI_RESOURCES_AVAILABLE
        report("WIFI_RESOURCES_SOFTWARE_PHYSICAL_MAP_PSCI_COMPILED_OUT=",1);
#endif
#if EFI_XNU_WIFI_NPA_READONLY_AVAILABLE
        report("WIFI_NPA_SOFTWARE_PHYSICAL_NAMESPACE_COMPILED_OUT=",1);
#endif
#if EFI_XNU_WIFI_RPMH_READONLY_AVAILABLE
        report("WIFI_RPMH_SOFTWARE_PHYSICAL_PROVIDER_RAM_COMPILED_OUT=",1);
#endif
#if EFI_XNU_WIFI_RPMH_CLIENT_AVAILABLE
        report("WIFI_RPMH_PRIVATE_SOFTWARE_PHYSICAL_CLIENT_COMPILED_OUT=",1);
#endif
#if EFI_XNU_WIFI_POWER_TRANSACTION_AVAILABLE
        report("WIFI_POWER_SOFTWARE_PHYSICAL_TRANSACTION_COMPILED_OUT=",1);
#endif
#if EFI_XNU_WIFI_CPU_RO_ADMISSION
        report("WIFI_CPU_RO_SOFTWARE_PHYSICAL_COMPILED_OUT=",1);
#if EFI_XNU_WIFI_CPU_MASKED_RO_ADMISSION
        report("WIFI_CPU_MASKED_RO_SOFTWARE_PHYSICAL_COMPILED_OUT=",1);
#endif
#endif
    }
#else
    /* Diagnostic only: all BootServices queries before any IRQ mask/change.
     * Failure records evidence and does not block the other runtime services. */
#if EFI_XNU_WIFI_FIRSTREAD_AVAILABLE || EFI_XNU_WIFI_NORMAL_NC_FIRSTREAD_AVAILABLE
    /* No text/report/console or PON call may enter this fresh interval. */
    if(!pwfc_record.attempted){
        int cache_ok=pwfc_collect_preboot(system_table,load_state);
        if(cache_ok){
#if EFI_XNU_WIFI_NORMAL_NC_FIRSTREAD_AVAILABLE
#if EFI_XNU_WIFI_RESOURCES_AVAILABLE
            pwnc_collect_preboot(&pwfc_record,load_state);
            (void)pfr_prepare(system_table,&pwfc_record,load_state);
            pwnc_report();
#else
            pwnc_prepare(&pwfc_record,load_state);
#endif
#else
            pwfr_prepare(&pwfc_record,load_state);
#endif
        }
        else {
#if EFI_XNU_WIFI_NORMAL_NC_FIRSTREAD_AVAILABLE
            report("WIFI_NORMAL_NC_FIRSTREAD_SKIPPED_CACHE_ERROR=",pwfc_record.error);
            report("WIFI_NORMAL_NC_FIRSTREAD_ATTEMPTED=",0);
#else
            report("WIFI_FIRSTREAD_SKIPPED_CACHE_ERROR=",pwfc_record.error);
            report("WIFI_FIRSTREAD_ATTEMPTED=",0);
#endif
        }
        pwfc_report();
#if EFI_XNU_WIFI_RESOURCES_AVAILABLE
        ram_report("WIFI_RESOURCES_ATTEMPTED=",pfr_record.attempted);
        ram_report("WIFI_RESOURCES_ERROR=",pfr_record.error);
        ram_report("WIFI_RESOURCES_RAW_V1_BYTES=",sizeof(pfr_record));
        ram_text("WIFI_RESOURCES_RAW_V1_BEGIN\r\n");ram_hex((const uint8_t*)&pfr_record,sizeof(pfr_record));
        ram_text("WIFI_RESOURCES_RAW_V1_END\r\nWIFI_RESOURCES_SCOPE=MAP_PSCI_OBSERVATIONS_ONLY NO_FREE_OR_OWNER_GRANT RMTFS_UNASSIGNED MSA_UNASSIGNED\r\n");
#endif
    }
#else
    pwfc_prepare(system_table,load_state);
#endif
#if EFI_XNU_WIFI_REMOTE_MEMORY_AVAILABLE
    if(!ppli_record.complete||ppli_record.unknown)ppli_parent_stop();
    if(!pbgi_seed.complete||pbgi_seed.unknown)pbgi_parent_stop();
    if(!pbha_handles.complete||pbha_handles.unknown)pbha_parent_stop();
    if(!pbhr_handles.complete||pbhr_handles.unknown)pbhr_parent_stop();
    if(!pbhd_handles.complete||pbhd_handles.unknown||!pbhd_timer_handles.complete||pbhd_timer_handles.unknown||!pbhi_handles.complete||!pbhi_handles.closed||pbhi_handles.unknown||!pbht_handles.complete||pbht_handles.unknown)pbhr_parent_stop();
    ppli_parent_raw();pbgi_parent_raw();pbha_parent_raw();pbhr_parent_raw();pbhd_parent_raw();
#endif
#endif
#endif
#if EFI_XNU_AUDIO_I2C_CACHE_AVAILABLE
    /* Audio is independent original-imageRAM only. All ofWiFi's fresh
     * collect/read/report is FINISHED before these BootServices orconsole. */
#if defined(POLARIS_EFI_TEST_QEMU)
    static unsigned audio_cache_software_reported;
    if(!audio_cache_software_reported){
        audio_cache_software_reported=1;
        report("AUDIO_I2C_CACHE_SOFTWARE_PHYSICAL_IMAGE_INSPECTION_COMPILED_OUT=",1);
    }
#else
#if EFI_XNU_AUDIO_CLOCK_GCD_QUERY_AVAILABLE
#if EFI_XNU_WIFI_CPU_RO_ADMISSION
    if(new_original_unknown()){original_service_unknown=1;power_unknown_hold();}
#endif
    if(original_service_unknown)return 0;
    struct pgcd_context *gcd=pgcd_prepare(system_table,load_state);
#if EFI_XNU_WIFI_REMOTE_MEMORY_AVAILABLE
    /* The four preparation constructors and client constructor inherit this
     * IO. Dispatch all six exact source/ticket pairs, keeping every lifetime
     * and its original calls independent; never reopen or renew a context. */
    if(gcd!=&pgcd_resident_context||gcd->record!=&pgcd_record||gcd->ticket!=&pgcd_ticket||
       gcd->opened||gcd->finished||pgcd_ticket.spent||pgcd_record.attempted||gcd->io.map!=pgcd_actual_map)current_private_stop();
    current_private_original_io=gcd->io;gcd->io.map=current_private_map;
#endif
    pacgq_collect_preboot(system_table,load_state,gcd
#if EFI_XNU_WIFI_POWER_TRANSACTION_AVAILABLE || EFI_XNU_WIFI_CPU_RO_ADMISSION
        ,&wln_cpu_on_issued
#endif
    );
    pacgq_report_preboot(ram_text);
    ram_report("ORIGINAL_GCD_ATTEMPTED=",pgcd_record.attempted);
    ram_report("ORIGINAL_GCD_ERROR=",pgcd_record.error);
    ram_report("ORIGINAL_GCD_RAW_V1_BYTES=",sizeof(pgcd_record));
    ram_text("ORIGINAL_GCD_RAW_V1_BEGIN\r\n");ram_hex((const uint8_t*)&pgcd_record,sizeof(pgcd_record));
    ram_text("ORIGINAL_GCD_RAW_V1_END\r\n");
    if(new_original_unknown()){
        original_service_unknown=1;ram_report("ORIGINAL_SERVICE_UNKNOWN_NATIVE_AND_RESET_BLOCKED=",1);
#if EFI_XNU_WIFI_POWER_TRANSACTION_AVAILABLE || EFI_XNU_WIFI_CPU_RO_ADMISSION
        ram_report("WIFI_POWER_UNKNOWN_RAM_ONLY_NO_FOREIGN_FIRMWARE_NO_ACK_HOLD=",1);
        power_unknown_hold();
#endif
        return 0;
    }
#elif EFI_XNU_AUDIO_CLOCK_QUERY_AVAILABLE
    pacq_collect_preboot(system_table,load_state);
    pacq_report_preboot(ram_text);
#else
    paic_prepare(system_table,load_state);
#endif
#endif
#endif
#if EFI_XNU_AUDIO_CLOCK_QUERY_AVAILABLE
#if defined(POLARIS_EFI_TEST_QEMU)
    static unsigned audio_clock_software_reported;
    if(!audio_clock_software_reported){
        audio_clock_software_reported=1;
        report("AUDIO_CLOCK_QUERY_SOFTWARE_PHYSICAL_ORIGINAL_QUERY_COMPILED_OUT=",1);
    }
#endif
#endif
#if EFI_XNU_GCD_MMIO_QUERY_AVAILABLE && defined(POLARIS_EFI_TEST_QEMU)
    report("ORIGINAL_GCD_SOFTWARE_PHYSICAL_SERVICE_FP_COMPILED_OUT=",1);
    report("AUDIO_CLOCK_GCD_SOFTWARE_PHYSICAL_QUERY_COMPILED_OUT=",1);
#endif
#if defined(EFI_XNU_WLED_NATIVE_RUNTIME)
    /* A BootServices lookup belongs BEFORE CPU0 IRQ ownership changes. */
    if(!cache_reset_protocol()){report("WLED_NATIVE_RESET_CACHE_REFUSED=",1);return 0;}
#endif
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
#if EFI_XNU_WIFI_NATIVE_MEMORY_AVAILABLE
    if(!pwks_begin(&wifi_native_kernel_copy,p,payload_count))return 0;
#endif
    for(uint32_t i=0;i<p->nsegs;i++){
        const struct polaris_segment *s=&p->segs[i];uint64_t dest=p->phys_base+s->vmaddr-p->virt_base;
        bytes_copy((void*)(uintptr_t)dest,payload+s->file_off,s->file_size);
        bytes_zero((void*)(uintptr_t)(dest+s->file_size),s->vmsize-s->file_size);clean(dest,s->vmsize);
#if EFI_XNU_WIFI_NATIVE_MEMORY_AVAILABLE
        if(!pwks_verify(&wifi_native_kernel_copy,i))return 0;
#endif
    }
#if EFI_XNU_HOST_UTC_AVAILABLE
    /* Exact file-backed native DATA symbol; after all copy/zero, before CPU_ON.
     * No native clock is changed until a later explicitly requested host SET. */
    if(!host_utc_prepare()){report("HOST_UTC_PREPARE_REFUSED=",1);return 0;}
    report("HOST_UTC_RAM_MAILBOX_PREPARED=",1);
#endif
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
    clean((uintptr_t)polaris_efi_ap_entry,4096);
#if EFI_XNU_WIFI_NATIVE_RUNTIME_AVAILABLE
    /* Keep state2/flag0 through fresh retained/MBA/CPU-owner admission. No
     * state3->2 rewrite or false completed runtime appears in the records. */
    wifi_native_prepared=1;
#else
    load_state=3;
#endif
    report("KERNEL_PREPARED_ENTRY=",plan.entry_pa);return 1;
}
#if EFI_XNU_WIFI_NATIVE_RUNTIME_AVAILABLE
/* Every original provider/query and all kernel/ADT/args copying has finished.
 * After entering this function, failures hold and never return to UsbFn or
 * an original provider. Full post-CE retirement is still required before the
 * builder may admit this feature into a physical candidate. */
/* Keep staging/owner acquisition out of the persistent service stack frame. */
__attribute__((noinline)) static void wifi_native_startup(void)
{
    if(load_state!=2||wifi_native_prepared!=1||wifi_native_boot_phase)power_unknown_hold();
    wifi_native_boot_phase=1;ram_lease.active=0;
#if defined(EFI_XNU_DURABLE_GUARD)
    struct args*a=(void*)(uintptr_t)plan.args_pa;bool physical=false;
#if defined(EFI_XNU_PHYSICAL_MARKER)
    physical=true;
#endif
    if(!polaris_marker_append_guard(a->cmdline,sizeof(a->cmdline),physical))power_unknown_hold();
    clean(plan.args_pa,sizeof(*a));
#endif
#if EFI_XNU_GCD_MMIO_QUERY_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
    if(new_original_unknown()||log_overflow||!pacgq_prestart_checkpoint(&pgcd_resident_context))power_unknown_hold();
#endif
    const struct pweh_input input={.early=&early_wifi_memory,.digest=early_wifi_digest,
        .payload_slot=&payload,.log_slot=&log_snapshot,.state=&load_state,.received=&received,.count=&payload_count,
        .logical_bytes=EFI_XNU_PAYLOAD_BYTES,.log_bytes=sizeof(log_buffer)+128+EFI_XNU_LOG_SIZE};
    if(!pweh_run(&retained_wifi_memory,&input))power_unknown_hold();
    wifi_native_boot_phase=2;
    uint8_t hash[32];pweh_digest(polaris_wifi_image_nonces,POLARIS_WIFI_IMAGE_NONCE_BYTES,hash);
    if(!pgcd_equal(hash,polaris_wifi_image_nonce_sha256,32))power_unknown_hold();
    mss_retained_attempted=1;mss_retained_ok=pmmn_retained(&mss_memory,mss_memory_digest,&retained_wifi_memory);
    if(!mss_retained_ok)power_unknown_hold();
#if EFI_XNU_MSS_PAYLOAD_FIRMWARE_AVAILABLE
    const uint8_t*firmware=payload+EFI_XNU_MSS_FIRMWARE_OFFSET;
#else
    const uint8_t*firmware=pmsf_blob;
#endif
    if(!pmsi_stage(&mss_stage,&mss_memory,mss_memory_digest,&retained_wifi_memory,
        firmware,PMSF_BLOB_BYTES,pmsf_assets,PMSF_ASSETS))power_unknown_hold();
    wifi_native_boot_phase=3;
    if(!pmsb_share(&mss_mba_share,&mss_stage))power_unknown_hold();
    wifi_native_boot_phase=4;
    /* No full-record RAM dumps or unrelated calls consume the fresh source
     * interval between final GetMap, staging/assignment and CPU exclusion. */
    if(!pwns_begin(&wifi_native_parent,&retained_wifi_memory,&mss_memory,mss_memory_digest,&mss_mba_share,
        &wifi_native_nv,&wifi_native_ce_memory,&wifi_native_htt_memory,pmsf_segments,
        polaris_wifi_image_nonces,polaris_wifi_image_nonce_sha256))power_unknown_hold();
}
/* The staged producer switch has its own bounded temporary storage. */
__attribute__((noinline)) static int wifi_native_startup_step(void)
{return pwns_step(&wifi_native_parent);}
__attribute__((noreturn)) static void wifi_native_boot(void)
{
    wifi_native_startup();
    wifi_native_boot_phase=5;
    for(;;){int result=wifi_native_startup_step();if(result<0)power_unknown_hold();if(result==2)break;}
    /* READY is rechecked by the actual handoff, not inferred from phase++ . */
    wifi_native_boot_phase=6;
    if(pwnu_run(&wifi_native_ui,&wifi_native_parent.owner,PWNU_PREPARE,0,0)!=1)power_unknown_hold();
    wln_cpu_on_issued=1; /* Publish before even an uncertain CPU_ON result. */
    if(pwkr_begin(&wifi_native_parent,&wifi_native_kernel_copy,&polaris_efi_ap_state,
        (uintptr_t)polaris_efi_ap_entry,(uintptr_t)ap_stack,sizeof(ap_stack),&plan,EFI_XNU_WIFI_MAILBOX_VA)!=1)power_unknown_hold();
    for(;;){int result=pwkr_poll(&wifi_native_parent);if(result!=1&&result!=2)power_unknown_hold();if(result==2)break;}
    cpu_status=wifi_native_parent.owner.runtime.result;wifi_native_boot_phase=7;
    if(!pwwn_begin(&wifi_native_worker,&wifi_native_parent,EFI_XNU_WIFI_COUNTRY))power_unknown_hold();
    wifi_native_boot_phase=8;
    for(;;){
        int result=pwwn_step(&wifi_native_worker);if(result!=1&&result!=2)power_unknown_hold();
        uint64_t now=wifi_native_parent.owner.last;
        if(now<wifi_native_ui_last)power_unknown_hold();
        if(now-wifi_native_ui_last>=192000){
            unsigned operation=wifi_native_worker.terminal_requested?PWNU_CLOSE:PWNU_POLL;
            if(!pwnu_run(&wifi_native_ui,&wifi_native_parent.owner,operation,0,0))power_unknown_hold();
            wifi_native_ui_last=wifi_native_parent.owner.last;
        }
        if(result==2)break;
    }
    if(!wifi_native_worker.terminal_requested)power_unknown_hold();
    for(;;){
        if(wifi_native_parent.owner.last>wifi_native_worker.close_deadline)power_unknown_hold();
        int result=pwnu_run(&wifi_native_ui,&wifi_native_parent.owner,PWNU_CLOSE,0,0);
        if(!result||wifi_native_parent.owner.last>wifi_native_worker.close_deadline)power_unknown_hold();
        if(result==2)break;
    }
    wifi_native_boot_phase=9;
    if(pwno_begin(&wifi_native_terminal,&wifi_native_worker,EFI_XNU_WIFI_SHUTDOWN_VA)!=1)power_unknown_hold();
    wifi_native_boot_phase=10;
    for(;;)if(pwno_step(&wifi_native_terminal)!=1)power_unknown_hold();
}
#endif
static void boot_kernel(void *context)
{
#if EFI_XNU_WIFI_NATIVE_RUNTIME_AVAILABLE
    (void)context;wifi_native_boot();
#else
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
#if EFI_XNU_GCD_MMIO_QUERY_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
    /* Final restoration checkpoint AFTER all original BS/PON/Console calls,
     * BEFORE intentional DAIF/Group1 change. All following evidence uses RAM
     * only. It does not renew the earlier namespace/Device read permission. */
    int original_safe=!new_original_unknown()&&pacgq_prestart_checkpoint(&pgcd_resident_context);
    ram_report("ORIGINAL_SERVICE_FINAL_PRESTART_SAFE=",original_safe);
    ram_report("AUDIO_CLOCK_GCD_FINAL_PRESTART_CHECKED=",pacgq_preboot_record.prestart_checked);
    ram_report("AUDIO_CLOCK_GCD_FINAL_PRESTART_PASSED=",pacgq_preboot_record.prestart_passed);
    ram_report("AUDIO_CLOCK_GCD_FINAL_UNCERTAIN=",pacgq_preboot_record.uncertain);
    ram_report("AUDIO_CLOCK_GCD_FINAL_OUTSTANDING=",pacgq_preboot_record.outstanding);
    ram_report("ORIGINAL_GCD_FINAL_PRESTART_COUNT=",pgcd_record.prestart_count);
    ram_report("ORIGINAL_GCD_FINAL_PRESTART_BYTES=",sizeof(pgcd_record.prestart));
    ram_text("ORIGINAL_GCD_FINAL_PRESTART_BEGIN\r\n");ram_hex((const uint8_t*)pgcd_record.prestart,sizeof(pgcd_record.prestart));ram_text("ORIGINAL_GCD_FINAL_PRESTART_END\r\n");
    if(!original_safe){original_service_unknown=1;load_state=3;ram_lease.active=0;
#if EFI_XNU_WIFI_POWER_TRANSACTION_AVAILABLE || EFI_XNU_WIFI_CPU_RO_ADMISSION
        ram_report("WIFI_POWER_FINAL_UNKNOWN_RAM_ONLY_NO_FOREIGN_FIRMWARE_NO_ACK_HOLD=",1);power_unknown_hold();
#endif
        return;
    }
    if(log_overflow){load_state=3;ram_lease.active=0;return;}
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
    int keys_prepared=buttons_prepare();
#if defined(POLARIS_EFI_TEST_QEMU) && defined(EFI_XNU_TEST_WLED_PREPARE_REFUSAL) && EFI_XNU_TEST_WLED_PREPARE_REFUSAL==3
    keys_prepared=0; /* Exercise the actual pre-WLED refusal return path. */
#endif
    if(!keys_prepared) {
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
#if defined(EFI_XNU_WLED_NATIVE_RUNTIME)
#if defined(EFI_XNU_WLED_NATIVE_START_REFUSAL) && EFI_XNU_WLED_NATIVE_START_REFUSAL==3
    (void)wln_begin;load_state=3;report("WLED_NATIVE_BEFORE_RUNTIME_REFUSED=",1);return;
#else
    if(!wln_begin()){load_state=3;report("WLED_NATIVE_PREPARE_REFUSED=",1);return;}
#endif
#endif
#if defined(EFI_XNU_WLED_NATIVE_RUNTIME)
    /* Publish before the SMC/HVC. Even an unknown PSCI result forbids the
     * independent no-CPU/no-WRITE reset path from now on. */
    wln_cpu_on_issued=1;
#endif
    cpu_status=psci(UINT64_C(0xc4000003),EFI_XNU_CPU,(uintptr_t)polaris_efi_ap_entry,(uintptr_t)&polaris_efi_ap_state);
    report("KERNEL_PSCI_STATUS=",(uint64_t)cpu_status);
#endif
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
#if EFI_XNU_WIFI_RESOURCES_AVAILABLE
    if(log_overflow){
        static const char incomplete[]="\nFIRMWARE_RAM_LOG_OVERFLOW=1 INCOMPLETE_PREFIX\n";
        bytes_copy(log_snapshot+at,incomplete,sizeof(incomplete)-1);at+=sizeof(incomplete)-1;
    }
#endif
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
#if defined(EFI_XNU_WLED_NATIVE_RUNTIME)
            if(!(i&4095))wln_poll();
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
        int same=slot->firmware.sequence==1&&slot->firmware.cookie==s->cookie&&slot->firmware.mode==mode&&
            s->phase>=POLARIS_Q_RUNNING&&s->phase<=POLARIS_Q_SEALED;
#if defined(EFI_XNU_WLED_NATIVE_RUNTIME)
        return same&&wln_close(mode);
#else
        return same;
#endif
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
    clean((uintptr_t)&slot->firmware,sizeof(slot->firmware));
#if defined(EFI_XNU_WLED_NATIVE_RUNTIME)
    if(!wln_close(mode))return 0;
#endif
    return 1;
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
#if defined(EFI_XNU_WLED_NATIVE_RUNTIME)
static unsigned runtime_reset_armed,runtime_reset_mode,runtime_reset_error;
#if !defined(POLARIS_EFI_TEST_QEMU)
static uint32_t runtime_reset_before;
static struct polaris_efi_reset_marker runtime_reset_marker;
#endif
static int cache_reset_protocol(void)
{
#if !defined(POLARIS_EFI_TEST_QEMU)
    if(reset_pon)return reset_pon->revision==0x10001&&reset_pon->get&&reset_pon->set;
    if(wln_cpu_on_issued||!identity(UINT64_C(0x146bf65c)))return 0;
    static const efi_guid guid={0x97044b58,0xfea4,0x4ad0,{0x9d,0x0b,0xe4,0x17,0xd6,0x0f,0x11,0xa1}};
    efi_status status=system_table->boot->locate_protocol(&guid,0,(void**)&reset_pon);
    if(status||!reset_pon||reset_pon->revision!=0x10001||!reset_pon->get||!reset_pon->set){reset_pon=0;return 0;}
#endif
    return 1;
}
static int runtime_unarm_reset(void)
{
    if(!runtime_reset_armed)return !runtime_reset_error;
#if !defined(POLARIS_EFI_TEST_QEMU)
    volatile uint32_t *reason=(void*)(uintptr_t)UINT64_C(0x146bf65c);
    *reason=runtime_reset_before;__asm__ volatile("dsb sy":::"memory");
    uint8_t restored=0;efi_status status=reset_pon->set(0,3,runtime_reset_marker.before,0xfe);
    if(!status)status=reset_pon->get(0,3,&restored);
    int matches=!status&&*reason==runtime_reset_before&&(restored&0xfe)==(runtime_reset_marker.before&0xfe);
    if(!matches)runtime_reset_error=1;
    report("RESET_ARM_RESTORE_STATUS=",status);report("RESET_ARM_RESTORE_MATCH=",matches);
    __asm__ volatile("msr daifset,#15; dsb sy; isb":::"memory");
    __asm__ volatile("msr ICC_IGRPEN1_EL1,%0; isb"::"r"(UINT64_C(0)):"memory");
#endif
    runtime_reset_armed=0;return !runtime_reset_error;
}
static int runtime_arm_reset(unsigned mode)
{
    if(mode!=2||runtime_reset_error||wln_actual_reset_entered)return 0;
    /* An existing native/WLED failure must reject BEFORE even the volatile
     * restart marker is prepared. Zero-CPU/no-WRITE refusal is separate. */
    if(wln_cpu_on_issued&&(wln_power.error||wln_runtime.error||wln_firmware.error||
       wln_power.uncertain||wln_runtime.pending||!wln_power.actual_on||wln_closing_mode!=mode))return 0;
    if(runtime_reset_armed)return runtime_reset_mode==mode;
    if(!cache_reset_protocol()||!system_table->runtime||!system_table->runtime->reset_system)return 0;
    uint64_t began=buttons_us(0);if(!began)return 0;
#if !defined(POLARIS_EFI_TEST_QEMU)
    volatile uint32_t *reason=(void*)(uintptr_t)UINT64_C(0x146bf65c);
    runtime_reset_before=*reason;
    int valid=polaris_efi_pon_marker(reset_pon,mode,&runtime_reset_marker);
    report("RESET_ARM_PON_STATUS=",runtime_reset_marker.status);
    report("RESET_ARM_PON_BEFORE=",runtime_reset_marker.before);
    report("RESET_ARM_PON_AFTER=",runtime_reset_marker.after);
    if(!valid){runtime_reset_error=1;report("RESET_ARM_PON_FAILURE_RESTORE=",runtime_reset_marker.restore_status);return 0;}
    runtime_reset_armed=1;runtime_reset_mode=mode;
    *reason=0x77665500u;__asm__ volatile("dsb sy":::"memory");
    if(*reason!=0x77665500u){runtime_reset_error=1;(void)runtime_unarm_reset();return 0;}
    /* Firmware protocol calls may restore masks. Reestablish the original
     * handoff context BEFORE any new saved-state WLED observation. */
    __asm__ volatile("msr daifset,#15; dsb sy; isb":::"memory");
    __asm__ volatile("msr ICC_IGRPEN1_EL1,%0; isb"::"r"(UINT64_C(0)):"memory");
#else
#if defined(EFI_XNU_WLED_NATIVE_RUNTIME_TEST)
    uint64_t at=began;do{at=buttons_us(0);__asm__ volatile("yield");}while(at>=began&&at-began<250000);
#endif
    runtime_reset_armed=1;runtime_reset_mode=mode;
#endif
    uint64_t ended=buttons_us(0);report("RESET_ARM_BEGAN_US=",began);report("RESET_ARM_ENDED_US=",ended);
    if(ended<began){runtime_reset_error=1;(void)runtime_unarm_reset();return 0;}
    return 1;
}
#endif
static int prepare_reset(void *context,unsigned mode)
{
    (void)context;if(mode!=1&&mode!=2)return 0;
#if EFI_XNU_GCD_MMIO_QUERY_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
    if(new_original_unknown())return 0; /* No PON/marker/receipt on unknown original state. */
#endif
#if defined(EFI_XNU_WLED_POWER_CYCLE_ONLY)
    if(!wled_cycle_reset_ready())return 0;
#endif
#if defined(EFI_XNU_WLED_NATIVE_RUNTIME)
    const uint8_t *native_data=0;uint64_t native_bytes=0;
    if(!wln_zero_ready(mode)) {
        if(!shutdown_reset_ready(context,mode)||!shutdown_status(context,&native_data,&native_bytes)||native_bytes!=128)return 0;
    }
    if(!runtime_arm_reset(mode))return 0;
    if(!wln_zero_ready(mode)) {
        const struct polaris_shutdown_status *native=(const void *)native_data;
        if(!wln_reset_ready(native->cookie,native->sequence,mode)){(void)runtime_unarm_reset();return 0;}
    }
    return 1;
#else
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
#if defined(EFI_XNU_WLED_NATIVE_RUNTIME)
    if(!reset_pon&&wln_cpu_on_issued)return 0; /* No post-handoff BS query. */
    if(!reset_pon) {
#else
    reset_pon=0;{
#endif
        efi_status s=system_table->boot->locate_protocol(&pon_guid,0,(void**)&reset_pon);
        if(s||!reset_pon||reset_pon->revision!=0x10001||!reset_pon->get||!reset_pon->set){
            reset_pon=0;if(mode==2)return 0;
        }
    }
#endif
    return 1;
#endif
}
static void reset(void *context,unsigned mode)
{
#if EFI_XNU_GCD_MMIO_QUERY_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
    if(new_original_unknown())return;
#endif
#if defined(EFI_XNU_WLED_NATIVE_RUNTIME)
    wln_reset_retryable=0;
    uint64_t at=buttons_us(0);report("RESET_FINAL_CHECK_US=",at);
    if(!wln_final_fresh(mode)) {
        wln_reset_retryable=1;(void)runtime_unarm_reset();return;
    }
    if(!runtime_reset_armed||runtime_reset_mode!=mode||runtime_reset_error||
       (!wln_zero_ready(mode)&&!shutdown_reset_ready(context,mode)))return;
#if defined(POLARIS_EFI_TEST_QEMU) && (defined(EFI_XNU_WLED_NATIVE_LIFECYCLE) || defined(EFI_XNU_WLED_NATIVE_EXIT_TEST))
    wln_actual_reset_entered=1;wln_test_reset_observed++;
    report("WLED_NATIVE_TEST_RESET_AFTER_GATES=",wln_test_reset_observed);return;
#endif
    if(!wln_final_fresh(mode)){wln_reset_retryable=1;(void)runtime_unarm_reset();return;}
    wln_actual_reset_entered=1;report("RESET_REQUESTED=",mode);
    system_table->runtime->reset_system(0,0,0,0);
    report("RESET_RETURNED=",1);runtime_reset_error=1;(void)runtime_unarm_reset();return;
#else
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
#if defined(EFI_XNU_WLED_NATIVE_RUNTIME)
    if(!wln_final_fresh(mode)) {
        wln_reset_retryable=1;report("RESET_WLED_FRESH_REFUSED=",1);
#if !defined(POLARIS_EFI_TEST_QEMU)
        if(reset_pon)report("RESET_PON_RESTORE=",reset_pon->set(0,3,marker.before,0xfe));
        *reason=before;__asm__ volatile("dsb sy":::"memory");
#endif
        return;
    }
    wln_actual_reset_entered=1;
#endif
    report("RESET_REQUESTED=",mode);system_table->runtime->reset_system(0,0,0,0);
    report("RESET_RETURNED=",1);
#if !defined(POLARIS_EFI_TEST_QEMU)
    if(reset_pon)report("RESET_PON_RESTORE=",reset_pon->set(0,3,marker.before,0xfe));
    *reason=before;__asm__ volatile("dsb sy":::"memory");
#endif
#endif
}
#if EFI_XNU_WIFI_REMOTE_MEMORY_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
/* Wraps exactly the two existing incoming admission maps. This captures their
 * genuine call/key/native/image evidence, without treating either pre-payload
 * phase as a later current MSS map or opening an allocation context. */
static efi_status incoming_parent_map_read(unsigned phase,const struct efi_loaded*image,
    uint64_t*size,uint64_t*key,uint64_t*stride,uint32_t*version)
{
    if(phase<1||phase>2){original_service_unknown=1;power_unknown_hold();}
    struct pwmc_parent_map*r=&incoming_parent_maps[phase-1];
    const struct pwmc_parent_input input={.system=system_table,.image=image,.native_flag=&wln_cpu_on_issued,
        .output=map_snapshot.data,.capacity=sizeof(map_snapshot.data),.image_handle=(uintptr_t)driver_image,
        .phase=phase,.bank=POLARIS_RAM_BASE,.bank_bytes=POLARIS_RAM_SIZE,
        .payload=(uintptr_t)payload,.payload_bytes=payload?EFI_XNU_PAYLOAD_BYTES:0,
        .log_snapshot=(uintptr_t)log_snapshot,.log_snapshot_bytes=log_snapshot?sizeof(log_buffer)+128+EFI_XNU_LOG_SIZE:0};
    const struct pgcd_io io={0,system_table,pgcd_actual_arch,pgcd_actual_map,pwfc_actual_identity,pgcd_actual_query,
        pgcd_actual_fp_save,pgcd_actual_fp_restore,pwfc_actual_order};
    int ok=pwmc_parent_map_read(r,&input,&io);
    ram_report("INCOMING_PARENT_MAP_PHASE=",phase);ram_report("INCOMING_PARENT_MAP_CALL_ACCEPTED=",ok);
    ram_report("INCOMING_PARENT_MAP_RAW_V1_BYTES=",sizeof(*r));
    ram_text("INCOMING_PARENT_MAP_RAW_V1_BEGIN\r\n");ram_hex((const uint8_t*)r,sizeof(*r));
    ram_text("INCOMING_PARENT_MAP_RAW_V1_END\r\n");
    if(!ok){original_service_unknown=1;power_unknown_hold();}
    *size=r->map.bytes;*key=r->map.key;*stride=r->map.stride;*version=r->map.version;return r->map.status;
}
#endif
static efi_status admission_gop(void)
{
    static const efi_guid graphics={0x9042a9de,0x23dc,0x4a38,{0x96,0xfb,0x7a,0xde,0xd0,0x80,0x51,0x6a}};
    efi_status s=system_table->boot->locate_protocol(&graphics,0,(void**)&gop);
#if !defined(POLARIS_EFI_TEST_QEMU)
    if((s&EFI_ERROR)||!gop||!gop->mode||!gop->mode->info)return EFI_ERROR|3;
    struct polaris_gop_mode *m=gop->mode;struct polaris_gop_info *i=m->info;
    if(m->base!=UINT64_C(0x9d400000)||i->width!=1080||i->height!=2160||i->stride!=1080||i->format>1||m->bytes<UINT64_C(9331200))return EFI_ERROR|3;
#else
    (void)s;
#endif
    return 0;
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
#if EFI_XNU_WIFI_REMOTE_MEMORY_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
    s=incoming_parent_map_read(1,image,&size,&key,&stride,&version);
#else
    s=system_table->boot->get_map(&size,map_snapshot.data,&key,&stride,&version);
#endif
    struct polaris_efi_memory check;
    report("EFI_MAP_STATUS=",s);report("EFI_MAP_BYTES=",size);report("EFI_MAP_STRIDE=",stride);
    if((s&EFI_ERROR)||!polaris_efi_memory_check(map_snapshot.data,size,sizeof(map_snapshot.data),stride,&check))return EFI_ERROR|3;
    if(!polaris_efi_range_owned(map_snapshot.data,size,stride,POLARIS_RAM_BASE,POLARIS_RAM_SIZE,7))return EFI_ERROR|9;
    map_snapshot.magic=UINT64_C(0x3150414d49464550);map_snapshot.bytes=size;map_snapshot.stride=stride;map_snapshot.version=version;map_bytes=32+size;
    uint64_t address=POLARIS_RAM_BASE;s=system_table->boot->allocate_pages(2,2,POLARIS_RAM_SIZE/4096,&address);
    if((s&EFI_ERROR)||address!=POLARIS_RAM_BASE)return EFI_ERROR|9;report("XNU_BANK_CLAIMED=",address);
    /* Re-read the map after claiming: success alone is not an ownership map.
     * Refuse gaps, runtime pages or a page still reported as free/firmware. */
    size=sizeof(map_snapshot.data);
#if EFI_XNU_WIFI_REMOTE_MEMORY_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
    s=incoming_parent_map_read(2,image,&size,&key,&stride,&version);
#else
    s=system_table->boot->get_map(&size,map_snapshot.data,&key,&stride,&version);
#endif
    if((s&EFI_ERROR)||!polaris_efi_memory_check(map_snapshot.data,size,sizeof(map_snapshot.data),stride,&check))return EFI_ERROR|3;
    if(!polaris_efi_range_owned(map_snapshot.data,size,stride,POLARIS_RAM_BASE,POLARIS_RAM_SIZE,2))return EFI_ERROR|9;
    report("XNU_BANK_OWNERSHIP=",1);
    map_snapshot.bytes=size;map_snapshot.stride=stride;map_snapshot.version=version;map_bytes=32+size;
#if defined(EFI_XNU_WLED_NATIVE_RUNTIME)
    if(!wln_image_owned(image))return EFI_ERROR|3;
#if EFI_XNU_WIFI_FIRSTREAD_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
    if(!pwfr_bind_resident(image))report("WIFI_FIRSTREAD_SELF_BIND_REFUSED=",1);
#endif
#if EFI_XNU_WIFI_NORMAL_NC_FIRSTREAD_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
    if(!pwnc_bind_resident(image))report("WIFI_NORMAL_NC_FIRSTREAD_SELF_BIND_REFUSED=",1);
#endif
#if EFI_XNU_WIFI_RESOURCES_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
    if(!pfr_bind_resident(image))report("WIFI_RESOURCES_SELF_BIND_REFUSED=",1);
#endif
#if EFI_XNU_GCD_MMIO_QUERY_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
    if(!pgcd_bind_resident(image))report("ORIGINAL_GCD_SELF_BIND_REFUSED=",1);
#endif
#endif
#if defined(POLARIS_EFI_TEST_QEMU)
    /* virt has no physical panel reservation. Claim the synthetic panel RAM
     * explicitly so subsequent firmware allocations cannot alias its pixels. */
    address=UINT64_C(0x9d400000);s=system_table->boot->allocate_pages(2,2,0x2400000/4096,&address);
    if((s&EFI_ERROR)||address!=UINT64_C(0x9d400000))return EFI_ERROR|9;
#endif
#if EFI_XNU_WIFI_EARLY_MEMORY_AVAILABLE
    /* A new incoming allocation producer, not a later PGCD context. The
     * ordinary bank is already claimed; payload/native/radio are not started.
     * Its retained pages remain excluded by all later complete EFI maps. */
    if(load_state||received||payload_count||payload||log_snapshot||wln_cpu_on_issued)return EFI_ERROR|3;
    s=admission_gop();if(s&EFI_ERROR)return s;
    if(!early_wifi_gop_bind(image,key)){early_wifi_gop_raw();return EFI_ERROR|3;}
    int early_ok=pwea_native_run(&early_wifi_memory,system_table,image,&wln_cpu_on_issued,POLARIS_RAM_BASE,POLARIS_RAM_SIZE);
    ram_report("EARLY_WIFI_MEMORY_ACCEPTED=",early_ok);
    ram_report("EARLY_WIFI_MEMORY_RAW_V1_BYTES=",sizeof(early_wifi_memory));
    ram_text("EARLY_WIFI_MEMORY_RAW_V1_BEGIN\r\n");ram_hex((const uint8_t*)&early_wifi_memory,sizeof(early_wifi_memory));
    ram_text("EARLY_WIFI_MEMORY_RAW_V1_END\r\n");
    if(!early_ok){original_service_unknown=1;power_unknown_hold();}
    pweh_digest(&early_wifi_memory,sizeof(early_wifi_memory),early_wifi_digest);
    const struct pwea_map*early_map=&early_wifi_memory.memory.map[2];
#if EFI_XNU_MSS_MEMORY_AVAILABLE
    int mss_ok=pmmn_run(&mss_memory,&early_wifi_memory,early_wifi_digest,EFI_XNU_MSS_METADATA_BYTES);
    ram_report("MSS_MEMORY_ACCEPTED=",mss_ok);
    ram_report("MSS_MEMORY_RAW_V1_BYTES=",sizeof(mss_memory));
    ram_text("MSS_MEMORY_RAW_V1_BEGIN\r\n");ram_hex((const void*)&mss_memory,sizeof(mss_memory));
    ram_text("MSS_MEMORY_RAW_V1_END\r\n");
    if(!mss_ok){original_service_unknown=1;power_unknown_hold();}
    pweh_digest(&mss_memory,sizeof(mss_memory),mss_memory_digest);
    early_map=&mss_memory.memory.map[3];
#endif
#if EFI_XNU_WIFI_NATIVE_MEMORY_AVAILABLE
    /* All original BlockIO reads and independent allocations finish before
     * the final retained map and before CPU0 takes continuous ownership.
     * The NV reader has no write/reset/flush callback. These three retained
     * banks are never inferred from firmware pointers or borrowed memory. */
    wifi_native_memory_stage=1;
    int nv_ok=pnnv_run(&wifi_native_nv,&early_wifi_memory,&polaris_nv_plan);
    ram_report("WIFI_NATIVE_FRESH_NV_ACCEPTED=",nv_ok);
    if(!nv_ok){original_service_unknown=1;power_unknown_hold();}
    wifi_native_memory_stage=2;
    int ce_memory_ok=pcdm_run(&wifi_native_ce_memory,&early_wifi_memory);
    ram_report("WIFI_NATIVE_CE_MEMORY_ACCEPTED=",ce_memory_ok);
    if(!ce_memory_ok){original_service_unknown=1;power_unknown_hold();}
    wifi_native_memory_stage=3;
    int htt_memory_ok=pcdm_run(&wifi_native_htt_memory,&early_wifi_memory);
    ram_report("WIFI_NATIVE_HTT_MEMORY_ACCEPTED=",htt_memory_ok);
    if(!htt_memory_ok){original_service_unknown=1;power_unknown_hold();}
    wifi_native_memory_stage=4;
    if(!pwea_disjoint(wifi_native_ce_memory.allocation.address,PWDM_BYTES,
                     wifi_native_htt_memory.allocation.address,PWDM_BYTES)||
       !pwea_disjoint(wifi_native_nv.allocation.address,PNV_BYTES,
                     wifi_native_ce_memory.allocation.address,PWDM_BYTES)||
       !pwea_disjoint(wifi_native_nv.allocation.address,PNV_BYTES,
                     wifi_native_htt_memory.allocation.address,PWDM_BYTES)){
        original_service_unknown=1;power_unknown_hold();
    }
    wifi_native_memory_stage=5;
    early_map=&wifi_native_htt_memory.map[1];
#endif
    bytes_copy(map_snapshot.data,early_map->data,early_map->map.bytes);
    map_snapshot.bytes=early_map->map.bytes;map_snapshot.stride=early_map->map.stride;
    map_snapshot.version=early_map->map.version;map_bytes=32+early_map->map.bytes;
#endif
    const uint64_t payload_pages=(EFI_XNU_PAYLOAD_BYTES+4095)/4096;
    address=POLARIS_RAM_BASE-1;s=system_table->boot->allocate_pages(1,2,payload_pages,&address);
    /* Check the entire returned page allocation before retaining its address.
     * Compare against the remaining span only after bounding the base. */
    if((s&EFI_ERROR)||!payload_pages||(address&4095)||address<UINT64_C(0x80000000)||address>POLARIS_RAM_BASE||
       payload_pages>(POLARIS_RAM_BASE-address)/4096)return EFI_ERROR|9;
    payload=(void*)(uintptr_t)address;
    s=system_table->boot->allocate_pool(2,sizeof(log_buffer)+128+EFI_XNU_LOG_SIZE,(void**)&log_snapshot);if(s&EFI_ERROR)return s;
    if(!log_snapshot)return EFI_ERROR|9;
#if !EFI_XNU_WIFI_EARLY_MEMORY_AVAILABLE
    s=admission_gop();if(s&EFI_ERROR)return s;
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
#if defined(EFI_XNU_WLED_NATIVE_RUNTIME)
    wln_poll();
#endif
#if EFI_XNU_BATTERY_AVAILABLE
    pb_runtime_poll();
#endif
#if defined(EFI_XNU_DURABLE_GUARD)
    if(load_state>=4)return;
#endif
    uint64_t now,frequency;__asm__ volatile("mrs %0,cntvct_el0":"=r"(now));
    __asm__ volatile("mrs %0,cntfrq_el0":"=r"(frequency));
    int lease_recovering=polaris_efi_ram_lease_expired(&ram_lease,now,frequency);
#if defined(EFI_XNU_WLED_NATIVE_RUNTIME)
    /* Expiry fires once. Native shutdown/restore requires later polls, too;
     * do not lose the pending recovery merely because lease.fired is set. */
    if(wln_lease_recovery)lease_recovering=1;
#endif
    if(lease_recovering){
#if defined(EFI_XNU_WLED_NATIVE_RUNTIME)
        if(!wln_lease_recovery)report("RAM_HOST_LEASE_EXPIRED=",POLARIS_RAM_LEASE_SECONDS);
#else
        report("RAM_HOST_LEASE_EXPIRED=",POLARIS_RAM_LEASE_SECONDS);
#endif
#if defined(EFI_XNU_WLED_NATIVE_RUNTIME)
        wln_lease_recovery=1;
        if(wln_exit_active)return; /* Do not reset midway through an exit transfer. */
        if(wln_exit_aborted&&wln_exit_attempt==1) {
            const uint8_t *footer=0,*receipt=0;uint64_t footer_bytes=0,receipt_bytes=0;
            wln_sync_history();
            if(wln_exit_begin(context,1,wln_cookie,wln_runtime.count,~wln_crc,&footer,&footer_bytes)&&
               wln_exit_finish(context,&receipt,&receipt_bytes)) {
                report("WLED_NATIVE_LEASE_READONLY_RECOVERY=",receipt_bytes);reset(context,2);
            }
            return;
        }
        if(!wln_zero_ready(2)&&!shutdown_begin(context,2))return;
#endif
        if(prepare_reset(context,2)){
#if defined(EFI_XNU_WLED_NATIVE_RUNTIME)
            const uint8_t *receipt;uint64_t receipt_bytes;
            if(!wln_lease_recovery||!wln_reset_receipt(context,2,&receipt,&receipt_bytes))return;
            report("WLED_NATIVE_LEASE_RESTORE_JOURNALED=",receipt_bytes);
#endif
            reset(context,2);
        }
    }
}
#if EFI_XNU_GCD_MMIO_QUERY_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
static int new_guarded_reset_receipt(void *context,unsigned mode,const uint8_t **data,uint64_t *bytes)
{
    if(new_original_unknown()){if(data)*data=0;if(bytes)*bytes=0;return 0;}
    return wln_reset_receipt(context,mode,data,bytes);
}
#endif
static struct polaris_usb_control controls={.begin=begin,.write=write_payload,.finish=finish,
    .prepare_boot=prepare_boot,.boot=boot_kernel,.prepare_reset=prepare_reset,.reset=reset,
    .state=state,.logs=logs,.running=running,.touch=touch,.input_status=input_status,.boot_options=boot_options,
#if defined(EFI_XNU_SHUTDOWN_BRIDGE)
    .shutdown_status=shutdown_status,.shutdown_begin=shutdown_begin,.shutdown_reset_ready=shutdown_reset_ready,
#endif
#if defined(EFI_XNU_WLED_OEM_STATUS)
    .wled_journal=wled_journal_capture,.reset_receipt=wled_reset_receipt,
#endif
#if defined(EFI_XNU_WLED_NATIVE_RUNTIME)
    .wled_runtime_page=wln_capture_page,
#if EFI_XNU_GCD_MMIO_QUERY_AVAILABLE && !defined(POLARIS_EFI_TEST_QEMU)
    .reset_receipt=new_guarded_reset_receipt,
#else
    .reset_receipt=wln_reset_receipt,
#endif
    .wled_exit_begin=wln_exit_begin,.wled_exit_finish=wln_exit_finish,.wled_exit_abort=wln_exit_abort,
#endif
#if EFI_XNU_HOST_UTC_AVAILABLE
    .host_utc=host_utc_command,
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
#if defined(EFI_XNU_WLED_NATIVE_RUNTIME_TEST) && defined(EFI_XNU_WLED_NATIVE_LIFECYCLE) && EFI_XNU_WLED_NATIVE_LIFECYCLE==4
    static unsigned request_reported,lease_polls;
    if(!sent&&s.cookie&&s.phase==POLARIS_Q_RUNNING&&!s.sequence&&!s.mode&&!s.error) {
        uint64_t ticks,frequency;
        __asm__ volatile("mrs %0,cntvct_el0":"=r"(ticks));
        __asm__ volatile("mrs %0,cntfrq_el0":"=r"(frequency));
        if(!frequency||frequency>UINT64_MAX/POLARIS_RAM_LEASE_SECONDS)return;
        cookie=s.cookie;sent=1;ram_lease.active=1;ram_lease.fired=0;
        ram_lease.last=ticks-frequency*POLARIS_RAM_LEASE_SECONDS;
        report("WLED_NATIVE_LEASE_SYNTHETIC_DEADLINE_INPUT=",1);
    }
    if(sent) {
        lease_polls++;idle_guard(0); /* Actual control callback, not a helper. */
        if(!request_reported&&slot->firmware.cookie==cookie&&slot->firmware.sequence==1&&slot->firmware.mode==2) {
            request_reported=1;test_uart_text("\nQEMU_RAM_DRAIN_REQUESTED=1\n");
        }
        if(polaris_q_ram_drained(&s,cookie,1,2)&&shutdown_reset_ready(0,2)&&wln_test_reset_observed) {
            report("WLED_NATIVE_LEASE_POLLS=",lease_polls);
            report("WLED_NATIVE_LEASE_FIRED=",ram_lease.fired);
            report("WLED_NATIVE_LEASE_LATCH=",wln_lease_recovery);
            test_uart_text("\nQEMU_RAM_DRAINED=1\n");finished=1;
        }
    }
    return;
#endif
#if defined(EFI_XNU_WLED_NATIVE_RUNTIME_TEST) && defined(EFI_XNU_WLED_NATIVE_FAULT)
    /* One actual normal native shutdown request. The WLED error may reject
     * the aggregate sender after it published that request; never retry it. */
    if(!sent&&wln_error_reported&&s.cookie&&s.phase==POLARIS_Q_RUNNING&&
       !s.sequence&&!s.mode&&!s.error) {
        sent=1;cookie=s.cookie;
        report("WLED_NATIVE_FAULT_SHUTDOWN_REPLY=",shutdown_begin(0,2));
        if(slot->firmware.cookie==cookie&&slot->firmware.sequence==1&&slot->firmware.mode==2)
            test_uart_text("\nQEMU_RAM_DRAIN_REQUESTED=1\n");
    }
    if(sent&&polaris_q_ram_drained(&s,cookie,1,2)&&shutdown_reset_ready(0,2)) {
        static uint8_t failed_page[980];
        const uint8_t *page=0,*receipt=0;uint64_t bytes=0,receipt_bytes=0;
        int captured=wln_capture_page(0,0,&page,&bytes);
        if(captured&&bytes<=sizeof(failed_page))bytes_copy(failed_page,page,bytes);else captured=0;
        report("WLED_NATIVE_FAULT_PAGE_ADDRESS=",captured?(uintptr_t)failed_page:0);
        report("WLED_NATIVE_FAULT_PAGE_BYTES=",captured?bytes:0);
        report("WLED_NATIVE_FAULT_KIND=",EFI_XNU_WLED_NATIVE_FAULT);
        report("WLED_NATIVE_RAW_COUNT=",wln_runtime.count);
        report("WLED_NATIVE_ISSUED=",wln_power.issued);
        report("WLED_NATIVE_COMPLETED=",wln_power.completed);
        report("WLED_NATIVE_ERROR=",wln_power.error);
        report("WLED_NATIVE_UNCERTAIN=",wln_power.uncertain);
        report("WLED_NATIVE_FAULT_RESET1_REFUSED=",!prepare_reset(0,1));
        report("WLED_NATIVE_FAULT_RESET2_REFUSED=",!prepare_reset(0,2));
        report("WLED_NATIVE_FAULT_RECEIPT_REFUSED=",!wln_reset_receipt(0,2,&receipt,&receipt_bytes));
        report("WLED_NATIVE_FAULT_FRESH_REFUSED=",!wln_final_fresh(2));
        test_uart_text("\nQEMU_RAM_DRAINED=1\nWLED_NATIVE_FAULT_AFTER_NATIVE_DRAIN=1\n");
        finished=1;
    }
    return;
#endif
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
#if defined(EFI_XNU_WLED_NATIVE_EXIT_TEST)
static uint8_t wln_test_exit_prefix[2][3][980],wln_test_exit_footer[2][212],wln_test_exit_reply[2][64];
static unsigned wln_test_exit_attempt,wln_test_exit_tx;
static uint64_t wln_test_exit_delay;
static int test_exit_tx(void *context,const uint8_t *data,uint64_t bytes)
{
    (void)context;unsigned at=wln_test_exit_attempt;
    if(at>=2)return 0;
    if(++wln_test_exit_tx==1)return bytes==12;
    if(wln_test_exit_tx==2) {
        if(bytes>212)return 0;bytes_copy(wln_test_exit_footer[at],data,bytes);
        report(at?"WLED_EXIT_FOOTER1_ADDRESS=":"WLED_EXIT_FOOTER0_ADDRESS=",(uintptr_t)wln_test_exit_footer[at]);
        report(at?"WLED_EXIT_FOOTER1_BYTES=":"WLED_EXIT_FOOTER0_BYTES=",bytes);
        uint64_t start=buttons_us(0),now=start;
        do{now=buttons_us(0);__asm__ volatile("yield");}while(now>=start&&now-start<250000);
        wln_test_exit_delay=now-start;return 1;
    }
    if(wln_test_exit_tx==3) {
        if(bytes!=64)return 0;bytes_copy(wln_test_exit_reply[at],data,bytes);
        report(at?"WLED_EXIT_REPLY1_ADDRESS=":"WLED_EXIT_REPLY0_ADDRESS=",(uintptr_t)wln_test_exit_reply[at]);
#if EFI_XNU_WLED_NATIVE_EXIT_TEST==2
        if(!at)return 0; /* Actual parser sees known failed final delivery. */
#endif
        return 1;
    }return 0;
}
static int test_exit_once(unsigned recover)
{
    for(unsigned n=0;n<3;n++) {
        const uint8_t *page=0;uint64_t bytes=0;
        if(!wln_capture_page(0,n,&page,&bytes)||bytes>980)return 0;
        bytes_copy(wln_test_exit_prefix[recover][n],page,bytes);
        char label[]="WLED_EXIT_P00_ADDRESS=",size[]="WLED_EXIT_P00_BYTES=";
        label[11]=size[11]=(char)('0'+recover);label[12]=size[12]=(char)('0'+n);
        report(label,(uintptr_t)wln_test_exit_prefix[recover][n]);report(size,bytes);
    }
    char cmd[64];const char *prefix=recover?"oem wled-recover:":"oem wled-exit:";unsigned at=0;
    while(*prefix)cmd[at++]=*prefix++;
    for(unsigned n=0;n<16;n++)cmd[at++]="0123456789abcdef"[(wln_cookie>>(60-n*4))&15];
    cmd[at++]=':';uint32_t words[2]={wln_runtime.count,~wln_crc};
    for(unsigned w=0;w<2;w++){for(unsigned n=0;n<8;n++)cmd[at++]="0123456789abcdef"[(words[w]>>(28-n*4))&15];if(!w)cmd[at++]=':';}
    struct polaris_usb_diag diag={.transmit=test_exit_tx};
    wln_test_exit_attempt=recover;wln_test_exit_tx=0;
    return polaris_usb_control_command(&diag,&controls,(const void *)cmd,at);
}
static void test_exit_run(void)
{
    int first=test_exit_once(0);
    report("WLED_EXIT_FIRST_RESULT=",first);report("WLED_EXIT_DELAY_US=",wln_test_exit_delay);
#if EFI_XNU_WLED_NATIVE_EXIT_TEST==2
    report("WLED_EXIT_FAILED_NO_RESET=",!wln_test_reset_observed&&wln_exit_aborted&&wln_exit_attempt==1);
    report("WLED_EXIT_RECOVERY_RESULT=",test_exit_once(1));
#endif
    report("WLED_EXIT_FINAL_COUNT=",wln_runtime.count);report("WLED_EXIT_FINAL_ISSUED=",wln_power.issued);
    report("WLED_EXIT_FINAL_COMPLETED=",wln_power.completed);
    report("WLED_EXIT_FINAL_ERROR=",wln_power.error|wln_runtime.error|wln_firmware.error);
    report("WLED_EXIT_RESET_OBSERVED=",wln_test_reset_observed);
    report("WLED_EXIT_ATTEMPTS=",wln_exit_attempt);
    text("WLED_EXIT_MODEL_HOLD\r\n");
}
#endif
static void test_monitor(void)
{
    uint64_t position=0,last=0;unsigned contact_phase=0;
#if defined(EFI_XNU_WLED_NATIVE_RUNTIME_TEST)
    uint64_t report_position=0;
#endif
#if EFI_XNU_BUTTONS_AVAILABLE
    unsigned keys_reported=0;
#endif
#if defined(EFI_XNU_WLED_POWER_CYCLE_ONLY)
    unsigned cycle_reset_checked=0,cycle_final_checked=0;
#endif
#if defined(EFI_XNU_RAM_DRAIN_TEST)
    int stress_done=0;
#endif
#if defined(EFI_XNU_WLED_NATIVE_RUNTIME_TEST)
    unsigned wln_final_reported=0;
#if defined(EFI_XNU_WLED_NATIVE_START_REFUSAL)
    unsigned wln_zero_reported=0;
#endif
#if !defined(EFI_XNU_WLED_NATIVE_EXIT_TEST)
    static uint8_t wln_test_pages[3][980];
#endif
#if defined(EFI_XNU_WLED_NATIVE_LIFECYCLE) && EFI_XNU_WLED_NATIVE_LIFECYCLE==3
    unsigned wln_age_checked=0;
#endif
#endif
    volatile uint32_t *uart=(void*)(uintptr_t)UINT64_C(0x9000000);
    for(;;){
        uint64_t now;__asm__ volatile("mrs %0,cntvct_el0":"=r"(now));
#if defined(EFI_XNU_WLED_NATIVE_RUNTIME_TEST)
        /* report() deliberately writes RAM only after handoff. Export those
         * actual bytes once on this QEMU monitor's existing UART, rather than
         * making the host synthesize a missing runtime/final observation. */
        uint64_t report_end=log_bytes;
        if(report_end<=sizeof(log_buffer)&&report_position<=report_end) {
            for(uint64_t i=report_position;i<report_end;i++) {
                while(uart[6]&(1u<<5))__asm__ volatile("yield");uart[0]=log_buffer[i];
            }
            report_position=report_end;
        }
#endif
#if defined(EFI_XNU_WLED_NATIVE_START_REFUSAL)
        if(load_state==3&&!wln_zero_reported) {
            wln_zero_reported=1;const uint8_t *receipt=0;uint64_t receipt_bytes=0;
            report("WLED_NATIVE_ZERO_MODE1_REFUSED=",!prepare_reset(0,1));
            report("WLED_NATIVE_ZERO_MODE2_READY=",prepare_reset(0,2));
            int made=wln_reset_receipt(0,2,&receipt,&receipt_bytes);
            report("WLED_NATIVE_ZERO_RECEIPT_ADDRESS=",made?(uintptr_t)receipt:0);
            report("WLED_NATIVE_ZERO_RECEIPT_BYTES=",receipt_bytes);
            report("WLED_NATIVE_ZERO_FRESH=",wln_final_fresh(2));
            report("WLED_NATIVE_ZERO_ONCE_REFUSED=",!wln_reset_receipt(0,2,&receipt,&receipt_bytes));
            report("WLED_NATIVE_ZERO_CPU_ISSUED=",wln_cpu_on_issued);
            report("WLED_NATIVE_ZERO_AP_STAGE=",polaris_efi_ap_state.stage);
            report("WLED_NATIVE_ZERO_AP_ADDRESS=",(uintptr_t)&polaris_efi_ap_state.stage);
            report("WLED_NATIVE_ZERO_ISSUED=",wln_power.issued);
            report("WLED_NATIVE_ZERO_COMPLETED=",wln_power.completed);
            report("WLED_NATIVE_ZERO_UNCERTAIN=",wln_power.uncertain);
            report("WLED_NATIVE_ZERO_ERROR=",wln_power.error);
            text("WLED_NATIVE_ZERO_MODEL_HOLD\r\n");
        }
#endif
#if defined(EFI_XNU_WLED_FAULT_WATCH)
        wled_fault_watch_poll();
#endif
#if defined(EFI_XNU_WLED_POWER_CYCLE_ONLY)
        wled_cycle_poll();
        if(cycle_stage==1&&!cycle_reset_checked) {
            cycle_reset_checked=1;
            report("WLED_POWER_OFF_RESET_REFUSED=",!prepare_reset(0,1)&&!prepare_reset(0,2));
        }
        int before_cycle_refused=0;
#if defined(EFI_XNU_TEST_WLED_PREPARE_REFUSAL) && EFI_XNU_TEST_WLED_PREPARE_REFUSAL==3
        before_cycle_refused=load_state==3&&!cycle_started;
#endif
        if((cycle_done||before_cycle_refused)&&!cycle_final_checked) {
            cycle_final_checked=1;
            if(before_cycle_refused) {
                report("WLED_POWER_MOCK_BACKEND=",1);
                report("WLED_POWER_UNSTARTED=",1);
                report("WLED_POWER_PREPARE_ERROR=",cycle_power.error);
                report("WLED_POWER_PREPARE_WRITES_ISSUED=",cycle_power.issued);
                report("WLED_POWER_PREPARE_READS=",cycle_bus.reads);
                report("WLED_KERNEL_AP_STAGE=",polaris_efi_ap_state.stage);
                report("WLED_AP_STAGE_ADDRESS=",(uintptr_t)&polaris_efi_ap_state.stage);
            }
            report("WLED_POWER_FINAL_RESET_ALLOWED=",prepare_reset(0,1)&&prepare_reset(0,2));
            report("WLED_POWER_FINAL_ERROR=",cycle_power.error);
            report("WLED_POWER_FINAL_UNCERTAIN=",cycle_power.uncertain);
#if defined(EFI_XNU_WLED_OEM_STATUS)
            const uint8_t *journal=0,*receipt=0;uint64_t journal_bytes=0,receipt_bytes=0;
            if((cycle_power.error||before_cycle_refused)&&!cycle_power.issued)wled_cycle_status_report();
            int captured=wled_journal_capture(0,&journal,&journal_bytes);
            report("WLED_JOURNAL_CAPTURED=",captured);
            report("WLED_JOURNAL_ADDRESS=",(uintptr_t)journal);
            report("WLED_JOURNAL_BYTES=",journal_bytes);
            int final_ready=prepare_reset(0,2);
            int final_receipt=final_ready&&wled_reset_receipt(0,2,&receipt,&receipt_bytes);
            report("WLED_RESET_RECEIPT_READY=",final_receipt);
            report("WLED_RESET_RECEIPT_ADDRESS=",(uintptr_t)receipt);
            report("WLED_RESET_RECEIPT_BYTES=",receipt_bytes);
#endif
            text("WLED_POWER_MODEL_HOLD: NO_CPU_ON\r\n");
        }
#endif
#if EFI_XNU_BUTTONS_AVAILABLE
        buttons_poll();
#endif
#if defined(EFI_XNU_WLED_NATIVE_RUNTIME_TEST)
        wln_poll();
#if EFI_XNU_BATTERY_AVAILABLE
        pb_runtime_poll();
#endif
        if(!wln_final_reported&&shutdown_reset_ready(0,2)&&wln_closing_mode==2&&
           !wln_runtime.pending&&wln_power.actual_on
#if defined(EFI_XNU_WLED_NATIVE_LIFECYCLE) && EFI_XNU_WLED_NATIVE_LIFECYCLE==4
           &&wln_test_reset_observed
#endif
           ) {
            wln_final_reported=1;
#if defined(EFI_XNU_WLED_NATIVE_EXIT_TEST)
            test_exit_run();
#else
#if defined(EFI_XNU_WLED_NATIVE_LIFECYCLE) && EFI_XNU_WLED_NATIVE_LIFECYCLE==4
            /* idle_guard() made the one-shot receipt and called reset's
             * guarded test observer. Preserve those actual original bytes. */
            int ready=wln_test_reset_observed&&wln_receipt_issued;
            const uint8_t *receipt=wln_receipt;uint64_t receipt_bytes=sizeof(wln_receipt);
            int witnessed=ready;
#else
            int ready=prepare_reset(0,2);const uint8_t *receipt=0;uint64_t receipt_bytes=0;
            int witnessed=ready&&wln_reset_receipt(0,2,&receipt,&receipt_bytes);
#endif
            report("WLED_NATIVE_FINAL_READY=",ready);report("WLED_NATIVE_FINAL_RECEIPT=",witnessed);
            report("WLED_NATIVE_RECEIPT_ADDRESS=",(uintptr_t)receipt);report("WLED_NATIVE_RECEIPT_BYTES=",receipt_bytes);
            for(unsigned n=0;n<3;n++) {
                const uint8_t *page=0;uint64_t page_bytes=0;
                int captured=wln_capture_page(0,n,&page,&page_bytes);
                if(captured&&page_bytes<=sizeof(wln_test_pages[n]))bytes_copy(wln_test_pages[n],page,page_bytes);
                report(n==0?"WLED_NATIVE_PAGE0_ADDRESS=":n==1?"WLED_NATIVE_PAGE1_ADDRESS=":"WLED_NATIVE_PAGE2_ADDRESS=",captured?(uintptr_t)wln_test_pages[n]:0);
                report(n==0?"WLED_NATIVE_PAGE0_BYTES=":n==1?"WLED_NATIVE_PAGE1_BYTES=":"WLED_NATIVE_PAGE2_BYTES=",captured?page_bytes:0);
            }
            report("WLED_NATIVE_RAW_COUNT=",wln_runtime.count);report("WLED_NATIVE_ISSUED=",wln_power.issued);
            report("WLED_NATIVE_COMPLETED=",wln_power.completed);report("WLED_NATIVE_REQUEST=",wln_power.request);
            report("WLED_NATIVE_ERROR=",wln_power.error|wln_runtime.error|wln_firmware.error);
            report("WLED_NATIVE_FINAL_MODE1_REFUSED=",!prepare_reset(0,1));
            report("WLED_NATIVE_FINAL_ONCE_REFUSED=",!wln_reset_receipt(0,2,&receipt,&receipt_bytes));
#endif
        }
#if defined(EFI_XNU_WLED_NATIVE_LIFECYCLE) && EFI_XNU_WLED_NATIVE_LIFECYCLE==3
        if(wln_final_reported&&!wln_age_checked&&wln_runtime.sealed&&wln_runtime.count) {
            uint64_t now_us=buttons_us(0),last_us=wln_archive[wln_runtime.count-1].raw.ended_us;
            if(now_us>=last_us&&now_us-last_us>=250000) {
                wln_age_checked=1;reset(0,2);
                report("WLED_NATIVE_RECEIPT_ACTUAL_AGE_US=",now_us-last_us);
                report("WLED_NATIVE_AGED_RESET_OBSERVER_COUNT=",wln_test_reset_observed);
                report("WLED_NATIVE_AGED_RESET_REFUSED=",!wln_test_reset_observed&&!wln_final_fresh(2));
            }
        }
#endif
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
    struct polaris_usb_control rescue={.prepare_reset=prepare_reset,.reset=reset,.state=rescue_state,.logs=rescue_logs,
#if defined(EFI_XNU_WLED_NATIVE_RUNTIME)
        .reset_receipt=wln_reset_receipt,
#endif
    };
    report("RESCUE_USB_RESULT=",polaris_efi_usb_serve_control(system_table,log_buffer,&log_bytes,0,0,report,&rescue));
    /* A refused admission never starts the kernel. If even the USB protocol
     * cannot initialize, use the already-proven PON FASTBOOT reset directly. */
    if(prepare_reset(0,2)) {
#if defined(EFI_XNU_WLED_NATIVE_RUNTIME)
        const uint8_t *receipt;uint64_t receipt_bytes;
        if(!wln_reset_receipt(0,2,&receipt,&receipt_bytes))return;
#endif
        reset(0,2);
    }
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
