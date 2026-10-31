/* Polaris actual-native one-shot SMEM diagnostic, resident touch thread only.
 * Own DT: qcom,smem@86000000 reg0x86000000/2MiB, qcom,mpu-enabled;
 * own c7cb50c1 legacy mpss edge, descriptor478/TX479/RX480.
 * No SmemDxe Get/Alloc, MPU/IRQ/remoteproc write, FIFO or radio operation.
 * CPU AT/PAR is only translation evidence, never external MPU permission.
 */
#include <sys/param.h>
#include <sys/errno.h>
#include <libkern/libkern.h>
#include <kern/kalloc.h>
#include <kern/thread.h>
#include <kern/cpu_data.h>
#include <machine/machine_routines.h>
#include <vm/pmap.h>
#include <vm/vm_kern.h>
#include <pexpert/pexpert.h>
#include <pexpert/device_tree.h>
#include "polaris-wifi-native-policy.h"
#include "polaris-wifi-smem-probe.h"

extern bool polaris_ram_overlay_allowed(void);
extern bool polaris_gpu_overlay_ready(void);
extern int polaris_uefi_shutdown_pending(void);
extern vm_offset_t ml_io_map_with_prot(vm_offset_t,vm_size_t,vm_prot_t);
void polaris_wifi_readonly_poll(void);

static struct {
    bool configured,disabled,attempted,read_admitted,failed,par_sampled;
    unsigned error;
    uint64_t epoch,mpidr,el,frequency,ctr,identity_par,identity_pa;
    vm_offset_t mapping;
    struct polaris_wifi_native_admission admission;
} pwn;

static bool pwn_dt_u32(DTEntry node,const char *key,uint32_t *out)
{
    const void *value=NULL;unsigned bytes=0;
    if(SecureDTGetProperty(node,key,&value,&bytes)!=kSuccess||bytes!=4)return false;
    memcpy(out,value,4);return true;
}
static bool pwn_board(void)
{
    DTEntry root;const void *value=NULL;unsigned bytes=0;
    if(SecureDTLookupEntry(NULL,"/",&root)!=kSuccess||
       SecureDTGetProperty(root,"compatible",&value,&bytes)!=kSuccess||!value||bytes>256)return false;
    const uint8_t *p=value;
    for(unsigned i=0;i<bytes;) {
        unsigned n=0;while(i+n<bytes&&p[i+n])n++;
        if(i+n==bytes)return false;
        if(n==14&&!memcmp(p+i,"xiaomi,polaris",14))return true;
        i+=n+1;
    }
    return false;
}
static uint64_t pwn_counter(void)
{uint64_t n;__asm__ volatile("isb\n\t" "mrs %0,cntvct_el0":"=r"(n)::"memory");return n;}
static bool pwn_order(void *context)
{
    if(context!=&pwn)return false;
    __asm__ volatile("dsb sy":::"memory");return true;
}
static bool pwn_at(uintptr_t address,uint64_t *physical,uint64_t *par)
{
    uint64_t saved;
    /* A single native assembly sequence preserves the thread's PAR value.
     * IRQ configuration is unchanged. Treat a mismatch as rejection; this is
     * diagnostic translation evidence and cannot grant any read permission. */
    disable_preemption();
    __asm__ volatile("mrs %0,par_el1\n\t"
        "at s1e1r,%2\n\t"
        "isb\n\t"
        "mrs %1,par_el1\n\t"
        "msr par_el1,%0"
        :"=&r"(saved),"=&r"(*par):"r"(address):"memory");
    enable_preemption();
    *physical=(*par&UINT64_C(0x0000fffffffff000))|(address&4095u);
    return !(*par&1);
}
static bool pwn_live(void *context,uint64_t epoch)
{
    return context==&pwn&&pwn.read_admitted&&!pwn.failed&&pwn.mapping&&epoch==pwn.epoch&&
        !polaris_uefi_shutdown_pending()&&polaris_ram_overlay_allowed()&&polaris_gpu_overlay_ready();
}
static bool pwn_translate(void *context,uintptr_t address,uint64_t *physical,uint64_t *par)
{
    if(!physical||!par||!pwn_live(context,pwn.epoch)||address<pwn.mapping||
       address-pwn.mapping>=PWF_SMEM_BYTES||!pwn_at(address,physical,par))return false;
    uint64_t expected=PWF_SMEM_PHYSICAL+(address-pwn.mapping);
    return *physical==expected&&(uint64_t)ml_vtophys((vm_offset_t)address)==expected;
}
static bool pwn_read(void *context,uintptr_t address,void *out,size_t bytes)
{
    if(!out||!bytes||!pwn_live(context,pwn.epoch)||address<pwn.mapping||
       address-pwn.mapping>PWF_SMEM_BYTES||bytes>PWF_SMEM_BYTES-(address-pwn.mapping))return false;
    /* ml_nofault_copy only validates mapped MANAGED wired RAM before physical
     * copy. It does not catch external MPU/SError. Therefore the independent
     * MPU read gate must precede this and no volatile-pointer fallback exists.
     * The mapping is VM_WIMG_IO + VM_PROT_READ: no dirty cache line is created,
     * and DSB provides ordering; no shared-memory clean/writeback is issued. */
    if(!ml_validate_nofault((vm_offset_t)address,(vm_size_t)bytes)||!pwn_order(context))return false;
    vm_size_t copied=ml_nofault_copy((vm_offset_t)address,(vm_offset_t)out,(vm_size_t)bytes);
    return copied==bytes&&pwn_order(context);
}
static bool pwn_independent_mpu_read_witness(void)
{
    /* Deliberately no fabricated provider: neither qcom,mpu-enabled, an AT
     * success, a host DT boolean, nor SmemDxe's success-with-NULL getter proves
     * CPU read access to this reserved window. No independent live MPU/read
     * witness has been obtained. A later separately reviewed implementation
     * must supply one before this actual-native path may dereference SMEM. */
    return false;
}
static void pwn_report(unsigned error,const struct polaris_wifi_probe_result *result)
{
    pwn.error=error;pwn.failed=error!=PWN_OK;
    printf("POLARIS WIFI RO: once error=%u enable=%u version=%u uefi=%u board=%u root=%u overlay=%u el=%llu mpidr=%llx frequency=%llu ctr=%llx; own-SMEM=86000000/200000 may_transmit=0\n",
        error,pwn.admission.enable,pwn.admission.version,pwn.admission.uefi,(unsigned)pwn.admission.board,
        (unsigned)pwn.admission.root,(unsigned)pwn.admission.overlay,pwn.el,pwn.mpidr,pwn.frequency,pwn.ctr);
    printf("POLARIS WIFI RO PAR: identity-candidate-va=86000000 sampled=%u raw=%llx pa=%llx fault=%u; no SMEM byte read from this candidate; CPU translation is not MPU/lease proof\n",
        (unsigned)pwn.par_sampled,pwn.identity_par,pwn.identity_pa,(unsigned)(pwn.identity_par&1));
    if(error==PWN_MPU_READ_UNKNOWN)
        printf("POLARIS WIFI RO: REJECTED independent MPU/read admission missing; map=0 smem_reads=0 descriptor_bytes=0 FIFO=0 radio=0; no Get/Alloc or retry\n");
    if(result) {
        printf("POLARIS WIFI RO RESULT: pages=%u reads=%u error=%u at=%x metadata=%u descriptor=%u empty=%u MPU=%u exclusive=%u may_transmit=0\n",
            result->pages,result->reads,result->error,result->error_offset,(unsigned)result->metadata_stable,
            (unsigned)result->descriptor_stable,(unsigned)result->queues_empty,(unsigned)result->mpu_verified,
            (unsigned)result->exclusive_owner_verified);
        if(result->descriptor_stable) {
            printf("POLARIS WIFI RO DESC RAW:");
            for(unsigned i=0;i<32;i++)printf("%02x",result->descriptor[i]);
            printf("\n");
        }
    }
}
void polaris_wifi_readonly_poll(void)
{
    if(pwn.disabled||pwn.attempted)return;
    if(!pwn.configured) {
        DTEntry node;
        if(SecureDTLookupEntry(NULL,"/polaris-runtime-services",&node)!=kSuccess){pwn.disabled=true;return;}
        const void *value=NULL;unsigned bytes=0;
        if(SecureDTGetProperty(node,"wifi-readonly",&value,&bytes)!=kSuccess){pwn.disabled=true;return;}
        pwn.configured=true;
        if(!pwn_dt_u32(node,"version",&pwn.admission.version)||
           !pwn_dt_u32(node,"wifi-readonly",&pwn.admission.enable)) {
            pwn.attempted=true;pwn_report(PWN_BAD_DT,NULL);return;
        }
        PE_parse_boot_argn("polarisuefi",&pwn.admission.uefi,sizeof(pwn.admission.uefi));
        pwn.admission.board=pwn_board();
        if(pwn.admission.version!=1||pwn.admission.enable!=1||pwn.admission.uefi!=1||!pwn.admission.board) {
            pwn.attempted=true;pwn_report(pwn.admission.uefi!=1?PWN_BAD_BOOT_MODE:
                !pwn.admission.board?PWN_BAD_BOARD:PWN_BAD_DT,NULL);return;
        }
    }
    pwn.admission.draining=polaris_uefi_shutdown_pending()!=0;
    if(pwn.admission.draining){pwn.attempted=true;pwn_report(PWN_DRAINING,NULL);return;}
    pwn.admission.root=polaris_ram_overlay_allowed();pwn.admission.overlay=polaris_gpu_overlay_ready();
    if(!pwn.admission.root||!pwn.admission.overlay)return; /* No candidate action before verified overlay. */
    pwn.attempted=true;
    __asm__ volatile("mrs %0,currentel":"=r"(pwn.el));
    __asm__ volatile("mrs %0,mpidr_el1":"=r"(pwn.mpidr));
    __asm__ volatile("mrs %0,cntfrq_el0":"=r"(pwn.frequency));
    __asm__ volatile("mrs %0,ctr_el0":"=r"(pwn.ctr));
    pwn.admission.el=(uint32_t)pwn.el;pwn.admission.frequency=pwn.frequency;
    if(pwn.el==4){pwn.par_sampled=true;(void)pwn_at((uintptr_t)PWF_SMEM_PHYSICAL,&pwn.identity_pa,&pwn.identity_par);}
    pwn.admission.independent_mpu_read=pwn_independent_mpu_read_witness();
    unsigned error=polaris_wifi_native_admit(&pwn.admission);
    if(error){pwn_report(error,NULL);return;}
    /* Real native callbacks are wired, but presently unreachable because the
     * independent read witness above is absent. No host property bypasses it. */
    pwn.epoch=pwn_counter();if(!pwn.epoch){pwn_report(PWN_BAD_CPU,NULL);return;}
    pwn.mapping=ml_io_map_with_prot(PWF_SMEM_PHYSICAL,PWF_SMEM_BYTES,VM_PROT_READ);
    if(!pwn.mapping){pwn_report(PWN_MAPPING_FAILED,NULL);return;}
    pwn.read_admitted=true;
    struct polaris_wifi_probe_workspace *work=kalloc_data(sizeof(*work),Z_NOWAIT|Z_ZERO);
    if(!work){pwn.read_admitted=false;pwn_report(PWN_ALLOCATION,NULL);return;}
    struct polaris_wifi_probe_io io={&pwn,pwn.mapping,pwn.epoch,pwn_live,pwn_translate,pwn_read,pwn_order};
    struct polaris_wifi_probe_result result;
    int status=polaris_wifi_smem_readonly_probe(&io,1,&result,work);
    pwn.read_admitted=false;
    pwn_report(status?PWN_PROBE_FAILED:PWN_OK,&result);
    kfree_data(work,sizeof(*work)); /* CPU-only scratch, never shared/DMA. */
    /* No GLINK start, writer/ring callback, getter, allocator, or radio call. */
}
