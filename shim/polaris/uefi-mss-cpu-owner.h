/* Separate continuous CPU-local MSS interval; default OFF and unregistered.
 * This is NOT the old200ms pwrpc interval and consumes none of its tickets.
 * Fresh retained map/source/MBA records precede masking. All seven peers must
 * be OFF after masking. Thereafter only our native code and explicitly typed
 * secure calls may execute; never original providers, console or USB. CPU_ON
 * belongs only to the separately gated complete-parent runtime handoff.
 * This proves CPU-local exclusion only: DRV2/GCD/QMP/VMID/DMA still need their
 * own current qualification. An unused interval may restore; after any effect
 * the full native retirement path must be implemented before restoration.
 */
#ifndef POLARIS_UEFI_MSS_CPU_OWNER_H
#define POLARIS_UEFI_MSS_CPU_OWNER_H
#ifndef EFI_XNU_MSS_CPU_OWNER_AVAILABLE
#define EFI_XNU_MSS_CPU_OWNER_AVAILABLE 0
#endif
#if EFI_XNU_MSS_CPU_OWNER_AVAILABLE
#if !EFI_XNU_MSS_MBA_SHARE_AVAILABLE || defined(POLARIS_EFI_TEST_QEMU)
#error MSS CPU interval requires the independent allocation/staging/MBA parent
#endif
#include "uefi-mss-mba-share.h"
#define PMSC_TOTAL UINT64_C(3456000000) /*180s whole interval, never renewable*/
#define PMSC_ADMISSION_TICKS UINT64_C(9600000) /*500ms own source/peer admission*/
#define PMSC_CHECKPOINTS 16u
#ifndef EFI_XNU_WIFI_RUNTIME_HANDOFF_AVAILABLE
#define EFI_XNU_WIFI_RUNTIME_HANDOFF_AVAILABLE 0
#endif
#if EFI_XNU_WIFI_RUNTIME_HANDOFF_AVAILABLE
/* Written only by the complete native parent handoff, never by a mailbox. */
struct pmsc_runtime {
    uint64_t parent,copy,entry,context,stack,stack_bytes,mailbox,started,last,live_checks,mailbox_owner;
    uint8_t copy_digest[32],ap_digest[32],bootstrap[128];
    struct pmsb_peer peer[7];int64_t result;
    uint32_t attempted,issued,returned,observed,complete,unknown;
};
#endif
enum pmsc_effect {PMSC_POWER=1,PMSC_SECURE=2,PMSC_REMOTE=4,PMSC_DMA=8};
struct pmsc_source {struct pwea_core core;struct pgcd_arch before,after;uint32_t complete,reserved;};
struct pmsc_owner {
    uint64_t retained,memory,mba,opening,last,current_map_key;
    uint8_t retained_digest[32],memory_digest[32],mba_digest[32];
    struct pgcd_arch entry,masked,current,restored;struct pgcd_fp_guard fp;
    struct pwrpc_transition mask,restore;struct pmsb_peer peer[2][7];
    struct pmsc_source source[PMSC_CHECKPOINTS];
#if EFI_XNU_WIFI_RUNTIME_HANDOFF_AVAILABLE
    struct pmsc_runtime runtime;
#endif
    uint32_t attempted,unknown,error,phase,held,complete,effects,checkpoints,live_checks,mask_issued,restore_issued,reserved;
};
#if defined(POLARIS_MSS_CPU_OWNER_SOFTWARE_PEER)
static int pmsc_affinity(uint64_t,int64_t*);
static int pmsc_mask(struct pwrpc_transition*);
static int pmsc_restore(struct pwrpc_transition*);
#else
static inline int pmsc_affinity(uint64_t target,int64_t*raw){return pwrpc_actual_affinity(0,target,raw);}
static inline int pmsc_mask(struct pwrpc_transition*t){return pwrpc_actual_mask(0,t);}
static inline int pmsc_restore(struct pwrpc_transition*t){return pwrpc_actual_restore(0,t);}
#endif
static inline int pmsc_fail(struct pmsc_owner*r,unsigned error)
{r->unknown=1;if(!r->error)r->error=error;return 0;}
/* Runtime is a separate lifecycle entered only after one recorded CPU_ON.
 * Startup keeps its original absolute deadline and original flag/state. */
static inline unsigned pmsc_native(const struct pmsc_owner*r)
{
#if EFI_XNU_WIFI_RUNTIME_HANDOFF_AVAILABLE
    return r->phase==4&&r->runtime.attempted==1&&r->runtime.issued==1&&
        !r->runtime.unknown&&r->runtime.parent&&r->runtime.copy&&r->runtime.entry&&r->runtime.context;
#else
    (void)r;return 0;
#endif
}
static inline int pmsc_persistent(const struct pmsc_owner*r)
{
#if EFI_XNU_WIFI_RUNTIME_HANDOFF_AVAILABLE
    return r&&!r->unknown&&!r->error&&r->held==1&&!r->complete&&pmsc_native(r)&&r->runtime.returned==1&&r->runtime.result==0&&
        r->runtime.observed==1&&r->runtime.complete==1;
#else
    (void)r;return 0;
#endif
}
static inline int pmsc_time(const struct pmsc_owner*r,uint64_t now)
{
    if(now<r->opening||now<r->last)return 0;
    return pmsc_persistent(r)||now-r->opening<=PMSC_TOTAL;
}
/* Finite startup counters become nonwrapping64-bit counters only after the
 * complete handoff. Individual operations still retain their timing bounds. */
static inline int pmsc_count_valid(const struct pmsc_owner*r,uint64_t used,uint64_t limit)
{return used<=limit||(r&&pmsc_persistent(r));}
static inline int pmsc_count_available(const struct pmsc_owner*r,uint64_t used,uint64_t limit)
{return used<UINT64_MAX&&(used<limit||(r&&pmsc_persistent(r)));}
static inline int pmsc_bound(const struct pmsc_owner*r)
{
    const struct pweh_result*h=(const void*)(uintptr_t)r->retained;
    const struct pmmn_native*m=(const void*)(uintptr_t)r->memory;
    const struct pmsb_result*b=(const void*)(uintptr_t)r->mba;
    unsigned native=pmsc_native(r);
    if(r->phase==4&&!native)return 0;
    uint8_t hash[32];pweh_digest(h,sizeof(*h),hash);
    if(!pgcd_equal(hash,r->retained_digest,32)||!pweh_binding_at(h,native,native?4:2))return 0;
    pweh_digest(m,sizeof(*m),hash);if(!pgcd_equal(hash,r->memory_digest,32)||!pmmn_binding_at(m,native))return 0;
    /* Never read the real descriptor or MBA target while checking this binding. */
    pweh_digest(b,PMSB_RAW_BYTES,hash);return pgcd_equal(hash,r->mba_digest,32)&&pmsb_binding_at(b,native,native?4:2);
}
static inline int pmsc_arch(struct pmsc_owner*r,struct pgcd_arch*out,unsigned masked)
{
    if(!pgcd_actual_arch(0,out))return pmsc_fail(r,2);
    const struct pwfc_arch*a=&r->entry.cpu,*b=&out->cpu;
    const struct pweh_result*h=(const void*)(uintptr_t)r->retained;
    uint64_t core=h->input.early->core;unsigned native=pmsc_native(r);
    if(r->phase==4&&!native)return pmsc_fail(r,2);
    /* Own Core's current key closes the normal-IRQ window between GetMap
     * and masking. A changed map is refused, never treated as a fresh lease.
     * These exact mutable roots are already bound by the Core text identity. */
    r->current_map_key=pwfi_le((const void*)(uintptr_t)(core+0x1cdb0),8);
    if(b->el!=a->el||b->mpidr!=a->mpidr||b->ttbr0!=a->ttbr0||b->ttbr1!=a->ttbr1||b->tcr!=a->tcr||
       b->sctlr!=a->sctlr||b->mair!=a->mair||b->sre!=a->sre||b->frequency!=a->frequency||out->cpacr!=r->entry.cpacr||
       b->daif!=(masked?0xc0:0)||b->group1!=(masked?0:1)||b->ticks<r->last||b->ticks<r->opening||
       !pmsc_time(r,b->ticks)||
       (r->phase==1&&b->ticks-r->opening>PMSC_ADMISSION_TICKS)||
       r->current_map_key!=h->map.map.key||!pwea_native_binding_at(h->input.early,native)||
       pwfi_le((const void*)(uintptr_t)(core+0x1b098),8)!=4||
       pwfi_le((const void*)(uintptr_t)(core+0x1cb78),8)||
       pwfi_le((const void*)(uintptr_t)(core+0x1cc08),8)||pwfi_le((const void*)(uintptr_t)(core+0x1dc10),8)||
       *h->input.state!=(native?4u:2u)||*h->input.received!=h->input.logical_bytes||*h->input.count!=h->input.logical_bytes||
       (uintptr_t)*h->input.payload_slot!=h->payload||(uintptr_t)*h->input.log_slot!=h->log)return pmsc_fail(r,2);
    const unsigned locks[]={0x1b340,0x1bd48,0x1c1f8};
    for(unsigned k=0;k<3;k++){
        const uint8_t*p=(const void*)(uintptr_t)(core+locks[k]);
        if(pwfi_le(p,8)!=16||pwfi_le(p+8,8)>16||pwfi_le(p+16,8)!=1)return pmsc_fail(r,2);
    }
#if EFI_XNU_WIFI_RUNTIME_HANDOFF_AVAILABLE
    if(native){
        if(r->runtime.live_checks==UINT64_MAX)return pmsc_fail(r,2);
        r->runtime.last=b->ticks;r->runtime.live_checks++;
    }else
#endif
    {if(r->live_checks==UINT32_MAX)return pmsc_fail(r,2);r->live_checks++;}
    r->last=b->ticks;return 1;
}
static inline int pmsc_live(struct pmsc_owner*r)
{
    if(!r||r->unknown||r->error||(r->phase!=2&&!pmsc_persistent(r))||r->held!=1||r->complete)return 0;
    return pmsc_arch(r,&r->current,1);
}
static inline int pmsc_checkpoint(struct pmsc_owner*r)
{
    if(!r||r->unknown||r->error)return 0;
    if((r->phase!=1&&r->phase!=2)||r->checkpoints>=PMSC_CHECKPOINTS)return pmsc_fail(r,3);
    const struct pweh_result*h=(const void*)(uintptr_t)r->retained;
    struct pmsc_source*s=&r->source[r->checkpoints];
    if(!pwmc_zero(s,sizeof(*s))||!pmsc_bound(r)||!pmsc_arch(r,&s->before,r->held)||
       !pwea_core_check(h->input.early,&s->core,&h->map)||!pmsc_bound(r)||
       !pmsc_arch(r,&s->after,r->held))return pmsc_fail(r,3);
    s->complete=1;r->checkpoints++;return 1;
}
static inline void pmsc_seal(const struct pmsc_owner*r,const void*output,size_t bytes,uint8_t hash[32])
{
    uintptr_t a=(uintptr_t)output,b=a+bytes;struct pwfi_sha256 h;pwfi_init(&h);
    for(size_t n=0;n<sizeof(*r);n++){
        uintptr_t p=(uintptr_t)r+n;if(p>=a&&p<b)continue;pwfi_byte(&h,((const uint8_t*)r)[n]);
    }pwfi_final(&h,hash);
}
static inline int pmsc_peers(struct pmsc_owner*r,unsigned phase)
{
    if(phase>1)return pmsc_fail(r,4);
    for(unsigned n=0;n<7;n++){
        struct pmsb_peer*p=&r->peer[phase][n];if(!pwmc_zero(p,sizeof(*p)))return pmsc_fail(r,4);
        if(!pmsc_arch(r,&r->current,1))return 0;
        p->target=(n+1)*0x100;p->issued=1;uint8_t before[32],after[32];
        pmsc_seal(r,&p->raw,sizeof(p->raw),before);int returned=pmsc_affinity(p->target,&p->raw);
        pmsc_seal(r,&p->raw,sizeof(p->raw),after);
        if(returned!=1||!pgcd_equal(before,after,32)||!pmsc_arch(r,&r->current,1)||!pmsc_bound(r))return pmsc_fail(r,4);
        p->returned=1;if(p->raw!=1)return pmsc_fail(r,4);
    }return 1;
}
static inline int pmsc_begin(struct pmsc_owner*r,const struct pweh_result*h,const struct pmmn_native*m,
    const uint8_t memory_digest[32],const struct pmsb_result*b)
{
    if(!r||!h||!m||!memory_digest||!b||!pwmc_zero(r,sizeof(*r)))return 0;r->attempted=1;
    const struct pwea_native*e=h->input.early;
    if(!e||!pmmn_retained(m,memory_digest,h)||b->complete!=1||b->unknown||b->error||b->cpu_held||
       b->assignment_returned_zero!=1||!pmsb_binding(b)||
       ((const struct pmsi_result*)(uintptr_t)b->stage)->memory!=(uintptr_t)m||
       !pmsi_image_range(e,&h->map,(uintptr_t)r,sizeof(*r))||
       !pwea_disjoint((uintptr_t)r,sizeof(*r),(uintptr_t)h,sizeof(*h))||
       !pwea_disjoint((uintptr_t)r,sizeof(*r),(uintptr_t)m,sizeof(*m))||
       !pwea_disjoint((uintptr_t)r,sizeof(*r),(uintptr_t)b,sizeof(*b))||
       !pwea_disjoint((uintptr_t)r,sizeof(*r),(uintptr_t)e,sizeof(*e)))return pmsc_fail(r,1);
    r->retained=(uintptr_t)h;r->memory=(uintptr_t)m;r->mba=(uintptr_t)b;
    pweh_digest(h,sizeof(*h),r->retained_digest);pweh_digest(m,sizeof(*m),r->memory_digest);pweh_digest(b,PMSB_RAW_BYTES,r->mba_digest);
    if(!pgcd_actual_arch(0,&r->entry)||!pwea_native_arch_valid(&r->entry)||(r->entry.cpu.sctlr&5)!=5||
       !pwfc_arch_stable(&h->final.cpu,&r->entry.cpu)||h->final.cpacr!=r->entry.cpacr||
       r->entry.cpu.ticks<h->final.cpu.ticks||r->entry.cpu.ticks<b->restored.cpu.ticks||
       r->entry.cpu.ticks-b->restored.cpu.ticks>PGCD_FRESH_TICKS||
       r->entry.cpu.ticks>UINT64_MAX-PMSC_TOTAL)return pmsc_fail(r,1);
    /* Staging and secure assignment already revalidated the retained chain.
     * Fresh handoff is measured from successful MBA restore, not the old
     * pre-staging GetMap. Admission has its own nonrenewable bounded window;
     * current map key/Core/locks/source/architecture checks still run below. */
    r->opening=r->last=r->entry.cpu.ticks;r->phase=1;
    if(!pmsc_checkpoint(r)||!pgcd_actual_fp_save(0,&r->fp)||r->fp.saved!=1||r->fp.restored||
       r->fp.cpacr_before!=r->entry.cpacr)return pmsc_fail(r,3);
    r->mask.target_daif=0xc0;r->mask_issued=r->held=r->unknown=1;
    r->mask.returned=pmsc_mask(&r->mask);
    if(r->mask.returned!=1||r->mask.precondition_error||r->mask.daif_before||r->mask.group_before!=1||
       r->mask.daif_written!=1||r->mask.daif_observed!=1||r->mask.daif_read!=0xc0||
       r->mask.group_written!=1||r->mask.group_observed!=1||r->mask.group_read||
       !pmsc_arch(r,&r->masked,1)||!pmsc_peers(r,0))return pmsc_fail(r,5);
    r->unknown=0;if(!pmsc_checkpoint(r))return 0;r->phase=2;return 1;
}
static inline int pmsc_mark_effect(struct pmsc_owner*r,unsigned effect)
{
    if(!r||!effect||(effect&~15u)||!pmsc_live(r))return 0;
    r->effects|=effect;return 1;
}
/* Only an empty CPU interval can restore through this function. This is not
 * power/remote/DMA cleanup. Even a failed issued effect permanently closes it. */
static inline int pmsc_close_unused(struct pmsc_owner*r)
{
    if(!r||r->phase!=2||r->effects||!pmsc_live(r))return 0;
    if(!pmsc_peers(r,1)||!pmsc_checkpoint(r)||!pgcd_actual_fp_restore(0,&r->fp)||r->fp.restored!=1)return pmsc_fail(r,6);
    r->restore.target_group=1;r->restore_issued=r->unknown=1;r->restore.returned=pmsc_restore(&r->restore);
    if(r->restore.returned!=1||r->restore.precondition_error||r->restore.daif_before!=0xc0||r->restore.group_before||
       r->restore.daif_written!=1||r->restore.daif_observed!=1||r->restore.daif_read||
       r->restore.group_written!=1||r->restore.group_observed!=1||r->restore.group_read!=1||
       !pmsc_arch(r,&r->restored,0)||!pmsc_bound(r))return pmsc_fail(r,7);
    r->unknown=r->held=0;r->phase=3;r->complete=1;return 1;
}
#endif
#endif
