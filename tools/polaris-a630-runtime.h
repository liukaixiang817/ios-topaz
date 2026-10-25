/* Included once by polaris_a630.c. Native 0046 bootstrap is immutable after
 * publication. These separate runtime snapshots/MMIO leases live forever.
 */
static struct a630_io a630_client_io;
static struct a630_submit a630_client_submit;
static uint32_t a630_client_ready, a630_client_dead;
void polaris_gpu_quarantine(void)
{
    if (!__atomic_exchange_n(&a630_client_dead,1,__ATOMIC_ACQ_REL))
        printf("POLARIS GPU: runtime quarantined; DMA pages/power retained, no further submissions\n");
}
bool polaris_gpu_ready(void)
{
    return __atomic_load_n(&a630_client_ready,__ATOMIC_ACQUIRE) &&
        !__atomic_load_n(&a630_client_dead,__ATOMIC_ACQUIRE);
}
void polaris_gpu_cache(void *address, uint64_t size)
{
    /* Wired kernel-owned memory only. CPU aliases of BOs/surfaces have the
     * same attributes. No 32-bit truncation of the virtual address. */
    uintptr_t at=(uintptr_t)address;
    if (!address || !size || size>UINTPTR_MAX-at) return;
    for (uintptr_t end=at+size, p=at&~(uintptr_t)63; p<end; p+=64)
        __asm__ volatile("dc civac, %0"::"r"(p):"memory");
    __asm__ volatile("dsb sy":::"memory");
}
static bool a630_client_begin(void)
{
    if (!polaris_gpu_ready()) return false;
    clock_interval_to_deadline(500,NSEC_PER_MSEC,&a630_client_io.deadline);
    return true;
}
bool polaris_gpu_timestamp(uint64_t *value)
{
    if(!value || !a630_client_begin())return false;
    /* Native A6XX_CP_ALWAYS_ON_COUNTER_{HI,LO}, no host-clock substitute. */
    for(unsigned n=0;n<4;n++) {
        uint32_t hi,lo,again;
        if(!a630_core_read(&a630_client_io,0x981,&hi) ||
            !a630_core_read(&a630_client_io,0x980,&lo) ||
            !a630_core_read(&a630_client_io,0x981,&again))return false;
        if(hi==again){*value=((uint64_t)hi<<32)|lo;return true;}
    }
    return false;
}
bool polaris_gpu_quiescent(void)
{
    if (!a630_client_begin()) return false;
    struct a630_core_snapshot *s=&a630_client_submit.live;
    const struct a630_core_io io={a630_core_owned,a630_core_read,a630_core_write,
        a630_gmu_sync,a630_delay_us,&a630_client_io};
    uint32_t halt,fsr,sctlr;uint64_t root;
    bool ok=a630_core_idle(&io,s) && a630_core_read(&a630_client_io,0x808,&halt) && halt==3 &&
        a630_smmu_read(&a630_client_io,0x8058,&fsr) && !(fsr&0xc00001feu) &&
        a630_smmu_read(&a630_client_io,0x8000,&sctlr) && (sctlr&0xc011ff)==0xc01127 &&
        a630_smmu_read64(&a630_client_io,0x8020,&root) && root==a630_core_tables.physical;
    if (!ok) polaris_gpu_quarantine();
    return ok;
}
bool polaris_gpu_map(uint64_t address,uint64_t physical,bool read_only,bool cached)
{
    if (!polaris_gpu_ready() || address<A630_CLIENT_IOVA || address>=A630_CLIENT_END ||
        (physical>=a630_dma_physical && physical-a630_dma_physical<a630_dma_bytes)) return false;
    unsigned flags=A630_MMU_USER|A630_MMU_EXEC|
        (read_only?A630_MMU_READONLY:0)|(cached?A630_MMU_CACHED:0);
    return a630_mmu_map(&a630_core_tables,address,physical,flags)==A630_MMU_OK;
}
bool polaris_gpu_commit(void)
{
    if (!polaris_gpu_quiescent()) return false;
    polaris_gpu_cache(a630_core_tables.memory,(uint64_t)a630_core_tables.used*4096);
    bool ok=a630_smmu_write(&a630_client_io,0x8610,0) &&
        a630_smmu_write(&a630_client_io,0x87f0,0) && a630_gmu_sync(&a630_client_io);
    uint32_t busy=1;
    for (unsigned n=0; ok && n<1000; n++) {
        ok=a630_smmu_read(&a630_client_io,0x87f4,&busy);
        if (!ok || !(busy&1)) break;
        a630_delay_us(&a630_client_io,1);
    }
    if (!ok || (busy&1)) {polaris_gpu_quarantine();return false;}
    a630_mmu_cleaned(&a630_core_tables);
    return true;
}
bool polaris_gpu_unmap(uint64_t address,uint64_t size)
{
    if ((address&4095) || !size || (size&4095) || address<A630_CLIENT_IOVA ||
        address>=A630_CLIENT_END || size>A630_CLIENT_END-address || !polaris_gpu_quiescent()) return false;
    for (uint64_t n=0; n<size; n+=4096)
        if (a630_mmu_unmap(&a630_core_tables,address+n)!=A630_MMU_OK) {
            polaris_gpu_quarantine();return false;
        }
    return polaris_gpu_commit();
}
bool polaris_gpu_submit(const uint64_t *addresses,const uint32_t *words,uint32_t count,uint32_t *fence)
{
    if (!addresses || !words || !fence || !count || count>A630_SUBMIT_MAX || !a630_client_begin()) return false;
    struct a630_ib ibs[A630_SUBMIT_MAX];
    for (unsigned n=0; n<count; n++) ibs[n]=(struct a630_ib){addresses[n],words[n]};
    const struct a630_core_io io={a630_core_owned,a630_core_read,a630_core_write,
        a630_gmu_sync,a630_delay_us,&a630_client_io};
    bool ok=a630_submit_run(&a630_client_submit,&io,(uint32_t*)(a630_dma+0x30000),
        (volatile uint32_t*)(a630_dma+0x38000),ibs,count);
    if (!ok || !polaris_gpu_quiescent()) {
        printf("POLARIS GPU: runtime failed error=%u wptr=%x rptr=%x CP=%x IRQ=%x; retaining BOs\n",
            a630_client_submit.error,a630_client_submit.live.wptr,a630_client_submit.live.rptr,
            a630_client_submit.live.cp_irq,a630_client_submit.live.irq);
        polaris_gpu_quarantine();return false;
    }
    *fence=a630_client_submit.completed;
    return true;
}
static void a630_client_adopt(const struct a630_io *io)
{
    if (!a630_client_requested || !a630_zap_saved.authenticated || !a630_zap_saved.retained ||
        !a630_submit_adopt(&a630_client_submit,&a630_core_saved)) return;
    a630_client_io=*io; /* Copy mappings, never retain the boot worker's stack. */
    a630_client_io.gmu_lease=true;a630_client_io.runtime_lease=true;
    a630_client_io.core_lease=true;a630_client_io.can_stop=false;a630_client_io.deadline=0;
    __atomic_store_n(&a630_client_ready,1,__ATOMIC_RELEASE);
    if (polaris_gpu_quiescent()) PolarisGPUStart();
}
