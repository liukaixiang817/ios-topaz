/* Included once by polaris_a630.c. Native 0046 bootstrap is immutable after
 * publication. These separate runtime snapshots/MMIO leases live forever.
 */
static struct a630_io a630_client_io;
static struct a630_submit a630_client_submit;
static uint32_t a630_client_ready, a630_client_dead;
struct a630_client_fault {
    uint32_t error,offset,expected,actual,cp,irq,hw,protect,wptr,rptr;
    uint32_t far[2],fsr,syndrome,valid;
};
static struct a630_client_fault a630_client_first_fault;
static uint32_t a630_client_fault_published;
uint32_t polaris_gpu_fault_line(unsigned line,char *out,uint32_t capacity)
{
    if(!out || !capacity || line>2 || !__atomic_load_n(&a630_client_fault_published,__ATOMIC_ACQUIRE))return 0;
    const struct a630_client_fault *s=&a630_client_first_fault;
    if(!line)return (uint32_t)snprintf(out,capacity,"GX E%x @%x e%x a%x",s->error,s->offset,s->expected,s->actual);
    if(line==1)return (uint32_t)snprintf(out,capacity,"GCP C%x I%x H%x P%x W%x/%x",s->cp,s->irq,s->hw,s->protect,s->wptr,s->rptr);
    return (uint32_t)snprintf(out,capacity,"GFAR %08x:%08x S%x Y%x V%x",s->far[1],s->far[0],s->fsr,s->syndrome,s->valid);
}
void polaris_gpu_quarantine(void)
{
    if (__atomic_exchange_n(&a630_client_dead,1,__ATOMIC_ACQ_REL))return;
    const struct a630_core_snapshot *s=&a630_client_submit.live;
    struct a630_client_fault *f=&a630_client_first_fault;
    *f=(struct a630_client_fault){.error=s->error,.offset=s->offset,.expected=s->expected,.actual=s->actual,
        .cp=s->cp_irq,.irq=s->irq,.hw=s->hw_fault,.protect=s->protect,.wptr=s->wptr,.rptr=s->rptr};
    /* Best-effort fixed RO capture under the EXISTING runtime lease/deadline.
     * Never renew that deadline, acknowledge an IRQ/FSR, resume, issue ATOS,
     * reset or free memory. Render timers only format this immutable result. */
    const uint32_t words[7]={0x823,0x821,0x824,0x8058,0x8060,0x8064,0x8068};
    uint32_t *values[7]={&f->cp,&f->hw,&f->protect,&f->fsr,&f->far[0],&f->far[1],&f->syndrome};
    for(unsigned n=0;n<7;n++) {
        bool ok=n<3?a630_core_read(&a630_client_io,words[n],values[n]):
            a630_smmu_read(&a630_client_io,words[n],values[n]);
        if(ok)f->valid|=1u<<n;
    }
    __atomic_store_n(&a630_client_fault_published,1,__ATOMIC_RELEASE);
    printf("POLARIS GPU: runtime quarantined E%x @%x e%x a%x CP%x IRQ%x HW%x P%x W%x/%x FAR%08x:%08x FSR%x SYN%x valid%x; retain all DMA pages/power\n",
        f->error,f->offset,f->expected,f->actual,f->cp,f->irq,f->hw,f->protect,f->wptr,f->rptr,
        f->far[1],f->far[0],f->fsr,f->syndrome,f->valid);
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
    uint32_t value;uint64_t root;
    s->error=0;s->offset=0;s->expected=0;s->actual=0;
    if(!a630_core_idle(&io,s))goto failed;
    s->offset=0x808;s->expected=3;
    if(!a630_core_read(&a630_client_io,s->offset,&value))goto io_failed;
    s->actual=value;if(value!=s->expected)goto mismatch;
    s->offset=0x8058;s->expected=0;
    if(!a630_smmu_read(&a630_client_io,s->offset,&value))goto io_failed;
    s->actual=value;
    if(value&0xc00001feu){s->error=A630_CORE_FAULT;goto failed;}
    s->offset=0x8000;s->expected=0xc01127;
    if(!a630_smmu_read(&a630_client_io,s->offset,&value))goto io_failed;
    s->actual=value;if((value&0xc011ff)!=s->expected)goto mismatch;
    s->offset=0x8020;s->expected=(uint32_t)a630_core_tables.physical;
    if(!a630_smmu_read64(&a630_client_io,s->offset,&root))goto io_failed;
    s->actual=(uint32_t)root;if(root!=a630_core_tables.physical)goto mismatch;
    s->offset=0;s->expected=0;s->actual=0;
    return true;
mismatch:
    s->error=A630_CORE_DATA;goto failed;
io_failed:
    s->error=A630_CORE_IO;
failed:
    /* Preserve the first failing predicate; no FSR/IRQ acknowledgement or
     * recovery. The saved panel can distinguish a translation fault from
     * a halt, register-read or address-space ownership failure. */
    polaris_gpu_quarantine();return false;
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
    if (!ok || (busy&1)) {
        a630_client_submit.live.error=A630_CORE_TIMEOUT;
        a630_client_submit.live.offset=0x87f4;a630_client_submit.live.expected=0;
        a630_client_submit.live.actual=busy;
        polaris_gpu_quarantine();return false;
    }
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
