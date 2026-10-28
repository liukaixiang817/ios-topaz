/* Included once by polaris_a630.c. Native 0046 bootstrap is immutable after
 * publication. These separate runtime snapshots/MMIO leases live forever.
 */
#include "polaris_a630_performance.h"
/* BEGIN BOUNDED THERMAL PLANNER: exact tested pure implementation. */
/* Pure bounded experiment planner. Eligibility is produced from actual native
 * TSENS observations separately. Neither a plan nor a host ACK is an actual
 * request-state confirmation. Caller confirms only after the original HFI
 * ownership/quiescence/ACK/return/readback transaction has succeeded.
 * A thermal renewal cannot restart the120s hard budget. Only10s in a known
 * low request state opens a new budget. Original stock target and idle remain.
 */
#define A630_THERMAL_HIGH_NS UINT64_C(120000000000)
#define A630_THERMAL_COOL_NS UINT64_C(10000000000)
#define A630_THERMAL_IDLE_NS UINT64_C(250000000)
enum { AT_REQUEST=0,AT_UNCONFIRMED,AT_IDLE,AT_SENSOR,AT_HARD_LIMIT,AT_COOLING };
struct a630_thermal_state {
    uint64_t last_ns,cycle_since_ns,low_since_ns;
    uint32_t confirmed,high,cooling,reason,fault;
};
static inline bool a630_thermal_clock(struct a630_thermal_state *s,uint64_t now)
{
    if(!s || s->fault || !now || now<s->last_ns ||
       now>UINT64_MAX-A630_THERMAL_HIGH_NS) {
        if(s)s->fault=1;
        return false;
    }
    s->last_ns=now;return true;
}
static inline bool a630_thermal_confirm(struct a630_thermal_state *s,uint64_t now,
    uint32_t perf,uint32_t bus)
{
    if(!a630_thermal_clock(s,now))return false;
    if(!((perf==1 && bus==4)||(perf==4 && bus==8))){s->fault=1;return false;}
    bool high=perf==4;
    if(high) {
        /* A desired high request without a prior successful low observation
         * is never the beginning of an admitted experiment. */
        if(!s->confirmed || s->cooling){s->fault=1;return false;}
        if(!s->cycle_since_ns)s->cycle_since_ns=now;
        s->low_since_ns=0;
    } else if(!s->confirmed || s->high)s->low_since_ns=now;
    s->confirmed=1;s->high=high;return true;
}
static inline bool a630_thermal_plan(struct a630_thermal_state *s,uint64_t now,
    uint64_t activity,bool eligible,uint32_t *perf,uint32_t *bus)
{
    if(!perf || !bus || !a630_thermal_clock(s,now))return false;
    if(activity>now){s->fault=1;return false;}
    *perf=1;*bus=4;
    if(!s->confirmed){s->reason=AT_UNCONFIRMED;return true;}
    /* This is time in a confirmed-low request, not an idle/cooldown intent or
     * time since a failed transaction. Repeated low confirmations don't move it. */
    if(!s->high && s->low_since_ns && now-s->low_since_ns>=A630_THERMAL_COOL_NS) {
        s->cooling=0;s->cycle_since_ns=0;
    }
    if(s->cycle_since_ns && now-s->cycle_since_ns>=A630_THERMAL_HIGH_NS) {
        s->cooling=1;s->reason=AT_HARD_LIMIT;
    }
    if(s->cooling){s->reason=AT_COOLING;return true;}
    if(!eligible){s->reason=AT_SENSOR;return true;}
    if(!activity || now-activity>A630_THERMAL_IDLE_NS){s->reason=AT_IDLE;return true;}
    *perf=4;*bus=8;s->reason=AT_REQUEST;return true;
}

/* END BOUNDED THERMAL PLANNER. */
static struct a630_io a630_client_io;
static struct a630_submit a630_client_submit;
static uint64_t a630_client_postcheck_ticks;
bool polaris_gpu_last_submit_us(uint32_t fence,uint64_t *stages);
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
        (read_only?A630_MMU_READONLY:0)|(cached?A630_MMU_CACHED:A630_MMU_NONSHARED);
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
static uint64_t a630_submit_now(void *unused)
{
    (void)unused;uint64_t now;clock_get_uptime(&now);return now;
}
static uint64_t a630_submit_us(uint64_t ticks)
{
    uint64_t ns;absolutetime_to_nanoseconds(ticks,&ns);return ns/1000;
}
/* Snapshot the already-observed completion while the caller still holds
 * gpuLock. No new hardware read, permission change, MMIO or cache operation. */
bool polaris_gpu_last_submit_us(uint32_t fence,uint64_t *stages)
{
    if(!stages || !fence || !polaris_gpu_ready() ||
        fence!=a630_client_submit.completed || a630_client_submit.timing_mask!=31 ||
        a630_client_postcheck_ticks==UINT64_MAX)return false;
    for(unsigned n=0;n<5;n++)stages[n]=a630_submit_us(a630_client_submit.timing[n]);
    stages[5]=a630_submit_us(a630_client_postcheck_ticks);return true;
}
/* Read-only fixed diagnostic after a completed idle/halted submission. The
 * caller already holds gpuLock. No app address/offset, clock request, counter
 * programming, reset, IRQ acknowledgement or readiness mutation is accepted.
 * Two GPUCC snapshots expose concurrent PLL/RCG transitions instead of
 * inferring a frequency from the HFI request alone. */
bool polaris_gpu_clock_snapshot(uint32_t *values,uint32_t capacity)
{
    if(!values || capacity!=19 || !polaris_gpu_ready() ||
        !a630_client_submit.completed || !a630_client_submit.live.idle ||
        !a630_client_submit.live.halted || a630_client_submit.live.keep_live ||
        !a630_client_begin())return false;
    const uint32_t gmu[4]={A630_POST_ACK,A630_POST_PERF,A630_POST_BW,A630_POST_RETURN};
    /* Pinned MiCode gpucc-sdm845 + clk-alpha-pll + clk-rcg2: graphics RCG,
     * Fabia PLL0 and its even post-divider. These are READ offsets only. */
    const uint32_t clock[7]={0x101c,0x1020,0,0x4,0x38,0xc,0x2c};
    uint32_t valid=0;
    for(unsigned n=0;n<4;n++)
        if(a630_read_register(&a630_client_io,2,gmu[n],&values[1+n]))valid|=1u<<n;
    for(unsigned pass=0;pass<2;pass++)for(unsigned n=0;n<7;n++) {
        unsigned index=4+pass*7+n;
        if(a630_read_register(&a630_client_io,1,clock[n],&values[1+index]))valid|=1u<<index;
    }
    values[0]=valid;return valid==0x3ffffu;
}
bool polaris_gpu_submit(const uint64_t *addresses,const uint32_t *words,uint32_t count,uint32_t *fence)
{
    if (!addresses || !words || !fence || !count || count>A630_SUBMIT_MAX || !a630_client_begin()) return false;
    struct a630_ib ibs[A630_SUBMIT_MAX];
    for (unsigned n=0; n<count; n++) ibs[n]=(struct a630_ib){addresses[n],words[n]};
    const struct a630_core_io io={a630_core_owned,a630_core_read,a630_core_write,
        a630_gmu_sync,a630_delay_us,&a630_client_io};
    bool ok=a630_submit_profiled(&a630_client_submit,&io,(uint32_t*)(a630_dma+0x30000),
        (volatile uint32_t*)(a630_dma+0x38000),ibs,count,a630_submit_now,NULL);
    uint64_t before=a630_submit_now(NULL);
    bool quiescent=ok&&polaris_gpu_quiescent();
    uint64_t after=a630_submit_now(NULL);
    if (!ok || !quiescent) {
        printf("POLARIS GPU: runtime failed error=%u wptr=%x rptr=%x CP=%x IRQ=%x; retaining BOs\n",
            a630_client_submit.error,a630_client_submit.live.wptr,a630_client_submit.live.rptr,
            a630_client_submit.live.cp_irq,a630_client_submit.live.irq);
        polaris_gpu_quarantine();return false;
    }
    a630_client_postcheck_ticks=after>=before?after-before:UINT64_MAX;
    *fence=a630_client_submit.completed;
    if (*fence<=4 || !(*fence%64)) {
        const struct a630_submit *p=&a630_client_submit;
        printf("POLARIS GPU CORE PERF: fence=%u valid=%x prior=%llu ring=%llu execute_idle=%llu visibility=%llu halt=%llu postcheck=%llu us polls=%u\n",
            *fence,p->timing_mask,a630_submit_us(p->timing[0]),a630_submit_us(p->timing[1]),
            a630_submit_us(p->timing[2]),a630_submit_us(p->timing[3]),a630_submit_us(p->timing[4]),
            after>=before?a630_submit_us(after-before):UINT64_MAX,p->timing_polls);
    }
    return true;
}
/* Only called with the resident service's gpuLock held. No new MMIO mapping
 * or caller-selected registers: original-board admission + native proof first.
 * Default OFF. Request success is not an instantaneous-frequency claim. */
static struct a630_perf_state a630_client_perf;
static struct a630_thermal_state a630_client_thermal;
static bool a630_client_thermal_enabled;
extern bool polaris_gpu_thermal_ready(void);
extern unsigned polaris_gpu_thermal_verdict(void);
static uint64_t a630_perf_now_ns(void)
{
    uint64_t ticks,ns;clock_get_uptime(&ticks);absolutetime_to_nanoseconds(ticks,&ns);return ns;
}
/* Executed in the real native QEMU kernel, but explicit synthetic state and
 * timestamps. No controller MMIO, temperature or physical-frequency claim. */
bool polaris_gpu_thermal_policy_vm_probe(void)
{
    struct a630_thermal_state s={0};uint32_t p=0,b=0;
    bool ok=a630_thermal_plan(&s,100,100,true,&p,&b) && p==1 && b==4 &&
        a630_thermal_confirm(&s,100,1,4) &&
        a630_thermal_plan(&s,101,101,true,&p,&b) && p==4 && b==8 &&
        a630_thermal_confirm(&s,101,4,8);
    ok=ok && a630_thermal_plan(&s,31000000101ULL,31000000101ULL,true,&p,&b) && p==4 &&
        s.cycle_since_ns==101 &&
        a630_thermal_plan(&s,120000000101ULL,120000000101ULL,true,&p,&b) && p==1 &&
        a630_thermal_plan(&s,140000000101ULL,140000000101ULL,true,&p,&b) && p==1 &&
        !s.low_since_ns && a630_thermal_confirm(&s,140000000101ULL,1,4) &&
        a630_thermal_plan(&s,150000000100ULL,150000000100ULL,true,&p,&b) && p==1 &&
        a630_thermal_plan(&s,150000000101ULL,150000000101ULL,true,&p,&b) && p==4;
    printf("POLARIS GPU THERMAL BUDGET VM: %s; actual native hard120s and confirmed-low10s planner only\n",ok?"PASS":"FAIL");
    return ok;
}

static struct a630_channel_io a630_client_perf_io(void)
{
    return (struct a630_channel_io){a630_core_owned,a630_read_register,
        a630_write_register,a630_gmu_sync,a630_delay_us,&a630_client_io};
}
bool polaris_gpu_performance_configure(void)
{
    uint32_t mode=0,cow=0,rw=0,marker=0,quiesce=0;
    PE_parse_boot_argn("polarisgpup",&mode,sizeof(mode));if(!mode)return true;
    PE_parse_boot_argn("polarisramcow",&cow,sizeof(cow));
    bool has_rw=PE_parse_boot_argn("ufsrw",&rw,sizeof(rw));
    PE_parse_boot_argn("polarisownedmarker",&marker,sizeof(marker));
    PE_parse_boot_argn("polarisquiesce",&quiesce,sizeof(quiesce));
    bool board=a630_firmware_ok && a630_abi_ok && a630_client_requested &&
        a630_zap_saved.authenticated && a630_zap_saved.retained &&
        a630_channel_saved.error==A630_CH_READY && a630_channel_saved.acks==5 &&
        a630_channel_saved.tables_done==7 && a630_channel_saved.version==0x10070000 &&
        a630_post_saved.dcvs_done && a630_post_saved.gpu_ready;
    bool admitted=a630_perf_intent(mode,a630_mode,cow,has_rw,rw,marker,quiesce,
        __builtin_arm_rsr64("MIDR_EL1"),__builtin_arm_rsr64("MPIDR_EL1")&0xffffffULL,
        __builtin_arm_rsr64("CNTFRQ_EL0"),board);
    if(!admitted){printf("POLARIS GPU STOCK: REFUSED platform/mode; no request write\n");return false;}
    uint32_t thermal=0;PE_parse_boot_argn("polaristsens",&thermal,sizeof(thermal));
    if(thermal>2 || (thermal==2 && (mode!=3 || !polaris_gpu_thermal_ready()))) {
        printf("POLARIS GPU THERMAL: REFUSED observer/platform/mode; no request write\n");return false;
    }
    a630_client_thermal_enabled=thermal==2;
    struct a630_channel_io io=a630_client_perf_io();
    bool ok=polaris_gpu_quiescent() && a630_perf_init(&a630_client_perf,mode,true,&io);
    printf("POLARIS GPU STOCK: armed=%u mode=%u saved=1/4 target=%u/%u error=%u; original table requests, not measured Hz\n",
        ok,mode,a630_client_perf.target_perf,a630_client_perf.target_bus,a630_client_perf.fault);
    if(ok && a630_client_thermal_enabled)
        printf("POLARIS GPU THERMAL: armed hard120s confirmed-low10s idle250ms; CPU fixed guard unchanged\n");
    return ok;
}
bool polaris_gpu_performance_tick(uint64_t now_ns,uint64_t activity_ns)
{
    struct a630_perf_state *s=&a630_client_perf;
    if(!s->armed || s->stopped)return !s->fault;
    uint32_t perf=0,bus=0;
    bool ok=a630_client_thermal_enabled ? a630_thermal_plan(&a630_client_thermal,now_ns,activity_ns,
        polaris_gpu_thermal_verdict()==0,&perf,&bus):a630_perf_desired(s,now_ns,activity_ns,&perf,&bus);
    if(!ok && a630_client_thermal_enabled) {
        struct a630_channel_snapshot fault={.error=A630_CH_ARGUMENT};a630_perf_fail(s,&fault);
    }
    bool changed=s->perf!=perf || s->bus!=bus;
    if(ok && (changed || (a630_client_thermal_enabled && !a630_client_thermal.confirmed))) {
        struct a630_channel_io io=a630_client_perf_io();
        ok=a630_perf_change(s,&io,perf,bus,polaris_gpu_quiescent());
        if(ok && a630_client_thermal_enabled) {
            /* Start low cooldown only AFTER real successful readback/ACK. */
            ok=a630_thermal_confirm(&a630_client_thermal,a630_perf_now_ns(),perf,bus);
            if(!ok){struct a630_channel_snapshot fault={.error=A630_CH_ARGUMENT};a630_perf_fail(s,&fault);}
            printf("POLARIS GPU THERMAL PLAN: us=%llu high_since=%llu low_since=%llu cooling=%u reason=%u confirmed=%u fault=%u\n",
                a630_perf_now_ns()/1000,a630_client_thermal.cycle_since_ns/1000,
                a630_client_thermal.low_since_ns/1000,a630_client_thermal.cooling,
                a630_client_thermal.reason,a630_client_thermal.confirmed,a630_client_thermal.fault);
        }
        if(changed)printf("POLARIS GPU STOCK SAMPLE: end_us=%llu mode=%u PERF=%u BW=%u transitions=%llu error=%u return=%u; request not measured Hz\n",
            now_ns/1000,s->mode,s->perf,s->bus,s->transitions,s->fault,s->returned);
    }
    if(!ok){printf("POLARIS GPU STOCK: FAILED error=%u offset=%x expected=%x actual=%x; retain DMA, refuse native reset\n",
        s->fault,s->offset,s->expected,s->actual);polaris_gpu_quarantine();}
    return ok;
}
bool polaris_gpu_performance_restore(void)
{
    struct a630_perf_state *s=&a630_client_perf;
    if(!s->armed)return !s->fault;
    struct a630_channel_io io=a630_client_perf_io();
    bool ok=a630_perf_stop(s,&io,polaris_gpu_quiescent());
    printf("POLARIS GPU STOCK RESTORE: restored=%u PERF=%u BW=%u error=%u; before peer OFF\n",ok,s->perf,s->bus,s->fault);
    if(!ok)polaris_gpu_quarantine();return ok;
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
