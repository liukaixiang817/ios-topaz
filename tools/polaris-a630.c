/* Original Polaris A630 firmware consumer and guarded hardware bring-up.
 * Mode3 briefly owns the CX request; mode4 also tests parked-CXO GMU clocks
 * under block reset. Mode5 also loads/verifies the original GMU image while
 * retaining block reset. Mode6 builds owned SMMU mappings and attempts a
 * fresh GMU firmware boot at the original200MHz, then contains and unwinds.
 * Mode7 requests original low GX/MX votes and probes HFI INIT/FW_VER.
 * Mode8 completes native HFI tables. Mode9 attempts owned core/SQE/ZAP/CP
 * and a checked64x64 offscreen image. No desktop acceleration service yet.
 */
#if defined(POLARIS_RAM_ONLY)
#include <sys/param.h>
#include <sys/systm.h>
#include <mach/mach_types.h>
#include <pexpert/pexpert.h>
#include <pexpert/device_tree.h>
#include <kern/clock.h>
#include <vm/pmap.h>
#include <vm/vm_kern.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha2.h>
#include "polaris_a630_probe.h"
#include "polaris_a630_power.h"
#include "polaris_a630_clock.h"
#include "polaris_a630_hfi.h"
#include "polaris_a630_channel.h"
#include "polaris_a630_images.h"
#include "polaris_a630_tcm.h"
#include "polaris_a630_gmu.h"
#include "polaris_a630_mmu.h"
#include "polaris_a630_smmu.h"
#include "polaris_a630_bus.h"
#include "polaris_a630_boot.h"
#include "polaris_a630_post.h"
#include "polaris_a630_zap.h"
#include "polaris_a630_core.h"
extern vm_offset_t ml_io_map(vm_offset_t, vm_size_t);
extern ppnum_t pmap_find_phys(pmap_t, addr64_t);
/* XNU-private declarations in osfmk/vm/pmap.h are not exported to BSD. */
extern unsigned int pmap_cache_attributes(ppnum_t);
extern void pmap_set_cache_attributes(ppnum_t,unsigned int);
void polaris_a630_init(void);
void polaris_a630_report(void);
uint32_t polaris_a630_status(void);
uint32_t polaris_a630_details(char *, uint32_t);
uint32_t polaris_a630_diagnostic_line(unsigned, char *, uint32_t);
static struct a630_probe a630_saved;
static struct a630_power_snapshot a630_power_saved;
static struct a630_clock_snapshot a630_clock_saved;
static struct a630_gmu_snapshot a630_gmu_saved;
static struct a630_smmu_snapshot a630_smmu_saved;
static struct a630_bus_snapshot a630_bus_saved;
static struct a630_boot_snapshot a630_boot_saved;
static struct a630_channel_snapshot a630_channel_saved;
static struct a630_mmu a630_tables,a630_core_tables;
static struct a630_smmu_snapshot a630_core_smmu;
static struct a630_post_snapshot a630_post_saved;
static struct a630_zap_snapshot a630_zap_saved;
static struct a630_core_snapshot a630_core_saved;
static struct a630_image a630_images[6];
static uint64_t a630_dma_physical;
static uint32_t a630_core_dma_ready;
static vm_offset_t a630_dma;
static uint32_t a630_dma_ready, a630_dma_bytes, a630_nc_pages;
static struct a630_image a630_gmu_image;
static uint32_t a630_mode;
static uint32_t a630_started, a630_published, a630_firmware_ok, a630_abi_ok;
static uint8_t a630_host_hfi[A630_HFI_BYTES] __attribute__((aligned(16384)));

uint32_t polaris_a630_status(void)
{
    if (!__atomic_load_n(&a630_published, __ATOMIC_ACQUIRE)) return 0;
    return a630_saved.result | (a630_firmware_ok << 8) | (a630_abi_ok << 9);
}

uint32_t polaris_a630_details(char *out, uint32_t capacity)
{
    if (!out || !capacity) return 0;
    if (!__atomic_load_n(&a630_published, __ATOMIC_ACQUIRE))
        return (uint32_t)snprintf(out, capacity, "GPU pending");
    if (a630_mode >= 4)
        return (uint32_t)snprintf(out, capacity, "G%x P%u K%u/%u F%x/%x R%x/%x",
            polaris_a630_status(), a630_power_saved.result, a630_clock_saved.result,
            a630_clock_saved.failed_step, a630_clock_saved.failed_offset, a630_clock_saved.failed_value,
            a630_clock_saved.before[2], a630_clock_saved.config);
    return (uint32_t)snprintf(out, capacity, "G%x P%u CX%08x HW%08x M%08x X%08x",
        polaris_a630_status(), a630_power_saved.result, a630_saved.cx, a630_saved.cx_hw,
        a630_saved.clocks[1], a630_saved.clocks[2]);
}

uint32_t polaris_a630_diagnostic_line(unsigned line, char *out, uint32_t size)
{
    if (!out || !size) return 0;
    out[0] = 0;
    if (line >= 20) return 0;
    if (!__atomic_load_n(&a630_published, __ATOMIC_ACQUIRE))
        return (uint32_t)snprintf(out, size, "GPU snapshot pending");
    const struct a630_post_snapshot *post=&a630_post_saved;
    const struct a630_zap_snapshot *zap=&a630_zap_saved;
    const struct a630_core_snapshot *core=&a630_core_saved;
    if(line==15 && a630_core_smmu.error && a630_core_smmu.error!=A630_SMMU_READY)
        return (uint32_t)snprintf(out,size,"GS0 %x/%x B%x S%x @%x e%x a%x",
            a630_core_smmu.error&15,a630_core_smmu.stage&15,a630_core_smmu.bank&255,
            a630_core_smmu.slot&255,a630_core_smmu.failed_offset,a630_core_smmu.expected,a630_core_smmu.actual);
    if(line==15)return (uint32_t)snprintf(out,size,"GD %x/%x D%x G%x/%x ret%x @%x a%x",
        post->error&15,post->stage&15,post->dcvs_done&1,post->gpu_ready&1,post->gpu_released&1,
        post->dcvs_return,post->offset,post->actual);
    if(line==16)return (uint32_t)snprintf(out,size,"GZ %x/%x fn%x t%x r%x S%x M%x A%x",
        zap->error&15,zap->stage&15,zap->fn,zap->transport,zap->secure,zap->signature&1,zap->region&1,zap->authenticated&1);
    if(line==17)return (uint32_t)snprintf(out,size,"GC0 %x/%x C%x/%x I%x F%08x H%x L%x M%x/%x",
        core->error&15,core->stage&15,core->rptr,core->wptr,core->init_done&1,core->fence,
        core->halted&1,core->keep_live&1,a630_core_smmu.error&15,a630_core_smmu.stage&15);
    if(line==18)return (uint32_t)snprintf(out,size,"GI %x px%x @%x e%x a%x",
        core->image&1,core->pixels,core->offset,core->expected,core->actual);
    if(line==19 && a630_core_smmu.restore_error)
        return (uint32_t)snprintf(out,size,"GS0 R%x @%x e%x a%x",
            a630_core_smmu.restore_error&15,a630_core_smmu.restore_offset,
            a630_core_smmu.restore_expected,a630_core_smmu.restore_actual);
    if(line==19)return (uint32_t)snprintf(out,size,"GF IRQ%x HW%x P%x CP%x",
        core->irq,core->hw_fault,core->protect,core->cp_irq);
    const struct a630_power_snapshot *p = &a630_power_saved;
    const struct a630_clock_snapshot *c = &a630_clock_saved;
    const struct a630_channel_snapshot *h=&a630_channel_saved;
    if(line==11)return (uint32_t)snprintf(out,size,"GH %x/%x NC%x C%x A%x V%08x @%x e%x a%x",
        h->error&15,h->stage&15,a630_nc_pages&3,h->commands&15,h->acks&15,h->version,
        h->failed_offset,h->expected,h->actual);
    if(line==12)return (uint32_t)snprintf(out,size,"HQ c%x/%x r%x/%x I%08x S%08x P%x",
        h->cmd_read&1023,h->cmd_write&1023,h->rsp_read&1023,h->rsp_write&1023,
        h->status,h->sp_status,h->power_state&255);
    if(line==13)return (uint32_t)snprintf(out,size,"HA %08x/%08x/%08x/%08x",
        h->response[0],h->response[1],h->response[2],h->response[3]);
    if(line==14 && h->full_requested)return (uint32_t)snprintf(out,size,"HR t%x p%x z%x r%x/%x @%x e%x a%x R%x/%x",
        h->tables_done&7,h->slumber_stage&15,h->slumber&1,h->restored&1,h->restore_error&15,
        h->restore_offset,h->restore_expected,h->restore_actual,h->rsc_before,h->rsc_status);
    if(line==14)return (uint32_t)snprintf(out,size,"HR g%x s%x h%x z%x r%x/%x @%x e%x a%x",
        h->gx_requested&1,h->sptp_requested&1,h->hfi_requested&1,h->slumber&1,
        h->restored&1,h->restore_error&15,h->restore_offset,h->restore_expected,h->restore_actual);
    if (!line) return (uint32_t)snprintf(out, size,
        "GP rq%08x/%08x hw%08x/%08x/%08x",
        p->before, p->after, p->before_hw, p->on_hw, p->after_hw);
    if (line == 1) return (uint32_t)snprintf(out, size, "GC rs%08x/%08x/%08x r%08x m%08x",
        c->before[4], c->live[4], c->after[4], c->live[2], c->live[3]);
    const struct a630_gmu_snapshot *g = &a630_gmu_saved;
    if (line == 2) return (uint32_t)snprintf(out, size,
        "GM %x/%x rs%08x/%08x fw%08x h%08x",
        g->result, g->stage, g->reset_before, g->reset_held, g->fw_init, g->hfi);
    if (line == 3) return (uint32_t)snprintf(out, size, "GT %x/%x @%08x w%x e%08x a%08x",
        g->tcm.result, g->tcm.phase, g->tcm.offset, g->tcm.writes,
        g->tcm.expected, g->tcm.actual);
    const struct a630_bus_snapshot *b=&a630_bus_saved;
    const struct a630_smmu_snapshot *m=&a630_smmu_saved;
    const struct a630_boot_snapshot *e=&a630_boot_saved;
    if (line == 4) return (uint32_t)snprintf(out,size,"GB %x/%x p%08x L%04x F%04x @%x:%05x v%08x",
        b->error&15,b->stage&15,b->pll[0],b->pll[1]&65535,b->pll[4]&65535,b->bank&15,b->offset&0xfffff,b->actual);
    if (line == 5) return (uint32_t)snprintf(out,size,"GS %x/%x c%x s%x @%x e%x a%x r%x/%x",
        m->error&15,m->stage&15,m->bank&255,m->slot&255,m->failed_offset,m->expected,m->actual,m->restored&1,m->restore_error&15);
    if (line == 6) return (uint32_t)snprintf(out,size,"GE %x/%x fw%08x @%x:%x e%x a%x r%x/%x",
        e->error&15,e->stage&15,e->fw,e->failed_bank&15,e->failed_offset,e->expected,e->actual,e->stopped&1,e->restore_error&15);
    if (line == 7) return (uint32_t)snprintf(out,size,"GL u%08x o%08x src%04x v%08x/%08x r%x/%x",
        b->pll[2],b->pll[3],b->source&65535,b->live[0],b->live[1],b->restored&1,b->restore_error&15);
    if(line==10)return (uint32_t)snprintf(out,size,"GR h%x a%llx m%x v%05x/%05x/%05x",
        e->retained_hidden&7,(unsigned long long)(e->attempted&0xffffffffffffull),
        e->pdc_len_zero&63,e->pdc_msgid_after[0],e->pdc_msgid_after[1],e->pdc_msgid_after[2]);
    if(line==9)return (uint32_t)snprintf(out,size,"SI h%x n%x ctl%08x cfg%08x ar%08x/%08x q%x f%x",
        m->preserved_impl&1,m->impl_checks&255,m->impl[0],m->impl[11],m->actlr,m->actlr_live,
        m->fault_quirk&1,m->fault_canonical&1);
    if(m->preserved_impl)return (uint32_t)snprintf(out,size,"SH r%x@%x e%08x a%08x q%x f%x",
        m->restore_error&15,m->restore_offset,m->restore_expected,m->restore_actual,
        m->fault_quirk&1,m->fault_canonical&1);
    return (uint32_t)snprintf(out,size,"SH b%08x l%08x a%08x p%x i%x r%x@%x",
        m->halt_before,m->halt_live,m->halt_after,m->halt_polls,m->impl_changed,
        m->restore_error&15,m->restore_offset);
}

static bool a630_property(DTEntry node, const char *name, const void **data, unsigned *size)
{
    return SecureDTGetProperty(node, name, data, size) == kSuccess;
}
static bool a630_u32(DTEntry node, const char *name, uint32_t expected)
{
    const void *p = NULL; unsigned n = 0; uint32_t value;
    if (!a630_property(node, name, &p, &n) || n != sizeof(value)) return false;
    memcpy(&value, p, sizeof(value)); return value == expected;
}
static bool a630_reg(DTEntry node, const char *name, uint64_t address, uint64_t length)
{
    const void *p = NULL; unsigned n = 0; uint64_t reg[2];
    if (!a630_property(node, name, &p, &n) || n != sizeof(reg)) return false;
    memcpy(reg, p, sizeof(reg)); return reg[0] == address && reg[1] == length;
}
static bool a630_image(DTEntry node, const char *key, unsigned minimum, unsigned maximum,
    const uint8_t **out, unsigned *bytes)
{
    const void *p = NULL, *expected = NULL; unsigned n = 0, hn = 0;
    char hashkey[32]; uint8_t digest[32];
    snprintf(hashkey, sizeof(hashkey), "%s-sha256", key);
    if (!a630_property(node, key, &p, &n) || n < minimum || n > maximum ||
        !a630_property(node, hashkey, &expected, &hn) || hn != sizeof(digest)) return false;
    /* Built-in LTC SHA256, independent of the unavailable external provider. */
    const struct ccdigest_info *di = &ccsha256_ltc_di;
    ccdigest_di_decl(di, context);
    ccdigest_init(di, context);
    ccdigest_update(di, context, n, p);
    ccdigest_final(di, context, digest);
    ccdigest_di_clear(di, context);
    if (memcmp(digest, expected, sizeof(digest))) return false;
    *out = p; *bytes = n; return true;
}
static bool a630_firmware(DTEntry node)
{
    const uint8_t *gmu, *sqe, *mdt, *b00, *b01, *b02;
    unsigned gn, sn, mn, n0, n1, n2;
    if (!a630_image(node, "gmu-bin", 32768, 32768, &gmu, &gn) ||
        !a630_image(node, "sqe-fw", 8, 1024 * 1024, &sqe, &sn) ||
        !a630_image(node, "zap-mdt", 148, 4 * 1024 * 1024, &mdt, &mn) ||
        !a630_image(node, "zap-b00", 148, 148, &b00, &n0) ||
        !a630_image(node, "zap-b01", 1, 4 * 1024 * 1024, &b01, &n1) ||
        !a630_image(node, "zap-b02", 1, 4 * 1024 * 1024, &b02, &n2)) return false;
    const struct a630_image images[6] = {{gmu, gn}, {sqe, sn}, {mdt, mn},
        {b00, n0}, {b01, n1}, {b02, n2}};
    if (!a630_images_valid(images)) return false;
    memcpy(a630_images,images,sizeof(images));
    a630_gmu_image = images[0]; /* Immutable, hash-checked ADT storage. */
    printf("POLARIS A630: verified original GMU%u SQE%u version=%x ZAP%u; no firmware executed\n",
        gn, sn, a630_image_word(sqe + 4), mn);
    return true;
}
struct a630_io { vm_offset_t base[6]; bool gmu_lease, runtime_lease, core_lease, can_stop; };
static bool a630_pdc_offset(uint32_t off)
{
    for (unsigned n=0;n<A630_BOOT_PROFILE;n++)
        if (a630_boot_profile[n].bank==4 && a630_boot_profile[n].offset==off) return true;
    return false;
}
static bool a630_smmu_offset(uint32_t off,bool wide)
{
    return off<0xd000 && !(off&3) &&
        (off<0x8000 || (off&0xfff)<0x800) &&
        (!wide || (off>=0x8000 && ((off&0xfff)==0x20 || (off&0xfff)==0x28)));
}
static uint32_t __attribute__((noinline)) a630_load32(vm_offset_t address)
{
    uint32_t v;__asm__ volatile("ldr %w0, [%1]":"=r"(v):"r"(address):"memory");return v;
}
static void __attribute__((noinline)) a630_store32(vm_offset_t address,uint32_t v)
{
    /* HYP emulates the register form; do not emit str wzr. */
    __asm__ volatile("str %w0, [%1]"::"r"(v),"r"(address):"memory");
}
static bool a630_read_register(void *opaque, unsigned region, uint32_t off, uint32_t *value)
{
    static const uint64_t addresses[6] = {0x100000, 0x5090000, 0x506a000,0x5040000,0xb200000,0x5000000};
    static const uint32_t sizes[6] = {0x90000, 0x9000, 0x30000,0x10000,0x300000,0x40000};
    struct a630_io *io = opaque;
    if (region >= 6 || (off & 3) || off > sizes[region] - 4) return false;
    if(region==5 && (!io->runtime_lease || !io->core_lease || a630_mode!=9))return false;
    if ((region==3 && (!io->runtime_lease || !a630_smmu_offset(off,false))) ||
        (region==4 && (!io->runtime_lease || !a630_pdc_offset(off)))) return false;
    if (!io->base[region]) io->base[region] = ml_io_map(addresses[region], sizes[region]);
    if (!io->base[region]) return false;
    *value = a630_load32(io->base[region] + off);
    __asm__ volatile("dsb sy" ::: "memory");
    return true;
}
static bool a630_write_register(void *opaque, unsigned region, uint32_t off, uint32_t value)
{
    struct a630_io *io = opaque;
    if(region==5 && io->runtime_lease && io->core_lease && a630_mode==9 && io->base[5]){
        bool allowed=false;
        const uint32_t words[]={0x800,0x801,0x802,0x804,0x805,0x807,0x808,0x830,0x831};
        for(unsigned n=0;n<sizeof(words)/sizeof(words[0]);n++)if(off==4*words[n])allowed=true;
        for(unsigned n=0;n<sizeof(a630_core_profile)/sizeof(a630_core_profile[0]);n++)
            if(off==4*a630_core_profile[n].word)allowed=true;
        if(!allowed)return false;
        a630_store32(io->base[5]+off,value);__asm__ volatile("dsb sy":::"memory");return true;
    }
    if (io->runtime_lease && region<5 && io->base[region]) {
        bool allowed = region==0 && (off==0x52000 || off==0x52004 || off==0x44038 || off==0x7100c || off==0x71018);
        if (region==1 && (off==0x1124 || (a630_mode>=7 && off==0x100c))) allowed=true;
        if (region==3 && a630_smmu_offset(off,false)) allowed=true;
        if (region==4 && a630_pdc_offset(off)) allowed=true;
        if (region==2) {
            const uint32_t config[]={0x14000,0x14730,0x14070,0x14004,0x14614,
                0x14610,0x24c44,0x14608,0x1303c,0x14300,0x143a0};
            for(unsigned n=0;n<sizeof(config)/sizeof(config[0]);n++)if(off==config[n])allowed=true;
            for(unsigned n=0;n<A630_BOOT_PROFILE;n++)
                if(a630_boot_profile[n].bank==2&&a630_boot_profile[n].offset==off)allowed=true;
            if(a630_mode>=9 && (off==A630_POST_ACK || off==A630_POST_PERF || off==A630_POST_BW))allowed=true;
            if(a630_mode>=7){
                const uint32_t channel[]={A630_CH_INTR_SET,A630_CH_INTR_CLEAR,A630_CH_INTR_MASK,
                    A630_CH_BOOT_OPTION,A630_CH_GX_VOTE,A630_CH_MX_VOTE,
                    A630_CH_SPTP_CONTROL,A630_CH_HFI_INIT,A630_CH_RSC_REQUEST,0x14100,0x24c40};
                for(unsigned n=0;n<sizeof(channel)/sizeof(channel[0]);n++)
                    if(off==channel[n])allowed=true;
            }
        }
        if (allowed) {a630_store32(io->base[region]+off,value);__asm__ volatile("dsb sy":::"memory");return true;}
    }
    /* Mode5's exclusive lease admits only CM3 reset assertion and the
     * original flat TCM window. No reset release, HFI, SMMU or GPU write. */
    if (region == 2 && io->gmu_lease && io->base[2] &&
        ((off == A630_GMU_CM3_RESET && value == 1) ||
         (off >= A630_GMU_FLAT_START && off < A630_GMU_FLAT_START + A630_GMU_FLAT_BYTES && !(off & 3)))) {
        a630_store32(io->base[2] + off,value);
        __asm__ volatile("dsb sy" ::: "memory");
        return true;
    }
    /* Exact GPUCC request/clock/reset allowlist. */
    if (region != 1 || !io->base[1] ||
        (off != A630_CX_REQUEST && off != 0x109c &&
         off != 0x1120 && off != 0x1098 && off != 0x111c)) return false;
    a630_store32(io->base[1] + off,value);
    __asm__ volatile("dsb sy" ::: "memory");
    return true;
}
static void a630_delay_us(void *opaque __unused, uint32_t us) { delay(us); }
static bool a630_gmu_admitted(void *opaque)
{
    struct a630_io *io = opaque;
    /* This lease exists only inside the clock hook, on its exclusive boot
     * thread, while CX and all required clocks are observed live and BCR=1. */
    return io->gmu_lease;
}
static bool a630_gmu_read(void *io, uint32_t off, uint32_t *value)
{ return a630_gmu_admitted(io) && a630_read_register(io, 2, off, value); }
static bool a630_gmu_write(void *io, uint32_t off, uint32_t value)
{ return a630_gmu_admitted(io) && a630_write_register(io, 2, off, value); }
static bool a630_gmu_sync(void *io)
{
    if (!a630_gmu_admitted(io)) return false;
    __asm__ volatile("dsb sy" ::: "memory"); return true;
}
static bool a630_runtime_owned(void *opaque)
{struct a630_io *io=opaque;return io->gmu_lease&&io->runtime_lease;}
static bool a630_runtime_held(void *opaque)
{
    struct a630_io *io=opaque;uint32_t bcr,reset,gx;
    return a630_runtime_owned(io) && a630_read_register(io,1,0x111c,&bcr) &&
        a630_read_register(io,2,0x14000,&reset) && a630_read_register(io,1,0x100c,&gx) &&
        (bcr&1) && reset==1 && !(gx&0x80000000u);
}
static bool a630_clean_owned(void *opaque,const void *p,size_t bytes)
{
    uintptr_t va=(uintptr_t)p;
    if(!a630_runtime_owned(opaque)||!a630_dma_ready||va<a630_dma||
        va-a630_dma>a630_dma_bytes||bytes>a630_dma_bytes-(va-a630_dma))return false;
    for(uintptr_t at=va&~(uintptr_t)63;at<va+bytes;at+=64){
        /* NC HFI/dump pages have no cached aliases after pmap conversion.
         * Never invalidate a line concurrently modified by the GMU. */
        if(a630_nc_pages==2 && at>=a630_dma+0x20000)continue;
        __asm__ volatile("dc civac, %0"::"r"(at):"memory");
    }
    __asm__ volatile("dsb sy":::"memory");return true;
}
static bool a630_smmu_read(void *io,uint32_t off,uint32_t *v)
{return a630_read_register(io,3,off,v);}
static bool a630_smmu_write(void *io,uint32_t off,uint32_t v)
{return a630_write_register(io,3,off,v);}
static bool a630_smmu_read64(void *opaque,uint32_t off,uint64_t *v)
{
    struct a630_io *io=opaque;
    if(!a630_runtime_owned(io)||!a630_smmu_offset(off,true)||!io->base[3])return false;
    __asm__ volatile("ldr %0, [%1]":"=r"(*v):"r"(io->base[3]+off):"memory");
    __asm__ volatile("dsb sy":::"memory");return true;
}
static bool a630_smmu_write64(void *opaque,uint32_t off,uint64_t v)
{
    struct a630_io *io=opaque;
    if(!a630_runtime_owned(io)||!a630_smmu_offset(off,true)||!io->base[3])return false;
    __asm__ volatile("str %0, [%1]"::"r"(v),"r"(io->base[3]+off):"memory");
    __asm__ volatile("dsb sy":::"memory");return true;
}
static bool a630_prepare_dma(void)
{
    a630_dma_bytes=a630_mode>=9?0x44000:a630_mode>=7?0x28000:0x24000;
    if(kmem_alloc_contig(kernel_map,&a630_dma,a630_dma_bytes,PAGE_MASK,0,0,
        KMA_DATA|KMA_ZERO|KMA_PERMANENT,VM_KERN_MEMORY_IOKIT)!=KERN_SUCCESS)return false;
    ppnum_t pn=pmap_find_phys(kernel_pmap,(addr64_t)a630_dma);
    if(!pn)return false;
    uint64_t physical=ptoa_64(pn);
    if(physical>=A630_MMU_PA_LIMIT-a630_dma_bytes)return false;
    for(unsigned n=0;n<a630_dma_bytes;n+=PAGE_SIZE)
        if(ptoa_64(pmap_find_phys(kernel_pmap,(addr64_t)a630_dma+n))!=physical+n)return false;
    a630_dma_physical=physical;
    if(!a630_mmu_init(&a630_tables,(void*)a630_dma,physical,a630_mode>=9?16:32))return false;
    if(a630_mode>=7){
        /* Change every physical alias before the GMU is released. WCOMB on
         * ARM64 is Normal noncacheable, not Device memory; legacy queues
         * are dword-aligned and can be read/written by either processor. */
        if(PAGE_SIZE!=A630_HFI_BYTES)return false;
        for(unsigned off=0x20000;off<a630_dma_bytes;off+=PAGE_SIZE){
            ppnum_t page=pmap_find_phys(kernel_pmap,(addr64_t)a630_dma+off);
            pmap_set_cache_attributes(page,VM_WIMG_WCOMB);
            if((pmap_cache_attributes(page)&VM_WIMG_MASK)!=VM_WIMG_WCOMB)return false;
            if(off<0x28000)a630_nc_pages++;
        }
    }
    for(unsigned n=0;n<(a630_mode>=7?0x8000:0x4000);n+=4096)
        if(a630_mmu_map(&a630_tables,0x60000000+n,physical+0x20000+n,0)!=A630_MMU_OK)return false;
    if(!a630_hfi_init((void*)(a630_dma+0x20000),A630_HFI_BYTES,0x60000000))return false;
    if(a630_mode>=9){
        if(a630_images[1].bytes>0x8004 || a630_images[2].bytes>PAGE_SIZE)return false;
        memcpy((void*)(a630_dma+0x28000),a630_images[1].data+4,a630_images[1].bytes-4);
        memcpy((void*)(a630_dma+0x40000),a630_images[2].data,a630_images[2].bytes);
        if(!a630_mmu_init(&a630_core_tables,(void*)(a630_dma+0x10000),physical+0x10000,16))return false;
        const uint32_t map[][4]={{A630_CORE_SQE,0x28000,0x8000,A630_MMU_USER|A630_MMU_READONLY|A630_MMU_EXEC},
            {A630_CORE_RING,0x30000,0x8000,A630_MMU_USER|A630_MMU_READONLY},
            {A630_CORE_SCRATCH,0x38000,0x4000,A630_MMU_USER},
            {A630_CORE_TARGET,0x3c000,0x4000,A630_MMU_USER}};
        for(unsigned k=0;k<4;k++)for(unsigned n=0;n<map[k][2];n+=4096)
            if(a630_mmu_map(&a630_core_tables,map[k][0]+n,physical+map[k][1]+n,map[k][3])!=A630_MMU_OK)return false;
        a630_core_dma_ready=1;
    }
    a630_dma_ready=1;return true;
}
static bool a630_core_owned(void *opaque)
{
    struct a630_io *io=opaque;
    return a630_runtime_owned(io)&&io->core_lease&&a630_mode==9&&a630_core_dma_ready&&
        a630_core_smmu.error==A630_SMMU_READY&&a630_post_saved.gpu_ready;
}
static bool a630_core_read(void *io,uint32_t word,uint32_t *v)
{return a630_core_owned(io)&&word<0x10000&&a630_read_register(io,5,word*4,v);}
static bool a630_core_write(void *io,uint32_t word,uint32_t v)
{return a630_core_owned(io)&&word<0x10000&&a630_write_register(io,5,word*4,v);}
static int32_t a630_scm_call(void *opaque,uint32_t fn,uint32_t info,
    uint64_t a,uint64_t b,uint64_t c,uint64_t *answer)
{
    if(!a630_core_owned(opaque))return -1;
    for(unsigned retry=0;retry<4;retry++){
        register uint64_t x0 __asm__("x0")=fn,x1 __asm__("x1")=info;
        register uint64_t x2 __asm__("x2")=a,x3 __asm__("x3")=b,x4 __asm__("x4")=c;
        register uint64_t x5 __asm__("x5")=0,x6 __asm__("x6")=0;
        unsigned resumes=0;
        do{
            __asm__ volatile("dsb sy; smc #0; dsb sy"
                : "+r"(x0),"+r"(x1),"+r"(x2),"+r"(x3),"+r"(x4),"+r"(x5),"+r"(x6)
                ::"x7","x8","x9","x10","x11","x12","x13","x14","x15","x16","x17","memory","cc");
        }while(x0==1&&++resumes<1024);
        *answer=x1;
        if((int32_t)x0!=-12)return (int32_t)x0;
        a630_delay_us(opaque,30000);
    }
    return -12;
}
static bool a630_zap_publish(void *opaque)
{return a630_clean_owned(opaque,(void*)(a630_dma+0x40000),PAGE_SIZE);}
static bool a630_zap_segment(void *opaque,const uint8_t *data,uint32_t bytes)
{
    if(!a630_core_owned(opaque)||!a630_zap_saved.region||!data||bytes!=1968)return false;
    /* Exact own DT reserved8KiB; map alignment includes surrounding bytes,
     * but writes/readbacks are confined to the owned first4KiB segment. */
    vm_offset_t map=ml_io_map(0x8c414000,0x4000);
    if(!map)return false;vm_offset_t at=map+0x1000;
    for(unsigned n=0;n<4096;n+=4)
        a630_store32(at+n,n<bytes?a630_image_word(data+n):0);
    __asm__ volatile("dsb sy":::"memory");
    for(unsigned n=0;n<4096;n+=4)
        if(a630_load32(at+n)!=(n<bytes?a630_image_word(data+n):0))return false;
    return true;
}
static void a630_core_attempt(struct a630_io *io)
{
    io->core_lease=true;
    const struct a630_zap_io zap={a630_core_owned,a630_scm_call,a630_zap_publish,a630_zap_segment,io};
    const struct a630_core_io core={a630_core_owned,a630_core_read,a630_core_write,a630_gmu_sync,a630_delay_us,io};
    if(a630_zap_start(true,&zap,a630_images,a630_dma_physical+0x40000,&a630_zap_saved))
        a630_core_run(true,a630_core_dma_ready,true,&core,(uint32_t*)(a630_dma+0x30000),
            (volatile uint32_t*)(a630_dma+0x38000),(volatile uint32_t*)(a630_dma+0x3c000),&a630_core_saved);
    /* After INIT_IMAGE, a failed secure call leaves ownership uncertain.
     * Never remove its powered execution environment or backing allocation. */
    if(!a630_zap_saved.authenticated && (a630_zap_saved.signature||a630_zap_saved.region||
       (a630_zap_saved.error==A630_ZAP_TRANSPORT&&a630_zap_saved.stage>=3)))
        a630_core_saved.keep_live=1;
    io->core_lease=false;
}
/* Synthetic-guest regression for the exact managed-page cache transition
 * used by HFI. No GPU/MMIO is involved, and phone arguments never enable it. */
static void a630_cache_selftest(bool synthetic_guest)
{
    unsigned test=0;PE_parse_boot_argn("polarisgpucachetest",&test,sizeof(test));
    if(!test)return;
    unsigned stage=1,nc=0,restored=0;vm_offset_t memory=0;uint64_t physical=0;
    if(test!=1||!synthetic_guest||PAGE_SIZE!=16384)goto failed;
    if(kmem_alloc_contig(kernel_map,&memory,2*PAGE_SIZE,PAGE_MASK,0,0,
        KMA_DATA|KMA_ZERO|KMA_PERMANENT,VM_KERN_MEMORY_IOKIT)!=KERN_SUCCESS)goto failed;
    for(unsigned n=0;n<2;n++){
        stage=2+n*3;
        vm_offset_t va=memory+n*PAGE_SIZE;
        ppnum_t pn=pmap_find_phys(kernel_pmap,(addr64_t)va);
        uint64_t pa=ptoa_64(pn);if(!n)physical=pa;
        if(!pn||pa<=UINT32_MAX)goto failed;
        unsigned before=pmap_cache_attributes(pn)&VM_WIMG_MASK;
        if(before!=VM_WIMG_DEFAULT)goto failed;
        pmap_set_cache_attributes(pn,VM_WIMG_WCOMB);
        if((pmap_cache_attributes(pn)&VM_WIMG_MASK)!=VM_WIMG_WCOMB)goto failed;
        nc++;stage++;
        volatile uint64_t *first=(volatile uint64_t*)va;
        volatile uint64_t *last=(volatile uint64_t*)(va+PAGE_SIZE-8);
        if(*first||*last)goto failed;
        uint64_t marker=0x6300004000000000ull+n;
        *first=marker;*last=~marker;__asm__ volatile("dsb sy":::"memory");
        if(*first!=marker||*last!=~marker)goto failed;
        stage++;
        pmap_set_cache_attributes(pn,before);
        if((pmap_cache_attributes(pn)&VM_WIMG_MASK)!=before||
           *first!=marker||*last!=~marker)goto failed;
        restored++;
    }
    printf("POLARIS A630 CACHE TEST: PASS physical=%llx high=1 NC=%u restored=%u; RAM only\n",
        (unsigned long long)physical,nc,restored);return;
failed:
    printf("POLARIS A630 CACHE TEST: FAIL stage=%u physical=%llx NC=%u restored=%u; RAM only\n",
        stage,(unsigned long long)physical,nc,restored);
}
static bool a630_resources_can_stop(void *opaque)
{return ((struct a630_io*)opaque)->can_stop;}
static void a630_runtime_boot(struct a630_io *io)
{
    const struct a630_bus_io bus={a630_read_register,a630_write_register,
        a630_delay_us,a630_runtime_held,io};
    const struct a630_smmu_io smmu={a630_runtime_held,a630_smmu_read,a630_smmu_write,
        a630_smmu_read64,a630_smmu_write64,a630_clean_owned,a630_gmu_sync,a630_delay_us};
    const struct a630_boot_io boot={a630_read_register,a630_write_register,a630_delay_us,
        a630_runtime_owned,a630_gmu_sync,io};
    const struct a630_tcm_io tcm={a630_gmu_admitted,a630_gmu_read,a630_gmu_write,a630_gmu_sync};
    const struct a630_channel_io channel={a630_runtime_owned,a630_read_register,
        a630_write_register,a630_gmu_sync,a630_delay_us,io};
    bool bcr_attempted=false,channel_attempted=false,clean=true;
    io->runtime_lease=true;io->can_stop=false;
    printf("POLARIS GMU: original200MHz/bus, owned stream5/HFI; fresh firmware boot trial\n");
    if(a630_bus_begin(true,&bus,&a630_bus_saved)!=A630_BUS_READY)goto cleanup;
    if(a630_smmu_begin_handoff(true,true,&a630_tables,&smmu,io,&a630_smmu_saved)!=A630_SMMU_READY)goto cleanup;
    if(a630_mode>=9 && a630_smmu_begin_core(true,true,&a630_core_tables,&smmu,io,&a630_core_smmu)!=A630_SMMU_READY)goto cleanup;
    if(!a630_clean_owned(io,(void*)(a630_dma+0x20000),A630_HFI_BYTES))goto cleanup;
    bcr_attempted=true;
    if(!a630_boot_set(&boot,&a630_boot_saved,1,0x111c,0,1))goto cleanup;
    /* BCR can reset TCM/control state: assert CM3 reset and reload/read back
     * the original image AFTER deasserting BCR, before executing anything. */
    if(!a630_boot_set(&boot,&a630_boot_saved,2,0x14000,1,UINT32_MAX))goto cleanup;
    if(!a630_boot_configure(&boot,&a630_boot_saved))goto cleanup;
    if(!a630_boot_set(&boot,&a630_boot_saved,2,0x14730,1,UINT32_MAX))goto cleanup;
    if(a630_gmu_prepare(true,true,&a630_gmu_image,&tcm,a630_delay_us,io,&a630_gmu_saved)!=A630_GMU_LOADED)goto cleanup;
    if(a630_boot_start(&boot,&a630_boot_saved) && a630_mode>=7){
        channel_attempted=true;
        a630_channel_probe_complete(true,a630_nc_pages==2,a630_mode>=8,&channel,
            (void*)(a630_dma+0x20000),&a630_channel_saved);
        if(a630_mode>=9 && a630_post_begin(true,&channel,&a630_channel_saved,&a630_post_saved))
            a630_core_attempt(io);
    }
cleanup:
    /* An uncertain CP/rendering engine keeps GMU, both translations and all
     * backing pages LIVE. CM3/BCR reset is not a GPU DMA drain operation. */
    if(a630_core_saved.keep_live){io->can_stop=false;return;}
    if(a630_mode>=9 && (a630_post_saved.dcvs_requested||a630_post_saved.gpu_requested) &&
       !a630_post_end(&channel,&a630_post_saved)){io->can_stop=false;return;}
    if(channel_attempted && !a630_channel_slumber(&channel,&a630_channel_saved)){
        /* Contain CM3, but keep the power sequencer, mappings and clocks
         * intact when GX slumber cannot be proven. No profile teardown. */
        clean=false;
        bool held=a630_boot_set(&boot,&a630_boot_saved,2,0x14000,1,UINT32_MAX);
        held=a630_boot_set(&boot,&a630_boot_saved,1,0x111c,1,1)&&held;
        a630_boot_saved.stopped=held;
    }
    if(clean && bcr_attempted && !a630_boot_stop(&boot,&a630_boot_saved))clean=false;
    if(clean && channel_attempted && !a630_channel_restore(&channel,&a630_channel_saved))clean=false;
    if(clean && a630_mode>=9 && !a630_smmu_end(&smmu,io,&a630_core_smmu))clean=false;
    if(clean && !a630_smmu_end(&smmu,io,&a630_smmu_saved))clean=false;
    if(clean && !a630_bus_end(&bus,&a630_bus_saved))clean=false;
    /* Uncertain containment retains CX/clocks/BCR and permanent DMA pages.
     * No asynchronous client can acquire this exclusive boot-time lease. */
    io->can_stop=clean;
    if(clean)io->runtime_lease=false;
}
static bool a630_gmu_on(void *opaque)
{
    struct a630_io *io = opaque;
    const struct a630_tcm_io tcm = {a630_gmu_admitted, a630_gmu_read,
        a630_gmu_write, a630_gmu_sync};
    io->gmu_lease = true;
    printf("POLARIS GMU: accessing CSR/TCM under block reset; no firmware execution\n");
    a630_gmu_prepare(true, a630_firmware_ok, &a630_gmu_image, &tcm,
        a630_delay_us, io, &a630_gmu_saved);
    if(a630_mode>=6 && a630_dma_ready && a630_gmu_saved.result==A630_GMU_LOADED)
        a630_runtime_boot(io);
    io->gmu_lease = false;
    return !a630_gmu_saved.retain_block_reset;
}
static void a630_clock_on(void *io)
{
    a630_clock_trial_with_lifetime(true, true, a630_read_register, a630_write_register,
        a630_delay_us, io, &a630_clock_saved, a630_mode >= 5 ? a630_gmu_on : NULL, io,
        a630_mode>=6 ? a630_resources_can_stop : NULL);
    if(a630_mode>=6 && (a630_clock_saved.result==A630_CLK_RESTORE_FAILED ||
        a630_clock_saved.resources_retained))((struct a630_io*)io)->can_stop=false;
}
void polaris_a630_report(void)
{
    if (!__atomic_load_n(&a630_published, __ATOMIC_ACQUIRE)) return;
    const struct a630_probe *s = &a630_saved;
    const struct a630_power_snapshot *p = &a630_power_saved;
    const struct a630_clock_snapshot *c = &a630_clock_saved;
    const struct a630_gmu_snapshot *g = &a630_gmu_saved;
    const struct a630_smmu_snapshot *m=&a630_smmu_saved;
    const struct a630_bus_snapshot *b=&a630_bus_saved;
    const struct a630_boot_snapshot *e=&a630_boot_saved;
    printf("D GPU BUS: error=%u stage=%u PLL=%x/%x/%x/%x/%x cfg=%x cmd=%x source=%x fail=%u:%x expected=%x actual=%x restored=%u/%u held=%u/%u\n",
        b->error,b->stage,b->pll[0],b->pll[1],b->pll[2],b->pll[3],b->pll[4],b->config,b->command,b->source,
        b->bank,b->offset,b->expected,b->actual,b->restored,b->restore_error,c->resources_retained,p->resources_retained);
    printf("D GPU SMMU: error=%u stage=%u ID=%x/%x/%x/%x cb=%u stream=%u slot=%u root=%llx fail=%x expected=%x actual=%x restored=%u/%u ATOS=disabled DMA=%u\n",
        m->error,m->stage,m->id[0],m->id[1],m->id[2],m->id[3],m->bank,A630_SMMU_STREAM,m->slot,
        (unsigned long long)m->root,m->failed_offset,m->expected,m->actual,m->restored,m->restore_error,a630_dma_ready);
    printf("D GPU SMMU HALT: before=%x idle=%x after=%x owned=%u polls=%u impl_changed=%x restore=%u offset=%x expected=%x actual=%x\n",
        m->halt_before,m->halt_live,m->halt_after,m->halt_changed,m->halt_polls,m->impl_changed,
        m->restore_error,m->restore_offset,m->restore_expected,m->restore_actual);
    printf("D GPU SMMU HANDOFF: preserve=%u checks=%u ctrl=%x impl6b68=%x ACTLR=%x/%x owned=%u\n",
        m->preserved_impl,m->impl_checks,m->impl[0],m->impl[11],m->actlr,m->actlr_live,m->actlr_changed);
    printf("D GPU SMMU FAULT: quirk=%u canonical=%u requested=%x actual=%x attempts=%u\n",
        m->fault_quirk,m->fault_canonical,m->fault_requested,m->fault_actual,m->fault_attempts);
    printf("D GPU HIDDEN TCS: retained=%x before=%x/%x/%x after=%x/%x/%x attempted=%llx; issued request, not cleared-address proof\n",
        e->retained_hidden,e->hidden_before[0],e->hidden_before[1],e->hidden_before[2],
        e->hidden_after[0],e->hidden_after[1],e->hidden_after[2],(unsigned long long)e->attempted);
    printf("D GPU PDC MSGID: length_read_zero=%x actual=%x/%x/%x/%x/%x/%x; native requests issued, not PDC execution proof\n",
        e->pdc_len_zero,e->pdc_msgid_after[0],e->pdc_msgid_after[1],e->pdc_msgid_after[2],
        e->pdc_msgid_after[3],e->pdc_msgid_after[4],e->pdc_msgid_after[5]);
    printf("D GPU EXEC: error=%u stage=%u FW_INIT=%x started=%u stopped=%u profile=%u fail=%u:%x expected=%x actual=%x polls=%u restored=%u/%u; see HFI result; see CORE; desktop CPU\n",
        e->error,e->stage,e->fw,e->started,e->stopped,e->changed,e->failed_bank,e->failed_offset,e->expected,e->actual,e->polls,e->restored,e->restore_error);
    printf("D GPU EXEC RESTORE: error=%u bank=%u offset=%x expected=%x actual=%x\n",
        e->restore_error,e->restore_bank,e->restore_offset,e->restore_expected,e->restore_actual);
    const struct a630_channel_snapshot *h=&a630_channel_saved;
    printf("D GPU HFI: error=%u stage=%u NC=%u commands=%u ACKs=%u version=%x fail=%x expected=%x actual=%x polls=%u\n",
        h->error,h->stage,a630_nc_pages,h->commands,h->acks,h->version,
        h->failed_offset,h->expected,h->actual,h->polls);
    printf("D GPU HFI QUEUE: cmd=%x/%x rsp=%x/%x IRQ=%x SPTP=%x state=%x async=%u ACK=%x/%x/%x/%x\n",
        h->cmd_read,h->cmd_write,h->rsp_read,h->rsp_write,h->status,h->sp_status,
        h->power_state,h->async_messages,h->response[0],h->response[1],h->response[2],h->response[3]);
    printf("D GPU HFI TABLES: full=%u done=%x slumber_stage=%u RSC=%u/%x/%x; see CORE; desktop CPU\n",
        h->full_requested,h->tables_done,h->slumber_stage,h->rsc_requested,h->rsc_before,h->rsc_status);
    printf("D GPU CORE SMMU: error=%u stage=%u bank=%u slot=%u root=%llx offset=%x expected=%x actual=%x restored=%u/%u roffset=%x rexpected=%x ractual=%x\n",
        a630_core_smmu.error,a630_core_smmu.stage,a630_core_smmu.bank,a630_core_smmu.slot,
        (unsigned long long)a630_core_smmu.root,a630_core_smmu.failed_offset,
        a630_core_smmu.expected,a630_core_smmu.actual,a630_core_smmu.restored,
        a630_core_smmu.restore_error,a630_core_smmu.restore_offset,
        a630_core_smmu.restore_expected,a630_core_smmu.restore_actual);
    printf("D GPU CORE POST: error=%u stage=%u DCVS=%u GPU=%u/%u return=%x offset=%x actual=%x\n",
        a630_post_saved.error,a630_post_saved.stage,a630_post_saved.dcvs_done,a630_post_saved.gpu_ready,
        a630_post_saved.gpu_released,a630_post_saved.dcvs_return,a630_post_saved.offset,a630_post_saved.actual);
    printf("D GPU ZAP: error=%u stage=%u fn=%x transport=%x secure=%x signature=%u region=%u authenticated=%u\n",
        a630_zap_saved.error,a630_zap_saved.stage,a630_zap_saved.fn,a630_zap_saved.transport,
        a630_zap_saved.secure,a630_zap_saved.signature,a630_zap_saved.region,a630_zap_saved.authenticated);
    printf("D GPU CORE: error=%u stage=%u CB0=%u/%u init=%u secure=%u fence=%x image=%u pixels=%u halted=%u live=%u RPTR=%x/%x IRQ=%x fault=%x protect=%x fail=%x expected=%x actual=%x\n",
        a630_core_saved.error,a630_core_saved.stage,a630_core_smmu.error,a630_core_smmu.stage,
        a630_core_saved.init_done,a630_core_saved.secure_done,a630_core_saved.fence,
        a630_core_saved.image,a630_core_saved.pixels,a630_core_saved.halted,a630_core_saved.keep_live,
        a630_core_saved.rptr,a630_core_saved.wptr,a630_core_saved.irq,a630_core_saved.hw_fault,
        a630_core_saved.protect,a630_core_saved.offset,a630_core_saved.expected,a630_core_saved.actual);
    printf("D GPU HFI STOP: GX=%u SPTP=%u HFI=%u slumber=%u restored=%u error=%u offset=%x expected=%x actual=%x; see CORE; desktop CPU\n",
        h->gx_requested,h->sptp_requested,h->hfi_requested,h->slumber,h->restored,
        h->restore_error,h->restore_offset,h->restore_expected,h->restore_actual);
    printf("D GPU LOAD: result=%u stage=%u block_reset_retained=%u reset=%x/%x fw=%x hfi=%x counter=%x polls=%u\n",
        g->result, g->stage, g->retain_block_reset, g->reset_before, g->reset_held,
        g->fw_init, g->hfi, g->counter, g->polls);
    printf("D GPU TCM: result=%u phase=%u offset=%x expected=%x actual=%x reads=%u writes=%u barriers=%u\n",
        g->tcm.result, g->tcm.phase, g->tcm.offset, g->tcm.expected, g->tcm.actual,
        g->tcm.reads, g->tcm.writes, g->tcm.barriers);
    printf("D GPU CLOCK: result=%u reads=%u writes=%u step=%u changed=%x restored=%u polls=%u rcg=%x/%x live=%x/%x/%x/%x reset=%x/%x/%x\n",
        c->result, c->reads, c->writes, c->step, c->changed, c->restored, c->polls,
        c->before[2], c->config, c->live[0], c->live[1], c->live[2], c->live[3],
        c->before[4], c->live[4], c->after[4]);
    printf("D GPU CLOCK FAIL: step=%u op=%u offset=%x expected=%x actual=%x mask=%x ack_polls=%u\n",
        c->failed_step, c->failed_op, c->failed_offset, c->failed_expected,
        c->failed_value, c->failed_mask, c->request_polls);
    printf("D GPU AON: readonly=%x/%x/%x; required=CXO,GMU_ROOT,CX_GMU\n",
        c->before[0], c->live[0], c->after[0]);
    printf("D GPU POWER: result=%u reads=%u writes=%u changed=%u restored=%u polls=%u req=%x/%x hw=%x/%x/%x\n",
        p->result, p->reads, p->writes, p->changed, p->request_restored, p->polls,
        p->before, p->after, p->before_hw, p->on_hw, p->after_hw);
    printf("D GPU: fw=%u abi=%u result=%u reads=%u cfg=%x mem=%x snoc=%x\n",
        a630_firmware_ok, a630_abi_ok, s->result, s->reads, s->gcc[0], s->gcc[1], s->gcc[2]);
    printf("D GMU: cx=%x hw=%x gx=%x clocks=%x/%x/%x init=%x counter=%x:%x\n",
        s->cx, s->cx_hw, s->gx, s->clocks[0], s->clocks[1], s->clocks[2],
        s->fw_init, s->counter_high, s->counter_low);
}
void polaris_a630_init(void)
{
    unsigned mode = 0;
    PE_parse_boot_argn("polarisgpu", &mode, sizeof(mode));
    if ((mode < 1 || mode > 9) ||
        __atomic_exchange_n(&a630_started, 1, __ATOMIC_ACQ_REL)) return;
    a630_mode = mode;
    DTEntry node;
    bool board = SecureDTLookupEntry(NULL, "/polaris-a630-firmware", &node) == kSuccess &&
        (a630_u32(node,"version",3) || a630_u32(node,"version",4) || (mode<6 && a630_u32(node,"version",2))) &&
        a630_u32(node, "chip-id", 0x06030001) &&
        a630_u32(node, "sqe-code-offset", 4) &&
        a630_reg(node, "gcc-reg", 0x100000, 0x90000) &&
        a630_reg(node, "gpucc-reg", 0x5090000, 0x9000) &&
        a630_reg(node, "gmu-reg", 0x506a000, 0x30000) &&
        a630_reg(node, "smmu-reg", 0x5040000, 0x10000);
    if(mode>=6)board=board && a630_reg(node,"pdc-reg",0xb200000,0x300000) &&
        a630_u32(node,"smmu-disable-atos",1) && a630_u32(node,"smmu-iommu-cells",1) &&
        a630_u32(node,"smmu-stream-id",5) && a630_u32(node,"gmu-hz",200000000);
    if(mode>=9)board=board && a630_u32(node,"version",4) &&
        a630_reg(node,"core-reg",0x5000000,0x40000) && a630_reg(node,"zap-reg",0x8c415000,0x2000) &&
        a630_u32(node,"core-smmu-stream-id",0) && a630_u32(node,"core-gmem-bytes",0x100000);
    a630_firmware_ok = board && a630_firmware(node);
    if (a630_firmware_ok)
        a630_abi_ok = a630_hfi_init(a630_host_hfi, sizeof(a630_host_hfi), 0x60000000);
    DTEntry gic;
    const void *reg = NULL; unsigned bytes = 0; uint64_t physical[4] = {0};
    bool hardware = SecureDTLookupEntry(NULL, "/arm-io/gic", &gic) == kSuccess &&
        a630_property(gic, "reg", &reg, &bytes) && bytes == sizeof(physical);
    if (hardware) memcpy(physical, reg, sizeof(physical));
    a630_cache_selftest(hardware && a630_firmware_ok && mode>=7 &&
        physical[0]==0x7000000 && physical[1]==0x10000 &&
        physical[2]==0x70a0000 && physical[3]==17*0x20000);
    hardware = hardware && physical[0] == 0x16a00000 && physical[1] == 0x10000 &&
        physical[2] == 0x16a60000 && physical[3] == 0x100000;
    struct a630_io io = {.can_stop=true};
    bool admitted = board && hardware && a630_firmware_ok && a630_abi_ok;
    if(mode>=6 && admitted)admitted=a630_prepare_dma();
    /* Mode1 checks firmware/host ABI only, including in a synthetic guest.
     * Modes2/3/4 first save the same read-only, initial hardware snapshot. */
    a630_probe((mode >= 2 && mode <= 9) ? 1 : 0, admitted,
        a630_read_register, &io, &a630_saved);
    /* Nested exclusive lifetime: mode5 only loads under reset; mode6 may
     * execute GMU firmware, then must contain it before removing mappings,
     * buses, clocks or CX. No GMU reads after clock/CX cleanup. */
    a630_power_trial_with_lifetime(mode >= 3 && a630_saved.result != A630_IO,
        admitted, a630_read_register, a630_write_register, a630_delay_us, &io,
        &a630_power_saved, mode >= 4 ? a630_clock_on : NULL, &io,
        mode>=6 ? a630_resources_can_stop : NULL);
    if (a630_power_saved.result == A630_POWER_IO ||
        a630_power_saved.result == A630_POWER_RESTORE_FAILED ||
        a630_clock_saved.result == A630_CLK_IO ||
        a630_clock_saved.result == A630_CLK_RESTORE_FAILED)
        a630_saved.result = A630_IO;
    __atomic_store_n(&a630_published, 1, __ATOMIC_RELEASE);
    polaris_a630_report();
}
#endif
