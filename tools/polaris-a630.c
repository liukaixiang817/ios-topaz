/* Original Polaris A630 firmware consumer and guarded hardware bring-up.
 * Mode3 briefly owns the CX request; mode4 also tests parked-CXO GMU clocks
 * under block reset. Neither executes firmware nor registers acceleration.
 */
#if defined(POLARIS_RAM_ONLY)
#include <sys/param.h>
#include <sys/systm.h>
#include <mach/mach_types.h>
#include <pexpert/pexpert.h>
#include <pexpert/device_tree.h>
#include <kern/clock.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha2.h>
#include "polaris_a630_probe.h"
#include "polaris_a630_power.h"
#include "polaris_a630_clock.h"
#include "polaris_a630_hfi.h"
#include "polaris_a630_images.h"
extern vm_offset_t ml_io_map(vm_offset_t, vm_size_t);
void polaris_a630_init(void);
void polaris_a630_report(void);
uint32_t polaris_a630_status(void);
uint32_t polaris_a630_details(char *, uint32_t);
uint32_t polaris_a630_diagnostic_line(unsigned, char *, uint32_t);
static struct a630_probe a630_saved;
static struct a630_power_snapshot a630_power_saved;
static struct a630_clock_snapshot a630_clock_saved;
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
    if (a630_mode == 4)
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
    if (line >= 2) return 0;
    if (!__atomic_load_n(&a630_published, __ATOMIC_ACQUIRE))
        return (uint32_t)snprintf(out, size, "GPU snapshot pending");
    const struct a630_power_snapshot *p = &a630_power_saved;
    const struct a630_clock_snapshot *c = &a630_clock_saved;
    if (!line) return (uint32_t)snprintf(out, size,
        "GP rq%08x/%08x hw%08x/%08x/%08x",
        p->before, p->after, p->before_hw, p->on_hw, p->after_hw);
    return (uint32_t)snprintf(out, size, "GC rs%08x/%08x/%08x r%08x m%08x",
        c->before[4], c->live[4], c->after[4], c->live[2], c->live[3]);
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
    printf("POLARIS A630: verified original GMU%u SQE%u version=%x ZAP%u; no firmware executed\n",
        gn, sn, a630_image_word(sqe + 4), mn);
    return true;
}
struct a630_io { vm_offset_t base[3]; };
static bool a630_read_register(void *opaque, unsigned region, uint32_t off, uint32_t *value)
{
    static const uint64_t addresses[3] = {0x100000, 0x5090000, 0x506a000};
    static const uint32_t sizes[3] = {0x90000, 0x9000, 0x30000};
    struct a630_io *io = opaque;
    if (region >= 3 || (off & 3) || off > sizes[region] - 4) return false;
    if (!io->base[region]) io->base[region] = ml_io_map(addresses[region], sizes[region]);
    if (!io->base[region]) return false;
    *value = *(volatile uint32_t *)(io->base[region] + off);
    __asm__ volatile("dsb sy" ::: "memory");
    return true;
}
static bool a630_write_register(void *opaque, unsigned region, uint32_t off, uint32_t value)
{
    struct a630_io *io = opaque;
    /* Exact GPUCC request/clock/reset allowlist; no GMU CSR write. */
    if (region != 1 || !io->base[1] ||
        (off != A630_CX_REQUEST && off != 0x109c &&
         off != 0x1120 && off != 0x1098 && off != 0x111c)) return false;
    *(volatile uint32_t *)(io->base[1] + off) = value;
    __asm__ volatile("dsb sy" ::: "memory");
    return true;
}
static void a630_delay_us(void *opaque __unused, uint32_t us) { delay(us); }
static void a630_clock_on(void *io)
{
    a630_clock_trial(true, true, a630_read_register, a630_write_register,
        a630_delay_us, io, &a630_clock_saved);
}
void polaris_a630_report(void)
{
    if (!__atomic_load_n(&a630_published, __ATOMIC_ACQUIRE)) return;
    const struct a630_probe *s = &a630_saved;
    const struct a630_power_snapshot *p = &a630_power_saved;
    const struct a630_clock_snapshot *c = &a630_clock_saved;
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
    if ((mode != 1 && mode != 2 && mode != 3 && mode != 4) ||
        __atomic_exchange_n(&a630_started, 1, __ATOMIC_ACQ_REL)) return;
    a630_mode = mode;
    DTEntry node;
    bool board = SecureDTLookupEntry(NULL, "/polaris-a630-firmware", &node) == kSuccess &&
        a630_u32(node, "version", 2) && a630_u32(node, "chip-id", 0x06030001) &&
        a630_u32(node, "sqe-code-offset", 4) &&
        a630_reg(node, "gcc-reg", 0x100000, 0x90000) &&
        a630_reg(node, "gpucc-reg", 0x5090000, 0x9000) &&
        a630_reg(node, "gmu-reg", 0x506a000, 0x30000) &&
        a630_reg(node, "smmu-reg", 0x5040000, 0x10000);
    a630_firmware_ok = board && a630_firmware(node);
    if (a630_firmware_ok)
        a630_abi_ok = a630_hfi_init(a630_host_hfi, sizeof(a630_host_hfi), 0x60000000);
    DTEntry gic;
    const void *reg = NULL; unsigned bytes = 0; uint64_t physical[4] = {0};
    bool hardware = SecureDTLookupEntry(NULL, "/arm-io/gic", &gic) == kSuccess &&
        a630_property(gic, "reg", &reg, &bytes) && bytes == sizeof(physical);
    if (hardware) memcpy(physical, reg, sizeof(physical));
    hardware = hardware && physical[0] == 0x16a00000 && physical[1] == 0x10000 &&
        physical[2] == 0x16a60000 && physical[3] == 0x100000;
    struct a630_io io = {{0, 0, 0}};
    bool admitted = board && hardware && a630_firmware_ok && a630_abi_ok;
    /* Mode1 checks firmware/host ABI only, including in a synthetic guest.
     * Modes2/3/4 first save the same read-only, initial hardware snapshot. */
    a630_probe((mode >= 2 && mode <= 4) ? 1 : 0, admitted,
        a630_read_register, &io, &a630_saved);
    /* Clock/reset trial is nested inside our observed CX-ON interval. No
     * GMU register/firmware/SMMU access, and no reads after CX cleanup. */
    a630_power_trial_with_hook((mode == 3 || mode == 4) && a630_saved.result != A630_IO,
        admitted, a630_read_register, a630_write_register, a630_delay_us, &io,
        &a630_power_saved, mode == 4 ? a630_clock_on : NULL, &io);
    if (a630_power_saved.result == A630_POWER_IO ||
        a630_power_saved.result == A630_POWER_RESTORE_FAILED ||
        a630_clock_saved.result == A630_CLK_IO ||
        a630_clock_saved.result == A630_CLK_RESTORE_FAILED)
        a630_saved.result = A630_IO;
    __atomic_store_n(&a630_published, 1, __ATOMIC_RELEASE);
    polaris_a630_report();
}
#endif
