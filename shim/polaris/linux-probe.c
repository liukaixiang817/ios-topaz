/* Put raw entry registers into a preallocated FDT property, then boot Linux.
 * This changes only the in-RAM tree. Linux exposes it over the root ADB
 * recovery at /sys/firmware/devicetree/base/chosen/polaris,boot-registers.
 */
#include "dt.h"
#define RSR(r) ({ uint64_t v; __asm__ volatile("mrs %0, " #r : "=r"(v)); v; })

static void put64(uint8_t *p, uint64_t v)
{
    for (unsigned i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}

#ifdef POLARIS_UFS_SNAPSHOT
/* UFSHCI read-only registers only: no UIC/SCSI command, doorbell, reset,
 * interrupt acknowledgement or DMA setup. Match the verified SDM845 FDT. */
static void ufs_snapshot(uint64_t address)
{
    const char magic[16] = "POLARISUFS1";
    const uint8_t expected_reg[8] = {1, 0xd8, 0x40, 0, 0, 0, 0x25, 0};
    const uint32_t offsets[12] = {0, 8, 0x30, 0x34, 0x20, 0x24,
                                  0x50, 0x54, 0x58, 0x60, 0x78, 0x80};
    uint32_t size = 0;
    uint8_t *p = (uint8_t *)polaris_dt_prop((void *)address, 2 * 1024 * 1024,
                                         "/chosen", "polaris,ufs-handoff", &size);
    if (!p || size != 128) return;
    for (unsigned i = 0; i < 16; i++) if (p[i] != (uint8_t)magic[i]) return;
    const uint8_t *reg = polaris_dt_prop((void *)address, 2 * 1024 * 1024,
                                        "/soc/ufshc@1d84000", "reg", &size);
    if (!reg || size != sizeof(expected_reg)) return;
    for (unsigned i = 0; i < size; i++) if (reg[i] != expected_reg[i]) return;
    put64(p + 24, 0x1d84000);
    for (unsigned i = 0; i < 12; i++) {
        uint32_t value = *(const volatile uint32_t *)(0x1d84000UL + offsets[i]);
        put64(p + 32 + i * 8, ((uint64_t)value << 32) | offsets[i]);
    }
    __asm__ volatile("dsb sy" ::: "memory");
    put64(p + 16, 1);
}
#endif

void linux_probe_record(uint64_t address)
{
    const char magic[16] = "POLARISREGS1";
    uint32_t size = 0;
    if (!address || (address & 7)) return;
    /* ABL must enter Linux with translation/data cache disabled. Refuse
     * instrumentation on unsupported entry, but still resume the kernel. */
    uint64_t el = RSR(CurrentEL);
    if (el != 4 && el != 8) return;
    if ((el == 4 ? RSR(sctlr_el1) : RSR(sctlr_el2)) & 5) return;
    if (!polaris_dt_matches((void *)address, 2 * 1024 * 1024)) return;
    uint8_t *p = (uint8_t *)polaris_dt_prop((void *)address, 2 * 1024 * 1024,
                                         "/chosen", "polaris,boot-registers", &size);
    if (!p || size != 112) return;
    for (unsigned i = 0; i < 16; i++) if (p[i] != (uint8_t)magic[i]) return;
    put64(p + 24, el);
    put64(p + 32, RSR(midr_el1));
    put64(p + 40, RSR(mpidr_el1));
    put64(p + 48, RSR(id_aa64mmfr0_el1));
    put64(p + 56, RSR(id_aa64mmfr1_el1));
    put64(p + 64, RSR(id_aa64pfr0_el1));
    put64(p + 72, RSR(sctlr_el1));
    put64(p + 80, RSR(cntfrq_el0));
    put64(p + 88, RSR(cntvct_el0));
    put64(p + 96, address);
    put64(p + 104, RSR(daif));
    __asm__ volatile("dsb sy" ::: "memory");
    put64(p + 16, 1); /* Completion marker, written last. */
    __asm__ volatile("dsb sy" ::: "memory");
#ifdef POLARIS_UFS_SNAPSHOT
    ufs_snapshot(address);
#endif
}
