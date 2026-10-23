/*
 * MIX 2S first-stage diagnostic. No UFS, SCSI, loader, power-controller or
 * persistent-log code is linked. It only reads CPU registers/FDT and draws
 * into the firmware's framebuffer, then parks with interrupts masked.
 *
 * Framebuffer parameters are corroborated by edk2-porting/edk2-msm commit
 * e1952621f419f8db60ed28271264e1b5184c571d: polaris.dsc, sdm845.dsc and
 * SimpleFbDxe.c. Actual ABL scanout still requires a hardware observation.
 */
#include "../console.h"
#include "dt.h"

#define RSR(r) ({ uint64_t v; __asm__ volatile("mrs %0, " #r : "=r"(v)); v; })
static int console_ready;

static void park(void)
{
    for (;;) __asm__ volatile("wfe");
}

void secondary_main(uint64_t unused)
{
    (void)unused;
    park();
}

void exc_handler(uint64_t slot, uint64_t *regs)
{
    if (console_ready) {
        con_clear(BLUE);
        con_str("POLARIS", "diagnostic exception");
        con_hex("SLOT", slot);
        con_hex("ESR", RSR(esr_el1));
        con_hex("ELR", RSR(elr_el1));
        con_hex("FAR", RSR(far_el1));
        con_hex("X0", regs[0]);
    }
    park();
}

void shim_main(uint64_t dtb)
{
    /* Refuse all framebuffer writes if the supplied tree does not identify
     * this board and the independently verified splash reservation. */
    if ((dtb & 3) || !polaris_dt_matches((const void *)dtb, 2 * 1024 * 1024)) park();
    if (RSR(sctlr_el1) & 1) park(); /* entry with MMU on is unsupported */
    console_ready = 1;
    con_clear(0xff10243a);
    con_str("POLARIS", "MIX 2S boot diagnostic 0001");
    con_str("STORAGE", "no disk driver linked");
    con_hex("DTB", dtb);
    con_hex("EL", RSR(CurrentEL));
    con_hex("MIDR", RSR(midr_el1));
    con_hex("MPIDR", RSR(mpidr_el1));
    con_hex("MMFR0", RSR(id_aa64mmfr0_el1));
    con_hex("MMFR1", RSR(id_aa64mmfr1_el1));
    con_hex("PFR0", RSR(id_aa64pfr0_el1));
    con_hex("SCTLR", RSR(sctlr_el1));
    con_hex("CNTFRQ", RSR(cntfrq_el0));
    con_hex("CNTVCT", RSR(cntvct_el0));
    con_skip();
    con_str("STATE", "parked; hold Power to restart");
    park();
}
