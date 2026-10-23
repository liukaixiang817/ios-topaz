/* Separate from diagnostic0001: bounded XNU RAM handoff, no disk driver. */
#include "../console.h"
#include "../loader.h"
#include "dt.h"

#define RSR(r) ({ uint64_t v; __asm__ volatile("mrs %0, " #r : "=r"(v)); v; })
static int console_ready;
static void park(void) { for (;;) __asm__ volatile("wfe"); }
void secondary_main(uint64_t unused) { (void)unused; park(); }
void exc_handler(uint64_t slot, uint64_t *regs)
{
    (void)regs;
    if (console_ready) {
        con_str("POLARIS", "loader exception");
        con_hex("SLOT", slot); con_hex("ESR", RSR(esr_el1));
        con_hex("ELR", RSR(elr_el1)); con_hex("FAR", RSR(far_el1));
    }
    park();
}
void shim_main(uint64_t dtb)
{
    if ((dtb & 3) || !polaris_dt_matches((const void *)dtb, 2 * 1024 * 1024)) park();
    if (RSR(CurrentEL) != 4 || (RSR(sctlr_el1) & 5)) park();
    console_ready = 1;
    con_clear(0xff10243a);
    con_str("POLARIS", "XNU RAM loader 0001");
    con_str("STORAGE", "no disk driver linked in loader");
    con_hex("MIDR", RSR(midr_el1)); con_hex("MPIDR", RSR(mpidr_el1));
    con_hex("MMFR0", RSR(id_aa64mmfr0_el1));
    if (((RSR(id_aa64mmfr0_el1) >> 20) & 15) != 1 ||
        (RSR(mpidr_el1) & 0xffffff)) {
        con_str("REFUSED", "requires CPU0 and 16K granule");
        park();
    }
    con_str("STOP", loader_boot(dtb));
    park();
}
