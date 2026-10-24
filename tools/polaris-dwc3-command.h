/* DWC3 endpoint commands for the admitted, high-speed Polaris gadget.
 * DWC_usb3 3.30a (the phone reports 0x5533300a) needs both low-power controls
 * clear for HS endpoint commands. Checked against Linux v6.12 gadget.c.
 * The caller serializes commands and provides its existing MMIO barriers.
 */
#ifndef POLARIS_DWC3_COMMAND_H
#define POLARIS_DWC3_COMMAND_H
#include <stdint.h>
#define PDWC3_PHYCFG 0xc200u
#define PDWC3_SUSPHY (1u << 6)
#define PDWC3_ENBLSLPM (1u << 8)
#define PDWC3_LOW_POWER (PDWC3_SUSPHY | PDWC3_ENBLSLPM)
#define PDWC3_CMDACT (1u << 10)
#define PDWC3_COMMAND_POLLS 1000u
enum pdwc3_error { PDWC3_OK, PDWC3_STATUS, PDWC3_TIMEOUT, PDWC3_ARGUMENT };
struct pdwc3_result {
    uint32_t ep, command, response, phy_before, phy_after, polls, error;
};
struct pdwc3_io {
    void *ctx;
    uint32_t (*read)(void *, uint32_t);
    void (*write)(void *, uint32_t, uint32_t);
    void (*wait_us)(void *, uint32_t);
};
static inline enum pdwc3_error
polaris_dwc3_command(const struct pdwc3_io *io, unsigned ep, uint32_t command,
    uint32_t p0, uint32_t p1, uint32_t p2, struct pdwc3_result *s)
{
    if (!s) return PDWC3_ARGUMENT;
    *s = (struct pdwc3_result){.ep=ep,.command=command,.error=PDWC3_ARGUMENT};
    if (!io || !io->read || !io->write || !io->wait_us || ep >= 32 ||
        !(command & 15u) || (command & PDWC3_CMDACT)) return PDWC3_ARGUMENT;
    uint32_t base = 0xc800u + ep * 16u;
    s->phy_before = io->read(io->ctx, PDWC3_PHYCFG);
    uint32_t saved = s->phy_before & PDWC3_LOW_POWER;
    if (saved)
        io->write(io->ctx, PDWC3_PHYCFG, s->phy_before & ~PDWC3_LOW_POWER);
    io->write(io->ctx, base + 8, p0);
    io->write(io->ctx, base + 4, p1);
    io->write(io->ctx, base, p2);
    io->write(io->ctx, base + 12, command | PDWC3_CMDACT);
    s->error = PDWC3_TIMEOUT;
    for (unsigned i = 0; i < PDWC3_COMMAND_POLLS; i++) {
        s->response = io->read(io->ctx, base + 12);
        s->polls++;
        if (!(s->response & PDWC3_CMDACT)) {
            s->error = ((s->response >> 12) & 15u) ? PDWC3_STATUS : PDWC3_OK;
            break;
        }
        io->wait_us(io->ctx, 1);
    }
    /* Restore our two controls on every path, preserving unrelated bits. */
    s->phy_after = io->read(io->ctx, PDWC3_PHYCFG);
    if (saved) {
        s->phy_after = (s->phy_after & ~PDWC3_LOW_POWER) | saved;
        io->write(io->ctx, PDWC3_PHYCFG, s->phy_after);
    }
    return (enum pdwc3_error)s->error;
}
#endif
