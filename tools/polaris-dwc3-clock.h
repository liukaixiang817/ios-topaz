/* Polaris live DT requests snps,disable-clk-gating. Original MiCode
 * c7cb50c1 core.c sets GCTL.DSBLCLKGTNG for the internal-RAM clock erratum.
 * The admitted caller owns controller startup and supplies MMIO barriers.
 * Keep the request on for a working gadget. Undo only our newly set bit,
 * on a halted controller with no outstanding endpoint command.
 */
#ifndef POLARIS_DWC3_CLOCK_H
#define POLARIS_DWC3_CLOCK_H
#ifndef POLARIS_DWC3_COMMAND_H
#error Include Polaris DWC3 command definitions first
#endif
#include <stdbool.h>

#define PDWC3_GATE_GCTL 0xc110u
#define PDWC3_GATE_DCTL 0xc704u
#define PDWC3_GATE_DSTS 0xc70cu
#define PDWC3_GATE_DISABLE 1u
#define PDWC3_GATE_POLLS 1000u
enum pdwc3_gate_error {
    PDWC3_GATE_OK, PDWC3_GATE_ARGUMENT, PDWC3_GATE_UNSAFE,
    PDWC3_GATE_ACK_TIMEOUT, PDWC3_GATE_RESTORE_TIMEOUT, PDWC3_GATE_COMMAND_ACTIVE
};
struct pdwc3_gate {
    uint32_t error, start_error, attempted, changed, restored;
    uint32_t before, live, after, dctl, dsts, busy_ep, busy_command;
    uint32_t reads, writes, polls, restore_polls;
};

static inline uint32_t pdwc3_gate_read(const struct pdwc3_io *io,
                                     struct pdwc3_gate *s, uint32_t off)
{
    s->reads++;
    return io->read(io->ctx, off);
}
static inline bool pdwc3_gate_halted(const struct pdwc3_io *io, struct pdwc3_gate *s)
{
    s->dctl = pdwc3_gate_read(io, s, PDWC3_GATE_DCTL);
    s->dsts = pdwc3_gate_read(io, s, PDWC3_GATE_DSTS);
    return !(s->dctl & ((1u << 31) | (1u << 30))) && (s->dsts & (1u << 22));
}
static inline bool pdwc3_gate_device(uint32_t gctl)
{
    return ((gctl >> 12) & 3u) == 2 && !(gctl & (1u << 11));
}
static inline enum pdwc3_gate_error
polaris_dwc3_clock_begin(const struct pdwc3_io *io, bool admitted, struct pdwc3_gate *s)
{
    if (!s) return PDWC3_GATE_ARGUMENT;
    *s = (struct pdwc3_gate){.error=PDWC3_GATE_ARGUMENT,
        .start_error=PDWC3_GATE_ARGUMENT, .busy_ep=UINT32_MAX};
    if (!io || !io->read || !io->write || !io->wait_us) return PDWC3_GATE_ARGUMENT;
    s->start_error = PDWC3_GATE_OK;
    if (!admitted) { s->error = s->start_error = PDWC3_GATE_UNSAFE; return PDWC3_GATE_UNSAFE; }
    s->attempted = 1;
    if (!pdwc3_gate_halted(io, s)) { s->error = s->start_error = PDWC3_GATE_UNSAFE; return PDWC3_GATE_UNSAFE; }
    s->before = pdwc3_gate_read(io, s, PDWC3_GATE_GCTL);
    if (!pdwc3_gate_device(s->before)) { s->error = s->start_error = PDWC3_GATE_UNSAFE; return PDWC3_GATE_UNSAFE; }
    s->changed = !(s->before & PDWC3_GATE_DISABLE);
    if (s->changed) {
        s->writes++;
        io->write(io->ctx, PDWC3_GATE_GCTL, s->before | PDWC3_GATE_DISABLE);
    }
    for (unsigned i = 0; i < PDWC3_GATE_POLLS; i++) {
        s->polls++;
        s->live = pdwc3_gate_read(io, s, PDWC3_GATE_GCTL);
        s->after = s->live;
        if (!pdwc3_gate_device(s->live)) {
            s->error = s->start_error = PDWC3_GATE_UNSAFE; return PDWC3_GATE_UNSAFE;
        }
        if (s->live & PDWC3_GATE_DISABLE) { s->error = PDWC3_GATE_OK; return PDWC3_GATE_OK; }
        io->wait_us(io->ctx, 1);
    }
    s->error = s->start_error = PDWC3_GATE_ACK_TIMEOUT; return PDWC3_GATE_ACK_TIMEOUT;
}

static inline enum pdwc3_gate_error
polaris_dwc3_clock_restore(const struct pdwc3_io *io, struct pdwc3_gate *s)
{
    if (!s || !io || !io->read || !io->write || !io->wait_us) return PDWC3_GATE_ARGUMENT;
    s->restored = s->restore_polls = 0;
    s->busy_ep = UINT32_MAX; s->busy_command = 0;
    if (!s->attempted || !pdwc3_gate_halted(io, s)) {
        s->error = PDWC3_GATE_UNSAFE; return PDWC3_GATE_UNSAFE;
    }
    uint32_t current = pdwc3_gate_read(io, s, PDWC3_GATE_GCTL);
    s->after = current;
    if (!pdwc3_gate_device(current)) { s->error = PDWC3_GATE_UNSAFE; return PDWC3_GATE_UNSAFE; }
    if (!s->changed) { s->restored = 1; s->error = s->start_error; return PDWC3_GATE_OK; }
    /* All used physical endpoints0..5 are halted before startup rollback.
     * Never re-enable gating underneath a timed-out active command. Keep
     * the owned request and report retention rather than false cleanup. */
    for (unsigned ep = 0; ep < 6; ep++) {
        uint32_t command = pdwc3_gate_read(io, s, 0xc80cu + 16u * ep);
        if (command & PDWC3_CMDACT) {
            s->busy_ep = ep; s->busy_command = command;
            s->error = PDWC3_GATE_COMMAND_ACTIVE; return PDWC3_GATE_COMMAND_ACTIVE;
        }
    }
    s->writes++;
    io->write(io->ctx, PDWC3_GATE_GCTL, current & ~PDWC3_GATE_DISABLE);
    for (unsigned i = 0; i < PDWC3_GATE_POLLS; i++) {
        s->restore_polls++;
        s->after = pdwc3_gate_read(io, s, PDWC3_GATE_GCTL);
        if (!pdwc3_gate_device(s->after)) { s->error = PDWC3_GATE_UNSAFE; return PDWC3_GATE_UNSAFE; }
        if (!(s->after & PDWC3_GATE_DISABLE)) {
            s->restored = 1; s->error = s->start_error; return PDWC3_GATE_OK;
        }
        io->wait_us(io->ctx, 1);
    }
    s->error = PDWC3_GATE_RESTORE_TIMEOUT; return PDWC3_GATE_RESTORE_TIMEOUT;
}
#endif
