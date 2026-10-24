/* Polaris HS session setup, before EP0 commands. Original dwc3-msm.c sets
 * UTMI_OTG_VBUS_VALID/SW_SESSVLD_SEL before starting peripheral mode.
 * Only these two HS request bits are owned; an HS gadget never writes SS.
 * The caller proves the controller halted before rolling requests back.
 */
#ifndef POLARIS_DWC3_SESSION_H
#define POLARIS_DWC3_SESSION_H
#include <stdbool.h>
#ifndef POLARIS_DWC3_COMMAND_H
#error Include the Polaris DWC3 command definitions first
#endif
#define PDWC3_HS_PHY_CTRL 0x10u
#define PDWC3_SESSION_MASK ((1u << 20) | (1u << 28))
enum pdwc3_session_error {
    PDWC3_SESSION_OK, PDWC3_SESSION_ARGUMENT, PDWC3_SESSION_TIMEOUT,
    PDWC3_SESSION_RESTORE_TIMEOUT, PDWC3_SESSION_NOT_HALTED
};
struct pdwc3_session {
    uint32_t error, start_error, before, live, after, changed, restored, polls, restore_polls;
};
static inline bool pdwc3_session_valid(const struct pdwc3_io *io)
{ return io && io->read && io->write && io->wait_us; }
static inline enum pdwc3_session_error polaris_dwc3_session_begin(
    const struct pdwc3_io *io, struct pdwc3_session *s)
{
    if (!s) return PDWC3_SESSION_ARGUMENT;
    *s = (struct pdwc3_session){.error=PDWC3_SESSION_ARGUMENT,
        .start_error=PDWC3_SESSION_ARGUMENT};
    if (!pdwc3_session_valid(io)) return PDWC3_SESSION_ARGUMENT;
    s->before = io->read(io->ctx, PDWC3_HS_PHY_CTRL);
    s->changed = ~s->before & PDWC3_SESSION_MASK;
    if (s->changed) io->write(io->ctx, PDWC3_HS_PHY_CTRL, s->before | s->changed);
    s->error = PDWC3_SESSION_TIMEOUT;
    for (unsigned i = 0; i < PDWC3_COMMAND_POLLS; i++) {
        s->polls++;
        s->live = io->read(io->ctx, PDWC3_HS_PHY_CTRL);
        if ((s->live & PDWC3_SESSION_MASK) == PDWC3_SESSION_MASK) {
            s->error = PDWC3_SESSION_OK; break;
        }
        io->wait_us(io->ctx, 1);
    }
    s->start_error = s->error;
    return (enum pdwc3_session_error)s->error;
}
static inline enum pdwc3_session_error polaris_dwc3_session_restore(
    const struct pdwc3_io *io, struct pdwc3_session *s, bool halted)
{
    if (!s) return PDWC3_SESSION_ARGUMENT;
    s->restored = 0; s->restore_polls = 0;
    if (!pdwc3_session_valid(io)) {
        s->error = PDWC3_SESSION_ARGUMENT; return PDWC3_SESSION_ARGUMENT;
    }
    if (!halted) {
        s->error = PDWC3_SESSION_NOT_HALTED; return PDWC3_SESSION_NOT_HALTED;
    }
    s->after = io->read(io->ctx, PDWC3_HS_PHY_CTRL);
    if (s->changed) {
        uint32_t target = (s->after & ~s->changed) | (s->before & s->changed);
        io->write(io->ctx, PDWC3_HS_PHY_CTRL, target);
        for (unsigned i = 0; i < PDWC3_COMMAND_POLLS; i++) {
            s->restore_polls++;
            s->after = io->read(io->ctx, PDWC3_HS_PHY_CTRL);
            if (!((s->after ^ s->before) & s->changed)) {
                s->restored = 1; return PDWC3_SESSION_OK;
            }
            io->wait_us(io->ctx, 1);
        }
        s->error = PDWC3_SESSION_RESTORE_TIMEOUT;
        return PDWC3_SESSION_RESTORE_TIMEOUT;
    }
    s->restored = 1;
    return PDWC3_SESSION_OK;
}
#endif
