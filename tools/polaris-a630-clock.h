/* SDM845 GMU clock acquisition at the already parked 19.2MHz CXO source.
 * Original gpucc-sdm845.c/clk-rcg2.c/clk-branch.c define these registers.
 * Called only inside an owned CX power interval. Keep GMU_BCR asserted
 * throughout clock activation; no GMU CSR/firmware/PLL/rail/GX operation.
 */
#ifndef POLARIS_A630_CLOCK_H
#define POLARIS_A630_CLOCK_H
#include <stddef.h>
#ifndef POLARIS_A630_POWER_H
#error Include the Polaris CX power definitions first
#endif
#define A630_CLK_POLLS 500u
enum a630_clock_result {
    A630_CLK_DISABLED, A630_CLK_IO, A630_CLK_REFUSED, A630_CLK_ROOT_TIMEOUT,
    A630_CLK_BRANCH_TIMEOUT, A630_CLK_RESTORE_FAILED, A630_CLK_READY_RESTORED,
    A630_CLK_REQUEST_TIMEOUT, A630_CLK_STATE_CHANGED, A630_CLK_READY_RESET_HELD
};
struct a630_clock_snapshot {
    uint32_t result, step, reads, writes, polls, changed, restored;
    uint32_t cfg_ahb, cx_hw, gx, gx_gmu, config;
    uint32_t failed_step, failed_op, failed_offset, failed_expected, failed_value, failed_mask;
    uint32_t request_polls, reset_retained;
    uint32_t before[5], live[5], after[5];
};
struct a630_clock_io {
    a630_read read; a630_write write; a630_wait_us wait; void *ctx;
    struct a630_clock_snapshot *s;
};
/* AON observation only, CXO, source force-enable, CX GMU, GMU block reset.
 * The live SDM845 GMU clock list requests CX_GMU/CXO, not CXO_AON. Keep
 * 0x1004 read-only:0028 found its request bit never acknowledged. Neither
 * its request nor its status is a prerequisite for these required clocks.
 */
static const uint32_t a630_clock_offsets[5] = {0x1004, 0x109c, 0x1120, 0x1098, 0x111c};
static const uint32_t a630_clock_masks[5] = {0, 1, 2, 1, 1};
/* Preserve the first failure across cleanup. Ops:1read/2write/3request
 * acknowledgement/4clock-status wait/5live state. Offsets are GPUCC unless
 * the operation is the initial GCC cfg-AHB read. */
static inline void a630_clk_failure(struct a630_clock_io *io, uint32_t op,
    uint32_t off, uint32_t expected, uint32_t value, uint32_t mask)
{
    if (io->s->failed_op) return;
    io->s->failed_step = io->s->step; io->s->failed_op = op;
    io->s->failed_offset = off; io->s->failed_expected = expected;
    io->s->failed_value = value; io->s->failed_mask = mask;
}
static inline bool a630_clk_read(struct a630_clock_io *io, unsigned region,
    uint32_t off, uint32_t *value)
{
    io->s->reads++;
    if (io->read(io->ctx, region, off, value)) return true;
    io->s->result = A630_CLK_IO;
    a630_clk_failure(io, 1, off, 0, 0, 0); return false;
}
static inline bool a630_clk_set(struct a630_clock_io *io, unsigned index, uint32_t value)
{
    uint32_t current, mask = a630_clock_masks[index], off = a630_clock_offsets[index];
    if (!a630_clk_read(io, 1, off, &current)) return false;
    value = (current & ~mask) | (value & mask);
    /* Mark before issuing: a callback may fail after a posted write. */
    io->s->changed |= 1u << index; io->s->writes++;
    if (!io->write(io->ctx, 1, off, value)) {
        io->s->result = A630_CLK_IO;
        a630_clk_failure(io, 2, off, value, current, mask); return false;
    }
    /* Request fields can cross clock domains. A single immediate mismatch
     * is not an I/O error. Confirm within the existing500us clock bound. */
    for (unsigned n = 0; n < A630_CLK_POLLS; n++) {
        io->s->request_polls++;
        if (!a630_clk_read(io, 1, off, &current)) return false;
        if ((current & mask) == (value & mask)) return true;
        io->wait(io->ctx, 1);
    }
    io->s->result = A630_CLK_REQUEST_TIMEOUT;
    a630_clk_failure(io, 3, off, value, current, mask); return false;
}
static inline bool a630_clk_poll(struct a630_clock_io *io, unsigned index, bool on)
{
    uint32_t value = 0, off = a630_clock_offsets[index];
    for (unsigned n = 0; n < A630_CLK_POLLS; n++) {
        io->s->polls++;
        if (!a630_clk_read(io, 1, off, &value)) return false;
        if (on ? !(value & A630_POWER_ON) : !!(value & A630_POWER_ON)) return true;
        io->wait(io->ctx, 1);
    }
    a630_clk_failure(io, 4, off, on ? 0 : A630_POWER_ON, value, A630_POWER_ON);
    return false;
}
/* Hook runs exclusively after verified clocks, under GMU_BCR. Returning
 * false retains block reset through/after clock cleanup, including on error.
 * This permits TCM access without ever running partially loaded firmware. */
static inline enum a630_clock_result a630_clock_trial_with_hook(bool enabled, bool exact_board,
    a630_read read, a630_write write, a630_wait_us wait, void *ctx,
    struct a630_clock_snapshot *s, bool (*hook)(void *), void *hook_ctx)
{
    if (!s) return A630_CLK_DISABLED;
    *s = (struct a630_clock_snapshot){0};
    if (!enabled || !exact_board || !read || !write || !wait) return A630_CLK_DISABLED;
    struct a630_clock_io io = {read, write, wait, ctx, s};
    s->result = A630_CLK_IO; s->step = 1;
    if (!a630_clk_read(&io, 0, 0x71004, &s->cfg_ahb)) goto done;
    if (s->cfg_ahb & A630_POWER_ON) { s->result = A630_CLK_REFUSED; goto done; }
    if (!a630_clk_read(&io, 1, A630_CX_STATUS, &s->cx_hw)) goto done;
    if (!(s->cx_hw & A630_POWER_ON)) { s->result = A630_CLK_REFUSED; goto done; }
    if (!a630_clk_read(&io, 1, 0x100c, &s->gx) ||
        !a630_clk_read(&io, 1, 0x1064, &s->gx_gmu) ||
        !a630_clk_read(&io, 1, 0x1124, &s->config)) goto done;
    for (unsigned i = 0; i < 5; i++)
        if (!a630_clk_read(&io, 1, a630_clock_offsets[i], &s->before[i])) goto done;
    s->result = A630_CLK_REFUSED;
    /* Do not reparent an unknown PLL or take over an existing clock/reset.
     * Parked TCXO divider0 (bypass) or1 both mean19.2MHz, normal mode. */
    if ((s->gx & A630_POWER_ON) || (s->gx_gmu & 1) || !(s->gx_gmu & A630_POWER_ON) ||
        (s->config & 0x103700u) || (s->config & 31u) > 1 ||
        (s->before[2] & 0xf3u) || !(s->before[2] & A630_POWER_ON) ||
        (s->before[3] & 3u) || !(s->before[3] & A630_POWER_ON) ||
        (s->before[1] & 2u) || (s->before[4] & 1u)) goto done;
    s->result = A630_CLK_IO; s->step = 2;
    if (!a630_clk_set(&io, 4, 1)) goto restore; /* Hold processor in block reset first. */
    /* Do not enable CXO_AON: it is not a clock consumed by this GMU. */
    s->step = 4; s->result = A630_CLK_IO;
    if (!a630_clk_set(&io, 1, 1)) goto restore;
    s->result = A630_CLK_BRANCH_TIMEOUT;
    if (!a630_clk_poll(&io, 1, true)) goto restore;
    s->step = 5; s->result = A630_CLK_IO;
    if (!a630_clk_set(&io, 2, 2)) goto restore;
    s->step = 6; s->result = A630_CLK_ROOT_TIMEOUT;
    if (!a630_clk_poll(&io, 2, true)) goto restore;
    s->step = 7; s->result = A630_CLK_IO;
    if (!a630_clk_set(&io, 3, 1)) goto restore;
    s->step = 8; s->result = A630_CLK_BRANCH_TIMEOUT;
    if (!a630_clk_poll(&io, 3, true)) goto restore;
    s->step = 9; s->result = A630_CLK_IO;
    for (unsigned i = 0; i < 5; i++)
        if (!a630_clk_read(&io, 1, a630_clock_offsets[i], &s->live[i])) goto restore;
    s->result = A630_CLK_STATE_CHANGED;
    if (!(s->live[4] & 1)) {
        a630_clk_failure(&io, 5, a630_clock_offsets[4], 1, s->live[4], 1); goto restore;
    }
    for (unsigned i = 1; i < 4; i++) if (s->live[i] & A630_POWER_ON) {
        a630_clk_failure(&io, 5, a630_clock_offsets[i], 0, s->live[i], A630_POWER_ON); goto restore;
    }
    s->result = A630_CLK_READY_RESTORED;
    if (hook && !hook(hook_ctx)) s->reset_retained = 1;
restore:
    s->step = 10;
    {
        bool ok = true;
        for (int i = 3; i >= 0; i--) if (s->changed & (1u << i)) {
            if (!a630_clk_set(&io, (unsigned)i, s->before[i])) ok = false;
            if ((i == 3 || i == 2) && !a630_clk_poll(&io, (unsigned)i, false)) ok = false;
        }
        /* Release our block-reset only once source and GMU clock are stopped.
         * A failed cleanup keeps reset asserted and never claims restoration. */
        if (ok && !s->reset_retained && (s->changed & (1u << 4)))
            if (!a630_clk_set(&io, 4, s->before[4])) ok = false;
        for (unsigned i = 0; i < 5; i++) {
            if (!a630_clk_read(&io, 1, a630_clock_offsets[i], &s->after[i])) { ok = false; continue; }
            uint32_t expected = i == 4 && s->reset_retained ? s->before[i] | 1u : s->before[i];
            if ((s->after[i] ^ expected) & a630_clock_masks[i]) {
                a630_clk_failure(&io, 5, a630_clock_offsets[i], s->before[i],
                    s->after[i], a630_clock_masks[i]); ok = false;
            }
        }
        if (ok && s->reset_retained) s->result = A630_CLK_READY_RESET_HELD;
        else if (ok) s->restored = 1;
        else s->result = A630_CLK_RESTORE_FAILED;
    }
done:
    return (enum a630_clock_result)s->result;
}
static inline enum a630_clock_result a630_clock_trial(bool enabled, bool exact_board,
    a630_read read, a630_write write, a630_wait_us wait, void *ctx,
    struct a630_clock_snapshot *s)
{
    return a630_clock_trial_with_hook(enabled, exact_board, read, write, wait,
        ctx, s, NULL, NULL);
}
#endif
