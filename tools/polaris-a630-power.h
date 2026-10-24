/* One bounded CX power-request trial, following the live Polaris DT and
 * MiCode c7cb50c1 gdsc-regulator.c. No clocks, rails, resets, GMU or SMMU
 * are changed. The only writable register is GPUCC_CX_GDSCR.SW_COLLAPSE.
 * A successful trial observes POWER_ON and restores the original request;
 * other masters may keep the domain on (DT: no-status-check-on-disable).
 */
#ifndef POLARIS_A630_POWER_H
#define POLARIS_A630_POWER_H
#ifndef POLARIS_A630_PROBE_H
#error Include the Polaris read-only probe definitions first
#endif
#define A630_CX_REQUEST 0x106cu
#define A630_CX_STATUS 0x1540u
#define A630_POWER_ON (1u << 31)
#define A630_COLLAPSE 1u
#define A630_HW_CONTROL 2u
#define A630_SW_OVERRIDE 4u
#define A630_POWER_POLLS 500u
enum a630_power_result {
    A630_POWER_DISABLED, A630_POWER_IO, A630_POWER_AHB_OFF,
    A630_POWER_ALREADY_ON, A630_POWER_REFUSED, A630_POWER_ON_REQUEST_RESTORED,
    A630_POWER_TIMEOUT, A630_POWER_RESTORE_FAILED
};
struct a630_power_snapshot {
    uint32_t result, step, reads, writes, changed, request_restored, polls;
    uint32_t cfg, before, before_hw, gx, on_hw, after, after_hw;
};
typedef bool (*a630_write)(void *, unsigned, uint32_t, uint32_t);
typedef void (*a630_wait_us)(void *, uint32_t);
static inline enum a630_power_result
a630_power_trial(bool enabled, bool exact_board, a630_read read,
    a630_write write, a630_wait_us wait_us, void *ctx,
    struct a630_power_snapshot *s)
{
    if (!s) return A630_POWER_DISABLED;
    *s = (struct a630_power_snapshot){0};
    if (!enabled || !exact_board || !read || !write || !wait_us)
        return A630_POWER_DISABLED;
    s->result = A630_POWER_IO; s->step = 1;
#define CX_READ(region, offset, value) (s->reads++, read(ctx, region, offset, &(value)))
#define CX_WRITE(value) (s->writes++, write(ctx, 1, A630_CX_REQUEST, (value)))
    if (!CX_READ(0, 0x71004, s->cfg)) goto done;
    if (s->cfg & A630_POWER_ON) { s->result = A630_POWER_AHB_OFF; goto done; }
    if (!CX_READ(1, A630_CX_REQUEST, s->before) ||
        !CX_READ(1, A630_CX_STATUS, s->before_hw) ||
        !CX_READ(1, 0x100c, s->gx)) goto done;
    s->after = s->before; s->after_hw = s->before_hw;
    if (s->before_hw & A630_POWER_ON) {
        s->result = A630_POWER_ALREADY_ON; goto done; /* Preserve another owner's vote. */
    }
    if ((s->before & (A630_HW_CONTROL | A630_SW_OVERRIDE)) || !(s->before & A630_COLLAPSE) ||
        (s->gx & A630_POWER_ON)) {
        s->result = A630_POWER_REFUSED; goto done;
    }
    s->changed = 1; s->step = 2;
    /* A write callback can fail after issuing a posted write. Always clean up. */
    if (!CX_WRITE(s->before & ~A630_COLLAPSE)) goto restore;
    wait_us(ctx, 1); /* Eight XO cycles before the first status poll. */
    s->result = A630_POWER_TIMEOUT;
    for (unsigned i = 0; i < A630_POWER_POLLS; i++) {
        s->polls++;
        if (!CX_READ(1, A630_CX_STATUS, s->on_hw)) {
            s->result = A630_POWER_IO; goto restore;
        }
        if (s->on_hw & A630_POWER_ON) {
            s->step = 3; s->result = A630_POWER_ON_REQUEST_RESTORED;
            break;
        }
        wait_us(ctx, 1);
    }
restore:
    s->step = 4;
    {
        uint32_t current;
        if (!CX_READ(1, A630_CX_REQUEST, current) || (current & A630_HW_CONTROL) ||
            !CX_WRITE(current | A630_COLLAPSE)) {
            s->result = A630_POWER_RESTORE_FAILED; goto done;
        }
        wait_us(ctx, 1);
        if (!CX_READ(1, A630_CX_REQUEST, s->after) ||
            !(s->after & A630_COLLAPSE) || (s->after & A630_HW_CONTROL)) {
            s->result = A630_POWER_RESTORE_FAILED; goto done;
        }
        s->request_restored = 1;
        if (!CX_READ(1, A630_CX_STATUS, s->after_hw)) s->result = A630_POWER_IO;
        /* DT explicitly avoids an OFF-status wait: other masters can vote ON. */
    }
done:
    s->step = 5;
#undef CX_READ
#undef CX_WRITE
    return (enum a630_power_result)s->result;
}
#endif
