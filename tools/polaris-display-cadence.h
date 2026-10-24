/* CPU presentation interval: requested limit plus a measured copy budget.
 * Elapsed wall time can include preemption, so one outlier is capped at
 * a 200ms interval; it must not freeze the UI for seconds after a pause.
 */
#ifndef POLARIS_DISPLAY_CADENCE_H
#define POLARIS_DISPLAY_CADENCE_H
#include <stdint.h>
static inline uint32_t polaris_fb_interval_us(uint32_t hz, uint32_t elapsed_us)
{
    if (!hz) hz = 10;
    if (hz > 30) hz = 30;
    uint32_t base = (1000000u + hz - 1) / hz;
    uint64_t budget = (uint64_t)elapsed_us * 4;
    if (budget > 200000) budget = 200000;
    return budget > base ? (uint32_t)budget : base;
}
#endif
