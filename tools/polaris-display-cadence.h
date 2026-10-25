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
/* Only after completed desktop GPU work. Keep at least half the measured
 * copy interval for other CPU work; one scheduling outlier cannot stall UI. */
static inline uint32_t polaris_fb_gpu_interval_us(uint32_t hz,uint32_t elapsed_us)
{
    if(!hz)hz=10;
    if(hz>60)hz=60;
    uint32_t base=(1000000u+hz-1)/hz;
    uint64_t budget=(uint64_t)elapsed_us*2;
    if(budget>200000)budget=200000;
    return budget>base?(uint32_t)budget:base;
}
/* The old timer added a complete tick AFTER spending time copying. Account
 * for that work, and always yield at least1ms instead of a catch-up spin. */
static inline uint32_t polaris_fb_gpu_tick_us(uint32_t elapsed_us)
{return elapsed_us>=15667?1000:16667-elapsed_us;}
/* Notifications and copying have different deadlines. A copy budget just
 * over one tick must not wait an entire second tick. An early copy wake
 * never sends an extra VSYNC. Late callbacks skip missed notifications. */
static inline uint64_t polaris_fb_next_vsync_us(uint64_t now,uint64_t deadline)
{
    if(!deadline || now<deadline)return deadline?deadline:now+16667;
    return deadline+((now-deadline)/16667+1)*16667;
}
static inline uint32_t polaris_fb_deadline_delay_us(uint64_t now,uint64_t vsync,
    uint64_t present,int dirty)
{
    uint64_t next=vsync;
    /* A renderer awakened by this VSYNC may publish after we unlock. Keep
     * a future copy wake even if it has not marked the new frame dirty yet.
     * A past clean deadline must not create an idle1ms polling loop. */
    if(present && (dirty || present>now) && present<next)next=present;
    if(next<=now || next-now<1000)return 1000;
    return next-now>16667?16667:(uint32_t)(next-now);
}
#endif
