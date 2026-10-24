#ifndef POLARIS_TOUCH_WAKE_H
#define POLARIS_TOUCH_WAKE_H

#include <stdint.h>
#include <stdbool.h>

/* Explicit board opt-in only. Live polaris DT: fixed TP enableGPIO23,
 * active-low resetGPIO99, IRQ125. Never pulse an already released reset.
 * PMIC/voltage registers and panel resetGPIO6 are outside this interface. */
enum { PW_OK, PW_ARGUMENT, PW_OWNER, PW_ENABLE, PW_LINES, PW_RESET, PW_IRQ };
struct polaris_touch_wake {
    void *ctx;
    uint32_t (*read)(void *, unsigned, unsigned);
    void (*write)(void *, unsigned, unsigned, uint32_t);
    void (*sleep_ms)(void *, unsigned);
    unsigned (*lines)(void *);
    unsigned step, error, changed, failed_pin, line_state;
    bool rolled_back, irq_input;
    uint32_t old_enable_cfg, old_enable_io, old_reset_cfg, old_reset_io;
    uint32_t enable_cfg, enable_io, reset_cfg, reset_io;
    uint32_t old_irq_cfg, old_irq_io, irq_cfg, irq_io;
};

static inline bool pw_gpio_output(uint32_t cfg)
{ return !(cfg & 0x3cu) && (cfg & 0x200u); }
static inline bool pw_pad_high(uint32_t cfg, uint32_t io)
{ return pw_gpio_output(cfg) && (io & 3u) == 3u; }

static inline int
pw_failed(struct polaris_touch_wake *g, unsigned error, unsigned pin)
{
    g->error=error; g->failed_pin=pin;
    /* Restore only changes made here. An inherited running controller is
     * never asserted/reset. Keep failure snapshots instead of replacing
     * them with the restored values. */
    if (g->changed & 2u) {
        g->write(g->ctx,99,4,g->old_reset_io & 2u);
        g->write(g->ctx,99,0,g->old_reset_cfg);
        g->sleep_ms(g->ctx,5);
    }
    if (g->changed & 1u) {
        g->write(g->ctx,23,4,g->old_enable_io & 2u);
        g->write(g->ctx,23,0,g->old_enable_cfg);
    }
    if (g->changed & 4u) {
        /* Reset restored first. Never write the IRQ output latch. */
        g->write(g->ctx,125,0,g->old_irq_cfg);
    }
    g->rolled_back=g->changed!=0;
    return (int)error;
}

static inline int polaris_touch_wake(struct polaris_touch_wake *g)
{
    if (!g || !g->read || !g->write || !g->sleep_ms || !g->lines) { return PW_ARGUMENT; }
    g->step=1;g->error=g->changed=g->failed_pin=g->line_state=0;g->rolled_back=false;
    g->old_enable_cfg=g->enable_cfg=g->read(g->ctx,23,0);
    g->old_enable_io=g->enable_io=g->read(g->ctx,23,4);
    g->old_reset_cfg=g->reset_cfg=g->read(g->ctx,99,0);
    g->old_reset_io=g->reset_io=g->read(g->ctx,99,4);
    g->old_irq_cfg=g->irq_cfg=g->read(g->ctx,125,0);
    g->old_irq_io=g->irq_io=g->read(g->ctx,125,4);
    if (!pw_gpio_output(g->reset_cfg)) { return pw_failed(g,PW_OWNER,99); }
    if (g->irq_cfg&0x23cu) {
        /* Separate exact-board opt-in, only observed GPIO/output-low with
         * reset held. Vendor ts_active: GPIO,16mA,pull-up; direction input. */
        if (!g->irq_input || (g->reset_io&2u) ||
            (g->irq_cfg&0x3ffu)!=0x201u || (g->irq_io&3u)) {
            return pw_failed(g,PW_OWNER,125);
        }
        g->step=9;g->changed|=4u;
        g->write(g->ctx,125,0,(g->irq_cfg&~0x3ffu)|0x1c3u);
        g->irq_cfg=g->read(g->ctx,125,0);g->irq_io=g->read(g->ctx,125,4);
        if ((g->irq_cfg&0x3ffu)!=0x1c3u) { return pw_failed(g,PW_IRQ,125); }
    }
    if (g->reset_io & 2u) {
        /* Preserve an already running controller; no power/reset writes. */
        g->line_state=g->lines(g->ctx)&3u;g->step=8;return PW_OK;
    }
    g->step=2;
    if (g->enable_cfg & 0x3cu) { return pw_failed(g,PW_OWNER,23); }
    if (!pw_gpio_output(g->enable_cfg) || !(g->enable_io & 2u)) {
        /* Reset is already asserted. Preload high while input, then enable
         * this exact fixed-regulator GPIO; no voltage selection exists. */
        g->changed|=1u;
        g->write(g->ctx,23,4,2u);
        g->write(g->ctx,23,0,(g->enable_cfg & ~0x3ffu)|0x200u);
    }
    /* Fixed regulator startup=4ms, board power delay=5ms: wait at least5. */
    g->sleep_ms(g->ctx,5);g->step=3;
    g->enable_cfg=g->read(g->ctx,23,0);g->enable_io=g->read(g->ctx,23,4);
    if (!pw_pad_high(g->enable_cfg,g->enable_io)) { return pw_failed(g,PW_ENABLE,23); }
    g->line_state=g->lines(g->ctx)&3u;g->step=4;
    if (g->line_state!=3u) { return pw_failed(g,PW_LINES,0); }
    /* Check a released bus repeatedly; no bus-clear pulses or PMIC writes. */
    for (unsigned i=0;i<4;i++) {
        g->line_state=g->lines(g->ctx)&3u;
        if (g->line_state!=3u) { return pw_failed(g,PW_LINES,0); }
    }
    g->sleep_ms(g->ctx,5);g->step=5; /* reset remains low for >=5ms after power */
    g->changed|=2u;
    g->write(g->ctx,99,0,(g->old_reset_cfg & ~3u)|3u); /* active pull-up, same drive */
    g->write(g->ctx,99,4,2u); /* deassert only; never pulse an inherited high */
    g->sleep_ms(g->ctx,200);g->step=6;
    g->reset_cfg=g->read(g->ctx,99,0);g->reset_io=g->read(g->ctx,99,4);
    if (!pw_pad_high(g->reset_cfg,g->reset_io)) { return pw_failed(g,PW_RESET,99); }
    g->line_state=g->lines(g->ctx)&3u;
    if (g->line_state!=3u) { return pw_failed(g,PW_LINES,0); }
    g->step=7;return PW_OK;
}

#endif
