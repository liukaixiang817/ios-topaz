#ifndef POLARIS_GPIO_I2C_H
#define POLARIS_GPIO_I2C_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Exact-board fallback for an idle GENI I2C engine without usable FIFOs.
 * low(...,false) MUST release the pin, never drive it high. No bus-clear
 * pulses, controller reset, address scan or firmware upload. SDA=0,SCL=1.
 * Shared with wire-level native tests; only slave0x20 is permitted.
 */
enum { PB_OK, PB_BAD_ARGUMENT, PB_BUSY, PB_IO, PB_TIMEOUT, PB_NO_DEVICE,
       PB_ARBITRATION };
struct polaris_gpio_i2c {
    void *ctx;
    void (*low)(void *, unsigned, bool);
    unsigned (*levels)(void *);
    void (*delay_us)(void *, unsigned);
    unsigned remaining;
    bool held, dead;
};

/* An idle I2C sequencer is mandatory for either transport. A disabled or
 * inherited nonempty FIFO must remain untouched; the board can instead
 * release/remux its two verified bus pins and use open-drain GPIO. */
enum { PB_DENY, PB_FIFO, PB_GPIO };
static inline unsigned
pb_transport(uint32_t fw, uint32_t status, uint32_t disabled,
    uint32_t tx, uint32_t rx)
{
    if (((fw >> 8) & 255u) != 3 || (status & 0x1001u)) { return PB_DENY; }
    return (disabled & 1u) || (tx & 0xfffffffu) || (rx & 0x1ffffffu) ? PB_GPIO : PB_FIFO;
}

static inline void pb_release(struct polaris_gpio_i2c *g)
{
    g->low(g->ctx, 0, false); g->low(g->ctx, 1, false); g->held = false;
}
static inline bool pb_pause(struct polaris_gpio_i2c *g, unsigned us)
{
    if (us > g->remaining) { return false; }
    g->remaining -= us; g->delay_us(g->ctx, us); return true;
}
static inline int pb_scl_high(struct polaris_gpio_i2c *g)
{
    g->low(g->ctx, 1, false);
    while (!(g->levels(g->ctx) & 2u)) {
        if (!pb_pause(g, 1)) { return PB_TIMEOUT; }
    }
    return PB_OK;
}
static inline int pb_start(struct polaris_gpio_i2c *g)
{
    if (!g->held) {
        pb_release(g);
        /* No attempt to recover an inherited busy/stuck bus. */
        for (unsigned i = 0; i < 4; ++i) {
            if ((g->levels(g->ctx) & 3u) != 3u) { return PB_BUSY; }
            if (!pb_pause(g, 5)) { return PB_TIMEOUT; }
        }
    } else {
        g->low(g->ctx, 0, false);
        if (!pb_pause(g, 5)) { return PB_TIMEOUT; }
        int e = pb_scl_high(g); if (e) { return e; }
        if (!pb_pause(g, 5)) { return PB_TIMEOUT; }
        if (!(g->levels(g->ctx) & 1u)) { return PB_ARBITRATION; }
    }
    g->low(g->ctx, 0, true);
    if (!pb_pause(g, 5)) { return PB_TIMEOUT; }
    g->low(g->ctx, 1, true); g->held = true;
    return PB_OK;
}
static inline int pb_stop(struct polaris_gpio_i2c *g)
{
    g->low(g->ctx, 0, true);
    if (!pb_pause(g, 5)) { return PB_TIMEOUT; }
    int e = pb_scl_high(g); if (e) { return e; }
    if (!pb_pause(g, 5)) { return PB_TIMEOUT; }
    g->low(g->ctx, 0, false); g->held = false;
    if (!pb_pause(g, 5)) { return PB_TIMEOUT; }
    return (g->levels(g->ctx) & 3u) == 3u ? PB_OK : PB_IO;
}
static inline int pb_write_bit(struct polaris_gpio_i2c *g, bool bit)
{
    g->low(g->ctx, 0, !bit);
    if (!pb_pause(g, 5)) { return PB_TIMEOUT; }
    int e = pb_scl_high(g); if (e) { return e; }
    if (!pb_pause(g, 5)) { return PB_TIMEOUT; }
    if (bit && !(g->levels(g->ctx) & 1u)) { return PB_ARBITRATION; }
    g->low(g->ctx, 1, true);
    return PB_OK;
}
static inline int pb_read_bit(struct polaris_gpio_i2c *g, bool *bit)
{
    g->low(g->ctx, 0, false);
    if (!pb_pause(g, 5)) { return PB_TIMEOUT; }
    int e = pb_scl_high(g); if (e) { return e; }
    if (!pb_pause(g, 5)) { return PB_TIMEOUT; }
    *bit = (g->levels(g->ctx) & 1u) != 0;
    g->low(g->ctx, 1, true);
    return PB_OK;
}
static inline int pb_tx(struct polaris_gpio_i2c *g, uint8_t byte)
{
    for (unsigned i = 0; i < 8; ++i) {
        int e = pb_write_bit(g, (byte & (0x80u >> i)) != 0); if (e) { return e; }
    }
    bool nack; int e = pb_read_bit(g, &nack);
    return e ? e : nack ? PB_NO_DEVICE : PB_OK;
}
static inline int pb_rx(struct polaris_gpio_i2c *g, uint8_t *byte, bool last)
{
    uint8_t value = 0;
    for (unsigned i = 0; i < 8; ++i) {
        bool bit; int e = pb_read_bit(g, &bit); if (e) { return e; }
        value = (uint8_t)((value << 1) | bit);
    }
    int e = pb_write_bit(g, last); if (e) { return e; }
    g->low(g->ctx, 0, false); *byte = value;
    return PB_OK;
}
static inline int
pb_message(struct polaris_gpio_i2c *g, const uint8_t *tx, size_t nt,
    uint8_t *rx, size_t nr, bool stretch)
{
    if (!g || !g->low || !g->levels || !g->delay_us || nt > 2 || nr > 80 ||
        (!nt && !nr) || (nt && nr) || (nt && !tx) || (nr && !rx) || (nr && stretch)) {
        return PB_BAD_ARGUMENT;
    }
    if (g->dead) { return PB_IO; }
    /* 80 bytes at <=100kHz fit comfortably; clock stretching shares this
     * finite budget with every bit/START/STOP, not a fresh timeout per bit. */
    g->remaining = 24000;
    int e = pb_start(g);
    if (!e) { e = pb_tx(g, nr ? 0x41u : 0x40u); }
    for (size_t i = 0; !e && i < nt; ++i) { e = pb_tx(g, tx[i]); }
    for (size_t i = 0; !e && i < nr; ++i) { e = pb_rx(g, &rx[i], i + 1 == nr); }
    if (!e && stretch) { g->low(g->ctx, 0, false); return PB_OK; }
    if (!e || e == PB_NO_DEVICE) {
        int stop = pb_stop(g); if (stop) { e = stop; }
    }
    /* Never force a STOP after lost arbitration, a foreign busy bus or a
     * failed clock rise. Release both lines without recovery clock pulses. */
    if (e && e != PB_NO_DEVICE) { g->dead = true; }
    pb_release(g);
    return e;
}

#endif
