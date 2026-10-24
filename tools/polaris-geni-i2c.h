#ifndef POLARIS_GENI_I2C_H
#define POLARIS_GENI_I2C_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Bounded FIFO messages. Register access is supplied by the board driver;
 * native tests exercise the identical transaction/error/abort state machine.
 * No DMA, firmware loading, address scan, reset or power controller access.
 */
#define PG_STATUS 0x40u
#define PG_CMD 0x600u
#define PG_CTRL 0x604u
#define PG_IRQ 0x610u
#define PG_CLEAR 0x618u
#define PG_TX 0x700u
#define PG_RX 0x780u
#define PG_TX_COUNT 0x800u
#define PG_RX_COUNT 0x804u
#define PG_TX_WM 0x80cu
#define PG_DONE 1u
#define PG_NACK (1u << 10)
#define PG_ERRORS (0x3eu | (1u << 9) | (1u << 10) | (1u << 12) | \
                   (1u << 13) | (3u << 24) | (3u << 28))
#define PG_WATERMARKS ((1u << 26) | (1u << 27) | (1u << 30))

enum { PG_OK, PG_BAD_ARGUMENT, PG_BUSY, PG_IO, PG_TIMEOUT, PG_NO_DEVICE };
struct polaris_geni {
    void *ctx;
    uint32_t (*read)(void *, uint32_t);
    void (*write)(void *, uint32_t, uint32_t);
    void (*delay_us)(void *, unsigned);
    bool dead, held;
    uint32_t irq_seen;
};

static inline bool pg_wait_idle(struct polaris_geni *g, unsigned us)
{
    for (unsigned i = 0; i < us; ++i) {
        if (!(g->read(g->ctx, PG_STATUS) & 1u)) { return true; }
        g->delay_us(g->ctx, 1);
    }
    return false;
}

/* Never call this for an inherited busy sequencer; only our own command/bus. */
static inline void pg_abort_owned(struct polaris_geni *g)
{
    g->write(g->ctx, PG_CTRL, 2u);
    bool done = false;
    for (unsigned i = 0; i < 5000; ++i) {
        if (g->read(g->ctx, PG_IRQ) & (1u << 5)) { done = true; break; }
        g->delay_us(g->ctx, 1);
    }
    if (!done || !pg_wait_idle(g, 5000)) { g->dead = true; }
    /* Drain at most the verified hardware FIFO depth (<=64 words). */
    unsigned count = g->read(g->ctx, PG_RX_COUNT) & 0x1ffffffu;
    if (count > 64) { g->dead = true; count = 64; }
    for (unsigned i = 0; i < count; ++i) { (void)g->read(g->ctx, PG_RX); }
    g->write(g->ctx, PG_CLEAR, 0xffffffffu);
    if (g->read(g->ctx, PG_TX_COUNT) & 0xfffffffu) { g->dead = true; }
    g->held = false;
}

static inline int
pg_message(struct polaris_geni *g, const uint8_t *tx, size_t nt,
    uint8_t *rx, size_t nr, bool stretch)
{
    if (!g || !g->read || !g->write || !g->delay_us || nt > 2 || nr > 80 ||
        (!nt && !nr) || (nt && nr) || (nt && !tx) || (nr && !rx) || (nr && stretch)) {
        return PG_BAD_ARGUMENT;
    }
    if (g->dead) { return PG_IO; }
    if (!pg_wait_idle(g, 5000)) {
        if (g->held) { pg_abort_owned(g); }
        return PG_BUSY;
    }
    if (!g->held && (g->read(g->ctx, PG_STATUS) & 0x1000u)) {
        return PG_BUSY; /* An inherited held bus is not ours to abort. */
    }
    if ((g->read(g->ctx, PG_TX_COUNT) & 0xfffffffu) ||
        (g->read(g->ctx, PG_RX_COUNT) & 0x1ffffffu)) {
        if (g->held) { pg_abort_owned(g); }
        g->dead = true;
        return PG_IO;
    }
    g->irq_seen = 0;
    g->write(g->ctx, PG_CLEAR, 0xffffffffu);
    g->write(g->ctx, PG_TX_WM, nt ? 1u : 0u);
    g->write(g->ctx, nr ? 0x270u : 0x26cu, (uint32_t)(nr ? nr : nt));
    /* Only the observed Synaptics address0x20; no scanning other ICs. */
    g->write(g->ctx, PG_CMD, ((nr ? 2u : 1u) << 27) | (0x20u << 9) |
        (stretch ? 4u : 0u));
    unsigned got = 0, sent = 0;
    int error = PG_TIMEOUT;
    for (unsigned i = 0; i < 20000; ++i) {
        uint32_t irq = g->read(g->ctx, PG_IRQ);
        g->irq_seen |= irq;
        if (irq & PG_ERRORS) {
            error = (irq & PG_NACK) ? PG_NO_DEVICE : PG_IO;
            for (unsigned j = 0; j < 5000 && !(irq & PG_DONE); ++j) {
                g->delay_us(g->ctx, 1);
                irq = g->read(g->ctx, PG_IRQ); g->irq_seen |= irq;
            }
            if ((irq & PG_DONE) && !(g->read(g->ctx, PG_STATUS) & 1u) &&
                !(g->read(g->ctx, PG_TX_COUNT) & 0xfffffffu) &&
                !(g->read(g->ctx, PG_RX_COUNT) & 0x1ffffffu)) {
                g->write(g->ctx, PG_CLEAR, irq); g->held = false;
                return error;
            }
            break;
        }
        if (nt && !sent && (irq & (1u << 30))) {
            uint32_t word = tx[0];
            if (nt == 2) { word |= (uint32_t)tx[1] << 8; }
            g->write(g->ctx, PG_TX, word); sent = (unsigned)nt;
            g->write(g->ctx, PG_TX_WM, 0);
        }
        uint32_t count = g->read(g->ctx, PG_RX_COUNT) & 0x1ffffffu;
        if (count > 64 || count > (nr - got + 3u) / 4u) { error = PG_IO; break; }
        while (count--) {
            uint32_t word = g->read(g->ctx, PG_RX);
            for (unsigned j = 0; j < 4 && got < nr; ++j) { rx[got++] = (uint8_t)(word >> (8u * j)); }
        }
        if (irq & PG_DONE) {
            irq = g->read(g->ctx, PG_IRQ); g->irq_seen |= irq;
            if (irq & PG_ERRORS) { continue; }
            g->write(g->ctx, PG_CLEAR, irq);
            if (got == nr && sent == nt && !(g->read(g->ctx, PG_STATUS) & 1u)) {
                g->held = stretch; return PG_OK;
            }
            error = PG_IO; break;
        }
        g->write(g->ctx, PG_CLEAR, irq & PG_WATERMARKS);
        g->delay_us(g->ctx, 1);
    }
    pg_abort_owned(g);
    return error;
}

#endif
