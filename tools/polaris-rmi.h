#ifndef POLARIS_RMI_H
#define POLARIS_RMI_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Synaptics RMI4/F12 register interpretation, independent of the bus.
 * Discover present registers and the existing report format; never upload
 * firmware or guess fixed coordinate/data addresses. Return values are local
 * protocol errors, not kernel errno values. Read callback returns zero on success.
 */
#define POLARIS_RMI_FINGERS 10u
enum { POLARIS_RMI_OK, POLARIS_RMI_IO, POLARIS_RMI_FORMAT,
       POLARIS_RMI_UNSUPPORTED, POLARIS_RMI_RESET };
typedef int (*polaris_rmi_read_fn)(void *, uint16_t, uint8_t *, size_t);

struct polaris_rmi_layout {
    uint16_t f01_query, f01_control, f01_data;
    uint16_t f12_query, f12_control, f12_data, report, presence;
    uint16_t max_x, max_y;
    uint8_t fingers, stride, report_mask, interrupt_bytes, presence_bytes;
};
struct polaris_rmi_frame {
    uint16_t mask;
    uint16_t x[POLARIS_RMI_FINGERS], y[POLARIS_RMI_FINGERS];
};

static inline uint16_t polaris_rmi_le16(const uint8_t *p)
{ return (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); }

static inline unsigned polaris_rmi_bits(uint32_t v)
{
    unsigned n = 0;
    while (v) { n += v & 1u; v >>= 1; }
    return n;
}

static inline bool polaris_rmi_span(uint16_t reg, size_t n)
{
    /* 0xff is the page selector; do not turn a register read into a page wrap. */
    return n && n <= 80 && (unsigned)(reg & 255u) + n <= 255u;
}

static inline int
polaris_rmi_read(polaris_rmi_read_fn read, void *ctx, uint16_t reg,
    uint8_t *buf, size_t n)
{
    if (!read || !buf || !polaris_rmi_span(reg, n)) { return POLARIS_RMI_FORMAT; }
    return read(ctx, reg, buf, n) ? POLARIS_RMI_IO : POLARIS_RMI_OK;
}

static inline int
polaris_rmi_discover(polaris_rmi_read_fn read, void *ctx, struct polaris_rmi_layout *out)
{
    struct polaris_rmi_layout l = {0};
    bool f01 = false, f12 = false;
    unsigned intr = 0;
    uint8_t d[6], b[9], q5[9] = {0}, q8[5] = {0};
    if (!out) { return POLARIS_RMI_FORMAT; }
    /* Vendor PDT has five six-byte descriptors/page, up to ten pages. */
    for (unsigned page = 0; page < 10; ++page) {
        for (unsigned at = 0xe9; at > 0xd0; at -= 6) {
            uint16_t a = (uint16_t)((page << 8) | at);
            int e = polaris_rmi_read(read, ctx, a, d, sizeof(d));
            if (e) { return e; }
            if (!d[5]) { break; }
            intr += d[4] & 7u;
            if (intr > 64) { return POLARIS_RMI_UNSUPPORTED; }
            if (d[5] == 1 || d[5] == 0x12) {
                if ((d[5] == 1 && f01) || (d[5] == 0x12 && f12)) {
                    return POLARIS_RMI_UNSUPPORTED;
                }
                uint16_t q = (uint16_t)((page << 8) | d[0]);
                uint16_t c = (uint16_t)((page << 8) | d[2]);
                uint16_t data = (uint16_t)((page << 8) | d[3]);
                if (d[5] == 1) {
                    f01 = true; l.f01_query = q; l.f01_control = c; l.f01_data = data;
                } else {
                    f12 = true; l.f12_query = q; l.f12_control = c; l.f12_data = data;
                }
            }
        }
    }
    if (!f01 || !f12 || !intr) { return POLARIS_RMI_UNSUPPORTED; }
    l.interrupt_bytes = (uint8_t)((intr + 7u) / 8u);
    int e = polaris_rmi_read(read, ctx, l.f01_query, b, 1);
    if (e) { return e; }
    if (b[0] != 1) { return POLARIS_RMI_UNSUPPORTED; } /* Synaptics manufacturer */
    if ((l.f12_query & 255u) > 246u) { return POLARIS_RMI_FORMAT; }
    e = polaris_rmi_read(read, ctx, l.f12_query + 4, b, 1);
    if (e) { return e; }
    unsigned size5 = b[0];
    if (size5 < 5 || size5 > sizeof(q5)) { return POLARIS_RMI_UNSUPPORTED; }
    e = polaris_rmi_read(read, ctx, l.f12_query + 5, q5, size5);
    if (e) { return e; }
    uint32_t controls = (uint32_t)q5[1] | ((uint32_t)q5[2] << 8) |
        ((uint32_t)q5[3] << 16) | ((uint32_t)q5[4] << 24);
    if ((controls & ((1u << 8) | (1u << 23) | (1u << 28))) !=
        ((1u << 8) | (1u << 23) | (1u << 28))) {
        return POLARIS_RMI_UNSUPPORTED;
    }
    unsigned c8 = polaris_rmi_bits(controls & 0xffu);
    unsigned c23 = polaris_rmi_bits(controls & ((1u << 23) - 1u));
    unsigned c28 = polaris_rmi_bits(controls & ((1u << 28) - 1u));
    if ((l.f12_control & 255u) + c28 >= 255u) { return POLARIS_RMI_FORMAT; }
    e = polaris_rmi_read(read, ctx, l.f12_control + c8, b, 4);
    if (e) { return e; }
    l.max_x = polaris_rmi_le16(b); l.max_y = polaris_rmi_le16(b + 2);
    if (!l.max_x || !l.max_y || l.max_x > 16383 || l.max_y > 16383) {
        return POLARIS_RMI_UNSUPPORTED;
    }
    e = polaris_rmi_read(read, ctx, l.f12_control + c23, b, 2);
    if (e) { return e; }
    if (!(b[0] & 1u) || !b[1] || b[1] > POLARIS_RMI_FINGERS) {
        return POLARIS_RMI_UNSUPPORTED;
    }
    l.fingers = b[1];
    e = polaris_rmi_read(read, ctx, l.f12_control + c28, b, 1);
    if (e) { return e; }
    l.report_mask = b[0]; l.stride = (uint8_t)polaris_rmi_bits(b[0]);
    if ((b[0] & 0x1fu) != 0x1fu) { return POLARIS_RMI_UNSUPPORTED; }
    e = polaris_rmi_read(read, ctx, l.f12_query + 7, b, 1);
    if (e) { return e; }
    unsigned size8 = b[0];
    if (size8 < 2 || size8 > sizeof(q8)) { return POLARIS_RMI_UNSUPPORTED; }
    e = polaris_rmi_read(read, ctx, l.f12_query + 8, q8, size8);
    if (e) { return e; }
    if (!(q8[1] & 2u)) { return POLARIS_RMI_UNSUPPORTED; }
    if ((l.f12_data & 255u) + (q8[1] & 1u) >= 255u) { return POLARIS_RMI_FORMAT; }
    l.report = l.f12_data + (q8[1] & 1u);
    if (!polaris_rmi_span(l.report, (size_t)l.fingers * l.stride) ||
        !polaris_rmi_span(l.f01_data, (size_t)l.interrupt_bytes + 1u)) {
        return POLARIS_RMI_FORMAT;
    }
    if (size8 >= 3 && (q8[2] & 0x80u)) {
        uint16_t present = (uint16_t)(q8[1] | ((uint16_t)q8[2] << 8));
        unsigned offset = polaris_rmi_bits(present & 0x7fffu);
        if ((l.f12_data & 255u) + offset >= 255u) { return POLARIS_RMI_FORMAT; }
        l.presence = l.f12_data + offset;
        l.presence_bytes = (uint8_t)((l.fingers + 7u) / 8u);
        if (!polaris_rmi_span(l.presence, l.presence_bytes)) { return POLARIS_RMI_FORMAT; }
    }
    *out = l;
    return POLARIS_RMI_OK;
}

static inline int
polaris_rmi_sample(polaris_rmi_read_fn read, void *ctx,
    const struct polaris_rmi_layout *l, struct polaris_rmi_frame *out)
{
    struct polaris_rmi_frame f = {0};
    uint8_t status[9], buf[80], present[2];
    if (!l || !out || !l->fingers || l->fingers > POLARIS_RMI_FINGERS ||
        l->stride < 5 || l->stride > 8 || !l->interrupt_bytes || l->interrupt_bytes > 8 ||
        l->presence_bytes > 2 || !l->max_x || !l->max_y ||
        l->max_x > 16383 || l->max_y > 16383 || (l->report_mask & 0x1fu) != 0x1fu) {
        return POLARIS_RMI_FORMAT;
    }
    int e = polaris_rmi_read(read, ctx, l->f01_data, status, l->interrupt_bytes + 1u);
    if (e) { return e; }
    if ((status[0] & 0xc0u) || (status[0] & 15u) > 1u) { return POLARIS_RMI_RESET; }
    uint16_t active = (uint16_t)((1u << l->fingers) - 1u);
    if (l->presence_bytes) {
        present[0] = present[1] = 0;
        e = polaris_rmi_read(read, ctx, l->presence, present, l->presence_bytes);
        if (e) { return e; }
        active &= polaris_rmi_le16(present);
    }
    if (active) {
        unsigned count = l->fingers;
        while (count && !(active & (1u << (count - 1u)))) { --count; }
        e = polaris_rmi_read(read, ctx, l->report, buf, (size_t)count * l->stride);
        if (e) { return e; }
        for (unsigned i = 0; i < count; ++i) {
            const uint8_t *p = buf + i * l->stride;
            if (!(active & (1u << i)) || (p[0] != 1 && p[0] != 6)) { continue; }
            unsigned x = polaris_rmi_le16(p + 1), y = polaris_rmi_le16(p + 3);
            if (x > l->max_x || y > l->max_y) { return POLARIS_RMI_FORMAT; }
            f.mask |= (uint16_t)(1u << i); f.x[i] = (uint16_t)x; f.y[i] = (uint16_t)y;
        }
    }
    *out = f;
    return POLARIS_RMI_OK;
}

#endif
