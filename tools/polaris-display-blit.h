/* Bounded CPU-only BGRA presentation. No device registers or storage access.
 * Caller serializes swaps and supplies persistent column workspace. */
#ifndef POLARIS_DISPLAY_BLIT_H
#define POLARIS_DISPLAY_BLIT_H
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

struct polaris_fb_view { uint32_t x, y, width, height; };
struct polaris_fb_rect { int32_t x, y, width, height; };

static inline bool
polaris_fb_fit(uint32_t pw, uint32_t ph, uint32_t lw, uint32_t lh,
    struct polaris_fb_view *v)
{
    if (!v || pw < 2 || ph < 2 || lw < 2 || lh < 2 ||
        pw > 4096 || ph > 4096 || lw > 4096 || lh > 4096) return false;
    uint32_t w = pw, h = ph;
    if ((uint64_t)pw * lh > (uint64_t)ph * lw)
        w = (uint32_t)((uint64_t)ph * lw / lh);
    else h = (uint32_t)((uint64_t)pw * lh / lw);
    if (w < 2 || h < 2) return false;
    *v = (struct polaris_fb_view){(pw - w) / 2, (ph - h) / 2, w, h};
    return true;
}

static inline bool
polaris_fb_buffer(uint32_t w, uint32_t h, uint32_t stride,
    size_t offset, size_t length)
{
    if (!w || !h || w > 16384 || h > 16384 || stride < (uint64_t)w * 4 ||
        stride > (1u << 20) || offset > length) return false;
    uint64_t end = (uint64_t)(h - 1) * stride + (uint64_t)w * 4;
    return end <= length - offset;
}

/* Preserve both endpoints when resampling, including a one-pixel source. */
static inline uint32_t
polaris_fb_sample(uint32_t value, uint32_t source, uint32_t target)
{
    return source > 1 && target > 1 ?
        (uint32_t)((uint64_t)value * (source - 1) / (target - 1)) : 0;
}

static inline uint64_t
polaris_fb_blit(uint8_t *dst, size_t dstlen, uint32_t pw, uint32_t ph,
    uint32_t dstride, uint32_t lw, uint32_t lh,
    const uint8_t *src, size_t srclen, uint32_t sw, uint32_t sh,
    uint32_t sstride, size_t offset, struct polaris_fb_rect a,
    struct polaris_fb_rect b, uint32_t *columns, size_t column_count)
{
    struct polaris_fb_view v;
    if (!dst || !src || !columns || !polaris_fb_fit(pw, ph, lw, lh, &v) ||
        column_count < v.width || !polaris_fb_buffer(pw, ph, dstride, 0, dstlen) ||
        !polaris_fb_buffer(sw, sh, sstride, offset, srclen) ||
        a.x < 0 || a.y < 0 || a.width <= 0 || a.height <= 0 ||
        (uint64_t)a.x + a.width > sw || (uint64_t)a.y + a.height > sh ||
        b.width <= 0 || b.height <= 0 || b.width > 16384 || b.height > 16384 ||
        b.x < -16384 || b.x > 16384 || b.y < -16384 || b.y > 16384)
        return 0;
    /* One division per column/row, none in the inner pixel loop. */
    for (uint32_t x = 0; x < v.width; x++) {
        int64_t logical = polaris_fb_sample(x, lw, v.width);
        int64_t relative = logical - b.x;
        columns[x] = relative < 0 || relative >= b.width ? UINT32_MAX :
            (uint32_t)a.x + polaris_fb_sample((uint32_t)relative,
                (uint32_t)a.width, (uint32_t)b.width);
    }
    uint64_t copied = 0;
    for (uint32_t y = 0; y < v.height; y++) {
        int64_t relative = (int64_t)polaris_fb_sample(y, lh, v.height) - b.y;
        if (relative < 0 || relative >= b.height) continue;
        uint32_t sy = (uint32_t)a.y + polaris_fb_sample((uint32_t)relative,
            (uint32_t)a.height, (uint32_t)b.height);
        const uint8_t *row = src + offset + (uint64_t)sy * sstride;
        uint8_t *out = dst + (uint64_t)(y + v.y) * dstride + (uint64_t)v.x * 4;
        for (uint32_t x = 0; x < v.width; x++) {
            if (columns[x] == UINT32_MAX) continue;
            __builtin_memcpy(out + (uint64_t)x * 4, row + (uint64_t)columns[x] * 4, 4);
            copied++;
        }
    }
    return copied;
}

static inline bool
polaris_fb_black_bars(uint8_t *dst, size_t length, uint32_t pw, uint32_t ph,
    uint32_t stride, uint32_t lw, uint32_t lh)
{
    struct polaris_fb_view v;
    if (!dst || !polaris_fb_fit(pw, ph, lw, lh, &v) ||
        !polaris_fb_buffer(pw, ph, stride, 0, length)) return false;
    for (uint32_t y = 0; y < ph; y++) {
        uint8_t *row = dst + (uint64_t)y * stride;
        for (uint32_t x = 0; x < pw; x++) {
            if (x >= v.x && x < v.x + v.width && y >= v.y && y < v.y + v.height) continue;
            __builtin_memset(row + (uint64_t)x * 4, 0, 4);
        }
    }
    return true;
}
#endif
