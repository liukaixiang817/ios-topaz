/* Cacheable scanline gather followed by one contiguous panel copy.
 * Include polaris-display-blit.h first. Caller supplies private persistent
 * row/column workspaces and serializes presentation with panel capture.
 */
#ifndef POLARIS_DISPLAY_STAGED_H
#define POLARIS_DISPLAY_STAGED_H
#ifndef POLARIS_DISPLAY_BLIT_H
#error Include the original Polaris display geometry helpers first
#endif
static inline uint64_t
polaris_fb_blit_staged(uint8_t *dst, size_t dstlen, uint32_t pw, uint32_t ph,
    uint32_t dstride, uint32_t lw, uint32_t lh,
    const uint8_t *src, size_t srclen, uint32_t sw, uint32_t sh,
    uint32_t sstride, size_t offset, struct polaris_fb_rect a,
    struct polaris_fb_rect b, uint32_t *columns, size_t column_count,
    uint32_t *row_buffer, size_t row_count)
{
    struct polaris_fb_view v;
    if (!dst || !src || !columns || !row_buffer ||
        !polaris_fb_fit(pw, ph, lw, lh, &v) || column_count < v.width ||
        row_count < v.width || !polaris_fb_buffer(pw, ph, dstride, 0, dstlen) ||
        !polaris_fb_buffer(sw, sh, sstride, offset, srclen) ||
        a.x < 0 || a.y < 0 || a.width <= 0 || a.height <= 0 ||
        (uint64_t)a.x + a.width > sw || (uint64_t)a.y + a.height > sh ||
        b.width <= 0 || b.height <= 0 || b.width > 16384 || b.height > 16384 ||
        b.x < -16384 || b.x > 16384 || b.y < -16384 || b.y > 16384) return 0;
    /* Keep the original sequential semantics for any aliased surfaces. */
    uintptr_t dp = (uintptr_t)dst, sp = (uintptr_t)src;
    if ((dp >= sp && dp - sp < srclen) || (sp >= dp && sp - dp < dstlen))
        return polaris_fb_blit(dst, dstlen, pw, ph, dstride, lw, lh, src,
            srclen, sw, sh, sstride, offset, a, b, columns, column_count);
    uint32_t first = v.width, end = 0;
    for (uint32_t x = 0; x < v.width; x++) {
        int64_t relative = (int64_t)polaris_fb_sample(x, lw, v.width) - b.x;
        if (relative < 0 || relative >= b.width) continue;
        columns[x] = (uint32_t)a.x + polaris_fb_sample((uint32_t)relative,
            (uint32_t)a.width, (uint32_t)b.width);
        if (first == v.width) first = x;
        end = x + 1;
    }
    if (!end) return 0;
    /* Monotonic logical coordinates make the valid columns contiguous. */
    uint32_t width = end - first;
    uint64_t copied = 0;
    for (uint32_t y = 0; y < v.height; y++) {
        int64_t relative = (int64_t)polaris_fb_sample(y, lh, v.height) - b.y;
        if (relative < 0 || relative >= b.height) continue;
        uint32_t sy = (uint32_t)a.y + polaris_fb_sample((uint32_t)relative,
            (uint32_t)a.height, (uint32_t)b.height);
        const uint8_t *row = src + offset + (uint64_t)sy * sstride;
        for (uint32_t x = first; x < end; x++)
            __builtin_memcpy(row_buffer + x - first, row + (uint64_t)columns[x] * 4, 4);
        uint8_t *out = dst + (uint64_t)(y + v.y) * dstride + (uint64_t)(v.x + first) * 4;
        __builtin_memcpy(out, row_buffer, (size_t)width * 4);
        copied += width;
    }
    return copied;
}
#endif
