#ifndef POLARIS_TOUCH_MAP_H
#define POLARIS_TOUCH_MAP_H

#include <stdint.h>
#include <stdbool.h>

/* Inverse of the verified 1125x2436 -> 997x2160 fit at (41,0).
 * Coordinates refer to physical 1080x2160 pixels, not the old 2400px panel.
 * Letterbox contacts clamp to the adjacent logical edge. */
static inline bool
polaris_touch_map(int x, int y, int32_t *nx, int32_t *ny, bool *edge)
{
    if (!nx || !ny || !edge || x < 0 || x >= 1080 || y < 0 || y >= 2160) {
        return false;
    }
    *edge = x < 48 || x > 1079 - 48 || y < 48 || y > 2159 - 48;
    int vx = x - 41;
    if (vx < 0) { vx = 0; }
    if (vx > 996) { vx = 996; }
    /* The copier maps first/last destination pixels to first/last source
     * pixels; normalize those logical coordinates by the iPhone canvas. */
    *nx = (int32_t)(((int64_t)vx * 1124 * 65536) / (996 * 1125));
    *ny = (int32_t)(((int64_t)y * 2435 * 65536) / (2159 * 2436));
    return true;
}

#endif
