/* Bounded ARM64 frame chain for opt-in, best-effort polaris diagnostics.
 * The reader must only copy an already-resident 16-byte frame, or fail.
 * No heap/stack scan, pointer chasing beyond 1MiB, or target writes. */
#ifndef POLARIS_STACK_WALK_H
#define POLARIS_STACK_WALK_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
enum polaris_bt_stop { POLARIS_BT_END, POLARIS_BT_INVALID,
    POLARIS_BT_UNMAPPED, POLARIS_BT_LIMIT, POLARIS_BT_DISABLED };
struct polaris_bt_result { unsigned count, stop; };
typedef bool (*polaris_frame_read)(void *, uint64_t, uint64_t [2]);
static inline struct polaris_bt_result
polaris_walk_frames(uint64_t sp, uint64_t fp, uint64_t *out, unsigned capacity,
    polaris_frame_read read_frame, void *context)
{
    struct polaris_bt_result result = {0, POLARIS_BT_END};
    uint64_t upper = sp > UINT64_MAX - 1048576 ? UINT64_MAX : sp + 1048576;
    while (fp) {
        uint64_t frame[2];
        if ((fp & 15) || fp < sp || fp > upper || upper - fp < 16) {
            result.stop = POLARIS_BT_INVALID; break;
        }
        if (result.count == capacity) { result.stop = POLARIS_BT_LIMIT; break; }
        if (!read_frame(context, fp, frame)) { result.stop = POLARIS_BT_UNMAPPED; break; }
        if (!frame[1]) { break; }
        out[result.count++] = frame[1];
        if (!frame[0]) { break; }
        if (frame[0] <= fp) { result.stop = POLARIS_BT_INVALID; break; }
        fp = frame[0];
    }
    return result;
}
#endif
