/* Shared, host-testable validation for a read-only FIEMAP snapshot.
 * Inputs and outputs are bytes relative to the containing filesystem.
 * A valid map is still transient: never use it as a raw-write capability.
 */
#ifndef POLARIS_EXTENT_POLICY_H
#define POLARIS_EXTENT_POLICY_H
#include <stdbool.h>
#include <stdint.h>

static inline bool
polaris_extent_valid(uint64_t next, uint64_t logical, uint64_t physical,
    uint64_t length, uint32_t flags, uint64_t file_bytes,
    uint64_t filesystem_bytes, bool last)
{
    /* FIEMAP_EXTENT_LAST = 1 is the only supported flag. In particular,
     * UNKNOWN/DELALLOC/ENCODED/UNWRITTEN/INLINE/SHARED all fail closed. */
    if (flags != (last ? 1u : 0u) || logical != next || !length || !physical ||
        ((logical | physical | length | file_bytes | filesystem_bytes) & 4095)) {
        return false;
    }
    if (logical > file_bytes || length > file_bytes - logical ||
        physical > filesystem_bytes || length > filesystem_bytes - physical) {
        return false;
    }
    return last == (length == file_bytes - logical);
}
#endif
