/* Bounded file-backed root I/O and nonterminal cache synchronization.
 * Requires runtime-owner.h and runtime-quiesce.h first. The caller holds the
 * SAME native UFS mutex throughout each call. Its callback must independently
 * admit the CDB and report actual descriptor/completion results. These helpers
 * neither open a device nor grant a writable root or permission to reset.
 */
#ifndef POLARIS_RUNTIME_FILE_H
#define POLARIS_RUNTIME_FILE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#ifndef POLARIS_RUNTIME_OWNER_H
#error "runtime-owner.h must precede runtime-file.h"
#endif
#ifndef POLARIS_RUNTIME_QUIESCE_H
#error "runtime-quiesce.h must precede runtime-file.h"
#endif

enum polaris_file_error {
    POLARIS_FILE_OK, POLARIS_FILE_INVALID, POLARIS_FILE_STOPPED, POLARIS_FILE_IO_ERROR
};
struct polaris_file_result {
    unsigned status;
    int io_error;
    uint32_t transferred;
};
typedef int (*polaris_file_transfer_fn)(void *, uint64_t, uint32_t, void *, bool);

/* Maps only a previously verified, disjoint owner map. Every chunk remains
 * inside ONE extent, the filesystem bound, READ/WRITE10's LBA range and the
 * native bounce capacity. A partial write first reads the whole device block;
 * read or write failures stop immediately without advancing residual bytes.
 */
static inline struct polaris_file_result
polaris_file_io(const struct polaris_owner_work *w, uint64_t offset,
    uint32_t bytes, void *buffer, void *bounce, uint32_t bounce_bytes,
    bool read, bool halted, polaris_file_transfer_fn transfer, void *context)
{
    struct polaris_file_result out={POLARIS_FILE_INVALID,0,0};
    if (!w || !w->metadata_verified || !w->admitted || w->error || !w->file_blocks ||
        w->file_blocks > UINT64_MAX/4096 || !w->map_count || w->map_count>POLARIS_OWNER_MAPS ||
        !w->filesystem_blocks || w->filesystem_blocks>w->partition_blocks ||
        !bounce || !bounce_bytes || bounce_bytes>1u<<20 || bounce_bytes%4096 ||
        !transfer || (bytes && !buffer) || offset>w->file_blocks*4096 ||
        bytes>w->file_blocks*4096-offset) return out;
    if (halted) {out.status=POLARIS_FILE_STOPPED;return out;}
    while (out.transferred<bytes) {
        uint64_t position=offset+out.transferred,logical=position/4096;
        uint32_t skip=(uint32_t)(position%4096),remaining=bytes-out.transferred;
        const struct polaris_owner_extent *extent=NULL;
        for (unsigned i=0;i<w->map_count;i++) {
            const struct polaris_owner_extent *e=&w->map[i];
            if (logical>=e->logical && logical-e->logical<e->blocks) {extent=e;break;}
        }
        if (!extent) return out;
        uint64_t within=logical-extent->logical;
        if (extent->physical>UINT64_MAX-within) return out;
        uint64_t physical=extent->physical+within,available=extent->blocks-within;
        uint64_t wanted=((uint64_t)skip+remaining+4095)/4096;
        uint32_t blocks=bounce_bytes/4096;
        if (wanted<blocks) blocks=(uint32_t)wanted;
        if (available<blocks) blocks=(uint32_t)available;
        if (!blocks || physical>UINT32_MAX || blocks-1>UINT32_MAX-physical ||
            physical<w->partition_start || physical-w->partition_start>=w->filesystem_blocks ||
            blocks>w->filesystem_blocks-(physical-w->partition_start)) return out;
        uint32_t chunk=blocks*4096-skip;
        if (remaining<chunk) chunk=remaining;
        if (read || skip || chunk!=blocks*4096) {
            int error=transfer(context,physical,blocks,bounce,false);
            if (error) {out.status=POLARIS_FILE_IO_ERROR;out.io_error=error;return out;}
        }
        if (read) {
            __builtin_memcpy((uint8_t *)buffer+out.transferred,(uint8_t *)bounce+skip,chunk);
        } else {
            __builtin_memcpy((uint8_t *)bounce+skip,(const uint8_t *)buffer+out.transferred,chunk);
            int error=transfer(context,physical,blocks,bounce,true);
            if (error) {out.status=POLARIS_FILE_IO_ERROR;out.io_error=error;return out;}
        }
        out.transferred+=chunk;
    }
    out.status=POLARIS_FILE_OK;
    return out;
}

/* HFS fsync/cache-flush while mounted MUST NOT enter terminal SAFE. This
 * operation excludes data I/O under the native mutex and records a completed
 * device flush at its captured write epoch. Even an up-to-date running flush
 * never replaces the final post-unmount, sealed queue flush/CPU park.
 */
struct polaris_file_sync {
    uint64_t cookie,epoch;
    uint32_t phase;
    bool active;
};
static inline bool polaris_file_sync_begin(struct polaris_q *q,struct polaris_file_sync *s)
{
    if (!q || !s || s->active || !q->cookie || q->error || q->inflight ||
        q->pending_bytes || q->pending_write || q->flushed_epoch>q->write_epoch ||
        (q->phase!=POLARIS_Q_RUNNING && q->phase!=POLARIS_Q_REQUESTED)) return false;
    s->cookie=q->cookie;s->epoch=q->write_epoch;s->phase=q->phase;s->active=true;
    q->inflight=true;
    return true;
}
static inline bool polaris_file_sync_complete(struct polaris_q *q,struct polaris_file_sync *s,
    bool command_completed,bool success)
{
    if (!q || !s || !s->active) return false;
    if (q->error || !q->inflight || q->cookie!=s->cookie || q->write_epoch!=s->epoch ||
        q->phase!=s->phase || (s->phase!=POLARIS_Q_RUNNING && s->phase!=POLARIS_Q_REQUESTED) ||
        q->pending_bytes || q->pending_write || !command_completed)
        return polaris_q_fail(q,POLARIS_Q_IO_ERROR); /* Unknown completion retains inflight. */
    q->inflight=false;s->active=false;
    if (!success) return polaris_q_fail(q,POLARIS_Q_IO_ERROR);
    q->flushed_epoch=s->epoch;
    return true; /* q->phase is RUNNING/REQUESTED, never SAFE. */
}
#endif
