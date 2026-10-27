/* Serialized runtime I/O/shutdown policy, not wired to the native driver yet.
 * A caller must supply REAL VFS mount/buffer counts and actual UFS completion
 * results. Unit tests of this policy do not prove kernel shutdown or durability.
 * No timer, host ACK, panic path or retry can manufacture a safe-reset state.
 */
#ifndef POLARIS_RUNTIME_QUIESCE_H
#define POLARIS_RUNTIME_QUIESCE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
enum polaris_q_phase {POLARIS_Q_OFF,POLARIS_Q_RUNNING,POLARIS_Q_REQUESTED,
    POLARIS_Q_SEALED,POLARIS_Q_FLUSHING,POLARIS_Q_SAFE,POLARIS_Q_FAILED};
enum polaris_q_error {POLARIS_Q_NO_ERROR,POLARIS_Q_IO_ERROR,POLARIS_Q_COUNTER_ERROR};
struct polaris_q {
    uint64_t cookie,write_epoch,flushed_epoch;
    uint32_t sequence,mode,phase,error,pending_bytes;
    bool inflight,pending_write;
};
struct polaris_shutdown_request {
    uint64_t cookie;uint32_t sequence,mode;uint8_t reserved[112];
} __attribute__((aligned(128)));
struct polaris_shutdown_status {
    uint64_t cookie;uint32_t sequence,mode,phase,error;
    uint64_t write_epoch,flushed_epoch;uint32_t capabilities;uint8_t reserved[84];
} __attribute__((aligned(128)));
struct polaris_shutdown_slot {
    struct polaris_shutdown_request firmware;
    struct polaris_shutdown_status kernel;
} __attribute__((aligned(128)));
_Static_assert(sizeof(struct polaris_shutdown_request)==128,"firmware cacheline ownership");
_Static_assert(sizeof(struct polaris_shutdown_status)==128,"kernel cacheline ownership");
_Static_assert(offsetof(struct polaris_shutdown_slot,kernel)==128,"separate producer cachelines");
_Static_assert(sizeof(struct polaris_shutdown_slot)==256,"bounded shutdown mailbox");
#define POLARIS_Q_SAFE_CAPABILITIES 0x1fu
static inline bool polaris_q_init(struct polaris_q *q,uint64_t cookie,bool owner_admitted)
{
    /* Fresh zeroed boot storage only; never clear sticky errors to retry. */
    if(!q||q->phase||q->cookie||q->write_epoch||q->flushed_epoch||q->sequence||
       q->mode||q->error||q->pending_bytes||q->inflight||q->pending_write||
       !cookie||!owner_admitted)return false;
    q->cookie=cookie;q->phase=POLARIS_Q_RUNNING;return true;
}
static inline bool polaris_q_fail(struct polaris_q *q,unsigned error)
{q->phase=POLARIS_Q_FAILED;q->error=error;return false;}
/* Call under the same native mutex as descriptor construction/completion. */
static inline bool polaris_q_begin(struct polaris_q *q,uint32_t bytes,bool write)
{
    if(!q||(q->phase!=POLARIS_Q_RUNNING&&q->phase!=POLARIS_Q_REQUESTED)||q->error||
       q->inflight||!bytes||bytes>1u<<20||bytes%4096)return false;
    if(write){
        if(q->write_epoch==UINT64_MAX)return polaris_q_fail(q,POLARIS_Q_COUNTER_ERROR);
        q->write_epoch++;
    }
    q->inflight=true;q->pending_write=write;q->pending_bytes=bytes;return true;
}
static inline bool polaris_q_complete(struct polaris_q *q,bool command_completed,
    bool success,uint32_t transferred)
{
    if(!q||!q->inflight||(q->phase!=POLARIS_Q_RUNNING&&q->phase!=POLARIS_Q_REQUESTED))return false;
    if(!command_completed)return polaris_q_fail(q,POLARIS_Q_IO_ERROR); /* Retain unknown DMA. */
    q->inflight=false;
    if(!success||transferred!=q->pending_bytes)return polaris_q_fail(q,POLARIS_Q_IO_ERROR);
    q->pending_bytes=0;q->pending_write=false;return true;
}
static inline bool polaris_q_request(struct polaris_q *q,uint64_t cookie,
    uint32_t sequence,unsigned mode)
{
    if(!q||!cookie||cookie!=q->cookie||!sequence||(mode!=1&&mode!=2)||q->error)return false;
    if(q->phase>=POLARIS_Q_REQUESTED&&q->phase<=POLARIS_Q_SAFE)
        return sequence==q->sequence&&mode==q->mode; /* Exact idempotent retry only. */
    if(q->phase!=POLARIS_Q_RUNNING||sequence<=q->sequence)return false;
    q->sequence=sequence;q->mode=mode;q->phase=POLARIS_Q_REQUESTED;return true;
}
/* Only AFTER real reboot_kernel() process exit, complete VFS unmount and zero
 * busy buffers. The native mutex must also exclude strategy/IOCTL submissions.
 * An unfinished mount, busy buffer or transfer leaves reset unavailable. */
static inline bool polaris_q_seal(struct polaris_q *q,unsigned mounts,unsigned busy)
{
    if(!q||q->phase!=POLARIS_Q_REQUESTED||q->inflight||q->error||mounts||busy)return false;
    q->phase=POLARIS_Q_SEALED;return true;
}
static inline bool polaris_q_flush_begin(struct polaris_q *q)
{
    if(!q||q->phase!=POLARIS_Q_SEALED||q->inflight||q->error)return false;
    q->inflight=true;q->phase=POLARIS_Q_FLUSHING;return true;
}
static inline bool polaris_q_flush_complete(struct polaris_q *q,bool command_completed,bool success)
{
    if(!q||q->phase!=POLARIS_Q_FLUSHING||!q->inflight)return false;
    if(!command_completed)return polaris_q_fail(q,POLARIS_Q_IO_ERROR);
    q->inflight=false;
    if(!success)return polaris_q_fail(q,POLARIS_Q_IO_ERROR);
    q->flushed_epoch=q->write_epoch;q->phase=POLARIS_Q_SAFE;return true;
}
static inline struct polaris_shutdown_status polaris_q_status(const struct polaris_q *q)
{
    struct polaris_shutdown_status out={0};
    if(!q)return out;
    out.cookie=q->cookie;out.sequence=q->sequence;out.mode=q->mode;
    out.phase=q->phase;out.error=q->error;out.write_epoch=q->write_epoch;out.flushed_epoch=q->flushed_epoch;
    if(q->phase==POLARIS_Q_SAFE&&!q->error&&!q->inflight&&q->flushed_epoch==q->write_epoch)
        out.capabilities=POLARIS_Q_SAFE_CAPABILITIES;
    return out;
}
/* Firmware must invalidate its kernel-owned128byte line before copying it.
 * Kernel publishes only after final cache sync, IO sealing and IRQ masking,
 * cleans its own line to PoC, then parks. Neither side writes the other's line.
 * These cache/IRQ operations are integration work, not performed by this model.
 */
static inline bool polaris_q_reset_ready(const struct polaris_shutdown_status *status,
    uint64_t cookie,uint32_t sequence,unsigned mode)
{
    return status&&cookie&&sequence&&(mode==1||mode==2)&&status->cookie==cookie&&
        status->sequence==sequence&&status->mode==mode&&status->phase==POLARIS_Q_SAFE&&
        !status->error&&status->write_epoch==status->flushed_epoch&&
        status->capabilities==POLARIS_Q_SAFE_CAPABILITIES;
}
#endif
