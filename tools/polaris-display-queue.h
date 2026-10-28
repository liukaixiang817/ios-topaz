/* Latest-frame publication, called only with the framebuffer's existing
 * IOLock held. A wake is a coalesced work-loop poke, never a VSYNC or a
 * synchronous panel copy. The native work loop owns copy/notify deadlines.
 */
#ifndef POLARIS_DISPLAY_QUEUE_H
#define POLARIS_DISPLAY_QUEUE_H
#include <stdint.h>
#include <stdbool.h>
struct pfb_queue {
    uint64_t sequence, ready_us, replaced;
    uint32_t swap;
    bool pending, wake_pending, fault;
};
struct pfb_publication {
    uint64_t sequence, ready_us, replaced;
    uint32_t swap;
};
static inline bool pfb_publish(struct pfb_queue *q, uint64_t now,
    uint32_t swap, bool wake_enabled)
{
    if (!q) return false;
    if (q->fault || !now || q->sequence == UINT64_MAX || now < q->ready_us) {
        q->fault=true; q->pending=false;
        return false;
    }
    if (q->pending && q->replaced != UINT64_MAX) q->replaced++;
    q->sequence++; q->ready_us=now; q->swap=swap; q->pending=true;
    if (!wake_enabled || q->wake_pending) return false;
    q->wake_pending=true;
    return true;
}
static inline void pfb_wake_consumed(struct pfb_queue *q)
{if (q) q->wake_pending=false;}
static inline bool pfb_take(struct pfb_queue *q, struct pfb_publication *out)
{
    if (!q || !out || q->fault || !q->pending || !q->sequence || !q->ready_us) return false;
    out->sequence=q->sequence; out->ready_us=q->ready_us;
    out->swap=q->swap; out->replaced=q->replaced;
    q->pending=false;
    return true;
}
#endif
