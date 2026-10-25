/* A630 GMU host/firmware ABI, independently implemented from the original
 * MiCode polaris driver at c7cb50c18f812629b9620b2b8fa684bc40d82080:
 * drivers/gpu/msm/kgsl_hfi.{c,h}. No MMIO, power control or GPU submission.
 *
 * The gated polaris hardware adapter must serialize host producers, use
 * compatible noncacheable shared pages (or safe DMA cache maintenance), and
 * ring the GMU doorbell AFTER publishing a command. CPU release/acquire
 * alone does not make a noncoherent device see this memory.
 */
#ifndef POLARIS_A630_HFI_H
#define POLARIS_A630_HFI_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define A630_HFI_BYTES 16384u
#define A630_HFI_QUEUES 3u
#define A630_HFI_QUEUE_WORDS 1024u
#define A630_HFI_GUARD_BYTES 16u
#define A630_HFI_MAX_WORDS 255u
struct a630_hfi_queue {
    uint32_t status, start_addr, type, queue_size, msg_size, drop_count;
    uint32_t rx_watermark, tx_watermark, rx_request, tx_request;
    uint32_t read_index, write_index;
};
struct a630_hfi_table {
    uint32_t version, size, header_offset, header_size, queues, active;
    struct a630_hfi_queue q[A630_HFI_QUEUES];
};
enum a630_hfi_error {
    A630_HFI_INVALID = -1, A630_HFI_FULL = -2,
    A630_HFI_PACKET = -3, A630_HFI_OUTPUT = -4
};

static inline uint32_t a630_hfi_offset(unsigned queue)
{
    return (uint32_t)sizeof(struct a630_hfi_table) +
        queue * (A630_HFI_QUEUE_WORDS * 4 + A630_HFI_GUARD_BYTES);
}

static inline bool a630_hfi_memory(const void *memory, size_t bytes, uint32_t iova)
{
    return memory && !((uintptr_t)memory & 3) && bytes == A630_HFI_BYTES &&
        !(iova & (A630_HFI_BYTES - 1)) && iova >= 0x60000000u &&
        (uint64_t)iova + bytes <= 0x80000000ull;
}

static inline bool a630_hfi_init(void *memory, size_t bytes, uint32_t iova)
{
    if (!a630_hfi_memory(memory, bytes, iova)) return false;
    __builtin_memset(memory, 0, bytes);
    struct a630_hfi_table *t = (struct a630_hfi_table *)memory;
    t->size = (uint32_t)sizeof(*t) / 4;
    t->header_offset = 6;
    t->header_size = (uint32_t)sizeof(t->q[0]) / 4;
    t->queues = t->active = A630_HFI_QUEUES;
    for (unsigned i = 0; i < A630_HFI_QUEUES; i++) {
        struct a630_hfi_queue *q = &t->q[i];
        q->status = 1;
        q->start_addr = iova + a630_hfi_offset(i);
        /* Original firmware queue IDs0/4/5, priorities10/10/40. */
        q->type = i == 0 ? 0x0a00 : i == 1 ? 0x0a04 : 0x2805;
        q->queue_size = A630_HFI_QUEUE_WORDS;
        q->rx_watermark = q->tx_watermark = q->rx_request = 1;
    }
    return true;
}

static inline struct a630_hfi_queue *
a630_hfi_queue(void *memory, size_t bytes, uint32_t iova, unsigned queue)
{
    if (!a630_hfi_memory(memory, bytes, iova) || queue >= A630_HFI_QUEUES) return NULL;
    struct a630_hfi_table *t = (struct a630_hfi_table *)memory;
    if (t->version || t->size != 42 || t->header_offset != 6 ||
        t->header_size != 12 || t->queues != 3 || t->active != 3) return NULL;
    struct a630_hfi_queue *q = &t->q[queue];
    uint32_t want_type = queue == 0 ? 0x0a00 : queue == 1 ? 0x0a04 : 0x2805;
    if (q->status != 1 || q->start_addr != iova + a630_hfi_offset(queue) ||
        q->type != want_type || q->queue_size != A630_HFI_QUEUE_WORDS || q->msg_size)
        return NULL;
    return q;
}

static inline bool a630_hfi_header(unsigned id, unsigned words, unsigned type,
    unsigned sequence, uint32_t *out)
{
    if (!out || id > 255 || !words || words > A630_HFI_MAX_WORDS ||
        type > 2 || sequence > 4095) return false;
    *out = id | (words << 8) | (type << 16) | (sequence << 20);
    return true;
}

/* Command ring only. One slot remains empty so full never resembles empty.
 * A positive return means RAM enqueue only, not delivery/execution by GMU. */
static inline int a630_hfi_push(void *memory, size_t bytes, uint32_t iova,
    const uint32_t *message, unsigned words)
{
    struct a630_hfi_queue *q = a630_hfi_queue(memory, bytes, iova, 0);
    if (!q) return A630_HFI_INVALID;
    if (!message || !words || words > A630_HFI_MAX_WORDS ||
        ((message[0] >> 8) & 255) != words || ((message[0] >> 16) & 15) > 1)
        return A630_HFI_PACKET;
    uint32_t read = __atomic_load_n(&q->read_index, __ATOMIC_ACQUIRE);
    uint32_t write = __atomic_load_n(&q->write_index, __ATOMIC_RELAXED);
    if (read >= A630_HFI_QUEUE_WORDS || write >= A630_HFI_QUEUE_WORDS) return A630_HFI_INVALID;
    uint32_t free = (read + A630_HFI_QUEUE_WORDS - write - 1) % A630_HFI_QUEUE_WORDS;
    if (words > free) return A630_HFI_FULL;
    uint32_t *ring = (uint32_t *)((uint8_t *)memory + a630_hfi_offset(0));
    for (unsigned i = 0; i < words; i++) {
        ring[write] = message[i];
        write = (write + 1) % A630_HFI_QUEUE_WORDS;
    }
    __atomic_store_n(&q->write_index, write, __ATOMIC_RELEASE);
    return (int)words;
}

/* Firmware response/debug rings only. Malformed/truncated packets leave the
 * read cursor unchanged; the adapter must stop and diagnose the channel. */
static inline int a630_hfi_pop(void *memory, size_t bytes, uint32_t iova,
    unsigned queue, uint32_t *out, unsigned capacity)
{
    if (queue != 1 && queue != 2) return A630_HFI_INVALID;
    struct a630_hfi_queue *q = a630_hfi_queue(memory, bytes, iova, queue);
    if (!q) return A630_HFI_INVALID;
    uint32_t read = __atomic_load_n(&q->read_index, __ATOMIC_RELAXED);
    uint32_t write = __atomic_load_n(&q->write_index, __ATOMIC_ACQUIRE);
    if (read >= A630_HFI_QUEUE_WORDS || write >= A630_HFI_QUEUE_WORDS) return A630_HFI_INVALID;
    if (read == write) return 0;
    uint32_t *ring = (uint32_t *)((uint8_t *)memory + a630_hfi_offset(queue));
    unsigned words = (ring[read] >> 8) & 255;
    unsigned used = (write + A630_HFI_QUEUE_WORDS - read) % A630_HFI_QUEUE_WORDS;
    if (!words || words > used || ((ring[read] >> 16) & 15) > 2)
        return A630_HFI_PACKET;
    if (!out || words > capacity) return A630_HFI_OUTPUT;
    for (unsigned i = 0; i < words; i++) {
        out[i] = ring[read];
        read = (read + 1) % A630_HFI_QUEUE_WORDS;
    }
    __atomic_store_n(&q->read_index, read, __ATOMIC_RELEASE);
    return (int)words;
}
#endif
