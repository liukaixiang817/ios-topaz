/* Bounded physical-read adapter for an ALREADY mapped own-DT SMEM span.
 * This inventories live metadata and FIFO indices; it grants no write lease. */
#ifndef POLARIS_WIFI_SMEM_PROBE_H
#define POLARIS_WIFI_SMEM_PROBE_H
#include "polaris-glink-inventory.h"
#define PWF_SMEM_PHYSICAL UINT64_C(0x86000000)
#define PWF_SMEM_BYTES 0x200000u
#define PWF_SMEM_PAGES (PWF_SMEM_BYTES / 4096u)
struct polaris_wifi_probe_io {
    void *context;
    uintptr_t virtual_base;
    uint64_t epoch;
    /* Native callback: read-only identity/lifetime check; no Get/Alloc. */
    bool (*live)(void *, uint64_t);
    /* Return actual translated PA and raw architectural PAR for this mapping.
     * Caller must check current EL/regime before AT. Failure never dereferences. */
    bool (*translate_read)(void *, uintptr_t, uint64_t *, uint64_t *);
    /* Must be fault-contained: an MPU/bus denial returns false; do not install
     * a mapping or probe arbitrary MMIO to make this callback succeed. */
    bool (*read)(void *, uintptr_t, void *, size_t);
    bool (*order)(void *);
};
struct polaris_wifi_probe_result {
    uint64_t epoch;
    uint32_t pages, reads, error, error_offset;
    struct polaris_glink_layout layout;
    uint8_t descriptor[32];
    uint32_t tx_consumer, tx_producer, rx_consumer, rx_producer;
    bool metadata_stable, descriptor_stable, queues_empty;
    /* Translation/readability never proves MPU programming/exclusive owner. */
    bool mpu_verified, exclusive_owner_verified, may_transmit;
};
struct polaris_wifi_probe_workspace {
    struct polaris_glink_workspace inventory;
    struct polaris_wifi_probe_result candidate;
    uint64_t page_par[PWF_SMEM_PAGES]; /* Actual before and after must match. */
    const struct polaris_wifi_probe_io *io;
};
static inline bool pwfp_error(struct polaris_wifi_probe_workspace *w, uint32_t error, uint32_t at)
{ if (!w->candidate.error) { w->candidate.error = error; w->candidate.error_offset = at; } return false; }
static inline bool pwfp_read(void *ctx, uint32_t at, void *dst, size_t n)
{
    struct polaris_wifi_probe_workspace *w = ctx;
    const struct polaris_wifi_probe_io *io = w->io;
    if (!n || at > PWF_SMEM_BYTES || n > PWF_SMEM_BYTES - at ||
        !io->live(io->context, io->epoch) || !io->order(io->context)) return pwfp_error(w, 2, at);
    w->candidate.reads++;
    if (!io->read(io->context, io->virtual_base + at, dst, n) || !io->order(io->context))
        return pwfp_error(w, 3, at);
    return true;
}
static inline bool pwfp_pages(struct polaris_wifi_probe_workspace *w, bool before)
{
    const struct polaris_wifi_probe_io *io = w->io;
    for (uint32_t i = 0; i < PWF_SMEM_PAGES; i++) {
        uint64_t physical = 0, par = 0;
        if (!io->live(io->context, io->epoch) ||
            !io->translate_read(io->context, io->virtual_base + i * 4096u, &physical, &par) ||
            (par & 1) || physical != PWF_SMEM_PHYSICAL + i * 4096u ||
            (!before && par != w->page_par[i])) return pwfp_error(w, 4, i * 4096u);
        if (before) { w->page_par[i] = par; w->candidate.pages++; }
    }
    return true;
}
/* Workspace is caller-owned reserved memory, never a kernel/UEFI stack object.
 * Result is populated even on failure, preserving the first failed stage.
 * No write/ring/SMEM protocol callback exists in this API. */
static inline bool polaris_wifi_smem_probe(const struct polaris_wifi_probe_io *io,
    uint32_t own_remote, struct polaris_wifi_probe_result *out, struct polaris_wifi_probe_workspace *w)
{
    if (!out) return false;
    uint8_t *result_zero = (uint8_t *)out;
    for (size_t i = 0; i < sizeof(*out); i++) result_zero[i] = 0;
    out->error = 1;
    if (!io || !w || !own_remote || own_remote >= PSM_HOST_COUNT || !io->epoch || !io->virtual_base ||
        (io->virtual_base & 4095u) || UINTPTR_MAX - io->virtual_base < PWF_SMEM_BYTES ||
        !io->live || !io->translate_read || !io->read || !io->order) return false;
    uint8_t *zero = (uint8_t *)&w->candidate;
    for (size_t i = 0; i < sizeof(w->candidate); i++) zero[i] = 0;
    w->io = io; w->candidate.epoch = io->epoch;
    struct polaris_smem_reader reader = { pwfp_read, w, PWF_SMEM_BYTES };
    uint8_t after[32];
    bool ok = pwfp_pages(w, true) &&
        polaris_glink_inventory(&reader, own_remote, &w->candidate.layout, &w->inventory);
    if (!ok) { if (!w->candidate.error) pwfp_error(w, 5, 0); goto done; }
    w->candidate.metadata_stable = true;
    uint32_t desc = w->candidate.layout.descriptor.offset;
    ok = pwfp_read(w, desc, w->candidate.descriptor, 32) && pwfp_read(w, desc, after, 32) &&
        psm_equal(w->candidate.descriptor, after, 32);
    if (!ok) { if (!w->candidate.error) pwfp_error(w, 6, desc); goto done; }
    w->candidate.descriptor_stable = true;
    w->candidate.tx_consumer = psm_u32(after);
    w->candidate.tx_producer = psm_u32(after + 4);
    w->candidate.rx_consumer = psm_u32(after + 8);
    w->candidate.rx_producer = psm_u32(after + 12);
    if (((w->candidate.tx_consumer | w->candidate.tx_producer |
          w->candidate.rx_consumer | w->candidate.rx_producer) & 7) ||
        w->candidate.tx_consumer >= w->candidate.layout.tx.bytes ||
        w->candidate.tx_producer >= w->candidate.layout.tx.bytes ||
        w->candidate.rx_consumer >= w->candidate.layout.rx.bytes ||
        w->candidate.rx_producer >= w->candidate.layout.rx.bytes) {
        ok = pwfp_error(w, 7, desc); goto done;
    }
    w->candidate.queues_empty = w->candidate.tx_consumer == w->candidate.tx_producer &&
        w->candidate.rx_consumer == w->candidate.rx_producer;
    struct polaris_glink_layout after_layout;
    ok = polaris_glink_inventory(&reader, own_remote, &after_layout, &w->inventory) &&
        psm_equal((const uint8_t *)&w->candidate.layout, (const uint8_t *)&after_layout, sizeof(after_layout)) &&
        pwfp_pages(w, false) && io->live(io->context, io->epoch);
    if (!ok && !w->candidate.error) pwfp_error(w, 8, 0);
done:
    *out = w->candidate;
    return ok;
}
int polaris_wifi_smem_readonly_probe(const struct polaris_wifi_probe_io *, uint32_t,
    struct polaris_wifi_probe_result *, struct polaris_wifi_probe_workspace *);
#endif
