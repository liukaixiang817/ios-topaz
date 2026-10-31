/* Polaris legacy-SMEM GLINK/QRTR transport. See polaris-wifi-glink.c for
 * Dipper original MIT notice and adaptation provenance. No hardware startup. */
#ifndef POLARIS_WIFI_GLINK_H
#define POLARIS_WIFI_GLINK_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "polaris-glink-inventory.h"

struct polaris_wifi_qrtr_port;
typedef void (*polaris_wifi_qrtr_receive_t)(void *, uint32_t, uint32_t, const void *, size_t);
typedef void (*polaris_wifi_qrtr_server_t)(void *, bool, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
/* Same callback contract as the pinned HackiOS native QRTR interface. The
 * caller can bridge it explicitly; do not cast foreign port objects. */
struct polaris_wifi_qrtr_ops {
    struct polaris_wifi_qrtr_port *(*open)(polaris_wifi_qrtr_receive_t, polaris_wifi_qrtr_server_t, void *);
    int (*send)(struct polaris_wifi_qrtr_port *, uint32_t, uint32_t, const void *, size_t);
    int (*lookup)(struct polaris_wifi_qrtr_port *, uint32_t, uint32_t, uint32_t);
    void (*close)(struct polaris_wifi_qrtr_port *);
};
enum polaris_wifi_fault {
    PWF_OK, PWF_SCOPE, PWF_BOUNDS, PWF_READ, PWF_CACHE, PWF_WRITE,
    PWF_ORDER, PWF_RING, PWF_PROTOCOL, PWF_CLOCK, PWF_PENDING
};
struct polaris_wifi_glink_cfg {
    uint64_t epoch, smem_phys;
    uint32_t smem_bytes, local_node;
    struct polaris_glink_layout layout;
    /* Mandatory native lifetime/ownership gate. Must establish an existing own
     * DT mapping of SMEM 0x86000000/2MiB, MPU access, exclusive APPS TX producer /
     * RX consumer, stable selected inventory, remote lifecycle, and correct
     * own doorbell ownership for this epoch. Inventory alone is insufficient.
     * Must be read-only and fail on stale/unknown; never call SMEM Get/Alloc. */
    bool (*scope)(void *, uint64_t, const struct polaris_glink_layout *);
    bool (*smem_read)(void *, uint32_t, void *, uint32_t);
    /* Success means known full 32-bit write; failure is uncertain and sticky. */
    bool (*smem_write32)(void *, uint32_t, uint32_t);
    bool (*invalidate)(void *, uint32_t, uint32_t);
    /* Platform device/cache barrier, not merely a compiler barrier. */
    bool (*order)(void *);
    /* Own DT mpss route if this is its admitted edge (0x1799000c bit12),
     * not a WCN6750/IPCC host13 route. No built-in MMIO callback is supplied. */
    bool (*ring)(void *);
    void (*sleep_us)(void *, uint32_t);
    uint64_t (*now_us)(void *);
    void (*log)(void *, const char *, ...);
    void *ctx;
};
struct polaris_wifi_qrtr_server { uint32_t service, version, instance, node, port; };
struct polaris_wifi_glink_status {
    uint64_t epoch;
    uint32_t first_error, detail, reads, writes, rings, cache_ops;
    bool up, opened, peer_seen, stopping, uncertain, pending, quiescent;
};
#define POLARIS_WIFI_GLINK_MAX_DATAGRAM (65536u - 32u)
struct polaris_wifi_glink;
struct polaris_wifi_glink *polaris_wifi_glink_create(const struct polaris_wifi_glink_cfg *);
int polaris_wifi_glink_start(struct polaris_wifi_glink *);
int polaris_wifi_glink_poll_once(struct polaris_wifi_glink *);
int polaris_wifi_glink_close_port(struct polaris_wifi_qrtr_port *);
int polaris_wifi_glink_status(struct polaris_wifi_glink *, struct polaris_wifi_glink_status *);
/* stop is nonblocking: EBUSY while ports/data/intents/CLOSE_ACK remain. Keep
 * polling on the same lease, close clients, then call stop again. Broken or
 * uncertain never becomes quiescent through retry. No raw reset fallback. */
int polaris_wifi_glink_stop(struct polaris_wifi_glink *);
/* Callers must quiesce and discard all handles first. Rejects active/broken. */
int polaris_wifi_glink_destroy(struct polaris_wifi_glink *);
const struct polaris_wifi_qrtr_ops *polaris_wifi_glink_qrtr_ops(struct polaris_wifi_glink *);
int polaris_wifi_glink_qrtr_servers(struct polaris_wifi_glink *, struct polaris_wifi_qrtr_server *, unsigned);
int polaris_wifi_glink_qrtr_publish(struct polaris_wifi_glink *, struct polaris_wifi_qrtr_port *, uint32_t, uint32_t, uint32_t);
/* API/callback gate is a bounded try gate. Callbacks may send/lookup/close,
 * nesting <=4; never wait for another caller. Lifecycle outside callbacks.
 * send success means copied to ordered SMEM TX, NOT remote DONE / firmware
 * start / radio scan / association; transport stop additionally waits DONE. */
#endif
