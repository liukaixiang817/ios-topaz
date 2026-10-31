/* Own-NV RAM shadow service over the admitted Polaris GLINK/QRTR transport.
 * No partition writes, physical allocation, SCM call, or radio startup. */
#ifndef POLARIS_WIFI_RMTFS_H
#define POLARIS_WIFI_RMTFS_H
#include "polaris-wifi-glink.h"

enum polaris_rmtfs_part { PWR_MODEMST1, PWR_MODEMST2, PWR_FSG, PWR_FSC, PWR_PARTS };
struct polaris_rmtfs_input {
    const void *data; /* Entire verified, owned, immutable RAM input. */
    uint32_t bytes;
    uint8_t sha256[32];
};
struct polaris_rmtfs_cfg {
    struct polaris_wifi_glink *transport;
    uint64_t epoch;
    uint32_t remote_node;
    /* Own DT: client1, dynamic2MiB + guard-memory. No default PA is supplied.
     * The provider must independently allocate/share/guard these exact pages;
     * camera/modem reserved ranges are NOT an allocation or a lease. */
    uint64_t shared_phys;
    uint32_t shared_bytes;
    struct polaris_rmtfs_input inputs[PWR_PARTS];
    /* Revalidate fresh whole-NV/GPT provenance, all input RAM lifetimes, and
     * selected remote epoch. Historical backup digests alone must fail. */
    bool (*inputs_current)(void *, const struct polaris_rmtfs_cfg *);
    /* Read-only admission: exact PA/size/guards, MPU/VMID, owned cache mapping,
     * selected MSS node/lifetime and no competing producer. Never grants it. */
    bool (*scope)(void *, uint64_t, uint32_t, uint64_t, uint32_t);
    /* Relative to shared_phys; must check the same scope at actual access.
     * read includes required RX invalidate; write includes TX clean/completion.
     * false may mean partial access: service retains UNKNOWN, never retries. */
    bool (*shared_read)(void *, uint64_t, uint32_t, void *, uint32_t);
    bool (*shared_write)(void *, uint64_t, uint32_t, const void *, uint32_t);
    bool (*order)(void *); /* Actual device/cache barrier, not compiler-only. */
    /* True only after actual remote stop/DMA drain and shared-memory handback.
     * Required after transport DONE before releasing any exposed RAM shadow. */
    bool (*retired)(void *, uint64_t);
    void *ctx;
};
struct polaris_rmtfs_status {
    uint64_t epoch, bytes_to_shadow, bytes_to_remote;
    uint32_t first_error, received, replied, replayed, rejected_peer;
    uint32_t operations_issued, operations_completed, handles, queued;
    bool started, stopping, stopped, uncertain, dirty;
    bool durable_nv; /* Always false. SYNC acknowledges volatile RAM only. */
};
struct polaris_rmtfs;
struct polaris_rmtfs *polaris_rmtfs_create(const struct polaris_rmtfs_cfg *);
int polaris_rmtfs_start(struct polaris_rmtfs *);
/* Sole workloop polls GLINK then executes queued requests; receive callbacks
 * only enqueue, including callbacks reentered by a synchronous QRTR send.
 * Other GLINK users must use the same workloop; no blocking cross-thread wait. */
int polaris_rmtfs_poll(struct polaris_rmtfs *);
int polaris_rmtfs_status(struct polaris_rmtfs *, struct polaris_rmtfs_status *);
/* EBUSY while handles/requests/DONE/remote retirement remain. Fault/UNKNOWN
 * never becomes releasable by retry; no reset/clear-error/force-free API. */
int polaris_rmtfs_stop(struct polaris_rmtfs *);
int polaris_rmtfs_destroy(struct polaris_rmtfs *);
#endif
