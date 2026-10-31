/* Polaris CCI identity transaction. Register facts: own MiCode c7cb50c1.
 * Independent source; no integration into any existing frozen image.
 * This API never powers/configures clocks, rails, pins, resets or DMA.
 * Under an exclusive whole-CCI/GIC-quiesced lease it temporarily enables ONLY
 * this master's RD_DONE source bit, then restores/readbacks the saved zero mask.
 * A real platform lease verifier is intentionally absent and rejects by default.
 */
#ifndef POLARIS_CAMERA_CCI_ID_H
#define POLARIS_CAMERA_CCI_ID_H
#include <stdint.h>
#ifndef POLARIS_CAMERA_CCI_ENABLE
#define POLARIS_CAMERA_CCI_ENABLE 0
#endif
#ifndef POLARIS_CAMERA_CCI_SOFTWARE_TEST
#define POLARIS_CAMERA_CCI_SOFTWARE_TEST 0
#endif
#if (POLARIS_CAMERA_CCI_ENABLE != 0 && POLARIS_CAMERA_CCI_ENABLE != 1) || \
    (POLARIS_CAMERA_CCI_SOFTWARE_TEST != 0 && POLARIS_CAMERA_CCI_SOFTWARE_TEST != 1)
#error Camera flags must be literal zero or one
#endif
#define PCCI_BASE UINT64_C(0x0ac4a000)
#define PCCI_BYTES 0x4000u
#define PCCI_RAW_CAP 640u
#define PCCI_REQUIRED_FACTS 0x3ffu
/* Facts must be established by the live platform verifier, never by an input
 * file or this struct alone: entire CCI exclusive lifetime; safe identity MMIO;
 * no firmware/AP observer; GIC route and source quiesced; CAMCC source/rate and
 * enabled branches; titan GDSC; selected MCLK; TLMM bus/reset pins; shared rail
 * ownership/settling; complete saved-state + shutdown restoration ownership.
 * GIC quiescence must remain valid when this master's RD_DONE source is enabled;
 * this core does not change the GIC route/type/enable state or install an ISR.
 * Masked error visibility is NOT inferred: no DONE means bounded refusal/held
 * state; even known DONE/ID completion is not a whole-controller SAFE receipt.
 */
enum pcci_origin { PCCI_PHYSICAL = 1, PCCI_SOFTWARE = 2 };
enum pcci_error {
    PCCI_OK_HELD = 0, PCCI_OFF, PCCI_ARGUMENT, PCCI_CONSUMED, PCCI_NO_PLATFORM,
    PCCI_LEASE, PCCI_CLOCK, PCCI_READ, PCCI_WRITE, PCCI_SAVED_STATE,
    PCCI_TIMING, PCCI_QUEUE, PCCI_IRQ, PCCI_POLL_BOUND, PCCI_FIFO,
    PCCI_RESTORE, PCCI_ID_MISMATCH, PCCI_TRACE_FULL, PCCI_DEADLINE
};
enum pcci_phase { PCCI_ADMIT = 1, PCCI_SNAPSHOT, PCCI_QUEUE_LOAD, PCCI_START,
                  PCCI_WAIT, PCCI_DATA, PCCI_ACK, PCCI_READBACK,
                  PCCI_IRQ_ARM, PCCI_IRQ_RESTORE };
struct pcci_lease {
    uint64_t epoch, sampled_us, expires_us, cci_base;
    uint32_t facts, cci_bytes, slot, cci_clock_hz, mclk_hz, hw_version;
};
struct pcci_raw {
    uint32_t phase, offset, value, write, completed;
    uint64_t issued_us;
};
struct pcci_result {
    uint32_t attempted, error, origin, slot, outstanding, lease_retained;
    uint32_t queue_dirty, bus_start_issued, bus_start_completed, uncertain;
    uint32_t saved_irq_mask, irq_mask_dirty;
    uint32_t irq_arm_issued, irq_arm_completed, irq_arm_readback;
    uint32_t irq_restore_issued, irq_restore_completed, irq_restore_readback;
    uint32_t reads_issued, reads_completed, writes_issued, writes_completed;
    uint32_t id_complete, id_matches_candidate, observed_id, raw_fifo, raw_tag, hw_version;
    uint32_t observable_registers_restored, full_controller_restore_proven;
    uint32_t raw_count, poll_count, irq_observed_or;
    uint64_t epoch, first_us, last_us, deadline_us, rejected_clock_us;
    struct pcci_lease first_lease, last_lease;
    struct pcci_raw raw[PCCI_RAW_CAP];
};
struct pcci_ops {
    void *context;
    uint32_t origin;
    uint64_t (*now_us)(void *);
    void (*dsb)(void *);
    int (*wait_us)(void *, uint32_t); /* Bounded cooperative delay, no clock programming. */
    int (*read32)(void *, uint32_t offset, uint32_t *value);
    /* Nonzero means the single write completed; zero means UNKNOWN, never retry. */
    int (*write32)(void *, uint32_t offset, uint32_t value);
    /* Only compiled SOFTWARE tests may use this injected lease provider. */
    int (*software_lease)(void *, uint32_t slot, struct pcci_lease *out);
};
/* Strong override requires a separately reviewed actual platform implementation.
 * It must validate exclusive ownership and live clock/rail/pin/saved-state facts
 * for this exact slot, refresh the sample and retain the same epoch throughout.
 * Merely filling expected fields or having an identity mapping is insufficient.
 */
int pcci_platform_verify_live_lease(uint32_t slot, struct pcci_lease *out);
/* r must be fresh zeroed controller-owned memory; never reset/reuse it after
 * any result. This is ONE attempt in an exclusive lease, not a retry API. */
int pcci_id_once(struct pcci_result *, const struct pcci_ops *, uint32_t slot);
#endif
