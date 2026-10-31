#include "camera-cci-id.h"

/* No current production ownership provider: zero MMIO and zero power actions. */
__attribute__((weak)) int pcci_platform_verify_live_lease(uint32_t slot, struct pcci_lease *out)
{ (void)slot; (void)out; return 0; }

#if POLARIS_CAMERA_CCI_ENABLE
/* Entire controller: a fresh result or another slot cannot create a retry.
 * This boot-lifetime ticket is never cleared, including on zero-write refusal. */
static uint32_t controller_attempted;
struct target { uint32_t master, sid, reg, mclk, id0, id1; };
static const struct target targets[3] = {
    {0, 0x1a, 0x0016, 24000000, 0x0363, 0x0333},
    {1, 0x10, 0x0002, 24000000, 0xa001, 0xb001},
    {1, 0x36, 0x300b, 19200000, 0x5675, 0x5675}
};
/* Own raw DT fast-mode values for 37.5MHz CCI source. Read/compare only. */
static const uint32_t timing[5] = {0x00260038, 0x00280028, 0x00160023, 0x3e, 0x163};
struct work { struct pcci_result *r; const struct pcci_ops *o; const struct target *t; };

static int stop(struct work *w, uint32_t error)
{
    if (!w->r->error) w->r->error = error;
    if (w->r->writes_issued) { w->r->uncertain = 1; w->r->lease_retained = 1; }
    return 0;
}

static int clock_now(struct work *w, uint64_t *out)
{
    uint64_t n = w->o->now_us(w->o->context);
    if (!n || n < w->r->last_us) { w->r->rejected_clock_us = n; return stop(w, PCCI_CLOCK); }
    w->r->last_us = n;
    *out = n;
    if (w->r->deadline_us && n >= w->r->deadline_us) { w->r->rejected_clock_us = n; return stop(w, PCCI_DEADLINE); }
    return 1;
}

static int lease(struct work *w)
{
    struct pcci_lease l = {0};
    uint64_t n;
    int ok = 0;
    if (!clock_now(w, &n)) return 0;
    if (w->o->origin == PCCI_PHYSICAL)
        ok = pcci_platform_verify_live_lease(w->r->slot, &l);
#if POLARIS_CAMERA_CCI_SOFTWARE_TEST
    else if (w->o->origin == PCCI_SOFTWARE && w->o->software_lease)
        ok = w->o->software_lease(w->o->context, w->r->slot, &l);
#endif
    w->r->last_lease = l;
    if (!ok) return stop(w, w->o->origin == PCCI_PHYSICAL ? PCCI_NO_PLATFORM : PCCI_LEASE);
    /* Time is sampled again AFTER the verifier, before any target access. */
    if (!clock_now(w, &n)) return 0;
    if (!l.epoch || (w->r->epoch && l.epoch != w->r->epoch) || l.facts != PCCI_REQUIRED_FACTS ||
        l.cci_base != PCCI_BASE || l.cci_bytes != PCCI_BYTES || l.slot != w->r->slot ||
        l.cci_clock_hz != 37500000 || l.mclk_hz != w->t->mclk || !l.hw_version ||
        (w->r->hw_version && l.hw_version != w->r->hw_version) ||
        !l.sampled_us || l.sampled_us > n || n - l.sampled_us > 200000 || l.expires_us <= n)
        return stop(w, PCCI_LEASE);
    if (!w->r->epoch) w->r->first_lease = l;
    w->r->epoch = l.epoch;
    w->r->hw_version = l.hw_version;
    return 1;
}

static int access32(struct work *w, uint32_t phase, uint32_t offset, uint32_t *value, int write)
{
    struct pcci_raw *raw;
    uint64_t n;
    int ok;
    uint32_t q = 0x400 + w->t->master * 0x200;
    if (!lease(w) || !clock_now(w, &n)) return 0;
    if ((offset & 3) || offset >= PCCI_BYTES) return stop(w, PCCI_ARGUMENT);
    if (write && (w->r->writes_issued >= 12 ||
        !((offset == q + 0x10) || (offset == q && (*value == 5 || *value == 0)) ||
          (offset == 8 && *value == (1u << (w->t->master * 2 + 1))) ||
          (offset == 0xc08 && *value == (w->t->master ? 0x1000u : 1u)) ||
          (offset == 0xc04 &&
           ((phase == PCCI_IRQ_ARM && !w->r->irq_arm_issued &&
             *value == (w->t->master ? 0x1000u : 1u)) ||
            (phase == PCCI_IRQ_RESTORE && !w->r->irq_restore_issued &&
             w->r->irq_arm_readback && *value == w->r->saved_irq_mask && !*value))) ||
          (offset == 0xc00 && *value == 1)))) return stop(w, PCCI_ARGUMENT);
    if (w->r->raw_count == PCCI_RAW_CAP) return stop(w, PCCI_TRACE_FULL);
    raw = &w->r->raw[w->r->raw_count++];
    *raw = (struct pcci_raw){phase, offset, *value, (uint32_t)write, 0, n};
    if (write) {
        ++w->r->writes_issued;
        if (offset == 0x410 || offset == 0x610) w->r->queue_dirty = 1;
        if (offset == 8) w->r->bus_start_issued = 1;
        if (offset == 0xc04) {
            /* A failed return can still have changed the mask. Preserve intent
             * and dirty state before either arm OR restoration is issued. */
            w->r->irq_mask_dirty = 1;
            if (phase == PCCI_IRQ_ARM) w->r->irq_arm_issued = 1;
            else w->r->irq_restore_issued = 1;
        }
    } else ++w->r->reads_issued;
    /* Append intent and issued counters before any possibly side-effecting IO. */
    w->o->dsb(w->o->context);
    if (write) {
        ok = w->o->write32(w->o->context, offset, *value);
    } else {
        ok = w->o->read32(w->o->context, offset, value);
        /* Even an incomplete backend read may return partial raw bits. */
        raw->value = *value;
        if (offset == 0xc0c) w->r->irq_observed_or |= *value;
    }
    /* An unknown return does not remove the ordering requirement. A barrier
     * is not a claim of peripheral completion or recovery from external SError. */
    w->o->dsb(w->o->context);
    if (!ok) return stop(w, write ? PCCI_WRITE : PCCI_READ);
    if (write) {
        ++w->r->writes_completed;
        if (offset == 8) w->r->bus_start_completed = 1;
        if (offset == 0xc04) {
            if (phase == PCCI_IRQ_ARM) w->r->irq_arm_completed = 1;
            else w->r->irq_restore_completed = 1;
        }
    } else ++w->r->reads_completed;
    raw->completed = 1;
    return 1;
}
static int rd(struct work *w, uint32_t p, uint32_t off, uint32_t *v)
{ *v = 0; return access32(w, p, off, v, 0); }
static int wr(struct work *w, uint32_t p, uint32_t off, uint32_t v)
{ return access32(w, p, off, &v, 1); }

/* No FIFO pop in a snapshot. Whole CCI IRQ status and BOTH master queues must
 * be idle; this supports only an exclusive whole-controller lease, never a
 * shared queue assumption or an unknown saved interrupt configuration.
 */
static int snapshot(struct work *w, uint32_t phase, uint32_t out[18])
{
    uint32_t i, at = 0, v;
    if (!rd(w, phase, 0, &out[at++]) || out[0] != w->r->hw_version) return stop(w, PCCI_SAVED_STATE);
    if (!rd(w, phase, 0xc04, &out[at++]) || out[1]) return stop(w, PCCI_IRQ);
    if (!rd(w, phase, 0xc0c, &out[at++]) || out[2]) return stop(w, PCCI_IRQ);
    for (i = 0; i < 4; ++i) {
        uint32_t q = 0x300 + (i / 2) * 0x200 + (i % 2) * 0x100;
        if (!rd(w, phase, q, &out[at++]) || out[at - 1]) return stop(w, PCCI_QUEUE);
        if (!rd(w, phase, q + 4, &out[at++]) || out[at - 1]) return stop(w, PCCI_QUEUE);
    }
    for (i = 0; i < 2; ++i)
        if (!rd(w, phase, 0x11c + i * 0x100, &out[at++]) || out[at - 1]) return stop(w, PCCI_FIFO);
    for (i = 0; i < 5; ++i) {
        if (!rd(w, phase, 0x100 + w->t->master * 0x100 + i * 4, &v)) return 0;
        out[at++] = v;
        if (v != timing[i]) return stop(w, PCCI_TIMING);
    }
    return at == 18;
}
#endif

int pcci_id_once(struct pcci_result *r, const struct pcci_ops *o, uint32_t slot)
{
#if !POLARIS_CAMERA_CCI_ENABLE
    (void)o; (void)slot;
    if (r && __atomic_compare_exchange_n(&r->attempted, &(uint32_t){0}, 1, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) r->error = PCCI_OFF;
    return PCCI_OFF;
#else
    struct work w;
    uint32_t before[18], after[18], i, n, status, fifo, q, done, words[5];
    uint64_t now;
    if (!r) return PCCI_ARGUMENT;
    if (!__atomic_compare_exchange_n(&r->attempted, &(uint32_t){0}, 1, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return PCCI_CONSUMED;
    if (!__atomic_compare_exchange_n(&controller_attempted, &(uint32_t){0}, 1, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) { r->error = PCCI_CONSUMED; return r->error; }
    if (!o || slot > 2 || !o->now_us || !o->dsb || !o->wait_us || !o->read32 || !o->write32 ||
        (o->origin != PCCI_PHYSICAL && o->origin != PCCI_SOFTWARE)) { r->error = PCCI_ARGUMENT; return r->error; }
    r->origin = o->origin; r->slot = slot; r->outstanding = 1;
    w = (struct work){r, o, &targets[slot]};
    if (!clock_now(&w, &now)) goto failed;
    r->first_us = now;
    if (now > UINT64_MAX - 500000) { stop(&w, PCCI_CLOCK); goto failed; }
    r->deadline_us = now + 500000;
    if (!lease(&w) || !snapshot(&w, PCCI_SNAPSHOT, before)) goto failed;
    q = 0x400 + w.t->master * 0x200;
    done = w.t->master ? 0x1000u : 1u;
    r->saved_irq_mask = before[1]; /* snapshot permits ONLY a known zero mask. */
    words[0] = 1u | (w.t->sid << 4); /* Retry/id-map bits remain ZERO. */
    words[1] = 6u;
    words[2] = 11u | (2u << 4) | ((w.t->reg & 255u) << 16) | ((w.t->reg >> 8) << 8);
    words[3] = 10u | (2u << 4);
    words[4] = 7u;
    r->lease_retained = 1;
    /* Own c7cb init enables source masks before waiting for RD_DONE. Do not
     * assume STATUS latches while MASK=0. Enable ONLY this master's DONE bit,
     * with the external GIC route already quiesced by the live lease provider.
     * Never copy Linux's all-source mask or its error HALT/RESET path. */
    if (!wr(&w, PCCI_IRQ_ARM, 0xc04, done)) goto failed;
    if (!rd(&w, PCCI_IRQ_ARM, 0xc04, &n) || n != done) { stop(&w, PCCI_IRQ); goto failed; }
    r->irq_arm_readback = 1;
    if (!rd(&w, PCCI_IRQ_ARM, 0xc0c, &status) || status) { stop(&w, PCCI_IRQ); goto failed; }
    for (i = 0; i < 5; ++i) {
        if (!wr(&w, PCCI_QUEUE_LOAD, q + 0x10, words[i])) goto failed;
    }
    if (!rd(&w, PCCI_QUEUE_LOAD, q + 4, &n) || n != 5) { stop(&w, PCCI_QUEUE); goto failed; }
    if (!wr(&w, PCCI_START, q, 5)) goto failed;
    if (!wr(&w, PCCI_START, 8, 1u << (w.t->master * 2 + 1))) goto failed;
    for (i = 0; i < 512; ++i) {
        ++r->poll_count;
        if (!rd(&w, PCCI_WAIT, 0xc0c, &status)) goto failed;
        if (status & ~done) { stop(&w, PCCI_IRQ); goto failed; }
        if (status == done) break;
        if (!o->wait_us(o->context, 1000)) { stop(&w, PCCI_CLOCK); goto failed; }
    }
    if (i == 512) { stop(&w, PCCI_POLL_BOUND); goto failed; }
    if (!rd(&w, PCCI_DATA, 0x11c + w.t->master * 0x100, &n) || n != 1) { stop(&w, PCCI_FIFO); goto failed; }
    if (!rd(&w, PCCI_DATA, 0x118 + w.t->master * 0x100, &fifo)) goto failed;
    r->raw_fifo = fifo; r->raw_tag = fifo & 255; /* Tag encoding is NOT guessed. */
    r->observed_id = (((fifo >> 8) & 255) << 8) | ((fifo >> 16) & 255);
    r->id_complete = 1;
    r->id_matches_candidate = r->observed_id == w.t->id0 || r->observed_id == w.t->id1;
    if (!rd(&w, PCCI_DATA, 0x11c + w.t->master * 0x100, &n) || n) { stop(&w, PCCI_FIFO); goto failed; }
    /* READ_DONE must not authorize editing EXEC while the trailing UNLOCK or
     * any other queue word is still outstanding. Refuse without cleanup writes. */
    if (!rd(&w, PCCI_ACK, q + 4, &n) || n) { stop(&w, PCCI_QUEUE); goto failed; }
    if (!rd(&w, PCCI_ACK, 0xc0c, &status) || status != done) { stop(&w, PCCI_IRQ); goto failed; }
    /* Only this transaction's known RD_DONE is acknowledged. NEVER error bits,
     * IRQ type, HALT, RESET, clock, pin, regulator or other-master state. */
    if (!wr(&w, PCCI_ACK, 0xc08, done) || !wr(&w, PCCI_ACK, 0xc00, 1) || !wr(&w, PCCI_ACK, q, 0)) goto failed;
    /* Check completion cleared while its source is STILL enabled. Otherwise a
     * zero masked STATUS could conceal a completion that did not clear. */
    if (!rd(&w, PCCI_IRQ_RESTORE, 0xc0c, &status) || status) { stop(&w, PCCI_IRQ); goto failed; }
    if (!wr(&w, PCCI_IRQ_RESTORE, 0xc04, r->saved_irq_mask)) goto failed;
    if (!rd(&w, PCCI_IRQ_RESTORE, 0xc04, &n) || n != r->saved_irq_mask) { stop(&w, PCCI_RESTORE); goto failed; }
    r->irq_restore_readback = 1;
    r->irq_mask_dirty = 0;
    if (!snapshot(&w, PCCI_READBACK, after)) goto failed;
    for (i = 0; i < 18; ++i)
        if (before[i] != after[i]) { stop(&w, PCCI_RESTORE); goto failed; }
    r->observable_registers_restored = 1;
    r->queue_dirty = 0;
    /* Observable registers cannot establish restoration of internal SID/queue
     * state. Keep the exclusive lease/outstanding until a separately proven
     * controller shutdown/restore; this is never a drain/reset-safe receipt. */
    if (!r->id_matches_candidate) { r->error = PCCI_ID_MISMATCH; return r->error; }
    return PCCI_OK_HELD;
failed:
    if (!r->writes_issued) { r->outstanding = 0; r->lease_retained = 0; }
    return r->error;
#endif
}
