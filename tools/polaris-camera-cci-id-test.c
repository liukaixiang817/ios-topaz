/* Actual core with a SOFTWARE register backend. Never hardware evidence. */
#include "../shim/polaris/camera-cci-id.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct sim {
    struct pcci_result *result;
    const struct pcci_ops *ops;
    uint64_t now;
    uint32_t test, slot, master, sid, reg, id, words[5], loaded, exec[2];
    uint32_t status, clear, level[2], fifo_reads, writes, reads, waits;
    uint32_t regs[0x4000 / 4], reentrant_called, barriers;
};
static uint64_t now_us(void *v)
{
    struct sim *s = v;
    if (s->test == 14) return s->now; /* A frozen clock must still terminate. */
    if (s->test == 18 && s->writes >= 2) return s->now - 100;
    return ++s->now;
}
static void dsb(void *v) { ++((struct sim *)v)->barriers; }
static int wait_us(void *v, uint32_t us)
{
    struct sim *s = v;
    assert(us == 1000);
    ++s->waits;
    if (s->test != 14) s->now += us;
    return 1;
}
static int leased(void *v, uint32_t slot, struct pcci_lease *l)
{
    struct sim *s = v;
    assert(slot == s->slot);
    *l = (struct pcci_lease){99, s->now, s->now + 100000, PCCI_BASE,
                            PCCI_REQUIRED_FACTS, PCCI_BYTES, slot, 37500000,
                            slot == 2 ? 19200000u : 24000000u, 0x10060000};
    if (s->test == 5) --l->facts;
    if (s->test == 6) l->mclk_hz = 24000000;
    if (s->test == 7) l->sampled_us -= 200001;
    if (s->test == 15 && s->writes >= 2) ++l->epoch;
    if (s->test == 19) l->cci_clock_hz = 19200000;
    return 1;
}
static int rd(void *v, uint32_t off, uint32_t *out)
{
    struct sim *s = v;
    assert(off < 0x4000 && !(off & 3));
    assert(s->result->reads_issued == s->reads + 1);
    ++s->reads;
    if (off == 0xc0c) { *out = s->status; return 1; }
    if (off == 0xc04) {
        *out = s->regs[off / 4];
        if (s->test == 26 && s->result->irq_arm_issued) *out ^= 1;
        if (s->test == 33 && s->result->irq_arm_issued) return 0;
        if (s->test == 34 && s->result->irq_restore_issued) return 0;
        return 1;
    }
    if (off == 0x11c || off == 0x21c) { *out = s->level[(off - 0x11c) / 0x100]; return 1; }
    if (off == 0x118 + s->master * 0x100) {
        assert(s->level[s->master] == 1 && s->status);
        ++s->fifo_reads;
        *out = 0xabu | ((s->id >> 8) << 8) | ((s->id & 255) << 16);
        s->level[s->master] = 0;
        return s->test != 12; /* Unknown FIFO read still returns raw value. */
    }
    if (off == 0x404 + s->master * 0x200) { *out = s->test == 25 && s->fifo_reads ? 1 : s->loaded; return 1; }
    if (off == 0x400 || off == 0x600) { *out = s->exec[(off - 0x400) / 0x200]; return 1; }
    *out = s->regs[off / 4];
    return 1;
}
static int wr(void *v, uint32_t off, uint32_t value)
{
    struct sim *s = v;
    uint32_t q = 0x400 + s->master * 0x200;
    assert(s->result->writes_issued == s->writes + 1);
    assert(s->result->raw[s->result->raw_count - 1].completed == 0);
    ++s->writes;
    if (off == 0xc04) {
        assert(s->result->irq_mask_dirty);
        assert(value == 0 || value == (s->master ? 0x1000u : 1u));
        if (value) {
            assert(s->writes == 1 && s->result->irq_arm_issued && !s->result->irq_arm_completed);
            if (s->test == 31) s->status = 1; /* New status while arming: never clear it. */
        } else {
            assert(s->writes == 12 && s->result->irq_arm_readback);
            assert(s->result->irq_restore_issued && !s->result->irq_restore_completed);
            assert(s->status == 0 && s->exec[s->master] == 0);
        }
        if (!(s->test == 29 && value == 0)) s->regs[off / 4] = value;
    } else if (off == q + 0x10) {
        assert(s->result->irq_arm_readback && s->regs[0xc04 / 4] == (s->master ? 0x1000u : 1u));
        assert(s->loaded < 5);
        s->words[s->loaded++] = value;
    } else if (off == q) {
        assert(value == 5 || value == 0);
        s->exec[s->master] = value;
    } else if (off == 8) {
        assert(s->result->bus_start_issued == 1 && s->result->bus_start_completed == 0);
        assert(value == (1u << (s->master * 2 + 1)) && s->loaded == 5 && s->exec[s->master] == 5);
        assert(s->words[0] == (1u | (s->sid << 4))); /* No retry/id-map bits. */
        assert(s->words[1] == 6 && s->words[3] == 0x2a && s->words[4] == 7);
        assert(s->words[2] == (0x2bu | ((s->reg & 255) << 16) | ((s->reg >> 8) << 8)));
        s->loaded = 0;
        if (s->test != 13 && s->test != 14) {
            s->status = s->master ? 0x1000 : 1;
            s->level[s->master] = s->test == 11 ? 2 : 1;
            if (s->test == 10) s->status |= 2; /* Any error/foreign status is sticky. */
        }
    } else if (off == 0xc08) {
        assert(value == (s->master ? 0x1000u : 1u));
        s->clear = value;
    } else if (off == 0xc00) {
        assert(value == 1 && s->clear == (s->master ? 0x1000u : 1u));
        if (s->test != 30) s->status &= ~s->clear;
        if (s->test == 17) s->regs[(0x100 + s->master * 0x100) / 4] ^= 1;
    } else assert(!"forbidden write offset");
    if (s->test == 20 && !s->reentrant_called++)
        assert(pcci_id_once(s->result, s->ops, s->slot) == PCCI_CONSUMED);
    return !((s->test == 9 && s->writes == 3) ||
             (s->test == 27 && s->writes == 1) ||
             (s->test == 28 && s->writes == 12));
}

int main(int argc, char **argv)
{
    struct pcci_result result = {0};
#if POLARIS_CAMERA_CCI_ENABLE
    struct pcci_result another = {0};
#endif
    struct sim s = {0};
    struct pcci_ops ops = {&s, PCCI_SOFTWARE, now_us, dsb, wait_us, rd, wr, leased};
    uint32_t timing[5] = {0x00260038, 0x00280028, 0x00160023, 0x3e, 0x163};
    int rc;
    assert(argc == 2);
    s.test = (uint32_t)strtoul(argv[1], 0, 10);
    s.result = &result; s.ops = &ops; s.now = 1000000;
    s.slot = s.test == 2 || s.test == 3 ? 1 : (s.test == 4 || s.test == 6 ? 2 : 0);
    s.master = s.slot ? 1 : 0; s.sid = s.slot == 2 ? 0x36 : (s.slot ? 0x10 : 0x1a);
    s.reg = s.slot == 2 ? 0x300b : (s.slot ? 2 : 0x16);
    s.id = s.test == 1 ? 0x333 : (s.slot == 2 ? 0x5675 : (s.slot ? (s.test == 3 ? 0xb001 : 0xa001) : 0x363));
    s.regs[0] = 0x10060000;
    for (uint32_t m = 0; m < 2; ++m)
        for (uint32_t n = 0; n < 5; ++n) s.regs[(0x100 + m * 0x100 + n * 4) / 4] = timing[n];
    if (s.test == 8) s.regs[(0x100 + s.master * 0x100) / 4] ^= 1;
    if (s.test == 16) s.id = 0xdead;
    if (s.test == 21) s.status = 1; /* Stale completion before queue admission. */
    if (s.test == 22) s.regs[0x304 / 4] = 1; /* Other queue is not free. */
    if (s.test == 23) ops.origin = PCCI_PHYSICAL; /* SOFTWARE callback cannot grant physical access. */
    if (s.test == 24) s.regs[0] ^= 1;
    if (s.test == 32) s.regs[0xc04 / 4] = 2; /* Saved mask must be known zero. */
    rc = pcci_id_once(&result, &ops, s.slot);
#if !POLARIS_CAMERA_CCI_ENABLE
    assert(rc == PCCI_OFF && s.reads == 0 && s.writes == 0 && s.waits == 0);
#else
    if (s.test <= 4 || s.test == 20) {
        assert(rc == PCCI_OK_HELD && result.id_complete && result.id_matches_candidate && result.observed_id == s.id);
        assert(result.raw_tag == 0xab && result.observable_registers_restored && result.writes_issued == 12);
        assert(result.saved_irq_mask == 0 && !result.irq_mask_dirty);
        assert(result.irq_arm_issued && result.irq_arm_completed && result.irq_arm_readback);
        assert(result.irq_restore_issued && result.irq_restore_completed && result.irq_restore_readback);
    } else if (s.test == 5 || s.test == 6 || s.test == 7 || s.test == 19) {
        assert(rc == PCCI_LEASE && s.reads == 0 && s.writes == 0);
    } else if (s.test == 8) assert(rc == PCCI_TIMING && !s.writes);
    else if (s.test == 9) assert(rc == PCCI_WRITE && s.writes == 3 && result.writes_completed == 2 && !result.bus_start_issued);
    else if (s.test == 10) assert(rc == PCCI_IRQ && s.writes == 8 && !s.fifo_reads && result.irq_observed_or == 3);
    else if (s.test == 11) assert(rc == PCCI_FIFO && s.writes == 8 && !s.fifo_reads);
    else if (s.test == 12) {
        assert(rc == PCCI_READ && s.writes == 8 && s.fifo_reads == 1 && !result.id_complete);
        assert(result.raw[result.raw_count - 1].value != 0 && !result.raw[result.raw_count - 1].completed);
    } else if (s.test == 13) assert(rc == PCCI_DEADLINE && s.writes == 8 && result.poll_count < 512);
    else if (s.test == 14) assert(rc == PCCI_POLL_BOUND && s.writes == 8 && result.poll_count == 512);
    else if (s.test == 15) assert(rc == PCCI_LEASE && s.writes == 2 && !result.bus_start_issued);
    else if (s.test == 16) assert(rc == PCCI_ID_MISMATCH && result.id_complete && !result.id_matches_candidate && result.observable_registers_restored);
    else if (s.test == 17) assert(rc == PCCI_TIMING && result.id_complete && !result.observable_registers_restored);
    else if (s.test == 18) assert(rc == PCCI_CLOCK && s.writes == 2);
    else if (s.test == 21) assert(rc == PCCI_IRQ && !s.writes);
    else if (s.test == 22) assert(rc == PCCI_QUEUE && !s.writes);
    else if (s.test == 23) assert(rc == PCCI_NO_PLATFORM && !s.writes && !s.reads);
    else if (s.test == 24) assert(rc == PCCI_SAVED_STATE && !s.writes);
    else if (s.test == 25) assert(rc == PCCI_QUEUE && result.id_complete && s.writes == 8);
    else if (s.test == 26) assert(rc == PCCI_IRQ && s.writes == 1 && result.irq_arm_completed && !result.irq_arm_readback);
    else if (s.test == 27) assert(rc == PCCI_WRITE && s.writes == 1 && !result.writes_completed && !result.irq_arm_completed);
    else if (s.test == 28) assert(rc == PCCI_WRITE && s.writes == 12 && result.writes_completed == 11 && !result.irq_restore_completed);
    else if (s.test == 29) assert(rc == PCCI_RESTORE && s.writes == 12 && result.irq_restore_completed && !result.irq_restore_readback);
    else if (s.test == 30) assert(rc == PCCI_IRQ && s.writes == 11 && !result.irq_restore_issued);
    else if (s.test == 31) assert(rc == PCCI_IRQ && s.writes == 1 && result.irq_arm_readback && !result.queue_dirty);
    else if (s.test == 32) assert(rc == PCCI_IRQ && !s.writes && !result.irq_arm_issued);
    else if (s.test == 33) assert(rc == PCCI_READ && s.writes == 1 && !result.irq_arm_readback);
    else if (s.test == 34) assert(rc == PCCI_READ && s.writes == 12 && !result.irq_restore_readback);
    else assert(!"unknown test");
    if (s.writes) assert(result.outstanding && result.lease_retained);
    else assert(!result.outstanding && !result.lease_retained);
    if (s.writes && !result.irq_restore_readback) assert(result.irq_mask_dirty);
    if (s.test >= 26 && s.test != 32) assert(result.uncertain && !result.observable_registers_restored);
    assert(!result.full_controller_restore_proven);
    assert(pcci_id_once(&another, &ops, s.slot) == PCCI_CONSUMED); /* New result is NOT a retry. */
    uint32_t reads = s.reads, writes = s.writes;
    assert(pcci_id_once(&result, &ops, s.slot) == PCCI_CONSUMED);
    assert(reads == s.reads && writes == s.writes);
    assert(result.reads_issued == s.reads && result.writes_issued == s.writes);
    assert(s.barriers == 2 * (s.reads + s.writes)); /* Includes UNKNOWN read/write. */
#endif
    printf("SOFTWARE case %u PASS, read=%u write=%u ID=%x held=%u physical_ID=0\n", s.test, s.reads, s.writes, result.observed_id, result.lease_retained);
    return 0;
}
