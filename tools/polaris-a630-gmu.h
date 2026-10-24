/* Original A630 flat firmware loading. MiCode c7cb50c1 adreno_a6xx.c
 * a6xx_gmu_start defines CM3_SYSRESET=1 as processor reset; fw_load writes
 * 8192 words through ITCM_START. Reference redwood_adreno.c steps6/10/14
 * independently exercise CSR/TCM before execution. Use Polaris addresses
 * and format, not the A642L/A660 firmware or register namespace.
 *
 * Invoked only inside the verified, exclusive CX/clock lease, under GMU_BCR.
 * Never release block/CM3 reset, configure DMA, or execute this image. If a
 * reset write was attempted, caller MUST retain block reset even on failure.
 * A reset-held bus may refuse writes; report the first failure, not success.
 */
#ifndef POLARIS_A630_GMU_H
#define POLARIS_A630_GMU_H
#ifndef POLARIS_A630_TCM_H
#error Include Polaris TCM definitions first
#endif
enum a630_gmu_result {
    A630_GMU_DISABLED, A630_GMU_ARGUMENT, A630_GMU_LEASE,
    A630_GMU_IO, A630_GMU_RUNNING, A630_GMU_RESET_TIMEOUT,
    A630_GMU_LOADED, A630_GMU_TRANSFER_FAILED
};
struct a630_gmu_snapshot {
    uint32_t result, stage, retain_block_reset, polls;
    uint32_t reset_before, reset_held, fw_init, hfi, counter;
    struct a630_tcm_snapshot tcm;
};
static inline enum a630_gmu_result
a630_gmu_prepare(bool board, bool hash_verified, const struct a630_image *image,
    const struct a630_tcm_io *io, void (*wait)(void *, uint32_t), void *ctx,
    struct a630_gmu_snapshot *s)
{
    if (!s) return A630_GMU_ARGUMENT;
    *s = (struct a630_gmu_snapshot){0};
    if (!board || !hash_verified) return A630_GMU_DISABLED;
    if (!io || !io->admitted || !io->read || !io->write || !io->sync || !wait ||
        !image || !image->data || image->bytes != A630_GMU_FLAT_BYTES) {
        s->result = A630_GMU_ARGUMENT; return A630_GMU_ARGUMENT;
    }
    if (!io->admitted(ctx)) { s->result = A630_GMU_LEASE; return A630_GMU_LEASE; }
    s->stage = 1;
    if (!io->read(ctx, 0x14000, &s->reset_before) ||
        !io->read(ctx, 0x14070, &s->fw_init) ||
        !io->read(ctx, 0x14600, &s->hfi) ||
        !io->read(ctx, 0x14220, &s->counter)) {
        s->result = A630_GMU_IO; return A630_GMU_IO;
    }
    if (s->fw_init == 0xbabeface || s->hfi & 1u) {
        s->result = A630_GMU_RUNNING; return A630_GMU_RUNNING;
    }
    s->stage = 2;
    if (!io->admitted(ctx)) { s->result = A630_GMU_LEASE; return A630_GMU_LEASE; }
    s->retain_block_reset = 1; /* Includes failed or posted reset writes. */
    if (!io->write(ctx, 0x14000, 1) || !io->sync(ctx)) {
        s->result = A630_GMU_IO; return A630_GMU_IO;
    }
    for (unsigned n = 0; n < 1000; n++) {
        if (!io->admitted(ctx)) { s->result = A630_GMU_LEASE; return A630_GMU_LEASE; }
        s->polls++;
        if (!io->read(ctx, 0x14000, &s->reset_held)) {
            s->result = A630_GMU_IO; return A630_GMU_IO;
        }
        if (s->reset_held == 1) break;
        wait(ctx, 1);
    }
    if (s->reset_held != 1) {
        s->result = A630_GMU_RESET_TIMEOUT; return A630_GMU_RESET_TIMEOUT;
    }
    s->stage = 3;
    if (a630_tcm_load(board, hash_verified, image, io, ctx, &s->tcm) != A630_TCM_VERIFIED) {
        s->result = A630_GMU_TRANSFER_FAILED; return A630_GMU_TRANSFER_FAILED;
    }
    s->stage = 4; s->result = A630_GMU_LOADED; return A630_GMU_LOADED;
}
#endif
