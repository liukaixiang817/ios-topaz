/* Original Polaris A630 flat GMU transfer, not a firmware-start routine.
 *
 * MiCode c7cb50c1: adreno.c subtracts gmu2gpu_offset before word->byte
 * conversion; adreno_a6xx.c loads 0x2000 words from ITCM_START (0x1b400).
 * The contiguous 32KiB AHB window spans the named DTCM_START at 0x7000;
 * do not describe the entire window as instruction-only ITCM.
 *
 * NOT connected to a hardware mode. A future caller must own the upstream
 * power/clock/mapping lifetime, establish CM3 reset separately, and pass
 * only the immutable firmware already checked against its recorded hash.
 * On failure, the caller must retain CM3 reset; this helper does no cleanup
 * that could execute a partially written image.
 * This helper never releases reset, starts firmware, or configures DMA/HFI.
 */
#ifndef POLARIS_A630_TCM_H
#define POLARIS_A630_TCM_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "polaris-a630-images.h"

#define A630_GMU_GPU_WORD_BASE 0x1a800u
#define A630_GMU_REGISTER_BYTES 0x30000u
#define A630_GMU_CM3_RESET 0x14000u
#define A630_GMU_FLAT_START 0x3000u
#define A630_GMU_FLAT_BYTES 0x8000u

enum a630_tcm_result {
    A630_TCM_DISABLED, A630_TCM_ARGUMENT, A630_TCM_LEASE_LOST,
    A630_TCM_IO, A630_TCM_NOT_RESET, A630_TCM_MISMATCH,
    A630_TCM_VERIFIED
};
enum a630_tcm_phase { A630_TCM_ADMISSION, A630_TCM_COPY, A630_TCM_READBACK };
struct a630_tcm_snapshot {
    uint32_t result, phase, offset, expected, actual, reads, writes, barriers;
};
struct a630_tcm_io {
    bool (*admitted)(void *); /* exclusive, live power/clock/mapping lease */
    bool (*read)(void *, uint32_t byte_offset, uint32_t *);
    bool (*write)(void *, uint32_t byte_offset, uint32_t);
    bool (*sync)(void *); /* posted writes must finish before readback */
};

static inline bool a630_gmu_word_offset(uint32_t gpu_word, uint32_t *local_byte)
{
    if (!local_byte || gpu_word < A630_GMU_GPU_WORD_BASE ||
        gpu_word - A630_GMU_GPU_WORD_BASE >= A630_GMU_REGISTER_BYTES / 4)
        return false;
    *local_byte = (gpu_word - A630_GMU_GPU_WORD_BASE) * 4;
    return true;
}

static inline bool a630_tcm_guard(const struct a630_tcm_io *io, void *ctx,
                                struct a630_tcm_snapshot *s)
{
    if (!io->admitted(ctx)) { s->result = A630_TCM_LEASE_LOST; return false; }
    uint32_t reset;
    s->offset = A630_GMU_CM3_RESET;
    s->expected = 1;
    s->actual = 0;
    s->reads++;
    if (!io->read(ctx, A630_GMU_CM3_RESET, &reset)) {
        s->result = A630_TCM_IO; return false;
    }
    s->actual = reset;
    if (reset != 1) { s->result = A630_TCM_NOT_RESET; return false; }
    return true;
}

static inline enum a630_tcm_result
a630_tcm_load(bool exact_board, bool original_hash_verified,
              const struct a630_image *image, const struct a630_tcm_io *io,
              void *ctx, struct a630_tcm_snapshot *s)
{
    if (!s) return A630_TCM_ARGUMENT;
    *s = (struct a630_tcm_snapshot){0};
    if (!exact_board || !original_hash_verified) return A630_TCM_DISABLED;
    if (!image || !image->data || image->bytes != A630_GMU_FLAT_BYTES ||
        !io || !io->admitted || !io->read || !io->write || !io->sync) {
        s->result = A630_TCM_ARGUMENT; return A630_TCM_ARGUMENT;
    }
    /* Validate the original little-endian CM3 vector before any MMIO. */
    uint32_t sp = a630_image_word(image->data);
    uint32_t reset = a630_image_word(image->data + 4);
    if (sp < 0x40000 || sp > 0x44000 || (sp & 7) ||
        !(reset & 1) || reset >= image->bytes) {
        s->result = A630_TCM_ARGUMENT; return A630_TCM_ARGUMENT;
    }
    if (!a630_tcm_guard(io, ctx, s)) return (enum a630_tcm_result)s->result;
    s->phase = A630_TCM_COPY;
    for (uint32_t at = 0; at < image->bytes; at += 4) {
        if (!a630_tcm_guard(io, ctx, s)) return (enum a630_tcm_result)s->result;
        s->offset = A630_GMU_FLAT_START + at;
        s->expected = a630_image_word(image->data + at);
        s->actual = 0;
        s->writes++;
        if (!io->write(ctx, s->offset, s->expected)) {
            s->result = A630_TCM_IO; return A630_TCM_IO;
        }
    }
    /* No reset/firmware-start write occurs on either success or failure. */
    if (!a630_tcm_guard(io, ctx, s)) return (enum a630_tcm_result)s->result;
    s->barriers++;
    if (!io->sync(ctx)) { s->result = A630_TCM_IO; return A630_TCM_IO; }
    s->phase = A630_TCM_READBACK;
    for (uint32_t at = 0; at < image->bytes; at += 4) {
        if (!a630_tcm_guard(io, ctx, s)) return (enum a630_tcm_result)s->result;
        s->offset = A630_GMU_FLAT_START + at;
        s->expected = a630_image_word(image->data + at);
        s->actual = 0;
        s->reads++;
        if (!io->read(ctx, s->offset, &s->actual)) {
            s->result = A630_TCM_IO; return A630_TCM_IO;
        }
        if (s->actual != s->expected) {
            s->result = A630_TCM_MISMATCH; return A630_TCM_MISMATCH;
        }
    }
    if (!a630_tcm_guard(io, ctx, s)) return (enum a630_tcm_result)s->result;
    s->result = A630_TCM_VERIFIED; return A630_TCM_VERIFIED;
}
#endif
