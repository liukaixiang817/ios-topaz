/* Bounded original flat-GMU/SQE/three-part relocatable ZAP format.
 * Format inspection does not authenticate or execute any firmware.
 */
#ifndef POLARIS_A630_IMAGES_H
#define POLARIS_A630_IMAGES_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
struct a630_image { const uint8_t *data; uint32_t bytes; };
static inline uint32_t a630_image_word(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static inline bool a630_images_valid(const struct a630_image f[6])
{
    if (!f) return false;
    for (unsigned i = 0; i < 6; i++)
        if (!f[i].data || !f[i].bytes || f[i].bytes > 4 * 1024 * 1024) return false;
    const uint8_t *gmu = f[0].data, *sqe = f[1].data, *mdt = f[2].data;
    if (f[0].bytes != 32768 || f[1].bytes < 8 || f[1].bytes > 1024 * 1024 ||
        f[1].bytes % 4 || f[2].bytes < 148 || f[3].bytes != 148 ||
        f[2].bytes != f[3].bytes + f[4].bytes) return false;
    uint32_t sp = a630_image_word(gmu), reset = a630_image_word(gmu + 4);
    if (sp < 0x40000 || sp > 0x44000 || sp % 8 || !(reset & 1) || reset >= f[0].bytes ||
        a630_image_word(sqe) || __builtin_memcmp(mdt, "\177ELF\1\1\1", 7) ||
        a630_image_word(mdt + 16) != 0x00a40002 || a630_image_word(mdt + 20) != 1 ||
        a630_image_word(mdt + 28) != 52 || a630_image_word(mdt + 40) != 0x00200034 ||
        (a630_image_word(mdt + 44) & 0xffff) != 3 ||
        __builtin_memcmp(mdt, f[3].data, 148) ||
        __builtin_memcmp(mdt + 148, f[4].data, f[4].bytes)) return false;
    const uint8_t *p0 = mdt + 52, *p1 = p0 + 32, *p2 = p1 + 32;
    if (a630_image_word(p0) || a630_image_word(p0 + 4) || a630_image_word(p0 + 16) != 148 ||
        a630_image_word(p1) || a630_image_word(p1 + 16) != f[4].bytes ||
        (a630_image_word(p1 + 24) & 0x07000000) != 0x02000000) return false;
    uint32_t va = a630_image_word(p2 + 8), pa = a630_image_word(p2 + 12);
    uint32_t size = a630_image_word(p2 + 16), memory = a630_image_word(p2 + 20);
    uint32_t flags = a630_image_word(p2 + 24), align = a630_image_word(p2 + 28);
    return a630_image_word(p2) == 1 && size == f[5].bytes && size <= memory &&
        memory <= 4 * 1024 * 1024 && (uint64_t)va + memory <= 0x100000000ULL &&
        (uint64_t)pa + memory <= 0x100000000ULL && (flags & 0x08000000) &&
        (flags & 0x07000000) != 0x02000000 && align && !(align & (align - 1));
}
#endif
