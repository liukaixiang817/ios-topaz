/* Private USB-ECM diagnostics: snapshot logs or the panel, then read chunks.
 * No addresses, writes, shell commands or storage operations on this wire.
 * All fields are little endian; UDP payloads fit the existing 1500-byte MTU.
 */
#ifndef POLARIS_DEBUG_WIRE_H
#define POLARIS_DEBUG_WIRE_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define PDBG_REQUEST_BYTES 24u
#define PDBG_REPLY_BYTES 40u
#define PDBG_CHUNK 1400u
#define PDBG_LOG_LIMIT (4u << 20)
#define PDBG_FRAME_BYTES (4320u * 2160u)
enum pdbg_op { PDBG_LOG = 1, PDBG_FRAME = 2, PDBG_READ = 3 };
enum pdbg_status { PDBG_OK, PDBG_BAD, PDBG_NOT_READY, PDBG_NOMEM, PDBG_STALE };
struct pdbg_request { uint64_t token; uint32_t offset, length; uint16_t op; };
struct pdbg_snapshot { uint64_t token; uint32_t bytes, kind, width, height, stride; };

static inline uint32_t pdbg_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static inline void pdbg_put32(uint8_t *p, uint32_t v)
{
    for (unsigned i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static inline bool pdbg_parse(const uint8_t *p, size_t bytes, struct pdbg_request *out)
{
    if (!p || !out || bytes != PDBG_REQUEST_BYTES || pdbg_u32(p) != 0x47424450 ||
        p[4] != 1 || p[5] || p[7] || p[6] < PDBG_LOG || p[6] > PDBG_READ) return false;
    struct pdbg_request r = {
        .token = (uint64_t)pdbg_u32(p + 8) | (uint64_t)pdbg_u32(p + 12) << 32,
        .offset = pdbg_u32(p + 16), .length = pdbg_u32(p + 20), .op = p[6]
    };
    if (!r.token || (r.op == PDBG_READ ? (!r.length || r.length > PDBG_CHUNK) :
        (r.offset || r.length))) return false;
    *out = r;
    return true;
}
static inline bool pdbg_span(const struct pdbg_snapshot *s, const struct pdbg_request *r)
{
    return s && r && s->token && r->token == s->token && r->op == PDBG_READ &&
        ((s->kind == PDBG_LOG && s->bytes <= PDBG_LOG_LIMIT && !s->width && !s->height && !s->stride) ||
         (s->kind == PDBG_FRAME && s->bytes == PDBG_FRAME_BYTES && s->width == 1080 &&
          s->height == 2160 && s->stride == 4320)) &&
        r->length && r->length <= PDBG_CHUNK && r->offset <= s->bytes &&
        r->length <= s->bytes - r->offset;
}
static inline uint32_t pdbg_crc(const uint8_t *p, size_t bytes)
{
    uint32_t c = UINT32_MAX;
    for (size_t i = 0; i < bytes; i++) {
        c ^= p[i];
        for (unsigned b = 0; b < 8; b++) c = (c >> 1) ^ (0xedb88320u & (0u - (c & 1)));
    }
    return ~c;
}
/* Caller supplies PDBG_REPLY_BYTES of output. Errors never advertise data. */
static inline bool pdbg_reply(uint8_t *p, const struct pdbg_snapshot *s,
    const struct pdbg_request *r, unsigned status, const uint8_t *data, uint32_t bytes)
{
    if (!p || !s || !r || status > PDBG_STALE || bytes > PDBG_CHUNK ||
        (bytes && (!data || status != PDBG_OK || !pdbg_span(s, r) || bytes != r->length))) return false;
    __builtin_memset(p, 0, PDBG_REPLY_BYTES);
    pdbg_put32(p, 0x52424450); p[4] = 1; p[6] = (uint8_t)status;
    pdbg_put32(p + 8, (uint32_t)r->token); pdbg_put32(p + 12, (uint32_t)(r->token >> 32));
    if (status == PDBG_OK) {
        pdbg_put32(p + 16, s->kind); pdbg_put32(p + 20, r->op == PDBG_READ ? r->offset : 0);
        pdbg_put32(p + 24, s->bytes); pdbg_put32(p + 28, bytes);
        p[32] = (uint8_t)s->width; p[33] = (uint8_t)(s->width >> 8);
        p[34] = (uint8_t)s->height; p[35] = (uint8_t)(s->height >> 8);
        /* Frame geometry is fixed. Field36 is the payload CRC32. */
        pdbg_put32(p + 36, pdbg_crc(data, bytes));
    }
    return true;
}
#endif
