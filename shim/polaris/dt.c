/* Bounded FDT reader for the standalone polaris diagnostic. */
#include "dt.h"

static uint32_t be32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
           (uint32_t)p[2] << 8 | p[3];
}

static size_t bounded_len(const uint8_t *p, size_t limit)
{
    size_t n = 0;
    while (n < limit && p[n]) n++;
    return n;
}

static int equal(const char *a, const char *b)
{
    while (*a && *a == *b) a++, b++;
    return *a == *b;
}

const uint8_t *polaris_dt_prop(const void *blob, size_t available,
                             const char *path, const char *name, uint32_t *len)
{
    const uint8_t *b = blob;
    char current[256];
    current[0] = 0; /* Avoid a compiler-generated memset before FP/SIMD setup. */
    size_t levels[32], used = 0;
    unsigned depth = 0;
    if (!b || available < 40 || be32(b) != 0xd00dfeed) return 0;
    uint32_t total = be32(b + 4), off = be32(b + 8), strings = be32(b + 12);
    uint32_t string_size = be32(b + 32), structure_size = be32(b + 36);
    if (total > available || total < 40 || off < 40 || strings < 40 ||
        off > total || strings > total || structure_size > total - off ||
        string_size > total - strings || (off & 3)) return 0;
    size_t end = off + structure_size;
    while (off <= end && end - off >= 4) {
        uint32_t token = be32(b + off);
        off += 4;
        if (token == 1) {
            size_t n = bounded_len(b + off, end - off);
            if (n == end - off || depth == 32) return 0;
            levels[depth] = used;
            if (depth) {
                if (used + 1 + n >= sizeof(current)) return 0;
                current[used++] = '/';
                for (size_t i = 0; i < n; i++) current[used++] = b[off + i];
                current[used] = 0;
            } else if (n) return 0; /* FDT root node has an empty name */
            depth++;
            off = (off + n + 1 + 3) & ~(size_t)3;
        } else if (token == 2) {
            if (!depth) return 0;
            used = levels[--depth];
            current[used] = 0;
        } else if (token == 3) {
            if (!depth || end - off < 8) return 0;
            uint32_t size = be32(b + off), nameoff = be32(b + off + 4);
            off += 8;
            if (size > end - off || nameoff >= string_size ||
                bounded_len(b + strings + nameoff, string_size - nameoff) == string_size - nameoff)
                return 0;
            if (equal(current, path) && equal((const char *)b + strings + nameoff, name)) {
                *len = size;
                return b + off;
            }
            off = (off + (size_t)size + 3) & ~(size_t)3;
        } else if (token == 9) return 0;
        else if (token != 4) return 0;
    }
    return 0;
}

static int contains(const uint8_t *p, uint32_t len, const char *needle)
{
    if (!p) return 0;
    for (uint32_t i = 0; i < len; i++) {
        uint32_t j = 0;
        while (needle[j] && j < len - i && p[i + j] == needle[j]) j++;
        if (!needle[j]) return 1;
    }
    return 0;
}

int polaris_dt_matches(const void *blob, size_t available)
{
    uint32_t len = 0;
    const uint8_t *p = polaris_dt_prop(blob, available, "", "model", &len);
    if (!contains(p, len, "Polaris")) return 0;
    p = polaris_dt_prop(blob, available, "", "compatible", &len);
    if (!contains(p, len, "qcom,sdm845")) return 0;
    p = polaris_dt_prop(blob, available, "/reserved-memory/cont_splash_region@9d400000", "reg", &len);
    return p && len == 16 && be32(p) == 0 && be32(p + 4) == 0x9d400000 &&
           be32(p + 8) == 0 && be32(p + 12) == 0x2400000;
}
