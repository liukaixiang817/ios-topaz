/* Read-only SHA256 using the CPU's ARMv8 SHA2 instructions.
 * No splice/sendfile, keys, configuration changes, or writable source handles.
 * Block devices must already be read-only. Print digest only after exact EOF.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <asm/hwcap.h>
#include <sys/auxv.h>
#include <string.h>
#include "vendor/sha256-arm.h"
#include <linux/fs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>

#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "usage: polaris-sha256 READONLY_FILE_OR_BLOCK_DEVICE\n"); return 2; }
    int fd = open(argv[1], O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) { perror("source"); return 1; }
    struct stat st;
    uint64_t bytes = 0;
    if (fstat(fd, &st)) { perror("stat"); close(fd); return 1; }
    if (S_ISBLK(st.st_mode)) {
        int ro = 0;
        if (ioctl(fd, BLKROGET, &ro) || ro != 1 || ioctl(fd, BLKGETSIZE64, &bytes)) {
            fprintf(stderr, "requires an already read-only block device\n"); close(fd); return 1;
        }
    } else if (S_ISREG(st.st_mode) && st.st_size >= 0) {
        bytes = (uint64_t)st.st_size;
    } else { fprintf(stderr, "not a regular file or block device\n"); close(fd); return 1; }
    if (!(getauxval(AT_HWCAP) & HWCAP_SHA2) || bytes > UINT64_MAX / 8) {
        fprintf(stderr, "SHA2 CPU feature unavailable or source too large\n"); close(fd); return 1;
    }
    enum { CHUNK = 1024 * 1024 };
    unsigned char *data = malloc(CHUNK + 64);
    uint32_t state[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    unsigned carry = 0;
    int result = 1;
    if (!data) { perror("malloc"); goto out; }
    uint64_t total = 0, last_report = 0;
    for (;;) {
        ssize_t n = read(fd, data + carry, CHUNK);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { perror("read"); goto out; }
        if (!n) break;
        if (total > bytes || (uint64_t)n > bytes - total) {
            fprintf(stderr, "source size changed\n"); goto out;
        }
        unsigned available = carry + (unsigned)n;
        unsigned full = available & ~63u;
        sha256_process_arm(state, data, full);
        carry = available - full;
        memmove(data, data + full, carry);
        total += (uint64_t)n;
        if (total - last_report >= (UINT64_C(4) << 30)) {
            fprintf(stderr, "hashed %" PRIu64 " / %" PRIu64 " bytes\n", total, bytes);
            last_report = total;
        }
    }
    if (total != bytes) { fprintf(stderr, "short source\n"); goto out; }
    unsigned padded = carry < 56 ? 64 : 128;
    memset(data + carry, 0, padded - carry);
    data[carry] = 0x80;
    uint64_t bits = total * 8;
    for (unsigned i = 0; i < 8; i++) data[padded - 1 - i] = (unsigned char)(bits >> (8 * i));
    sha256_process_arm(state, data, padded);
    for (unsigned i = 0; i < 8; i++) printf("%08x", state[i]);
    putchar('\n'); result = 0;
out:
    free(data); close(fd); return result;
}
