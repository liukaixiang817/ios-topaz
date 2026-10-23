/* Export a point-in-time FIEMAP of an allocated, unencrypted image file.
 * Inspection only: no mounts, writes, sync ioctls, keys or raw block access.
 * The result is NOT permission to write raw extents or reuse after a remount.
 * Build: zig cc -target aarch64-linux-musl -static -O2 -Wall -Wextra -Werror
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/fiemap.h>
#include <linux/fs.h>
#include <linux/fscrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "polaris-extent-policy.h"

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: polaris-file-extents FILE_ON_READONLY_EXT4\n");
        return 2;
    }
    int fd = open(argv[1], O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) { perror("open image"); return 1; }
    struct stat st, after;
    struct statfs fs;
    struct statvfs space;
    unsigned long flags = 0;
    if (fstat(fd, &st) || fstatfs(fd, &fs) || fstatvfs(fd, &space) ||
        ioctl(fd, FS_IOC_GETFLAGS, &flags)) {
        perror("image metadata"); close(fd); return 1;
    }
    if (!S_ISREG(st.st_mode) || st.st_nlink != 1 || st.st_size <= 0 ||
        fs.f_type != 0xef53 || !(space.f_flag & ST_RDONLY) ||
        space.f_frsize != 4096 || st.st_size % 4096 ||
        space.f_blocks > UINT64_MAX / 4096 ||
        (flags & (FS_ENCRYPT_FL | FS_COMPR_FL | FS_INLINE_DATA_FL))) {
        fprintf(stderr, "requires allocated 4KiB-aligned regular image on read-only ext4\n");
        close(fd); return 1;
    }
    struct fscrypt_policy_v1 policy = {0};
    if (ioctl(fd, FS_IOC_GET_ENCRYPTION_POLICY, &policy) != -1 || errno != ENODATA) {
        fprintf(stderr, "cannot establish absence of encryption policy\n");
        close(fd); return 1;
    }
    /* statvfs.f_blocks excludes ext4 overhead; it is NOT a physical-address
     * bound. Read the size of the exact mounted backing device from sysfs. */
    char sys_path[128], extra;
    snprintf(sys_path, sizeof(sys_path), "/sys/dev/block/%u:%u/size",
             major(st.st_dev), minor(st.st_dev));
    FILE *size_file = fopen(sys_path, "r");
    uint64_t sectors = 0;
    if (!size_file) { perror("backing size"); close(fd); return 1; }
    int parsed = fscanf(size_file, "%" SCNu64 " %c", &sectors, &extra);
    fclose(size_file);
    if (parsed != 1 || !sectors || sectors > UINT64_MAX / 512 || sectors % 8) {
        fprintf(stderr, "invalid backing device size\n"); close(fd); return 1;
    }
    uint64_t backing_bytes = sectors * 512;
    snprintf(sys_path, sizeof(sys_path), "/sys/dev/block/%u:%u/ro",
             major(st.st_dev), minor(st.st_dev));
    FILE *ro_file = fopen(sys_path, "r");
    unsigned readonly = 0;
    if (!ro_file) { perror("backing readonly state"); close(fd); return 1; }
    parsed = fscanf(ro_file, "%u %c", &readonly, &extra);
    fclose(ro_file);
    if (parsed != 1 || readonly != 1) {
        fprintf(stderr, "backing block device must also be read-only\n");
        close(fd); return 1;
    }
    /* A bounded single ioctl avoids incomplete pagination and enormous maps.
     * Fail closed if more extents exist. Caller may choose another strategy. */
    enum { MAX_EXTENTS = 16384 };
    struct fiemap *fm = calloc(1, sizeof(*fm) + MAX_EXTENTS * sizeof(struct fiemap_extent));
    if (!fm) { perror("calloc"); close(fd); return 1; }
    fm->fm_length = (uint64_t)st.st_size;
    fm->fm_extent_count = MAX_EXTENTS;
    /* Deliberately omit FIEMAP_FLAG_SYNC on the read-only filesystem. */
    int error = 1;
    if (ioctl(fd, FS_IOC_FIEMAP, fm)) { perror("FIEMAP"); goto out; }
    if (!fm->fm_mapped_extents || fm->fm_mapped_extents > MAX_EXTENTS) {
        fprintf(stderr, "empty/oversized map\n"); goto out;
    }
    uint64_t end = 0;
    for (unsigned i = 0; i < fm->fm_mapped_extents; i++) {
        struct fiemap_extent *e = &fm->fm_extents[i];
        if (!polaris_extent_valid(end, e->fe_logical, e->fe_physical,
                e->fe_length, e->fe_flags, (uint64_t)st.st_size,
                backing_bytes,
                i + 1 == fm->fm_mapped_extents)) {
            fprintf(stderr, "refused sparse, unstable, encoded or out-of-bounds extent\n");
            goto out;
        }
        for (unsigned j = 0; j < i; j++) {
            struct fiemap_extent *p = &fm->fm_extents[j];
            if (e->fe_physical < p->fe_physical + p->fe_length &&
                p->fe_physical < e->fe_physical + e->fe_length) {
                fprintf(stderr, "overlapping physical extents\n"); goto out;
            }
        }
        end += e->fe_length;
    }
    if (end != (uint64_t)st.st_size || fstat(fd, &after) ||
        after.st_ino != st.st_ino || after.st_size != st.st_size ||
        after.st_ctim.tv_sec != st.st_ctim.tv_sec ||
        after.st_ctim.tv_nsec != st.st_ctim.tv_nsec) {
        fprintf(stderr, "image changed or incomplete mapping\n"); goto out;
    }
    printf("{\"version\":1,\"readonly_snapshot\":true,\"raw_write_allowed\":false,"
           "\"inode\":%" PRIu64 ",\"file_bytes\":%" PRIu64 ","
           "\"backing_device_bytes\":%" PRIu64 ",\"block_bytes\":4096,\"extents\":[",
           (uint64_t)st.st_ino, (uint64_t)st.st_size, backing_bytes);
    for (unsigned i = 0; i < fm->fm_mapped_extents; i++) {
        struct fiemap_extent *e = &fm->fm_extents[i];
        printf("%s{\"logical\":%" PRIu64 ",\"physical\":%" PRIu64 ",\"length\":%" PRIu64 "}",
               i ? "," : "", (uint64_t)e->fe_logical,
               (uint64_t)e->fe_physical, (uint64_t)e->fe_length);
    }
    puts("]}");
    error = 0;
out:
    free(fm);
    close(fd);
    return error;
}
