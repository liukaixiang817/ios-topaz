/* Read-only directory metadata inspection for an already read-only mount.
 * No file creation, policy changes, journal replay or filesystem repair.
 * Build with Zig: zig cc -target aarch64-linux-musl -static -O2 FILE -o OUT
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/fscrypt.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: polaris-fs-inspect READ_ONLY_DIRECTORY\n");
        return 2;
    }
    int fd = open(argv[1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) { perror("open directory"); return 1; }
    struct stat st;
    struct statfs fs;
    struct statvfs space;
    if (fstat(fd, &st) || fstatfs(fd, &fs) || fstatvfs(fd, &space)) {
        perror("directory metadata"); close(fd); return 1;
    }
    if (fs.f_type != 0xef53 || !(space.f_flag & ST_RDONLY)) {
        fprintf(stderr, "requires an already read-only ext4 mount\n");
        close(fd); return 1;
    }
    unsigned long flags = 0;
    if (ioctl(fd, FS_IOC_GETFLAGS, &flags)) {
        perror("FS_IOC_GETFLAGS"); close(fd); return 1;
    }
    struct fscrypt_policy_v1 policy = {0};
    int policy_result = ioctl(fd, FS_IOC_GET_ENCRYPTION_POLICY, &policy);
    int policy_error = policy_result < 0 ? errno : 0;
    /* Do not print key identifiers or filenames. An unsupported ioctl is
     * distinct from ENODATA; callers must not infer absence of a policy. */
    printf("{\"inode\":%llu,\"uid\":%u,\"gid\":%u,\"mode\":%u,"
           "\"inode_flags\":%lu,\"encrypted_flag\":%s,"
           "\"policy_errno\":%d,\"verified_no_policy\":%s,"
           "\"readonly\":true,\"block_bytes\":%lu,\"available_bytes\":%llu}\n",
           (unsigned long long)st.st_ino, st.st_uid, st.st_gid, st.st_mode & 07777,
           flags, (flags & FS_ENCRYPT_FL) ? "true" : "false", policy_error,
           !(flags & FS_ENCRYPT_FL) && policy_error == ENODATA ? "true" : "false",
           (unsigned long)space.f_frsize,
           (unsigned long long)space.f_bavail * space.f_frsize);
    close(fd);
    return 0;
}
