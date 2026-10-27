/* Create ONE NEW small owned marker through Linux ext4, never raw blocks.
 * No existing directory/file is opened for modification. Failure leaves the
 * new namespace for review; there is no unlink, repair, retry or overwrite.
 * Build without POLARIS_OWNED_FILE_VM_TEST for the exact physical phone.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/fs.h>
#include <linux/fscrypt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#define DIRECTORY "polaris-owned-v0077-0001"
#define NAME "marker.bin"
#define BYTES (8u*1024u*1024u)
#define PIN (FS_EXTENT_FL|FS_IMMUTABLE_FL|FS_NOATIME_FL)
#if defined(POLARIS_OWNED_FILE_VM_TEST) && defined(POLARIS_OWNED_FILE_INSPECT_ONLY)
#error "physical read-only inspection and synthetic allocation are distinct"
#endif
#if defined(POLARIS_OWNED_FILE_VM_TEST)
#define DEVICE_BYTES (128ull*1024u*1024u)
#define TEST_BUILD "true"
#define MIN_FREE (16u*1024u*1024u)
#else
#define DEVICE_BYTES UINT64_C(115167178752)
#define TEST_BUILD "false"
#define MIN_FREE (1024u*1024u*1024u)
#endif

static int failed(const char *operation)
{
    fprintf(stderr,"owned-file-create: %s failed errno=%d; never overwrite/remove/retry\n",operation,errno);
    return 1;
}
#if !defined(POLARIS_OWNED_FILE_INSPECT_ONLY)
static bool ordinary(const struct stat *s,uint64_t bytes)
{
    return S_ISREG(s->st_mode)&&s->st_uid==0&&s->st_gid==0&&
        (s->st_mode&07777)==0600&&s->st_nlink==1&&(uint64_t)s->st_size==bytes;
}
#endif
static bool block_state(dev_t device)
{
    char path[128],extra;uint64_t sectors=0;unsigned ro=1;
    snprintf(path,sizeof(path),"/sys/dev/block/%u:%u/size",major(device),minor(device));
    FILE *file=fopen(path,"r");if(!file)return false;
    int parsed=fscanf(file,"%"SCNu64" %c",&sectors,&extra);fclose(file);
    if(parsed!=1||sectors!=DEVICE_BYTES/512)return false;
    snprintf(path,sizeof(path),"/sys/dev/block/%u:%u/ro",major(device),minor(device));
    file=fopen(path,"r");if(!file)return false;
    parsed=fscanf(file,"%u %c",&ro,&extra);fclose(file);
    return parsed==1&&ro==
#if defined(POLARIS_OWNED_FILE_INSPECT_ONLY)
        1;
#else
        0;
#endif
}
#if !defined(POLARIS_OWNED_FILE_VM_TEST)
static bool physical_partition_name(dev_t device)
{
    char path[128],line[128];bool name=false,partition=false;
    snprintf(path,sizeof(path),"/sys/dev/block/%u:%u/uevent",major(device),minor(device));
    FILE *file=fopen(path,"r");if(!file)return false;
    while(fgets(line,sizeof(line),file)){
        if(!strcmp(line,"DEVNAME=sda22\n"))name=true;
        if(!strcmp(line,"PARTNAME=userdata\n"))partition=true;
    }
    bool clean=!ferror(file);fclose(file);return clean&&name&&partition;
}
#endif
int main(int argc,char **argv)
{
    setvbuf(stdout,NULL,_IONBF,0);umask(077);
    if(argc!=2||geteuid()!=0||getegid()!=0){errno=EPERM;return failed("root/MOUNT arguments");}
    int root=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    struct stat root_stat;
    struct statfs fs;struct statvfs space;
    if(root<0||fstat(root,&root_stat)||fstatfs(root,&fs)||fstatvfs(root,&space))return failed("mount metadata");
    if(fs.f_type!=0xef53||
#if defined(POLARIS_OWNED_FILE_INSPECT_ONLY)
       !(space.f_flag&ST_RDONLY)||
#else
       space.f_flag&ST_RDONLY||
#endif
       space.f_frsize!=4096||
       root_stat.st_ino!=2||
       space.f_bavail<((uint64_t)BYTES+MIN_FREE)/4096||!block_state(root_stat.st_dev)){
        errno=EINVAL;return failed("exact writable ext4/backing/free-space admission");
    }
#if !defined(POLARIS_OWNED_FILE_VM_TEST)
    /* Recovery uses Linux's extended partition dev_t. sda22 is NOT major8,
     * minor22: independently observed sysfs/stat identify259:6 and userdata.
     * Keep both the exact dev_t and literal sysfs partition identity checks.
     */
    if(major(root_stat.st_dev)!=259||minor(root_stat.st_dev)!=6||
       !physical_partition_name(root_stat.st_dev)){errno=EXDEV;return failed("exact userdata device/name");}
#endif
#if defined(POLARIS_OWNED_FILE_INSPECT_ONLY)
    printf("{\"diagnostic_readonly\":true,\"creation_api_present\":false,\"device_major\":%u,"
        "\"device_minor\":%u,\"backing_device_bytes\":%"PRIu64",\"root_inode\":%"PRIu64"}\n",
        major(root_stat.st_dev),minor(root_stat.st_dev),(uint64_t)DEVICE_BYTES,(uint64_t)root_stat.st_ino);
    return 0;
#else
    struct stat dir_stat,before,after;
    if(flock(root,LOCK_EX|LOCK_NB))return failed("exclusive directory operation");
    /* mkdir is exclusive: even an existing empty namespace or symlink fails. */
    if(mkdirat(root,DIRECTORY,0700))return failed("exclusive new namespace");
    int dir=openat(root,DIRECTORY,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(dir<0||fchown(dir,0,0)||fchmod(dir,0700)||fstat(dir,&dir_stat)||
       dir_stat.st_dev!=root_stat.st_dev||!S_ISDIR(dir_stat.st_mode)||fsync(root))return failed("new directory identity/sync");
    int fd=openat(dir,NAME,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0||fchown(fd,0,0)||fchmod(fd,0600)||fstat(fd,&before)||
       !ordinary(&before,0)||before.st_dev!=root_stat.st_dev)return failed("exclusive new file identity");
    unsigned long flags=0;long generation=0;
    if(ioctl(fd,FS_IOC_GETFLAGS,&flags)||flags!=FS_EXTENT_FL)return failed("new unencoded extent inode");
    struct fscrypt_policy_v1 policy={0};errno=0;
    if(ioctl(fd,FS_IOC_GET_ENCRYPTION_POLICY,&policy)!=-1||errno!=ENODATA)return failed("absence of encryption policy");
    static const uint8_t zero[65536]={0};uint64_t written=0;
    while(written<BYTES){
        ssize_t count=pwrite(fd,zero,sizeof(zero),(off_t)written);
        if(count<0&&errno==EINTR)continue;
        if(count<=0){if(!count)errno=EIO;return failed("full bounded allocation/write");}
        written+=(uint64_t)count;
        /* No failed or partial write is silently reported as complete. */
        if((size_t)count!=sizeof(zero)){errno=EIO;return failed("short write");}
    }
    if(fsync(fd)||fstat(fd,&before)||!ordinary(&before,BYTES)||
       (uint64_t)before.st_blocks<BYTES/512||ioctl(fd,FS_IOC_GETVERSION,&generation))return failed("completed allocation/data fsync");
    if(close(fd))return failed("close writable file");
    fd=openat(dir,NAME,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    long reopened_generation=0;
    if(fd<0||fstat(fd,&after)||!ordinary(&after,BYTES)||before.st_ino!=after.st_ino||
       before.st_dev!=after.st_dev||ioctl(fd,FS_IOC_GETVERSION,&reopened_generation)||
       generation!=reopened_generation)return failed("reopened inode generation");
    if(ioctl(fd,FS_IOC_GETFLAGS,&flags)||flags!=FS_EXTENT_FL)return failed("pre-pin flags");
    flags=PIN;
    if(ioctl(fd,FS_IOC_SETFLAGS,&flags)||ioctl(fd,FS_IOC_GETFLAGS,&flags)||flags!=PIN||
       fsync(fd)||fsync(dir)||fsync(root)||syncfs(fd))return failed("pin/inode/directory/filesystem synchronization");
    if(fstat(fd,&after)||!ordinary(&after,BYTES)||before.st_ino!=after.st_ino||
       ioctl(fd,FS_IOC_GETVERSION,&reopened_generation)||generation!=reopened_generation)return failed("final inode identity");
    uint8_t data[65536];
    for(uint64_t at=0;at<BYTES;at+=sizeof(data)){
        ssize_t count=pread(fd,data,sizeof(data),(off_t)at);
        if(count!=(ssize_t)sizeof(data)){errno=EIO;return failed("initial zero content readback");}
        for(size_t n=0;n<sizeof(data);n++)if(data[n]){errno=EIO;return failed("initial content mismatch");}
    }
    if(close(fd)||close(dir)||close(root))return failed("final close");
    printf("{\"version\":1,\"test_build\":"TEST_BUILD",\"created_namespace_exclusive\":true,"
           "\"created_file_exclusive\":true,\"relative_path\":\""DIRECTORY"/"NAME"\","
           "\"file_bytes\":%u,\"inode\":%"PRIu64",\"generation\":%"PRIu32","
           "\"flags\":%lu,\"links\":1,\"uid\":0,\"gid\":0,\"mode\":384,"
           "\"fully_written\":true,\"initial_zero_readback\":true,\"file_fsync\":true,"
           "\"directory_fsync\":true,\"syncfs\":true,\"raw_device_write_api\":false,"
           "\"persistent_unmount_or_powercycle_proven\":false}\n",
           BYTES,(uint64_t)after.st_ino,(uint32_t)generation,flags);
    return 0;
#endif
}
