/* Receive ONE new immutable iOS16.5 root through Linux ext4, never raw UFS.
 * No overwrite, unlink, retry, repair, unpin or access to existing file data.
 * Partial or failed namespaces remain for review. VM variant cannot admit UFS.
 */
#define _GNU_SOURCE
#include <asm/hwcap.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/fs.h>
#include <linux/fscrypt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include "vendor/sha256-arm.h"
#define DIRECTORY "polaris-ios-20F66-0124-0001"
#define NAME "root.img"
#define PIN (FS_EXTENT_FL|FS_IMMUTABLE_FL|FS_NOATIME_FL)
#ifdef POLARIS_ROOT_RECEIVE_VM_TEST
#define DEVICE_BYTES (128ull<<20)
#define BYTES (8ull<<20)
#define MIN_FREE (16ull<<20)
#define EXPECTED "30be714f7ba1516a4a135866e535d400d978cad0a7a8f4e16ba2c226059b7906"
#define TEST_BUILD "true"
#else
#define DEVICE_BYTES UINT64_C(115167178752)
#define BYTES (16ull<<30)
#define MIN_FREE (1ull<<30)
#define EXPECTED "91515474f2f886e1508e2ef62f0d8dce6fe4188c0dd382e566ba819264d37c0f"
#define TEST_BUILD "false"
#endif
#define CHUNK (1u<<20)
static uint8_t data[CHUNK];
static int fail(const char *s){fprintf(stderr,"root-receive: %s errno=%d; retained, no retry/remove\n",s,errno);return 1;}
static bool ordinary(const struct stat *s,uint64_t bytes){return S_ISREG(s->st_mode)&&s->st_uid==0&&s->st_gid==0&&(s->st_mode&07777)==0600&&s->st_nlink==1&&(uint64_t)s->st_size==bytes;}
static bool backing(dev_t dev){
 char p[128],extra,line[160];uint64_t sectors=0;unsigned ro=1;
 snprintf(p,sizeof(p),"/sys/dev/block/%u:%u/size",major(dev),minor(dev));
 FILE *f=fopen(p,"r");if(!f)return false;int n=fscanf(f,"%"SCNu64" %c",&sectors,&extra);fclose(f);if(n!=1||sectors!=DEVICE_BYTES/512)return false;
 snprintf(p,sizeof(p),"/sys/dev/block/%u:%u/ro",major(dev),minor(dev));
 f=fopen(p,"r");if(!f)return false;n=fscanf(f,"%u %c",&ro,&extra);fclose(f);if(n!=1||ro!=0)return false;
#ifndef POLARIS_ROOT_RECEIVE_VM_TEST
 if(major(dev)!=259||(minor(dev)!=6&&minor(dev)!=7))return false;
 snprintf(p,sizeof(p),"/sys/dev/block/%u:%u/uevent",major(dev),minor(dev));f=fopen(p,"r");if(!f)return false;
 bool name=false,partition=false;while(fgets(line,sizeof(line),f)){if(!strcmp(line,"DEVNAME=sda22\n"))name=true;if(!strcmp(line,"PARTNAME=userdata\n"))partition=true;}bool clean=!ferror(f);fclose(f);if(!name||!partition||!clean)return false;
#else
 (void)line;
#endif
 return true;
}
static int fullread(int fd,size_t n){size_t done=0;while(done<n){ssize_t k=read(fd,data+done,n-done);if(k<0&&errno==EINTR)continue;if(k<=0)return -1;done+=(size_t)k;}return 0;}
static uint32_t be32(const uint8_t*p){return (uint32_t)p[0]<<24|(uint32_t)p[1]<<16|(uint32_t)p[2]<<8|p[3];}
static bool hfs(void){return !memcmp(data+1024,"HX\0\5",4)&&be32(data+1064)>=512&&!(be32(data+1064)&(be32(data+1064)-1))&&(uint64_t)be32(data+1064)*be32(data+1068)==BYTES;}
static void hashinit(uint32_t s[8]){const uint32_t initial[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};memcpy(s,initial,sizeof(initial));}
static bool hashfinal(uint32_t s[8]){uint8_t tail[64]={0x80};char hex[65];uint64_t bits=BYTES*8;for(unsigned i=0;i<8;i++)tail[63-i]=(uint8_t)(bits>>(8*i));sha256_process_arm(s,tail,64);for(unsigned i=0;i<8;i++)snprintf(hex+8*i,9,"%08x",s[i]);return !strcmp(hex,EXPECTED);}
int main(int argc,char **argv){
 setvbuf(stdout,NULL,_IONBF,0);umask(077);alarm(600);
 if(argc!=2||geteuid()!=0||getegid()!=0||!(getauxval(AT_HWCAP)&HWCAP_SHA2))return fail("root/mount/SHA2 admission");
 int root=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);struct stat rs,ds,before,after;struct statfs fs;struct statvfs space;
 if(root<0||fstat(root,&rs)||fstatfs(root,&fs)||fstatvfs(root,&space)||fs.f_type!=0xef53||space.f_flag&ST_RDONLY||space.f_frsize!=4096||rs.st_ino!=2||space.f_bavail<(BYTES+MIN_FREE)/4096||!backing(rs.st_dev)||flock(root,LOCK_EX|LOCK_NB))return fail("exact writable ext4/free-space/backing admission");
 /* Receive/validate one bounded header before any allocation. */
 if(fullread(STDIN_FILENO,CHUNK)||!hfs())return fail("first full HFSX header");
 if(mkdirat(root,DIRECTORY,0700))return fail("exclusive new namespace");
 int dir=openat(root,DIRECTORY,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
 if(dir<0||fchown(dir,0,0)||fchmod(dir,0700)||fstat(dir,&ds)||ds.st_dev!=rs.st_dev||!S_ISDIR(ds.st_mode)||fsync(root))return fail("new directory identity/sync");
 int fd=openat(dir,NAME,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);unsigned long flags=0;long generation=0;
 if(fd<0||fstat(fd,&before)||!ordinary(&before,0)||before.st_dev!=rs.st_dev||ioctl(fd,FS_IOC_GETFLAGS,&flags)||flags!=FS_EXTENT_FL)return fail("new unencoded extent inode");
 struct fscrypt_policy_v1 policy={0};errno=0;if(ioctl(fd,FS_IOC_GET_ENCRYPTION_POLICY,&policy)!=-1||errno!=ENODATA)return fail("absence of encryption policy");
 uint32_t state[8];hashinit(state);
 for(uint64_t at=0;at<BYTES;at+=CHUNK){
  if(at&&fullread(STDIN_FILENO,CHUNK))return fail("short input");
  sha256_process_arm(state,data,CHUNK);ssize_t n=pwrite(fd,data,CHUNK,(off_t)at);
  if(n!=CHUNK)return fail("bounded complete file write");
  if((at+CHUNK)%(1ull<<30)==0)fprintf(stderr,"received %"PRIu64" / %"PRIu64" bytes\n",at+CHUNK,(uint64_t)BYTES);
 }
 if(!hashfinal(state)||fsync(fd)||fstat(fd,&after)||!ordinary(&after,BYTES)||after.st_ino!=before.st_ino||(uint64_t)after.st_blocks<BYTES/512||ioctl(fd,FS_IOC_GETVERSION,&generation))return fail("exact stream digest/allocated bytes/fsync");
 if(close(fd))return fail("writable close");fd=openat(dir,NAME,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);long reopened=0;
 if(fd<0||fstat(fd,&after)||!ordinary(&after,BYTES)||after.st_dev!=rs.st_dev||after.st_ino!=before.st_ino||ioctl(fd,FS_IOC_GETVERSION,&reopened)||generation!=reopened||ioctl(fd,FS_IOC_GETFLAGS,&flags)||flags!=FS_EXTENT_FL)return fail("read-only reopen identity/generation");
 hashinit(state);for(uint64_t at=0;at<BYTES;at+=CHUNK){if(fullread(fd,CHUNK))return fail("complete file readback");sha256_process_arm(state,data,CHUNK);}if(!hashfinal(state))return fail("readback digest");
 flags=PIN;if(ioctl(fd,FS_IOC_SETFLAGS,&flags)||ioctl(fd,FS_IOC_GETFLAGS,&flags)||flags!=PIN||fsync(fd)||fsync(dir)||fsync(root)||syncfs(fd)||fstat(fd,&after)||after.st_ino!=before.st_ino||ioctl(fd,FS_IOC_GETVERSION,&reopened)||generation!=reopened)return fail("pin/identity/file/directory/fs synchronization");
 if(close(fd)||close(dir)||close(root))return fail("final close");alarm(0);
 printf("{\"complete\":true,\"test_build\":"TEST_BUILD",\"new_file_exclusive\":true,\"bytes\":%"PRIu64",\"sha256\":\""EXPECTED"\",\"inode\":%"PRIu64",\"generation\":%"PRIu32",\"flags\":%lu,\"raw_device_write_api\":false,\"persistent_unmount_proven\":false}\n",(uint64_t)BYTES,(uint64_t)after.st_ino,(uint32_t)generation,flags);
 return 0;
}
