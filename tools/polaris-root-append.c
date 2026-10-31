/* Complete ONLY our independently reviewed partial new20F66 file by appending.
 * Existing bytes are read/hashed, never overwritten. No unlink/truncate/repair/
 * unpin/raw-write API. Fixed own namespace and final root digest;600s bound. */
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
static bool fullhashfinal(uint32_t s[8]){uint8_t tail[64]={0x80};char hex[65];uint64_t bits=BYTES*8;for(unsigned i=0;i<8;i++)tail[63-i]=(uint8_t)(bits>>(8*i));sha256_process_arm(s,tail,64);for(unsigned i=0;i<8;i++)snprintf(hex+8*i,9,"%08x",s[i]);return !strcmp(hex,EXPECTED);}
static bool prefixfinal(uint32_t state[8],uint64_t bytes,const char *expected){
 unsigned carry=(unsigned)(bytes%64),padded=carry<56?64:128;
 uint8_t tail[128]={0};char hex[65];memcpy(tail,data+((bytes%CHUNK)&~63ull),carry);tail[carry]=0x80;
 uint64_t bits=bytes*8;for(unsigned i=0;i<8;i++)tail[padded-1-i]=(uint8_t)(bits>>(8*i));
 sha256_process_arm(state,tail,padded);for(unsigned i=0;i<8;i++)snprintf(hex+8*i,9,"%08x",state[i]);return !strcmp(hex,expected);
}
static bool number(const char *s,uint64_t *v){char *end;errno=0;*v=strtoull(s,&end,10);return *s&&*s!='-'&&!errno&&!*end;}
int main(int argc,char **argv){
 setvbuf(stdout,NULL,_IONBF,0);umask(077);alarm(600);
 uint64_t prefix=0,inode=0,gen=0;
 if(argc!=6||geteuid()!=0||getegid()!=0||!(getauxval(AT_HWCAP)&HWCAP_SHA2)||
    !number(argv[2],&prefix)||!number(argv[3],&inode)||!number(argv[4],&gen)||!inode||gen>UINT32_MAX||
    prefix<BYTES/2||prefix>=BYTES||strlen(argv[5])!=64)return fail("exact reviewed prefix identity arguments");
 for(unsigned i=0;i<64;i++)if(!((argv[5][i]>='0'&&argv[5][i]<='9')||(argv[5][i]>='a'&&argv[5][i]<='f')))return fail("prefix digest spelling");
#ifndef POLARIS_ROOT_RECEIVE_VM_TEST
 if(prefix<14ull<<30)return fail("only observed near-complete production prefix");
#endif
 int root=open(argv[1],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);struct stat rs,ds,before,after;struct statfs fs;struct statvfs space;
 if(root<0||fstat(root,&rs)||fstatfs(root,&fs)||fstatvfs(root,&space)||fs.f_type!=0xef53||space.f_flag&ST_RDONLY||space.f_frsize!=4096||rs.st_ino!=2||space.f_bavail<(BYTES-prefix+MIN_FREE)/4096||!backing(rs.st_dev)||flock(root,LOCK_EX|LOCK_NB))return fail("exact writable ext4/backing/free admission");
 int dir=openat(root,DIRECTORY,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
 if(dir<0||fstat(dir,&ds)||ds.st_dev!=rs.st_dev||ds.st_uid||ds.st_gid||(ds.st_mode&07777)!=0700)return fail("existing own directory identity");
 int fd=openat(dir,NAME,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);unsigned long flags=0;long generation=0;
 if(fd<0||flock(fd,LOCK_EX|LOCK_NB)||fstat(fd,&before)||!ordinary(&before,prefix)||before.st_dev!=rs.st_dev||before.st_ino!=inode||ioctl(fd,FS_IOC_GETVERSION,&generation)||(uint32_t)generation!=gen||ioctl(fd,FS_IOC_GETFLAGS,&flags)||flags!=FS_EXTENT_FL)return fail("reviewed unpinned prefix inode/generation/size");
 struct fscrypt_policy_v1 policy={0};errno=0;if(ioctl(fd,FS_IOC_GET_ENCRYPTION_POLICY,&policy)!=-1||errno!=ENODATA)return fail("no encryption policy");
 uint32_t state[8];hashinit(state);
 for(uint64_t at=0;at<prefix;){size_t n=prefix-at<CHUNK?(size_t)(prefix-at):CHUNK;if(fullread(fd,n)||(!at&&!hfs()))return fail("full prefix/header read");sha256_process_arm(state,data,(uint32_t)(n&~63u));at+=n;}
 if(!prefixfinal(state,prefix,argv[5]))return fail("actual prefix differs from reviewed host bytes");
 int output=openat(dir,NAME,O_WRONLY|O_APPEND|O_NOFOLLOW|O_CLOEXEC);long reopened=0;
 if(output<0||fstat(output,&after)||!ordinary(&after,prefix)||after.st_dev!=rs.st_dev||after.st_ino!=inode||ioctl(output,FS_IOC_GETVERSION,&reopened)||(uint32_t)reopened!=gen)return fail("same reviewed append-only inode");
 for(uint64_t at=prefix;at<BYTES;){size_t n=BYTES-at<CHUNK?(size_t)(BYTES-at):CHUNK;if(fullread(STDIN_FILENO,n))return fail("short missing-tail input");ssize_t wrote=write(output,data,n);if(wrote!=(ssize_t)n)return fail("complete bounded append");at+=n;}
 if(fsync(output)||fstat(output,&after)||!ordinary(&after,BYTES)||after.st_ino!=inode||(uint64_t)after.st_blocks<BYTES/512||close(output))return fail("tail append fsync/size/identity");
 if(lseek(fd,0,SEEK_SET)!=0)return fail("readonly full final verification");hashinit(state);
 for(uint64_t at=0;at<BYTES;at+=CHUNK){if(fullread(fd,CHUNK))return fail("complete final content read");sha256_process_arm(state,data,CHUNK);}
 if(!fullhashfinal(state))return fail("final root digest");
 if(ioctl(fd,FS_IOC_GETFLAGS,&flags)||flags!=FS_EXTENT_FL)return fail("pre-pin unchanged flags");
 flags=PIN;if(ioctl(fd,FS_IOC_SETFLAGS,&flags)||ioctl(fd,FS_IOC_GETFLAGS,&flags)||flags!=PIN||fsync(fd)||fsync(dir)||fsync(root)||syncfs(fd)||fstat(fd,&after)||after.st_ino!=inode||ioctl(fd,FS_IOC_GETVERSION,&reopened)||(uint32_t)reopened!=gen)return fail("immutable final pin/file-directory-fs sync");
 if(close(fd)||close(dir)||close(root))return fail("final close");alarm(0);
 printf("{\"complete\":true,\"test_build\":"TEST_BUILD",\"append_only\":true,\"prefix_bytes_unchanged\":%"PRIu64",\"appended_bytes\":%"PRIu64",\"bytes\":%"PRIu64",\"sha256\":\""EXPECTED"\",\"inode\":%"PRIu64",\"generation\":%"PRIu32",\"flags\":%lu,\"raw_device_write_api\":false,\"post_unmount_proven\":false}\n",prefix,(uint64_t)BYTES-prefix,(uint64_t)BYTES,inode,(uint32_t)gen,flags);
 return 0;
}
