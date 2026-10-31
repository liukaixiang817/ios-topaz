/* Real isolated Linux/ext4 stream integration; four new synthetic disks.
 * No phone, host shares, network, Apple image or production-sized filesystem.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/wait.h>
#include <unistd.h>
#define DIR "/mnt/polaris-ios-20F66-0124-0001"
#define FILE_PATH DIR "/root.img"
static void stop(int ok){printf("ROOT_RECEIVE_VM_RESULT=%d\n",ok);fflush(NULL);sync();reboot(RB_POWER_OFF);for(;;)sleep(100);}
static int run(const char *binary,const char *input){pid_t p=fork();if(p<0)return -1;if(!p){int fd=open(input,O_RDONLY);if(fd<0||dup2(fd,0)<0)_exit(126);close(fd);execl(binary,binary,"/mnt",NULL);_exit(127);}int s;if(waitpid(p,&s,0)!=p)return -1;return WIFEXITED(s)?WEXITSTATUS(s):-1;}
static int absent(void){struct stat s;return lstat(DIR,&s)==-1&&errno==ENOENT;}
int main(void){
 setvbuf(stdout,NULL,_IONBF,0);mkdir("/dev",0755);mkdir("/proc",0755);mkdir("/sys",0755);mkdir("/mnt",0700);
 if(mount("proc","/proc","proc",0,NULL)||mount("sysfs","/sys","sysfs",0,NULL))stop(0);
 if(mount("devtmpfs","/dev","devtmpfs",0,NULL)&&errno!=EBUSY)stop(0);
 const char *devices[]={"/dev/vdb","/dev/vdc","/dev/vdd","/dev/vde"};
 for(unsigned i=0;i<4;i++){
  for(unsigned n=0;n<20&&access(devices[i],F_OK);n++)sleep(1);
  if(mount(devices[i],"/mnt","ext4",MS_NOATIME|MS_NODEV|MS_NOSUID|MS_NOEXEC,"noinit_itable,nodiscard"))stop(0);
  struct stat before,after;if(stat("/mnt/baseline.img",&before))stop(0);
  if(i==0){
   if(run("/physical-receiver","/input-good")!=1||!absent())stop(0);
   puts("ROOT_RECEIVE_PRODUCTION_REFUSES_VM_BEFORE_ALLOCATION=1");
   if(run("/receiver","/input-bad-header")!=1||!absent())stop(0);
   puts("ROOT_RECEIVE_BAD_HEADER_ZERO_ALLOCATION=1");
   if(run("/receiver","/input-good")!=0)stop(0);
   struct stat first,second;if(stat(FILE_PATH,&first)||run("/receiver","/input-good")!=1||stat(FILE_PATH,&second)||first.st_ino!=second.st_ino||first.st_size!=second.st_size||first.st_ctim.tv_sec!=second.st_ctim.tv_sec||first.st_ctim.tv_nsec!=second.st_ctim.tv_nsec)stop(0);
   puts("ROOT_RECEIVE_COMPLETE_AND_EXISTING_REFUSAL=1");
  }else if(i==1){
   if(symlink("baseline.img",DIR)||run("/receiver","/input-good")!=1)stop(0);
   puts("ROOT_RECEIVE_SYMLINK_REFUSED=1");
  }else{
   if(run("/receiver",i==2?"/input-short":"/input-bad-hash")!=1)stop(0);
   int fd=open(FILE_PATH,O_RDONLY|O_NOFOLLOW);unsigned long flags=0;
   if(fd<0||ioctl(fd,FS_IOC_GETFLAGS,&flags)||flags&FS_IMMUTABLE_FL||close(fd))stop(0);
   puts(i==2?"ROOT_RECEIVE_SHORT_RETAINED_UNCOMMITTED=1":"ROOT_RECEIVE_HASH_MISMATCH_RETAINED_UNCOMMITTED=1");
  }
  if(stat("/mnt/baseline.img",&after)||before.st_ino!=after.st_ino||before.st_size!=after.st_size||before.st_mtim.tv_sec!=after.st_mtim.tv_sec||before.st_mtim.tv_nsec!=after.st_mtim.tv_nsec)stop(0);
  if(umount("/mnt"))stop(0);int fd=open(devices[i],O_RDONLY),ro=1;
  if(fd<0||ioctl(fd,BLKROSET,&ro)||close(fd)||mount(devices[i],"/mnt","ext4",MS_RDONLY|MS_NODEV|MS_NOSUID|MS_NOEXEC,"noload"))stop(0);
  if(i==0){fd=open(FILE_PATH,O_RDONLY|O_NOFOLLOW);unsigned long flags=0;struct stat s;if(fd<0||fstat(fd,&s)||ioctl(fd,FS_IOC_GETFLAGS,&flags)||flags!=0x80090||s.st_size!=(8<<20)||close(fd))stop(0);puts("ROOT_RECEIVE_POST_UNMOUNT_RO_PIN_IDENTITY=1");}
  if(umount("/mnt"))stop(0);printf("ROOT_RECEIVE_ACTUAL_UNMOUNT_%u=1\n",i);
 }
 stop(1);return 1;
}
