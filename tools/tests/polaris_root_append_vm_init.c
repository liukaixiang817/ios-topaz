/* Complete a genuinely interrupted synthetic new file, with real Linux ext4. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/fs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#define TARGET "/mnt/polaris-ios-20F66-0124-0001/root.img"
static void stop(int ok){printf("ROOT_APPEND_VM_RESULT=%d\n",ok);fflush(NULL);sync();reboot(RB_POWER_OFF);for(;;)sleep(100);}
static int run(char *const args[],const char *input){pid_t p=fork();if(p<0)return -1;if(!p){int fd=open(input,O_RDONLY);if(fd<0||dup2(fd,0)<0)_exit(126);close(fd);execv(args[0],args);_exit(127);}int s;if(waitpid(p,&s,0)!=p)return -1;return WIFEXITED(s)?WEXITSTATUS(s):-1;}
static int same(const struct stat*a,const struct stat*b){return a->st_ino==b->st_ino&&a->st_size==b->st_size&&a->st_ctim.tv_sec==b->st_ctim.tv_sec&&a->st_ctim.tv_nsec==b->st_ctim.tv_nsec&&a->st_mtim.tv_sec==b->st_mtim.tv_sec&&a->st_mtim.tv_nsec==b->st_mtim.tv_nsec;}
int main(void){
 setvbuf(stdout,NULL,_IONBF,0);mkdir("/dev",0755);mkdir("/proc",0755);mkdir("/sys",0755);mkdir("/mnt",0700);
 if(mount("proc","/proc","proc",0,NULL)||mount("sysfs","/sys","sysfs",0,NULL))stop(0);
 if(mount("devtmpfs","/dev","devtmpfs",0,NULL)&&errno!=EBUSY)stop(0);
 for(unsigned i=0;i<20&&access("/dev/vdb",F_OK);i++)sleep(1);
 if(mount("/dev/vdb","/mnt","ext4",MS_NOATIME|MS_NODEV|MS_NOSUID|MS_NOEXEC,"noinit_itable,nodiscard"))stop(0);
 char *create[]={"/receiver","/mnt",NULL};if(run(create,"/input-short")!=1)stop(0);
 struct stat before,after;if(stat(TARGET,&before)||before.st_size!=(4<<20))stop(0);
 int fd=open(TARGET,O_RDONLY);long gen=0;if(fd<0||ioctl(fd,FS_IOC_GETVERSION,&gen)||close(fd))stop(0);
 char inode[32],generation[32],badgen[32],digest[65]={0};snprintf(inode,sizeof(inode),"%"PRIu64,(uint64_t)before.st_ino);snprintf(generation,sizeof(generation),"%u",(uint32_t)gen);snprintf(badgen,sizeof(badgen),"%u",(uint32_t)gen+1);
 FILE *f=fopen("/prefix.sha","r");if(!f||fread(digest,1,64,f)!=64||fclose(f))stop(0);
 char *append[]={"/append","/mnt","4194304",inode,generation,digest,NULL};
 char *physical[]={"/physical-append","/mnt","4194304",inode,generation,digest,NULL};
 if(run(physical,"/input-tail")!=1||stat(TARGET,&after)||!same(&before,&after))stop(0);puts("ROOT_APPEND_PRODUCTION_VM_REFUSAL_UNCHANGED=1");
 append[4]=badgen;if(run(append,"/input-tail")!=1||stat(TARGET,&after)||!same(&before,&after))stop(0);append[4]=generation;puts("ROOT_APPEND_WRONG_GENERATION_ZERO_WRITE=1");
 append[5]="0000000000000000000000000000000000000000000000000000000000000000";if(run(append,"/input-tail")!=1||stat(TARGET,&after)||!same(&before,&after))stop(0);append[5]=digest;puts("ROOT_APPEND_WRONG_PREFIX_ZERO_WRITE=1");
 if(run(append,"/input-tail")!=0||stat(TARGET,&after)||after.st_ino!=before.st_ino||after.st_size!=(8<<20))stop(0);puts("ROOT_APPEND_SAME_INODE_EXACT_COMPLETION=1");
 if(run(append,"/input-tail")!=1||stat(TARGET,&before)||!same(&before,&after))stop(0);puts("ROOT_APPEND_COMPLETE_IMMUTABLE_REUSE_REFUSED=1");
 if(umount("/mnt"))stop(0);fd=open("/dev/vdb",O_RDONLY);int ro=1;if(fd<0||ioctl(fd,BLKROSET,&ro)||close(fd)||mount("/dev/vdb","/mnt","ext4",MS_RDONLY|MS_NODEV|MS_NOSUID|MS_NOEXEC,"noload"))stop(0);
 fd=open(TARGET,O_RDONLY);unsigned long flags=0;if(fd<0||ioctl(fd,FS_IOC_GETFLAGS,&flags)||flags!=0x80090||close(fd)||umount("/mnt"))stop(0);puts("ROOT_APPEND_ACTUAL_UNMOUNT_RO_PIN=1");stop(1);return 1;
}
