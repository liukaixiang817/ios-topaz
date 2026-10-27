/* Minimal PID1 for an isolated Linux/QEMU filesystem test. Only /dev/vdb,
 * a newly created synthetic filesystem, is mounted. No host shares/network.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
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
#include <linux/fs.h>

#define TARGET "/mnt/polaris-owned-v0077-0001/marker.bin"
static int child(char *const arguments[])
{
    pid_t pid=fork();if(pid<0)return -1;
    if(!pid){execv(arguments[0],arguments);perror("exec");_exit(127);}
    int status;if(waitpid(pid,&status,0)!=pid)return -1;
    return WIFEXITED(status)?WEXITSTATUS(status):-1;
}
static void stop(int success)
{
    printf("OWNED_LINUX_VM_RESULT=%d\n",success);
    fflush(NULL);sync();reboot(RB_POWER_OFF);
    for(;;)sleep(100);
}
static int pseudo(const char *source,const char *path,const char *kind,unsigned long magic)
{
    if(!mount(source,path,kind,0,NULL))return 0;
    struct statfs fs;
    return errno==EBUSY&&!statfs(path,&fs)&&fs.f_type==magic?0:-1;
}
int main(void)
{
    setvbuf(stdout,NULL,_IONBF,0);
    mkdir("/proc",0755);mkdir("/sys",0755);mkdir("/dev",0755);mkdir("/mnt",0700);
    if(pseudo("proc","/proc","proc",0x9fa0)||pseudo("sysfs","/sys","sysfs",0x62656572)||
       pseudo("devtmpfs","/dev","devtmpfs",0x01021994)){perror("pseudo mounts");stop(0);}
    for(unsigned n=0;n<20&&access("/dev/vdb",F_OK);n++)sleep(1);
    if(mount("/dev/vdb","/mnt","ext4",MS_NOATIME|MS_NODIRATIME|MS_NODEV|MS_NOSUID|MS_NOEXEC,NULL)){
        perror("synthetic ext4 mount");
        FILE *p=fopen("/proc/filesystems","r");if(p){char s[160];while(fgets(s,sizeof(s),p))fputs(s,stdout);fclose(p);}
        stop(0);
    }
    char cmdline[1024]={0};FILE *f=fopen("/proc/cmdline","r");if(f){fgets(cmdline,sizeof(cmdline),f);fclose(f);}
    int symlink_case=strstr(cmdline,"owned_symlink=1")!=NULL;
    char *physical[]={"/physical-creator","/mnt",NULL};
    struct stat forbidden;
    if(child(physical)!=1||!lstat("/mnt/polaris-owned-v0077-0001",&forbidden)||errno!=ENOENT){
        puts("physical helper failed to refuse before namespace creation");stop(0);
    }
    puts("OWNED_PHYSICAL_BUILD_REFUSED_SYNTHETIC_DISK=1");
    if(symlink_case&&symlink("baseline.img","/mnt/polaris-owned-v0077-0001")){perror("test symlink");stop(0);}
    char *create[]={"/creator","/mnt",NULL};int first=child(create);
    if(symlink_case){
        if(first!=1){printf("unexpected symlink result=%d\n",first);stop(0);}
        puts("OWNED_SYMLINK_NAMESPACE_REFUSED=1");
    }else{
        if(first){printf("creator exit=%d\n",first);stop(0);}
        struct stat before,after;
        if(stat(TARGET,&before)||child(create)!=1||stat(TARGET,&after)||
           before.st_ino!=after.st_ino||before.st_size!=after.st_size||
           before.st_ctim.tv_sec!=after.st_ctim.tv_sec||before.st_ctim.tv_nsec!=after.st_ctim.tv_nsec){
            puts("existing namespace refusal/identity failed");stop(0);
        }
        puts("OWNED_EXISTING_NAMESPACE_REFUSED=1");
    }
    if(umount("/mnt")){perror("real ext4 unmount");stop(0);}
    puts("OWNED_REAL_EXT4_UNMOUNTED=1");
    int fd=open("/dev/vdb",O_RDONLY);int ro=1;
    if(fd<0||ioctl(fd,BLKROSET,&ro)||close(fd)||
       mount("/dev/vdb","/mnt","ext4",MS_RDONLY|MS_NOATIME|MS_NODEV|MS_NOSUID|MS_NOEXEC,"noload")){
        perror("blockRO ro/noload remount");stop(0);
    }
    if(!symlink_case){
        char *export[]={"/exporter","--identity",TARGET,NULL};
        if(child(export)){puts("real readonly FIEMAP export failed");stop(0);}
    }
    if(umount("/mnt")){perror("readonly unmount");stop(0);}
    puts("OWNED_LINUX_FILESYSTEM_TEST_COMPLETE=1");stop(1);
    return 1;
}
