/* Australia/Melbourne from the exact original20F66 TZif. HackiOS a79ff077
 * userland/build.sh:495-499 independently corrects the original cyclic/missing
 * zoneinfo link to zoneinfo.default. Keep its named-zone approach, not a fixed
 * offset. The original localtime inode is retained for verified rollback.
 */
#include "polaris-timezone.h"
#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <unistd.h>

#define PTZ_ZONE "Australia/Melbourne"
#define PTZ_SOURCE_PATH "/usr/share/zoneinfo.default/Australia/Melbourne"
static const char ptz_previous[]="/var/db/timezone/zoneinfo/US/Pacific";
static const char ptz_selected[]="/var/db/timezone/zoneinfo/" PTZ_ZONE;
static const char ptz_database[]="/usr/share/zoneinfo.default";
static const char ptz_new_zone[]=".polaris-0138-zoneinfo.new";
static const char ptz_new_local[]=".polaris-0138-localtime.new";
static const char ptz_backup[]=".polaris-0138-localtime.original";
static const uint8_t ptz_tzif_sha[32]={0x9c,0x49,0xd5,0xcf,0xe4,0x97,0x35,0x9d,
    0xcd,0xa1,0x75,0x30,0x05,0x43,0x5d,0x9c,0xdc,0x9e,0xb4,0x9a,0x06,0x34,0x5c,0xf4,
    0xd7,0x35,0x58,0xe5,0x41,0x14,0x65,0xd9};
static const uint8_t ptz_version_sha[32]={0x46,0x45,0x7f,0x81,0xa0,0x4a,0x81,0xf4,
    0x62,0xbf,0xa0,0xab,0x24,0x69,0x3e,0xff,0x21,0x40,0xce,0x81,0xa2,0x54,0xe6,0x43,
    0x54,0xe4,0x3b,0xd0,0xb9,0x96,0xdd,0x22};
struct ptz_run {
    struct polaris_timezone_report *r;
    uid_t uid;gid_t gid;
    int parent;
    struct stat original,zone_new,local_new;
    unsigned made_zone,made_local;
#ifdef POLARIS_TIMEZONE_FIXTURE
    int fault;
#endif
};
static int ptz_same(const struct stat *a,const struct stat *b)
{return a->st_dev==b->st_dev&&a->st_ino==b->st_ino;}
static int ptz_owner(struct ptz_run *p,const struct stat *s,mode_t mode)
{return s->st_uid==p->uid&&s->st_gid==p->gid&&s->st_mode==mode;}
/* Only compile-time paths reach this no-symlink component walk. /var is
 * deliberately spelled /private/var here; no link may redirect this writer. */
static int ptz_open_fixed(int root,const char *path,int flags)
{
    char copy[PATH_MAX];size_t n=strlen(path);
    if(!n||path[0]!='/'||n>=sizeof(copy)){errno=EINVAL;return -1;}
    memcpy(copy,path+1,n);int fd=dup(root);if(fd<0)return -1;
    char *part=copy;
    for(;;) {
        char *slash=strchr(part,'/');if(slash)*slash=0;
        if(!*part||!strcmp(part,".")||!strcmp(part,"..")){close(fd);errno=EINVAL;return -1;}
        int next=openat(fd,part,(slash?O_RDONLY|O_DIRECTORY:flags)|O_NOFOLLOW|O_CLOEXEC);
        close(fd);if(next<0)return -1;fd=next;if(!slash)return fd;part=slash+1;
    }
}
static int ptz_hash_file(struct ptz_run *p,int root,const char *path,size_t bytes,
    mode_t mode,const uint8_t sha[32],uint8_t *data)
{
    int fd=ptz_open_fixed(root,path,O_RDONLY);if(fd<0)return -1;
    struct stat before,after;int ok=0;
    if(fstat(fd,&before))goto done;
    if(!ptz_owner(p,&before,S_IFREG|mode)){errno=EPERM;goto done;}
    if(before.st_size!=(off_t)bytes){errno=EINVAL;goto done;}
    size_t at=0;
    while(at<bytes) {
        ssize_t n=pread(fd,data+at,bytes-at,(off_t)at);
        if(n<0&&errno==EINTR)continue;
        if(n<=0){if(!n)errno=EIO;goto done;}at+=(size_t)n;
    }
    uint8_t extra,digest[32];ssize_t n=pread(fd,&extra,1,(off_t)bytes);
    if(n||!CC_SHA256(data,(CC_LONG)bytes,digest)||memcmp(digest,sha,32)) {errno=EINVAL;goto done;}
    if(fstat(fd,&after)||!ptz_same(&before,&after)||before.st_mode!=after.st_mode||
       before.st_uid!=after.st_uid||before.st_gid!=after.st_gid||before.st_size!=after.st_size||
       before.st_mtimespec.tv_sec!=after.st_mtimespec.tv_sec||
       before.st_mtimespec.tv_nsec!=after.st_mtimespec.tv_nsec){errno=ESTALE;goto done;}
    ok=1;
done:
    {int saved=errno;close(fd);errno=saved;}return ok?0:-1;
}
static int ptz_link(struct ptz_run *p,int parent,const char *name,const char *target,
    const struct stat *identity,struct stat *out)
{
    char value[PATH_MAX];struct stat s;
    if(fstatat(parent,name,&s,AT_SYMLINK_NOFOLLOW))return -1;
    if(!ptz_owner(p,&s,S_IFLNK|0755)||(identity&&!ptz_same(identity,&s))){errno=ESTALE;return -1;}
    ssize_t n=readlinkat(parent,name,value,sizeof(value));
    if(n!=(ssize_t)strlen(target)||memcmp(value,target,(size_t)n)){errno=EINVAL;return -1;}
    if(out)*out=s;return 0;
}
static int ptz_absent(int parent,const char *name)
{
    struct stat s;if(!fstatat(parent,name,&s,AT_SYMLINK_NOFOLLOW)){errno=EEXIST;return -1;}
    return errno==ENOENT?0:-1;
}
static int ptz_remove(struct ptz_run *p,const char *name,const char *target,
    const struct stat *identity,unsigned *made)
{
    if(!*made)return 0;
    if(ptz_link(p,p->parent,name,target,identity,NULL)||unlinkat(p->parent,name,0))return -1;
    *made=0;return 0;
}
static int ptz_make(struct ptz_run *p,const char *name,const char *target,
    unsigned *made,struct stat *identity)
{
    if(symlinkat(target,p->parent,name))return -1;*made=1;
    if(fstatat(p->parent,name,identity,AT_SYMLINK_NOFOLLOW))return -1;
    if(fchownat(p->parent,name,p->uid,p->gid,AT_SYMLINK_NOFOLLOW)||
       fchmodat(p->parent,name,0755,AT_SYMLINK_NOFOLLOW))return -1;
    struct timespec times[2]={p->original.st_atimespec,p->original.st_mtimespec};
    if(utimensat(p->parent,name,times,AT_SYMLINK_NOFOLLOW)||
       ptz_link(p,p->parent,name,target,identity,NULL))return -1;
    p->r->prepared++;return 0;
}
static int ptz_fault(struct ptz_run *p,int point)
{
#ifdef POLARIS_TIMEZONE_FIXTURE
    if(p->fault==point||(p->fault==6&&point==5)){errno=EIO;return -1;}
#else
    (void)p;(void)point;
#endif
    return 0;
}
static int ptz_source(int root,struct ptz_run *p)
{
    uint8_t version[570],data[2195];struct stat directory;
    if(ptz_hash_file(p,root,"/System/Library/CoreServices/SystemVersion.plist",570,0444,ptz_version_sha,version)||
       ptz_hash_file(p,root,PTZ_SOURCE_PATH,2195,0644,ptz_tzif_sha,data))return -1;
    p->r->validated=2;
    CFDataRef tzdata=CFDataCreate(NULL,data,sizeof(data));
    CFTimeZoneRef zone=tzdata?CFTimeZoneCreate(NULL,CFSTR(PTZ_ZONE),tzdata):NULL;
    if(tzdata)CFRelease(tzdata);
    if(!zone){errno=EINVAL;return -1;}
    /* These are validation observations from the original file, never an
     * offset used to set the clock or implement timezone conversion. */
    p->r->january_offset=(int32_t)CFTimeZoneGetSecondsFromGMT(zone,790128000.0);
    p->r->july_offset=(int32_t)CFTimeZoneGetSecondsFromGMT(zone,805766400.0);
    int ok=CFEqual(CFTimeZoneGetName(zone),CFSTR(PTZ_ZONE))&&
        p->r->january_offset==39600&&p->r->july_offset==36000;
    CFRelease(zone);if(!ok){errno=EINVAL;return -1;}
    int share=ptz_open_fixed(root,"/usr/share",O_RDONLY|O_DIRECTORY);if(share<0)return -1;
    ok=!ptz_link(p,share,"zoneinfo","/var/db/timezone/zoneinfo",NULL,NULL);
    {int saved=errno;close(share);errno=saved;}if(!ok)return -1;p->r->validated++;
    p->parent=ptz_open_fixed(root,"/private/var/db/timezone",O_RDONLY|O_DIRECTORY);
    if(p->parent<0||fstat(p->parent,&directory))return -1;
    if(!ptz_owner(p,&directory,S_IFDIR|0755)){errno=EPERM;return -1;}
    if(ptz_link(p,p->parent,"localtime",ptz_previous,NULL,&p->original)||
       ptz_absent(p->parent,"zoneinfo")||ptz_absent(p->parent,ptz_new_zone)||
       ptz_absent(p->parent,ptz_new_local)||ptz_absent(p->parent,ptz_backup))return -1;
    p->r->validated+=2;return 0;
}
static int ptz_transaction(int root,struct ptz_run *p)
{
    struct polaris_timezone_report *r=p->r;r->stage=2;
    if(ptz_source(root,p)){r->error=errno?errno:EINVAL;return PTZ_SOURCE;}
    r->stage=3;
    if(ptz_make(p,ptz_new_zone,ptz_database,&p->made_zone,&p->zone_new)||
       ptz_fault(p,1)||ptz_make(p,ptz_new_local,ptz_selected,&p->made_local,&p->local_new)||
       fsync(p->parent)||ptz_fault(p,2))goto prepare_failed;
    r->stage=4;
    if(renameatx_np(p->parent,ptz_new_zone,p->parent,"zoneinfo",RENAME_EXCL))goto prepare_failed;
    p->made_zone=0;r->zoneinfo_active=1;
    if(ptz_fault(p,3)||ptz_link(p,p->parent,"localtime",ptz_previous,&p->original,NULL)||
       renameatx_np(p->parent,"localtime",p->parent,ptz_backup,RENAME_EXCL))goto rollback;
    r->original_saved=1;
    if(ptz_fault(p,4)||renameatx_np(p->parent,ptz_new_local,p->parent,"localtime",RENAME_EXCL))goto rollback;
    p->made_local=0;r->localtime_active=1;
    if(ptz_fault(p,5)||ptz_link(p,p->parent,"zoneinfo",ptz_database,&p->zone_new,NULL)||
       ptz_link(p,p->parent,"localtime",ptz_selected,&p->local_new,NULL)||
       ptz_link(p,p->parent,ptz_backup,ptz_previous,&p->original,NULL)||fsync(p->parent))goto rollback;
    r->stage=5;return PTZ_OK;
rollback:
    r->error=errno?errno:EIO;
    if(r->localtime_active) {
        unsigned made=1;if(ptz_remove(p,"localtime",ptz_selected,&p->local_new,&made))r->must_hold=1;
        else r->localtime_active=0;
    }
    if(r->original_saved) {
        if(ptz_fault(p,6)||ptz_link(p,p->parent,ptz_backup,ptz_previous,&p->original,NULL)||
           renameatx_np(p->parent,ptz_backup,p->parent,"localtime",RENAME_EXCL))r->must_hold=1;
        else {r->original_saved=0;r->restored=1;}
    }
    if(r->zoneinfo_active) {
        unsigned made=1;if(ptz_remove(p,"zoneinfo",ptz_database,&p->zone_new,&made))r->must_hold=1;
        else r->zoneinfo_active=0;
    }
    if(ptz_link(p,p->parent,"localtime",ptz_previous,&p->original,NULL)||
       ptz_absent(p->parent,"zoneinfo")||fsync(p->parent))r->must_hold=1;
    if(r->must_hold){r->stage=7;return PTZ_ROLLBACK_FAILED;}
    if(ptz_remove(p,ptz_new_zone,ptz_database,&p->zone_new,&p->made_zone))r->cleanup_failures++;
    if(ptz_remove(p,ptz_new_local,ptz_selected,&p->local_new,&p->made_local))r->cleanup_failures++;
    return PTZ_ROLLED_BACK;
prepare_failed:
    r->error=errno?errno:EIO;
    if(ptz_remove(p,ptz_new_zone,ptz_database,&p->zone_new,&p->made_zone))r->cleanup_failures++;
    if(ptz_remove(p,ptz_new_local,ptz_selected,&p->local_new,&p->made_local))r->cleanup_failures++;
    return PTZ_PREPARE;
}
static int ptz_context(struct polaris_timezone_report *r)
{
    if(getpid()!=1||getuid()!=0||geteuid()!=0){errno=EPERM;return -1;}
    char executable[PATH_MAX]={0};uint32_t bytes=sizeof(executable);
    if(_NSGetExecutablePath(executable,&bytes))return -1;
    if(strcmp(executable,"/usr/libexec/polaris-init")){errno=EPERM;return -1;}
    struct statfs fs={0};struct stat dev={0};
    if(statfs("/",&fs)||lstat("/dev/ufsroot0",&dev))return -1;
    if(strcmp(fs.f_fstypename,"hfs")||strcmp(fs.f_mntfromname,"root_device")||
       !(fs.f_flags&MNT_ROOTFS)||(fs.f_flags&MNT_RDONLY)||!S_ISBLK(dev.st_mode)||
       !dev.st_rdev||(uint32_t)dev.st_rdev!=(uint32_t)fs.f_fsid.val[0]){errno=EPERM;return -1;}
    struct {uint32_t version,bytes,flags,reserved;uint64_t values[9];} cow={0};size_t size=sizeof(cow);
    if(sysctlbyname("kern.polaris_ramcow_status",&cow,&size,NULL,0))return -1;
    fprintf(stderr,"POLARIS TIMEZONE CONTEXT: HFS root_device rdev=%x fsid=%x cowversion=%u size=%llu flags=%u remaining=%llu\n",
        (unsigned)dev.st_rdev,(unsigned)fs.f_fsid.val[0],cow.version,(unsigned long long)size,
        cow.flags,(unsigned long long)cow.values[3]);
    if(size!=sizeof(cow)||cow.version!=1||cow.bytes!=sizeof(cow)||cow.flags!=1||
       !cow.values[0]||cow.values[0]>32768||cow.values[3]<UINT64_C(33554432)) {errno=EPERM;return -1;}
    (void)r;return 0;
}
int polaris_timezone_install(struct polaris_timezone_report *report)
{
    if(!report)return PTZ_REFUSED;
    memset(report,0,sizeof(*report));report->version=1;report->stage=1;
#if !defined(PGPU_USERLAND_20F66)
    report->error=EPERM;return PTZ_REFUSED;
#else
    if(ptz_context(report)){report->error=errno?errno:EPERM;return PTZ_REFUSED;}
    int root=open("/",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(root<0){report->error=errno;return PTZ_REFUSED;}
    struct ptz_run run={.r=report,.uid=0,.gid=0,.parent=-1};
    int result=ptz_transaction(root,&run);if(run.parent>=0)close(run.parent);close(root);return result;
#endif
}
#ifdef POLARIS_TIMEZONE_FIXTURE
int polaris_timezone_fixture(const char *directory,int fault,struct polaris_timezone_report *report)
{
    if(!report)return PTZ_REFUSED;
    memset(report,0,sizeof(*report));report->version=1;
    if(!directory||strncmp(directory,"/private/tmp/",13)){report->error=EPERM;return PTZ_REFUSED;}
    int root=open(directory,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(root<0){report->error=errno;return PTZ_REFUSED;}
    struct ptz_run run={.r=report,.uid=getuid(),.gid=getgid(),.parent=-1,.fault=fault};
    int result=ptz_transaction(root,&run);if(run.parent>=0)close(run.parent);close(root);return result;
}
#endif
