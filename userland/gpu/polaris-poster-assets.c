/* Exact official default7400: originalCAML/5HEIC rendered by real hostCA
 * into one full staticPNG; simpleCAML retains the official default identity.
 * No HEIC overwrite, decode on phone, generic path
 * writer, persistent storage operation, placeholder or graphics-policy change.
 * All three packages retain Locked/Unlock/Sleep static CAStates and their
 * original published scene ID. WallpaperKit requires these states even for
 * a still image; omitting them triggers its real Swift assertion.
 * The frozen private header's whole SHA256 is 2377b197...; an independently
 * pinned table+payload digest below also rejects any alternate embedded data.
 */
#include "polaris-poster-assets.h"
#include <CommonCrypto/CommonDigest.h>
#include <copyfile.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <unistd.h>
#ifndef POLARIS_POSTER_ASSET_HEADER
#error Supply only the private prepared-static-states-0002 header, whole SHA 2377b197...
#endif
#include POLARIS_POSTER_ASSET_HEADER
#define PPA_CAP UINT64_C(33554432)
#define PPA_BASE "/Library/Wallpaper/Collections/iOS_16~iphone.wallpaperCollection/Wallpapers/7400.WWDC_2022-375w-812h@3x~iphone.wallpaper/7400.WWDC_2022_"
#define PPA_BACK PPA_BASE "Background-375w-812h@3x~iphone.ca/"
#define PPA_FLOAT PPA_BASE "Floating-375w-812h@3x~iphone.ca/"
#define PPA_FORE PPA_BASE "Foreground-375w-812h@3x~iphone.ca/"
static const char *const expected_path[8]={
    PPA_BACK "assets/Polaris-iOS16-Default.PNG",PPA_BACK "assets/Head.PNG",PPA_BACK "assets/Leg.PNG",
    PPA_FLOAT "assets/Arm.PNG",PPA_FORE "assets/Body.PNG",
    PPA_BACK "main.caml",PPA_FLOAT "main.caml",PPA_FORE "main.caml"};
static const char *const expected_source[8]={
    PPA_BACK "assets/Head Mask.HEIC",PPA_BACK "assets/Head.HEIC",PPA_BACK "assets/Leg.HEIC",
    PPA_FLOAT "assets/Arm.HEIC",PPA_FORE "assets/Body.HEIC",
    PPA_BACK "main.caml",PPA_FLOAT "main.caml",PPA_FORE "main.caml"};
static const uint32_t source_bytes[8]={65125,608897,310057,677535,808440,18842,11589,11646};
static const uint32_t output_bytes[8]={3571553,0,0,0,0,471,404,406};
static const uint8_t table_binding[32]={
    0x73,0x5e,0x6e,0x05,0xb7,0x59,0x61,0xc6,0xab,0xee,0x8e,0xfe,0x80,0x0b,0xbb,0x7c,
    0xb7,0x56,0x3a,0x79,0x66,0x61,0x72,0xf9,0x70,0xf1,0x8d,0xd3,0xf6,0x74,0xe4,0x00};
static const uint8_t version_binding[32]={
    0x46,0x45,0x7f,0x81,0xa0,0x4a,0x81,0xf4,0x62,0xbf,0xa0,0xab,0x24,0x69,0x3e,0xff,
    0x21,0x40,0xce,0x81,0xa2,0x54,0xe6,0x43,0x54,0xe4,0x3b,0xd0,0xb9,0x96,0xdd,0x22};
static const char *const new_name=".polaris-0134-main.caml.new";
static const char *const restore_name=".polaris-0134-main.caml.restore";
struct ppa_file {
    int parent,source,created,new_fd,restore_fd;
    const char *source_name,*target_name;
    struct stat original,new_stat,restore_stat,png_stat;
    uint8_t *original_bytes;
    unsigned made_png,made_new,made_restore,activated;
};
struct ppa_run {
    struct ppa_file file[8];
    struct polaris_poster_assets_report *report;
    uid_t uid;gid_t gid;
#ifdef POLARIS_POSTER_ASSET_FIXTURE
    int write_limit,activation_failure;
#endif
};
static int equal_sha(const void *data,size_t bytes,const uint8_t expected[32])
{uint8_t actual[32];return bytes<=UINT32_MAX&&CC_SHA256(data,(CC_LONG)bytes,actual)&&!memcmp(actual,expected,32);}
static int same_inode(const struct stat *a,const struct stat *b)
{return a->st_dev==b->st_dev&&a->st_ino==b->st_ino;}
static int checked_stat(struct ppa_run *run,int fd,uint64_t bytes,mode_t mode,struct stat *out)
{
    return !fstat(fd,out)&&S_ISREG(out->st_mode)&&out->st_size>=0&&
        (uint64_t)out->st_size==bytes&&out->st_uid==run->uid&&out->st_gid==run->gid&&
        (out->st_mode&07777)==mode;
}
/* Walk every component with openat(O_NOFOLLOW), keeping parent descriptors.
 * Only the eight compile-time known paths reach this function. */
static int fixed_parent(int root,const char *path,const char **leaf)
{
    char copy[PATH_MAX];size_t bytes=strlen(path);
    if(!bytes||path[0]!='/'||bytes>=sizeof(copy)){errno=EINVAL;return -1;}
    memcpy(copy,path+1,bytes);int fd=dup(root);if(fd<0)return -1;
    char *part=copy;
    for(;;) {
        char *slash=strchr(part,'/');
        if(!slash){*leaf=strrchr(path,'/')+1;return fd;}
        *slash=0;
        if(!part[0]||!strcmp(part,".")||!strcmp(part,"..")){close(fd);errno=EINVAL;return -1;}
        int next=openat(fd,part,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        close(fd);if(next<0)return -1;fd=next;part=slash+1;
    }
}
static int read_exact(int fd,uint8_t *out,size_t bytes)
{
    size_t at=0;
    while(at<bytes) {
        ssize_t n=pread(fd,out+at,bytes-at,(off_t)at);
        if(n<0&&errno==EINTR)continue;
        if(n<=0)return -1;at+=(size_t)n;
    }
    uint8_t extra;ssize_t n=pread(fd,&extra,1,(off_t)bytes);
    return n==0?0:-1;
}
static int file_hash_mode(struct ppa_run *run,int fd,uint64_t bytes,mode_t mode,
    const uint8_t sha[32],struct stat *out,uint8_t **retain)
{
    if(bytes>PPA_CAP||!checked_stat(run,fd,bytes,mode,out))return -1;
    uint8_t *data=malloc((size_t)bytes);if(!data)return -1;
    int ok=!read_exact(fd,data,(size_t)bytes)&&equal_sha(data,(size_t)bytes,sha);
    struct stat after;
    ok=ok&&checked_stat(run,fd,bytes,mode,&after)&&same_inode(out,&after)&&
        after.st_mtimespec.tv_sec==out->st_mtimespec.tv_sec&&
        after.st_mtimespec.tv_nsec==out->st_mtimespec.tv_nsec;
    if(ok&&retain)*retain=data;else free(data);
    return ok?0:-1;
}
/* All eight resource sources/outputs remain exact0644. SystemVersion has
 * a separately raw-catalog-proven0444 gate; never chmod that original. */
static int file_hash(struct ppa_run *run,int fd,uint64_t bytes,
    const uint8_t sha[32],struct stat *out,uint8_t **retain)
{return file_hash_mode(run,fd,bytes,0644,sha,out,retain);}
static int version_file(int root,struct ppa_run *run)
{
    const char *leaf;int parent=fixed_parent(root,"/System/Library/CoreServices/SystemVersion.plist",&leaf);
    int fd=parent<0?-1:openat(parent,leaf,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);struct stat st;
    int ok=fd>=0&&!file_hash_mode(run,fd,570,0444,version_binding,&st,NULL);
    if(fd>=0)close(fd);if(parent>=0)close(parent);
    return ok?0:-1;
}
/* Exact original plist bytes already select official7400 for this phone.
 * Keep that identity and all existing choices; replace only its volatile
 * three-scene rendering with the complete original static image. */
static int default_identity(int root,struct ppa_run *run)
{
    static const char *const path[]={"/Library/Wallpaper/DefaultWallpapers~iphone.plist","/Library/Wallpaper/Collections/iOS_16~iphone.wallpaperCollection/WallpaperCollection.plist","/Library/Wallpaper/Collections/iOS_16~iphone.wallpaperCollection/Wallpapers/7400.WWDC_2022-375w-812h@3x~iphone.wallpaper/Wallpaper.plist"};
    static const uint32_t bytes[]={371,168,536};
    static const uint8_t digest[3][32]={{0xe9,0xb9,0x02,0x14,0x8c,0xba,0xe4,0xa9,0xf0,0xe9,0x59,0x50,0x3a,0x02,0xed,0x1e,0x05,0x6a,0x5e,0xa0,0x38,0xf6,0x83,0xcc,0x01,0x31,0x4b,0x90,0xb0,0x3e,0x3a,0x6e},{0xa2,0x7d,0x92,0x19,0xc3,0x8d,0x64,0xba,0x24,0x9c,0x40,0x6f,0x10,0xd2,0xe0,0x8f,0x35,0xcb,0xfd,0xa9,0x94,0x14,0x9a,0x62,0xd3,0xfc,0xf0,0xe7,0x25,0x40,0x7f,0x16},{0x65,0xbb,0xda,0x84,0x78,0x56,0x38,0x03,0x03,0x84,0xfd,0x1f,0x25,0xc2,0x70,0x92,0x3c,0x1f,0xe6,0xd6,0xa9,0xe3,0x77,0x76,0x24,0x85,0xb7,0x8b,0xfc,0xcf,0x9c,0x5c}};
    for(unsigned i=0;i<3;i++) {
        const char *leaf;int parent=fixed_parent(root,path[i],&leaf);
        int fd=parent<0?-1:openat(parent,leaf,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);struct stat st;
        int ok=fd>=0&&!file_hash(run,fd,bytes[i],digest[i],&st,NULL);
        if(fd>=0)close(fd);if(parent>=0)close(parent);
        if(!ok)return -1;
    }
    return 0;
}
static int current_source(struct ppa_run *run,unsigned index)
{
    struct ppa_file *f=&run->file[index];struct stat current,fdstat;
    if(fstatat(f->parent,f->source_name,&current,AT_SYMLINK_NOFOLLOW)||
       !same_inode(&current,&f->original)||!S_ISREG(current.st_mode))return -1;
    return file_hash(run,f->source,source_bytes[index],
        polaris_wallpaper_assets[index].source_sha256,&fdstat,NULL);
}
static int bound_table(uint64_t *total)
{
    if(POLARIS_WALLPAPER_ASSET_COUNT!=8)return -1;
    CC_SHA256_CTX ctx;if(!CC_SHA256_Init(&ctx))return -1;*total=0;
    for(unsigned i=0;i<8;i++) {
        const struct polaris_wallpaper_embedded_asset *a=&polaris_wallpaper_assets[i];
        if(!a->path||!a->source_path||strcmp(a->path,expected_path[i])||
           strcmp(a->source_path,expected_source[i])||!a->data||a->bytes!=output_bytes[i]||
           a->mode!=0644||a->operation!=(i==0?1u:i<5?0u:2u)||
           !equal_sha(a->data,(size_t)a->bytes,a->sha256)||a->bytes>PPA_CAP-*total)return -1;
        *total+=a->bytes;uint8_t fields[16];
        for(unsigned n=0;n<8;n++)fields[n]=(uint8_t)(a->bytes>>(8*n));
        for(unsigned n=0;n<4;n++){fields[8+n]=(uint8_t)(a->mode>>(8*n));fields[12+n]=(uint8_t)(a->operation>>(8*n));}
        CC_SHA256_Update(&ctx,a->path,(CC_LONG)strlen(a->path)+1);
        CC_SHA256_Update(&ctx,a->source_path,(CC_LONG)strlen(a->source_path)+1);
        CC_SHA256_Update(&ctx,fields,sizeof(fields));
        CC_SHA256_Update(&ctx,a->source_sha256,32);CC_SHA256_Update(&ctx,a->sha256,32);
        CC_SHA256_Update(&ctx,a->data,(CC_LONG)a->bytes);
    }
    uint8_t sha[32];return CC_SHA256_Final(sha,&ctx)&&!memcmp(sha,table_binding,32)?0:-1;
}
static int write_all(struct ppa_run *run,int fd,const void *data,size_t bytes)
{
    size_t at=0;
    while(at<bytes) {
        size_t want=bytes-at;
#ifdef POLARIS_POSTER_ASSET_FIXTURE
        if(run->write_limit==0){errno=ENOSPC;return -1;}
        if(run->write_limit>0&&want>(size_t)run->write_limit)want=(size_t)run->write_limit;
#else
        (void)run;
#endif
        ssize_t n=write(fd,(const uint8_t *)data+at,want);
        if(n<0&&errno==EINTR)continue;
        if(n<=0)return -1;at+=(size_t)n;
#ifdef POLARIS_POSTER_ASSET_FIXTURE
        if(run->write_limit>0)run->write_limit-=(int)n;
#endif
    }
    return 0;
}
static int metadata(struct ppa_file *f,int fd,int copy_all)
{
    if(copy_all&&fcopyfile(f->source,fd,NULL,COPYFILE_METADATA))return -1;
    struct stat current;if(fstat(fd,&current))return -1;
    if((current.st_uid!=f->original.st_uid||current.st_gid!=f->original.st_gid)&&
       fchown(fd,f->original.st_uid,f->original.st_gid))return -1;
    if(fchmod(fd,f->original.st_mode&07777))return -1;
    struct timespec times[2]={f->original.st_atimespec,f->original.st_mtimespec};
    return futimens(fd,times);
}
static int prepare_one(struct ppa_run *run,unsigned index,const char *name,
    const void *bytes,size_t count,const uint8_t sha[32],int copy_all,int *out,
    unsigned *made,struct stat *identity)
{
    struct ppa_file *f=&run->file[index];
    int fd=openat(f->parent,name,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0)return -1;*out=fd;*made=1;
    if(fstat(fd,identity)||write_all(run,fd,bytes,count)||metadata(f,fd,copy_all)||fsync(fd))return -1;
    struct stat checked;
    if(file_hash(run,fd,count,sha,&checked,NULL)||!same_inode(identity,&checked))return -1;
    *identity=checked;return 0;
}
static int remove_owned(struct ppa_file *f,const char *name,unsigned *made,const struct stat *identity)
{
    if(!*made)return 0;struct stat current;
    if(fstatat(f->parent,name,&current,AT_SYMLINK_NOFOLLOW)||!same_inode(identity,&current))return -1;
    if(unlinkat(f->parent,name,0))return -1;*made=0;return 0;
}
static void release(struct ppa_run *run,int remove_png)
{
    for(unsigned i=0;i<8;i++) {
        struct ppa_file *f=&run->file[i];
        if(f->parent>=0) {
            if(i<5&&remove_png&&remove_owned(f,f->target_name,&f->made_png,&f->png_stat))run->report->cleanup_failures++;
            if(i>=5&&remove_owned(f,new_name,&f->made_new,&f->new_stat))run->report->cleanup_failures++;
            if(i>=5&&remove_owned(f,restore_name,&f->made_restore,&f->restore_stat))run->report->cleanup_failures++;
        }
        if(f->source>=0)close(f->source);if(f->created>=0)close(f->created);
        if(f->new_fd>=0)close(f->new_fd);if(f->restore_fd>=0)close(f->restore_fd);
        if(f->parent>=0)close(f->parent);free(f->original_bytes);
    }
}
static int install_fixed(int root,struct ppa_run *run)
{
    struct polaris_poster_assets_report *r=run->report;r->stage=2;
    for(unsigned i=0;i<8;i++) {
        struct ppa_file *f=&run->file[i];
        f->parent=fixed_parent(root,expected_path[i],&f->target_name);
        if(f->parent<0)goto source_failure;
        f->source_name=strrchr(expected_source[i],'/')+1;
        f->source=openat(f->parent,f->source_name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
        if(f->source<0||file_hash(run,f->source,source_bytes[i],
           polaris_wallpaper_assets[i].source_sha256,&f->original,
           i>=5?&f->original_bytes:NULL))goto source_failure;
        struct stat st;
        if(i<5) {
            if(polaris_wallpaper_assets[i].operation==1&&
               (!fstatat(f->parent,f->target_name,&st,AT_SYMLINK_NOFOLLOW)||errno!=ENOENT))goto source_failure;
        } else {
            if(f->original.st_nlink!=1)goto source_failure;
            if(!fstatat(f->parent,new_name,&st,AT_SYMLINK_NOFOLLOW)||errno!=ENOENT)goto source_failure;
            if(!fstatat(f->parent,restore_name,&st,AT_SYMLINK_NOFOLLOW)||errno!=ENOENT)goto source_failure;
        }
        r->validated++;
    }
    /* All8 sources validated before creating a single file. */
    r->stage=3;
    for(unsigned i=0;i<5;i++) {
        struct ppa_file *f=&run->file[i];const struct polaris_wallpaper_embedded_asset *a=&polaris_wallpaper_assets[i];
        if(a->operation==0)continue; /* Original HEIC source admission only. */
        if(prepare_one(run,i,f->target_name,a->data,(size_t)a->bytes,a->sha256,0,
            &f->created,&f->made_png,&f->png_stat))goto prepare_failure;
        r->created_png++;
    }
    for(unsigned i=5;i<8;i++) {
        struct ppa_file *f=&run->file[i];const struct polaris_wallpaper_embedded_asset *a=&polaris_wallpaper_assets[i];
        if(prepare_one(run,i,restore_name,f->original_bytes,source_bytes[i],a->source_sha256,1,
            &f->restore_fd,&f->made_restore,&f->restore_stat)||
           prepare_one(run,i,new_name,a->data,(size_t)a->bytes,a->sha256,1,
            &f->new_fd,&f->made_new,&f->new_stat))goto prepare_failure;
        r->prepared_caml++;
    }
    for(unsigned i=0;i<8;i++)if(current_source(run,i))goto prepare_failure;
    r->stage=4;
    for(unsigned i=5;i<8;i++) {
        struct ppa_file *f=&run->file[i];
#ifdef POLARIS_POSTER_ASSET_FIXTURE
        if(run->activation_failure==(int)(i-5)){errno=EIO;goto rollback;}
#endif
        if(current_source(run,i))goto rollback;
        if(renameat(f->parent,new_name,f->parent,f->target_name))goto rollback;
        f->made_new=0;f->activated=1;r->activated_caml++;
        struct stat current;
        if(fstatat(f->parent,f->target_name,&current,AT_SYMLINK_NOFOLLOW)||
           !same_inode(&current,&f->new_stat)||fsync(f->parent))goto rollback;
    }
    r->stage=5;release(run,0);return PPA_OK;
source_failure:
    r->error=errno?errno:EINVAL;release(run,1);return PPA_SOURCE;
prepare_failure:
    r->error=errno?errno:EIO;release(run,1);return PPA_PREPARE;
rollback:
    r->error=errno?errno:EIO;r->stage=6;
    for(unsigned i=5;i<8;i++)if(run->file[i].activated) {
        struct ppa_file *f=&run->file[i];struct stat current,checked;
        if(fstatat(f->parent,f->target_name,&current,AT_SYMLINK_NOFOLLOW)||
           !same_inode(&current,&f->new_stat)||renameat(f->parent,restore_name,f->parent,f->target_name)) {
            r->must_hold=1;continue;
        }
        f->made_restore=0;f->activated=0;
        int fd=openat(f->parent,f->target_name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
        if(fd<0||file_hash(run,fd,source_bytes[i],polaris_wallpaper_assets[i].source_sha256,&checked,NULL)||
           !same_inode(&checked,&f->restore_stat)||fsync(f->parent))r->must_hold=1;
        else r->restored_caml++;
        if(fd>=0)close(fd);
    }
    for(unsigned i=5;i<8;i++)if(!run->file[i].activated) {
        struct ppa_file *f=&run->file[i];struct stat checked;
        int fd=openat(f->parent,f->target_name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
        if(fd<0||file_hash(run,fd,source_bytes[i],polaris_wallpaper_assets[i].source_sha256,&checked,NULL))
            r->must_hold=1;
        if(fd>=0)close(fd);
    }
    /* A failed rollback is a PID1 HOLD result, never permission to launch
     * services against a mixed set. Leave recovery originals intact then. */
    if(r->must_hold) {r->stage=7;return PPA_ROLLBACK_FAILED;}
    release(run,1);return PPA_ACTIVATE_ROLLED_BACK;
}
static void initialize(struct ppa_run *run,struct polaris_poster_assets_report *report)
{
    memset(run,0,sizeof(*run));memset(report,0,sizeof(*report));run->report=report;report->version=1;
    for(unsigned i=0;i<8;i++)run->file[i].parent=run->file[i].source=run->file[i].created=
        run->file[i].new_fd=run->file[i].restore_fd=-1;
#ifdef POLARIS_POSTER_ASSET_FIXTURE
    run->write_limit=-1;run->activation_failure=-1;
#endif
}
int polaris_poster_assets_install(struct polaris_poster_assets_report *report)
{
    if(!report)return PPA_REFUSED;
    struct ppa_run run;initialize(&run,report);run.uid=0;run.gid=0;report->stage=1;
#if !defined(PGPU_USERLAND_20F66)
    report->error=EPERM;return PPA_REFUSED;
#else
    char path[PATH_MAX]={0};uint32_t bytes=sizeof(path);
    struct statfs fs={0};
    struct {uint32_t version,bytes,flags,reserved;uint64_t values[9];} cow={0};size_t size=sizeof(cow);
    pid_t pid=getpid();uid_t real=getuid(),effective=geteuid();
    fprintf(stderr,"POLARIS POSTER CONTEXT: pid=%d uid=%u euid=%u\n",pid,(unsigned)real,(unsigned)effective);
    if(pid!=1||real!=0||effective!=0){report->error=EPERM;return PPA_REFUSED;}
    errno=0;int result=_NSGetExecutablePath(path,&bytes),saved=errno;
    fprintf(stderr,"POLARIS POSTER CONTEXT EXEC: rc=%d errno=%d bytes=%u path=%.*s\n",
        result,saved,bytes,(int)sizeof(path),path);
    if(result||strcmp(path,"/usr/libexec/polaris-init")) {
        report->error=result&&saved?saved:EPERM;return PPA_REFUSED;
    }
    errno=0;result=statfs("/",&fs);saved=errno;
    fprintf(stderr,"POLARIS POSTER CONTEXT ROOT: rc=%d errno=%d type=%.*s from=%.*s flags=%x\n",
        result,saved,(int)sizeof(fs.f_fstypename),fs.f_fstypename,
        (int)sizeof(fs.f_mntfromname),fs.f_mntfromname,fs.f_flags);
    /* Actual linked0135 vfs_mountroot passes literal "root_device" to the
     * allocator; statfs copies it unchanged before launchd's remount. It is
     * not itself a device identity. Bind HFS's actual dev_t separately to the
     * original devfs block node, using metadata only, never opening the disk. */
    if(result||strcmp(fs.f_fstypename,"hfs")||strcmp(fs.f_mntfromname,"root_device")||
       !(fs.f_flags&MNT_ROOTFS)||(fs.f_flags&MNT_RDONLY)) {
        report->error=result&&saved?saved:EPERM;return PPA_REFUSED;
    }
    struct stat device={0};errno=0;result=lstat("/dev/ufsroot0",&device);saved=errno;
    fprintf(stderr,"POLARIS POSTER CONTEXT DEVICE: rc=%d errno=%d mode=%x rdev=%x rootfsid=%x\n",
        result,saved,(unsigned)device.st_mode,(unsigned)device.st_rdev,(unsigned)fs.f_fsid.val[0]);
    if(result||!S_ISBLK(device.st_mode)||!device.st_rdev||
       (uint32_t)device.st_rdev!=(uint32_t)fs.f_fsid.val[0]) {
        report->error=result&&saved?saved:EPERM;return PPA_REFUSED;
    }
    errno=0;result=sysctlbyname("kern.polaris_ramcow_status",&cow,&size,NULL,0);saved=errno;
    fprintf(stderr,"POLARIS POSTER CONTEXT COW: rc=%d errno=%d size=%llu version=%u bytes=%u flags=%u limit=%llu used=%llu available=%llu remaining=%llu\n",
        result,saved,(unsigned long long)size,cow.version,cow.bytes,cow.flags,
        (unsigned long long)cow.values[0],(unsigned long long)cow.values[1],
        (unsigned long long)cow.values[2],(unsigned long long)cow.values[3]);
    if(result||size!=sizeof(cow)||cow.version!=1||cow.bytes!=sizeof(cow)||
       cow.flags!=1||!cow.values[0]||cow.values[0]>32768||cow.values[3]<PPA_CAP) {
        report->error=result&&saved?saved:EPERM;return PPA_REFUSED;
    }
    result=bound_table(&report->embedded_bytes);
    fprintf(stderr,"POLARIS POSTER CONTEXT TABLE: rc=%d bytes=%llu\n",result,(unsigned long long)report->embedded_bytes);
    if(result){report->error=EINVAL;return PPA_REFUSED;}
    const char *const bundle[]={"/usr/lib/libPolarisMesa.dylib","/usr/lib/libPolarisGL.dylib",
        "/usr/lib/libPolarisInject.dylib","/usr/libexec/polaris-bbd-wrapper",
        "/usr/libexec/polaris-gl-test","/usr/libexec/polaris-init"};
    for(unsigned i=0;i<6;i++) {
        int fd=open(bundle[i],O_RDONLY|O_NOFOLLOW|O_CLOEXEC);struct stat st;
        if(fd<0||fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_size<=0||st.st_uid||
           (st.st_mode&022)||(uint64_t)st.st_size>PPA_CAP-report->bundle_bytes) {
            if(fd>=0)close(fd);report->error=EFBIG;return PPA_REFUSED;
        }
        report->bundle_bytes+=(uint64_t)st.st_size;close(fd);
    }
    int root=open("/",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(root<0)return PPA_REFUSED;
    if(version_file(root,&run)){close(root);report->error=EINVAL;return PPA_REFUSED;}
    result=default_identity(root,&run);
    fprintf(stderr,"POLARIS POSTER DEFAULT ID: rc=%d official7400 sourceplists unchanged\n",result);
    if(result){close(root);report->error=EINVAL;return PPA_REFUSED;}
    result=install_fixed(root,&run);close(root);return result;
#endif
}
#ifdef POLARIS_POSTER_ASSET_FIXTURE
int polaris_poster_assets_fixture(const char *directory,int limit,int activation_failure,
    struct polaris_poster_assets_report *report)
{
    if(!report)return PPA_REFUSED;
    struct ppa_run run;initialize(&run,report);run.uid=geteuid();run.gid=getegid();
    run.write_limit=limit;run.activation_failure=activation_failure;
    if(!directory||strncmp(directory,"/private/tmp/polaris-poster-assets-fixture-",43)||
       strstr(directory,"/../")||strstr(directory,"/./")||bound_table(&report->embedded_bytes))return PPA_REFUSED;
    int root=open(directory,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(root<0)return PPA_REFUSED;
    struct stat st;
    if(fstat(root,&st)||st.st_uid!=geteuid()||(st.st_mode&07777)!=0700){close(root);return PPA_REFUSED;}
    run.gid=st.st_gid;
    if(default_identity(root,&run)){close(root);report->error=EINVAL;return PPA_SOURCE;}
    int result=install_fixed(root,&run);close(root);return result;
}
/* Calls the production SystemVersion verifier, with only the private fixture
 * root/host identity substituted. No files are created or permissions changed. */
int polaris_poster_assets_version_fixture(const char *directory,
    struct polaris_poster_assets_report *report)
{
    if(!report)return PPA_REFUSED;
    struct ppa_run run;initialize(&run,report);run.uid=geteuid();run.gid=getegid();
    if(!directory||strncmp(directory,"/private/tmp/polaris-poster-assets-fixture-",43)||
       strstr(directory,"/../")||strstr(directory,"/./"))return PPA_REFUSED;
    int root=open(directory,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(root<0)return PPA_REFUSED;
    struct stat st;
    if(fstat(root,&st)||st.st_uid!=geteuid()||(st.st_mode&07777)!=0700){close(root);return PPA_REFUSED;}
    run.gid=st.st_gid;int result=version_file(root,&run)?PPA_SOURCE:PPA_OK;
    if(result)report->error=EINVAL;else report->validated=1;
    close(root);return result;
}
#endif
