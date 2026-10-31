/* PID1 RAM-overlay activation, then genuine Apple launchd. The kernel only
 * executes this after a complete verified bundle in the volatile COW root.
 * The original Apple binary is renamed, preserving all metadata/signature.
 */
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(PGPU_USERLAND_20F66)
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>

static int media_environment(CFDictionaryRef jobs)
{
    CFMutableDictionaryRef job=(CFMutableDictionaryRef)CFDictionaryGetValue(jobs,
        CFSTR("/System/Library/LaunchDaemons/com.apple.mediaserverd.plist"));
    if(!job || CFGetTypeID(job)!=CFDictionaryGetTypeID())return -1;
    CFTypeRef label=CFDictionaryGetValue(job,CFSTR("Label"));
    CFArrayRef args=CFDictionaryGetValue(job,CFSTR("ProgramArguments"));
    CFTypeRef program=CFDictionaryGetValue(job,CFSTR("Program"));
    if(!label || !CFEqual(label,CFSTR("com.apple.mediaserverd")) || !args ||
       CFGetTypeID(args)!=CFArrayGetTypeID() || CFArrayGetCount(args)!=1 ||
       !CFEqual(CFArrayGetValueAtIndex(args,0),CFSTR("/usr/sbin/mediaserverd")) ||
       (program && !CFEqual(program,CFSTR("/usr/sbin/mediaserverd"))))return -1;
    CFMutableDictionaryRef environment=(CFMutableDictionaryRef)CFDictionaryGetValue(job,CFSTR("EnvironmentVariables"));
    if(environment && CFGetTypeID(environment)!=CFDictionaryGetTypeID())return -1;
    if(!environment) {
        environment=CFDictionaryCreateMutable(NULL,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
        if(!environment)return -1;
        CFDictionarySetValue(job,CFSTR("EnvironmentVariables"),environment);CFRelease(environment);
    }
    const CFStringRef env_keys[]={CFSTR("DYLD_INSERT_LIBRARIES"),CFSTR("POLARIS_MEDIA_COMPAT")};
    const CFStringRef values[]={CFSTR("/usr/lib/libPolarisInject.dylib"),CFSTR("1")};
    for(unsigned i=0;i<2;i++) {
        CFTypeRef old=CFDictionaryGetValue(environment,env_keys[i]);
        if(old && !CFEqual(old,values[i]))return -1;
    }
    for(unsigned i=0;i<2;i++) {
        CFDictionarySetValue(environment,env_keys[i],values[i]);
    }
    return 0;
}

/* Prepare only the genuine PosterBoard and mediaserverd jobs' scoped shims
 * in RAM COW. Leave its executable, arguments and
 * all other jobs intact. Atomic replacement preserves a valid original on
 * every read/parse/encode/write failure. This does not suppress any fault.
 */
static int poster_console(const char *root)
{
    char path[1024],temporary[1024];
    int in=-1,out=-1,result=-1;
    struct stat st;
    void *bytes=NULL;
    CFDataRef data=NULL,encoded=NULL;
    CFPropertyListRef plist=NULL;
    CFDictionaryRef jobs=NULL;
    CFMutableDictionaryRef poster=NULL;
    if(snprintf(path,sizeof(path),"%s/System/Library/xpc/launchd.plist",root)>=(int)sizeof(path) ||
       snprintf(temporary,sizeof(temporary),"%s/System/Library/xpc/.polaris-poster-stdio.plist",root)>=(int)sizeof(temporary))goto done;
    in=open(path,O_RDONLY|O_NOFOLLOW);
    if(in<0 || fstat(in,&st) || !S_ISREG(st.st_mode) || st.st_size<=0 || st.st_size>2*1024*1024)goto done;
    bytes=malloc((size_t)st.st_size);
    if(!bytes)goto done;
    size_t at=0;
    while(at<(size_t)st.st_size) {
        ssize_t n=read(in,(char *)bytes+at,(size_t)st.st_size-at);
        if(n<0 && errno==EINTR)continue;
        if(n<=0)goto done;
        at+=(size_t)n;
    }
    data=CFDataCreate(NULL,bytes,(CFIndex)at);
    if(!data)goto done;
    plist=CFPropertyListCreateWithData(NULL,data,kCFPropertyListMutableContainersAndLeaves,NULL,NULL);
    if(!plist || CFGetTypeID(plist)!=CFDictionaryGetTypeID())goto done;
    jobs=CFDictionaryGetValue(plist,CFSTR("LaunchDaemons"));
    if(!jobs || CFGetTypeID(jobs)!=CFDictionaryGetTypeID())goto done;
    poster=(CFMutableDictionaryRef)CFDictionaryGetValue(jobs,CFSTR("/System/Library/LaunchAngels/com.apple.PosterBoard.plist"));
    if(!poster || CFGetTypeID(poster)!=CFDictionaryGetTypeID())goto done;
    CFTypeRef label=CFDictionaryGetValue(poster,CFSTR("Label"));
    CFArrayRef args=CFDictionaryGetValue(poster,CFSTR("ProgramArguments"));
    if(!label || !CFEqual(label,CFSTR("com.apple.PosterBoard")) || !args ||
       CFGetTypeID(args)!=CFArrayGetTypeID() || CFArrayGetCount(args)!=1 ||
       !CFEqual(CFArrayGetValueAtIndex(args,0),CFSTR("/Applications/PosterBoard.app/PosterBoard")))goto done;
    CFTypeRef program=CFDictionaryGetValue(poster,CFSTR("Program"));
    if(program && !CFEqual(program,CFSTR("/Applications/PosterBoard.app/PosterBoard")))goto done;
    const CFStringRef keys[]={CFSTR("StandardOutPath"),CFSTR("StandardErrorPath")};
    for(unsigned i=0;i<2;i++) {
        CFTypeRef old=CFDictionaryGetValue(poster,keys[i]);
        if(old && !CFEqual(old,CFSTR("/dev/console")))goto done;
    }
    for(unsigned i=0;i<2;i++)CFDictionarySetValue(poster,keys[i],CFSTR("/dev/console"));
    CFMutableDictionaryRef environment=(CFMutableDictionaryRef)CFDictionaryGetValue(poster,CFSTR("EnvironmentVariables"));
    if(environment && CFGetTypeID(environment)!=CFDictionaryGetTypeID())goto done;
    if(!environment) {
        environment=CFDictionaryCreateMutable(NULL,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
        if(!environment)goto done;
        CFDictionarySetValue(poster,CFSTR("EnvironmentVariables"),environment);
        CFRelease(environment);
    }
    const CFStringRef env_keys[]={CFSTR("DYLD_INSERT_LIBRARIES"),CFSTR("POLARIS_POSTER_PREVIEW")};
    const CFStringRef env_values[]={CFSTR("/usr/lib/libPolarisInject.dylib"),CFSTR("1")};
    for(unsigned i=0;i<2;i++) {
        CFTypeRef old=CFDictionaryGetValue(environment,env_keys[i]);
        if(old && !CFEqual(old,env_values[i]))goto done;
    }
    for(unsigned i=0;i<2;i++)CFDictionarySetValue(environment,env_keys[i],env_values[i]);
    /* Some launchd versions filter DYLD_ job variables. Run our verified init
     * as this one job's small exec wrapper, with Apple's argv unchanged. It
     * sets the library after launchd, then execs the genuine Apple binary. */
    CFDictionarySetValue(poster,CFSTR("Program"),CFSTR("/usr/libexec/polaris-init"));
    /* The second exact original job retains UserName, MachServices and every
     * Apple argument. Publish neither change if this validation fails. */
    if(media_environment(jobs))goto done;
    encoded=CFPropertyListCreateData(NULL,plist,kCFPropertyListBinaryFormat_v1_0,0,NULL);
    if(!encoded || CFDataGetLength(encoded)<=0 || CFDataGetLength(encoded)>2*1024*1024)goto done;
    out=open(temporary,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
    if(out<0)goto done;
    at=0;
    while(at<(size_t)CFDataGetLength(encoded)) {
        ssize_t n=write(out,CFDataGetBytePtr(encoded)+at,(size_t)CFDataGetLength(encoded)-at);
        if(n<0 && errno==EINTR)continue;
        if(n<=0)goto done;
        at+=(size_t)n;
    }
    if(fchown(out,st.st_uid,st.st_gid) || fchmod(out,st.st_mode&07777) || fsync(out))goto done;
    if(close(out)){out=-1;goto done;}
    out=-1;
    if(rename(temporary,path))goto done;
    result=0;
done:
    if(in>=0)close(in);
    if(out>=0)close(out);
    if(encoded)CFRelease(encoded);
    if(plist)CFRelease(plist);
    if(data)CFRelease(data);
    free(bytes);
    printf("POLARIS POSTER CONFIG: %s; Apple argv retained, RAM COW only\n",result?"unmodified (unavailable)":"console + scoped exec preview prepared");
    printf("POLARIS MEDIA CONFIG: %s; Apple services/user/argv retained, RAM COW only\n",result?"unmodified (unavailable)":"original Program/stdio + scoped environment prepared");
    return result;
}

/* The verified20F66 root carries these genuine applications in first-boot
 * staging. Publish real directories before launchd/LaunchServices scans them.
 * The admitted kernel supplies a volatile RAM COW root: only HFS metadata is
 * renamed, without copying app data or changing the immutable UFS base.
 * HackiOS a79ff077's init/select-system provided the staging correspondence;
 * this implementation uses our own HFS rename, not its APFS synthetic mounts.
 */
static unsigned publish_apps(const char *root)
{
    static const char *const names[]={
        "AppleTV","Books","Bridge","Calculator","Compass","Contacts",
        "FaceTime","Files","FindMy","Fitness","Freeform","Health","Home",
        "Magnifier","Maps","Measure","MobileCal","MobileMail","MobileNotes",
        "MobileStore","MobileTimer","Music","News","Passbook","Podcasts",
        "Reminders","SequoiaTranslator","Shortcuts","Stocks","Tips",
        "VoiceMemos","Weather"
    };
    unsigned published=0;
    for(unsigned i=0;i<sizeof(names)/sizeof(names[0]);i++) {
        char from[1024],to[1024],exe[1100],info[1100];
        struct stat st;
        uint32_t header[2];
        if(snprintf(from,sizeof(from),"%s/private/var/staged_system_apps/%s.app",root,names[i])>=(int)sizeof(from) ||
           snprintf(to,sizeof(to),"%s/Applications/%s.app",root,names[i])>=(int)sizeof(to))continue;
        if(lstat(from,&st) || !S_ISDIR(st.st_mode)) {
            printf("POLARIS STOCK APP: %s source unavailable\n",names[i]);continue;
        }
        snprintf(info,sizeof(info),"%s/Info.plist",from);
        if(lstat(info,&st) || !S_ISREG(st.st_mode) || !st.st_size)continue;
        snprintf(exe,sizeof(exe),"%s/%s",from,names[i]);
        int fd=open(exe,O_RDONLY|O_NOFOLLOW);
        ssize_t n=fd<0?-1:read(fd,header,sizeof(header));
        if(fd>=0)close(fd);
        if(n!=sizeof(header) || header[0]!=0xfeedfacf || header[1]!=0x0100000c) {
            printf("POLARIS STOCK APP: %s invalid executable\n",names[i]);continue;
        }
        /* Atomic exclusive rename: never replace an existing application,
         * even if the caller is unexpectedly run again. No copy fallback. */
        if(renamex_np(from,to,RENAME_EXCL)) {
            printf("POLARIS STOCK APP: %s publish errno=%d\n",names[i],errno);continue;
        }
        published++;
        printf("POLARIS STOCK APP: %s published\n",names[i]);
    }
    printf("POLARIS STOCK APPS: %u/32 published before Apple launchd; RAM COW only\n",published);
    fflush(stdout);
    return published;
}
#endif

#ifdef POLARIS_POSTER_STDIO_TEST
int main(int argc,char **argv)
{
    return argc==2?poster_console(argv[1]):2;
}
#elif defined(POLARIS_APPS_TEST)
int main(int argc,char **argv)
{
    if(argc!=2)return 2;
    return publish_apps(argv[1])==32?0:1;
}
#else
int main(int argc,char **argv)
{
    (void)argc;(void)argv;
#if defined(PGPU_USERLAND_20F66)
    if(getpid()!=1) {
        const char *flag=getenv("POLARIS_POSTER_PREVIEW");
        if(argc!=1 || !argv || !argv[0] ||
           strcmp(argv[0],"/Applications/PosterBoard.app/PosterBoard") ||
           !flag || strcmp(flag,"1"))return 125;
        if(setenv("DYLD_INSERT_LIBRARIES","/usr/lib/libPolarisInject.dylib",1))return 125;
        char *const child_args[]={"/Applications/PosterBoard.app/PosterBoard",NULL};
        fprintf(stderr,"POLARIS POSTER EXEC: scoped library set after launchd; genuine Apple binary\n");
        execv(child_args[0],child_args);
        perror("polaris: genuine PosterBoard exec");return 127;
    }
    int console=open("/dev/console",O_WRONLY|O_NOCTTY|O_CLOEXEC);
    if(console>=0) {
        (void)dup2(console,STDOUT_FILENO);
        (void)dup2(console,STDERR_FILENO);
        if(console>STDERR_FILENO)close(console);
    }
    setvbuf(stdout,NULL,_IONBF,0);
    (void)poster_console("");
    (void)publish_apps("");
#endif
    if(access("/usr/libexec/polaris-bbd-wrapper",X_OK)==0 &&
       access("/usr/libexec/polaris-bbd-real",F_OK)!=0) {
        if(rename("/usr/libexec/backboardd","/usr/libexec/polaris-bbd-real")==0) {
            if(rename("/usr/libexec/polaris-bbd-wrapper","/usr/libexec/backboardd")!=0) {
                perror("polaris: wrapper activation");
                if(rename("/usr/libexec/polaris-bbd-real","/usr/libexec/backboardd"))
                    perror("polaris: original restore");
            }
        }else perror("polaris: original rename");
    }
    char *const args[]={"/sbin/launchd",NULL};
    execv(args[0],args);perror("polaris: Apple launchd exec");
    for(;;)sleep(1);
}
#endif
