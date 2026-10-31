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

#ifdef POLARIS_APPS_TEST
int main(int argc,char **argv)
{
    if(argc!=2)return 2;
    return publish_apps(argv[1])==32?0:1;
}
#else
int main(void)
{
#if defined(PGPU_USERLAND_20F66)
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
