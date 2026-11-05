/* Explicit bring-up job in the already verified RAM-COW launchd dictionary.
 * Default OFF at compile time. Apple jobs and on-disk root remain unchanged. */
#ifndef POLARIS_WIFI_LAUNCH_H
#define POLARIS_WIFI_LAUNCH_H
#include <CoreFoundation/CoreFoundation.h>
int polaris_wifi_probe(void);
int polaris_wifi_control_main(int,char**);
static inline int polaris_wifi_launch_job(CFMutableDictionaryRef jobs)
{
    const CFStringRef path=CFSTR("/Library/LaunchDaemons/local.polaris.wifi-probe.plist");
    if(!jobs||CFGetTypeID(jobs)!=CFDictionaryGetTypeID()||CFDictionaryContainsKey(jobs,path))return -1;
    const void *arguments[]={CFSTR("/usr/libexec/polaris-init"),CFSTR("--wifi-probe")};
    CFArrayRef argv=CFArrayCreate(NULL,arguments,2,&kCFTypeArrayCallBacks);
    if(!argv)return -1;
    const void *keys[]={CFSTR("Label"),CFSTR("ProgramArguments"),CFSTR("UserName"),
        CFSTR("RunAtLoad"),CFSTR("KeepAlive"),CFSTR("StandardOutPath"),CFSTR("StandardErrorPath")};
    const void *values[]={CFSTR("local.polaris.wifi-probe"),argv,CFSTR("root"),
        kCFBooleanTrue,kCFBooleanFalse,CFSTR("/dev/console"),CFSTR("/dev/console")};
    CFDictionaryRef job=CFDictionaryCreate(NULL,keys,values,7,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    CFRelease(argv);if(!job)return -1;
    CFDictionarySetValue(jobs,path,job);CFRelease(job);return 0;
}
#endif
