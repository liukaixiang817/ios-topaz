/* Real CoreFoundation job construction, no launchd execution or root writes. */
#include "../userland/wifi/polaris-wifi-launch.h"
#include <assert.h>
int main(void)
{
    assert(polaris_wifi_launch_job(NULL)==-1);
    assert(polaris_wifi_launch_job((CFMutableDictionaryRef)CFSTR("wrong type"))==-1);
    CFMutableDictionaryRef jobs=CFDictionaryCreateMutable(NULL,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(jobs,CFSTR("apple-job"),CFSTR("unchanged"));
    assert(!polaris_wifi_launch_job(jobs)&&CFDictionaryGetCount(jobs)==2);
    assert(CFEqual(CFDictionaryGetValue(jobs,CFSTR("apple-job")),CFSTR("unchanged")));
    CFDictionaryRef job=CFDictionaryGetValue(jobs,CFSTR("/Library/LaunchDaemons/local.polaris.wifi-probe.plist"));
    assert(job&&CFDictionaryGetCount(job)==7);
    assert(CFEqual(CFDictionaryGetValue(job,CFSTR("Label")),CFSTR("local.polaris.wifi-probe")));
    assert(CFEqual(CFDictionaryGetValue(job,CFSTR("UserName")),CFSTR("root")));
    assert(CFDictionaryGetValue(job,CFSTR("RunAtLoad"))==kCFBooleanTrue);
    assert(CFDictionaryGetValue(job,CFSTR("KeepAlive"))==kCFBooleanFalse);
    CFArrayRef argv=CFDictionaryGetValue(job,CFSTR("ProgramArguments"));
    assert(CFArrayGetCount(argv)==2&&CFEqual(CFArrayGetValueAtIndex(argv,0),CFSTR("/usr/libexec/polaris-init"))&&CFEqual(CFArrayGetValueAtIndex(argv,1),CFSTR("--wifi-probe")));
    assert(CFEqual(CFDictionaryGetValue(job,CFSTR("StandardOutPath")),CFSTR("/dev/console")));
    assert(CFEqual(CFDictionaryGetValue(job,CFSTR("StandardErrorPath")),CFSTR("/dev/console")));
    assert(polaris_wifi_launch_job(jobs)==-1&&CFDictionaryGetCount(jobs)==2);
    CFRelease(jobs);return 0;
}
