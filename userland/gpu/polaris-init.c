/* PID1 RAM-overlay activation, then genuine Apple launchd. The kernel only
 * executes this after a complete verified bundle in the volatile COW root.
 * The original Apple binary is renamed, preserving all metadata/signature.
 */
#include <stdio.h>
#include <unistd.h>
int main(void)
{
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
