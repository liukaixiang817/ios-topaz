/* Run a separate-task GPU shader/shared-surface check before admitting the
 * EAGL backend. Task exit closes the exclusive GPU connection before the
 * genuine backboardd takes it. Failure launches the existing CPU path. */
#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <spawn.h>
#include <sys/wait.h>
#include <sys/sysctl.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
extern char **environ;
int main(int argc,char **argv)
{
    (void)argc;
    int console=open("/dev/console",O_WRONLY);
    if(console>=0){dup2(console,STDERR_FILENO);if(console!=STDERR_FILENO)close(console);}
    char args[2048]={0};size_t bytes=sizeof(args)-1;
    sysctlbyname("kern.bootargs",args,&bytes,NULL,0);
    io_service_t service=0;
    for(unsigned n=0;n<100;n++) {
        service=IOServiceGetMatchingService(0,IOServiceMatching("PolarisGPU"));
        if(service)break;
        usleep(100000);
    }
    int good=0;
    if(service) {
        CFTypeRef attempted=IORegistryEntryCreateCFProperty(service,CFSTR("PolarisDesktopAttempted"),kCFAllocatorDefault,0);
        int already=attempted==kCFBooleanTrue;
        if(attempted)CFRelease(attempted);
        IOObjectRelease(service);
        /* A failed GPU server gets one CPU restart, without rerunning the
         * shader test or filling the volatile root with crash-loop files. */
        if(already)goto launch;
        pid_t child;char *const test[]={"/usr/libexec/polaris-gl-test",NULL};
        int error=posix_spawn(&child,test[0],NULL,NULL,test,environ);
        if(!error) {
            int status=0,done=0;
            for(unsigned n=0;n<300;n++) {
                pid_t result=waitpid(child,&status,WNOHANG);
                if(result==child){done=1;good=WIFEXITED(status)&&WEXITSTATUS(status)==0;break;}
                if(result<0){done=1;break;}
                usleep(100000);
            }
            if(!done){kill(child,SIGKILL);waitpid(child,&status,0);}
        }
    }
launch:
    /* Only this process gets the bridge, after the actual GLSL+surface test.
     * No global launchd environment or other applications are modified. */
    if(good && strstr(args,"polarisgl=1")) {
        setenv("DYLD_INSERT_LIBRARIES","/usr/lib/libPolarisInject.dylib",1);
        setenv("OSMESA_SOFTWARE","0",1);
        setenv("POLARIS_GL_TESTED","1",1);
    }else {unsetenv("DYLD_INSERT_LIBRARIES");unsetenv("POLARIS_GL_TESTED");}
    fprintf(stderr,"POLARIS GL: shared-surface test %s; backboardd %s\n",good?"PASS":"not passed",good?"GPU trial":"CPU fallback");
    unsetenv("POLARIS_GPU_CONNECTION"); /* the child test owns its port, never the real server */
    argv[0]="backboardd";
    execv("/usr/libexec/polaris-bbd-real",argv);
    perror("polaris: backboardd exec");return 127;
}
