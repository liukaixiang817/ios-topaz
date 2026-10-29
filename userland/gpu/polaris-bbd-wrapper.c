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
#include <time.h>
#include <errno.h>
#include "../../tools/polaris-gl-status.h"
#include "../../tools/polaris-compositor-clock.h"
extern char **environ;
extern int __mac_syscall(const char *,int,void *);
static uint64_t test_milliseconds(void)
{
    struct timespec now={0};
    if(clock_gettime(CLOCK_MONOTONIC,&now))return 0;
    return (uint64_t)now.tv_sec*1000u+(uint64_t)now.tv_nsec/1000000u;
}
static void test_notice(unsigned event,unsigned value,uint64_t elapsed)
{
    struct pgpu_test_notice p={event,value,(uint32_t)(elapsed>600000?600000:elapsed),0};
    (void)__mac_syscall("AMFI",0x5c,&p);
}
/* Wall-clock bound includes cold dyld/CF pages, shader compilation and the
 * unchanged hardware/pixel check. Time passing never establishes success. */
static int run_acceptance(void)
{
    uint64_t start=test_milliseconds();
    test_notice(PGPU_TEST_BEGIN,0,0);
    if(!start){test_notice(PGPU_TEST_WAIT_ERROR,EIO,0);return 0;}
    pid_t child;char *const test[]={"/usr/libexec/polaris-gl-test",NULL};
    int error=posix_spawn(&child,test[0],NULL,NULL,test,environ);
    if(error){test_notice(PGPU_TEST_SPAWN_ERROR,(unsigned)error,test_milliseconds()-start);return 0;}
    for(;;) {
        int status=0;pid_t result=waitpid(child,&status,WNOHANG);
        uint64_t now=test_milliseconds();
        if(!now || now<start) {
            kill(child,SIGKILL);while(waitpid(child,&status,0)<0 && errno==EINTR){}
            test_notice(PGPU_TEST_WAIT_ERROR,EIO,0);return 0;
        }
        uint64_t elapsed=now-start;
        if(result==child) {
            if(WIFEXITED(status)) {
                test_notice(PGPU_TEST_EXIT,(unsigned)WEXITSTATUS(status),elapsed);
                return WEXITSTATUS(status)==0;
            }
            test_notice(PGPU_TEST_SIGNAL,(unsigned)WTERMSIG(status),elapsed);return 0;
        }
        if(result<0 && errno!=EINTR) {
            unsigned reason=(unsigned)errno;
            if(errno!=ECHILD){kill(child,SIGKILL);while(waitpid(child,&status,0)<0 && errno==EINTR){}}
            test_notice(PGPU_TEST_WAIT_ERROR,reason,elapsed);return 0;
        }
        if(elapsed>=PGPU_ACCEPTANCE_TIMEOUT_MS) {
            kill(child,SIGKILL);while(waitpid(child,&status,0)<0 && errno==EINTR){}
            test_notice(PGPU_TEST_TIMEOUT,SIGKILL,PGPU_ACCEPTANCE_TIMEOUT_MS>elapsed?PGPU_ACCEPTANCE_TIMEOUT_MS:elapsed);
            return 0;
        }
        usleep(100000);
    }
}
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
    int good=0,clock=0;
    if(service) {
        CFTypeRef attempted=IORegistryEntryCreateCFProperty(service,CFSTR("PolarisDesktopAttempted"),kCFAllocatorDefault,0);
        int already=attempted==kCFBooleanTrue;
        if(attempted)CFRelease(attempted);
        IOObjectRelease(service);
        /* A failed GPU server gets one CPU restart, without rerunning the
         * shader test or filling the volatile root with crash-loop files. */
        if(already)goto launch;
        good=run_acceptance();
    }
launch:
    /* Set before exec, not after QuartzCore may have cached its decision.
     * Scope is this tested window server only; no launchd-wide environment. */
    clock=pcc_environment(args,sizeof(args),good && strstr(args,"polarisgl=1"),
        getenv,setenv,unsetenv);
    if(clock || pcc_request(args,sizeof(args)))
        fprintf(stderr,"POLARIS CA CLOCK ENV: request=%d status=%d; no refresh-rate claim\n",
            pcc_request(args,sizeof(args)),clock);
    if(clock<0)return 125; /* never exec after an ambiguous/failed mutation */
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
