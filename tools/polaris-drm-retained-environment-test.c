/* Actual wrapper main, with independent process/IOKit/environment oracles.
 * No hardware service, test child, exec or console is opened by this fixture. */
#define main fixture_wrapper_main
#define open fixture_open
#define usleep fixture_usleep
#define getenv fixture_getenv
#define setenv fixture_setenv
#define unsetenv fixture_unsetenv
#define sysctlbyname fixture_sysctl
#define IOServiceGetMatchingService fixture_matching
#define IOServiceMatching fixture_match_dictionary
#define IORegistryEntryCreateCFProperty fixture_property
#define IOObjectRelease fixture_release
#define CFRelease fixture_cf_release
#define posix_spawn fixture_spawn
#define waitpid fixture_wait
#define execv fixture_exec
#define __mac_syscall fixture_mac
#include "../userland/gpu/polaris-bbd-wrapper.c"
#undef main
#include <assert.h>
#include <setjmp.h>

static const char *test;
static const char *bootargs="polarisgl=1 ca_vbl=1";
static bool service_available=true,already_attempted=false,acceptance_success=true,exec_failure=false;
static unsigned service_queries,spawn_calls,exec_calls,cache_sets,port_unsets,cache_unsets;
static jmp_buf escaped;
static int expected_cache=1;
struct entry {const char *name;char value[512];bool set;};
static struct entry environment[]={
    {"POLARIS_DRM_RETAIN_CACHE",{0},false},{"POLARIS_GPU_CONNECTION",{0},false},
    {"DYLD_INSERT_LIBRARIES",{0},false},{"OSMESA_SOFTWARE",{0},false},
    {"POLARIS_GL_TESTED",{0},false},{"CA_MOBILE_FRAMEWORKS",{0},false},
    {"CA_RENDER_SERVER",{0},false},{"CA_ASSERT_MAIN_THREAD_TRANSACTIONS",{0},false},
    {"CA_HIGH_FRAME_RATE_RANGE_ENABLED",{0},false},{"CA_WINDOW_SERVER_PRESENT_COMPLETION",{0},false},
    {"POLARIS_CA_VBL",{0},false},{"CA_VBL",{0},false},
    {"POLARIS_CA_CLOCK_TRIAL",{0},false},{"CA_FORCE_TIMER",{0},false},
};
static struct entry *entry(const char *name)
{
    for(unsigned n=0;n<sizeof(environment)/sizeof(environment[0]);n++)
        if(!strcmp(environment[n].name,name))return &environment[n];
    assert(!"unexpected environment variable");return NULL;
}
char *fixture_getenv(const char *name)
{struct entry *e=entry(name);return e->set?e->value:NULL;}
int fixture_setenv(const char *name,const char *value,int overwrite)
{
    (void)overwrite;struct entry *e=entry(name);
    if(!strcmp(name,PDRME_INTENT)) {
        cache_sets++;
        if(!strcmp(test,"set-failure"))return -1;
        if(!strcmp(test,"partial-set-failure")) {strcpy(e->value,"1");e->set=true;return -1;}
        if(!strcmp(test,"wrong-readback"))value="2";
    }
    assert(strlen(value)<sizeof(e->value));strcpy(e->value,value);e->set=true;
    if(!strcmp(test,"port-after-set")&&!strcmp(name,PDRME_INTENT)) {
        struct entry *port=entry(PDRME_PORT);strcpy(port->value,"99");port->set=true;
    }
    return 0;
}
int fixture_unsetenv(const char *name)
{
    struct entry *e=entry(name);
    if(!strcmp(name,PDRME_INTENT)) {
        cache_unsets++;
        if(!strcmp(test,"entry-clear-failure")&&cache_unsets==1)return -1;
        if(!strcmp(test,"launch-clear-failure")&&cache_unsets==2)return -1;
        if(!strcmp(test,"false-clear-success")&&cache_unsets==1)return 0;
    }
    if(!strcmp(name,PDRME_PORT)) {
        port_unsets++;
        if(!strcmp(test,"port-clear-failure")&&port_unsets==1)return -1;
    }
    e->set=false;return 0;
}
int fixture_open(const char *path,int flags,...)
{(void)flags;assert(!strcmp(path,"/dev/console"));return -1;}
int fixture_usleep(useconds_t delay)
{(void)delay;return 0;}
int fixture_sysctl(const char *name,void *old,size_t *size,void *newp,size_t newsize)
{
    (void)newp;(void)newsize;assert(!strcmp(name,"kern.bootargs"));
    size_t bytes=strlen(bootargs)+1;assert(bytes<=*size);memcpy(old,bootargs,bytes);*size=bytes;return 0;
}
CFMutableDictionaryRef fixture_match_dictionary(const char *name)
{assert(!strcmp(name,"PolarisGPU"));return (CFMutableDictionaryRef)(uintptr_t)1;}
io_service_t fixture_matching(mach_port_t mainPort,CFDictionaryRef dictionary)
{(void)mainPort;(void)dictionary;service_queries++;return service_available?1:0;}
CFTypeRef fixture_property(io_registry_entry_t entry,CFStringRef name,CFAllocatorRef allocator,IOOptionBits options)
{(void)entry;(void)name;(void)allocator;(void)options;return already_attempted?kCFBooleanTrue:kCFBooleanFalse;}
kern_return_t fixture_release(io_object_t object)
{(void)object;return 0;}
void fixture_cf_release(CFTypeRef object)
{(void)object;}
int fixture_mac(const char *policy,int op,void *notice)
{(void)notice;assert(!strcmp(policy,"AMFI")&&op==0x5c);return 0;}
int fixture_spawn(pid_t *pid,const char *path,const posix_spawn_file_actions_t *actions,
    const posix_spawnattr_t *attr,char *const argv[],char *const env[])
{
    (void)actions;(void)attr;(void)env;assert(!strcmp(path,"/usr/libexec/polaris-gl-test"));
    assert(!strcmp(argv[0],path));assert(!fixture_getenv(PDRME_INTENT)&&!fixture_getenv(PDRME_PORT));
    spawn_calls++;*pid=1234;return 0;
}
pid_t fixture_wait(pid_t pid,int *status,int options)
{(void)options;assert(pid==1234);*status=(acceptance_success?0:1)<<8;return pid;}
int fixture_exec(const char *path,char *const argv[])
{
    exec_calls++;assert(!strcmp(path,"/usr/libexec/polaris-bbd-real"));assert(!strcmp(argv[0],"backboardd"));
    assert(!fixture_getenv(PDRME_PORT));
    char *cache=fixture_getenv(PDRME_INTENT);
    assert(expected_cache?(cache&&!strcmp(cache,"1")):!cache);
    if(exec_failure){errno=ENOENT;return -1;}
    longjmp(escaped,1);
}
static void seed(void)
{
    struct entry *cache=entry(PDRME_INTENT),*port=entry(PDRME_PORT);
    strcpy(cache->value,"ambient-request");cache->set=true;strcpy(port->value,"42");port->set=true;
}
int main(int argc,char **argv)
{
    assert(argc==2);test=argv[1];seed();
    if(!strcmp(test,"fallback")){acceptance_success=false;expected_cache=0;}
    if(!strcmp(test,"restart")){already_attempted=true;expected_cache=0;}
    if(!strcmp(test,"no-service")){service_available=false;expected_cache=0;}
    if(!strcmp(test,"duplicate")){bootargs="polarisgl=1 polarisgl=1 ca_vbl=1";expected_cache=0;}
    if(!strcmp(test,"conflict")){bootargs="polarisgl=1 polarisgl=0 ca_vbl=1";expected_cache=0;}
    if(!strcmp(test,"substring")){bootargs="xpolarisgl=1 ca_vbl=1";expected_cache=0;}
    if(!strcmp(test,"wrong-value")){bootargs="polarisgl=10 ca_vbl=1";expected_cache=0;}
    if(!strcmp(test,"missing")){bootargs="ca_vbl=1";expected_cache=0;}
    if(!strcmp(test,"clock-failure"))bootargs="polarisgl=1 ca_vbl=1 ca_vbl=1";
    if(!strcmp(test,"exec-failure"))exec_failure=true;
    char name[]="polaris-bbd-wrapper";char *arguments[]={name,NULL};
    int code=-1;
    if(!setjmp(escaped))code=fixture_wrapper_main(1,arguments);
    if(!strcmp(test,"entry-clear-failure")||!strcmp(test,"false-clear-success")||!strcmp(test,"port-clear-failure")) {
        assert(code==125&&!service_queries&&!spawn_calls&&!exec_calls&&!cache_sets);
    } else if(!strcmp(test,"clock-failure")) {
        assert(code==125&&spawn_calls==1&&!exec_calls&&!cache_sets);
        assert(!fixture_getenv(PDRME_INTENT)&&!fixture_getenv(PDRME_PORT));
    } else if(!strcmp(test,"launch-clear-failure")||!strcmp(test,"set-failure")||
              !strcmp(test,"partial-set-failure")||!strcmp(test,"wrong-readback")||!strcmp(test,"port-after-set")) {
        assert(code==125&&spawn_calls==1&&!exec_calls);
        if(strcmp(test,"launch-clear-failure"))assert(!fixture_getenv(PDRME_INTENT)&&!fixture_getenv(PDRME_PORT));
    } else if(exec_failure) {
        assert(code==127&&exec_calls==1&&!fixture_getenv(PDRME_INTENT)&&!fixture_getenv(PDRME_PORT));
    } else {
        assert(code==-1&&exec_calls==1&&cache_sets==(unsigned)expected_cache);
        assert(spawn_calls==(unsigned)(service_available&&!already_attempted));
    }
    puts("PASS real-wrapper activation fixture");return 0;
}
