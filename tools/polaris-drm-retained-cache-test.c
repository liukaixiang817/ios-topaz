/* Executes the real DRM shim against an independent in-process native-client
 * oracle. No GPU, IOKit service, device, firmware or native ioctl is opened. */
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "../userland/mesa/redwood-drm/redwood_drm.c"

static _Atomic unsigned native_calls[256];
static _Atomic bool valid[1024];
static _Atomic unsigned fail_number,short_number,retained_zero,change_handle;
static pthread_mutex_t gate_mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gate_cond=PTHREAD_COND_INITIALIZER;
static bool block_wait,wait_entered,submitted,block_close,close_entered,release_close;
static bool block_madvise,madvise_entered,release_madvise;
static _Atomic bool close_fail;

CFMutableDictionaryRef IOServiceMatching(const char *name)
{(void)name;return (CFMutableDictionaryRef)(uintptr_t)1;}
io_service_t IOServiceGetMatchingService(mach_port_t mainPort,CFDictionaryRef matching)
{(void)mainPort;(void)matching;return 1;}
kern_return_t IOServiceOpen(io_service_t service,task_port_t task,uint32_t type,io_connect_t *out)
{(void)service;(void)task;(void)type;*out=7;return 0;}
kern_return_t IOObjectRelease(io_object_t object)
{(void)object;return 0;}
kern_return_t IOConnectMapMemory64(io_connect_t client,uint32_t type,task_port_t task,
    mach_vm_address_t *address,mach_vm_size_t *size,IOOptionBits options)
{(void)client;(void)type;(void)task;(void)address;(void)size;(void)options;return kIOReturnNoMemory;}
kern_return_t IOConnectUnmapMemory64(io_connect_t client,uint32_t type,task_port_t task,mach_vm_address_t address)
{(void)client;(void)type;(void)task;(void)address;return kIOReturnBadArgument;}

static void gate_wait(bool *predicate)
{
    struct timespec deadline;clock_gettime(CLOCK_REALTIME,&deadline);deadline.tv_sec+=3;
    while(!*predicate)assert(pthread_cond_timedwait(&gate_cond,&gate_mutex,&deadline)==0);
}
kern_return_t IOConnectCallStructMethod(mach_port_t port,uint32_t number,
    const void *input,size_t bytes,void *output,size_t *returned)
{
    (void)port;assert(input==output);atomic_fetch_add(&native_calls[number&255],1);
    if(number==fail_number&&fail_number)return kIOReturnNoMemory;
    if(number==0x47&&block_wait) {
        pthread_mutex_lock(&gate_mutex);wait_entered=true;pthread_cond_broadcast(&gate_cond);
        gate_wait(&submitted);pthread_mutex_unlock(&gate_mutex);
    } else if(number==0x46) {
        pthread_mutex_lock(&gate_mutex);submitted=true;pthread_cond_broadcast(&gate_cond);
        pthread_mutex_unlock(&gate_mutex);
    } else if(number==0x09) {
        if(block_close) {
            pthread_mutex_lock(&gate_mutex);close_entered=true;pthread_cond_broadcast(&gate_cond);
            gate_wait(&release_close);pthread_mutex_unlock(&gate_mutex);
        }
        if(close_fail)return kIOReturnBadArgument;
        if(bytes>=4){uint32_t handle;memcpy(&handle,input,4);if(handle<1024)valid[handle]=false;}
    } else if(number==0x42) {
        assert(bytes==16);uint32_t handle=1;valid[handle]=true;memcpy((char *)output+12,&handle,4);
    } else if(number==0x48) {
        if(bytes!=12||!input)return kIOReturnBadArgument;
        struct {uint32_t handle,madv,retained;} m;memcpy(&m,input,sizeof(m));
        if(block_madvise) {
            pthread_mutex_lock(&gate_mutex);madvise_entered=true;pthread_cond_broadcast(&gate_cond);
            gate_wait(&release_madvise);pthread_mutex_unlock(&gate_mutex);
        }
        if(m.handle>=1024||!valid[m.handle])return kIOReturnBadArgument;
        m.retained=retained_zero?0:1;if(change_handle)m.handle=2;
        memcpy(output,&m,sizeof(m));
    }
    if(number==short_number&&short_number)*returned=bytes?bytes-1:0;
    return 0;
}

static int advise(uint32_t handle,uint32_t madv)
{
    struct {uint32_t handle,madv,retained;} request={handle,madv,0xa5a5a5a5};
    int result=drmCommandWriteRead(0,8,&request,sizeof(request));
    if(!result&&!retained_zero)assert(request.retained==1);
    return result;
}
static void establish(void)
{assert(!advise(1,0));assert(!advise(1,0));}
static void *wait_thread(void *unused)
{(void)unused;uint64_t data=0;assert(!drmCommandWriteRead(0,7,&data,sizeof(data)));return NULL;}
static void *close_thread(void *unused)
{(void)unused;uint32_t data[2]={1,0};assert(!call(0x09,data,sizeof(data)));return NULL;}
static _Atomic int advice_result;
static void *advice_thread(void *unused)
{(void)unused;advice_result=advise(1,0);return NULL;}
static void *old_query_thread(void *unused)
{(void)unused;advice_result=advise(2,0);return NULL;}
static void wait_for(bool *predicate)
{pthread_mutex_lock(&gate_mutex);gate_wait(predicate);pthread_mutex_unlock(&gate_mutex);}
static void release(bool *predicate)
{pthread_mutex_lock(&gate_mutex);*predicate=true;pthread_cond_broadcast(&gate_cond);pthread_mutex_unlock(&gate_mutex);}

int main(int argc,char **argv)
{
    assert(argc==2);const char *test=argv[1];
    unsetenv("POLARIS_GPU_CONNECTION");setenv("POLARIS_DRM_RETAIN_CACHE","1",1);
    if(!strcmp(test,"no-intent"))unsetenv("POLARIS_DRM_RETAIN_CACHE");
    if(!strcmp(test,"bad-intent"))setenv("POLARIS_DRM_RETAIN_CACHE","1 extra",1);
    if(!strcmp(test,"inherited"))setenv("POLARIS_GPU_CONNECTION","42",1);
    for(unsigned n=1;n<1024;n++)valid[n]=true;
    int fd=drmOpenWithType("msm",NULL,0);assert(fd>=0);close(fd);
    if(!strcmp(test,"off")||!strcmp(test,"no-intent")||!strcmp(test,"bad-intent")||
       !strcmp(test,"inherited")||!strcmp(test,"nonpolaris")) {
        establish();assert(native_calls[0x48]==2);puts("PASS original-native-path");return 0;
    }
#if POLARIS_DRM_RETAIN_CACHE_TRIAL
    assert(retained_cache.enabled);
    if(!strcmp(test,"warm")) {
        for(unsigned frame=0;frame<64;frame++)for(unsigned h=1;h<=37;h++)assert(!advise(h,0));
        assert(native_calls[0x48]==37&&retained_cache.hits==37*63);
    } else if(!strcmp(test,"unknown")) {
        establish();assert(native_calls[0x48]==1);assert(advise(9999,0)==-EINVAL);
        assert(retained_cache.failed);assert(!advise(1,0));assert(!advise(1,0));assert(native_calls[0x48]==4);
    } else if(!strcmp(test,"retained-zero")) {
        retained_zero=1;establish();assert(native_calls[0x48]==2);
        retained_zero=0;establish();assert(native_calls[0x48]==3);
    } else if(!strcmp(test,"dontneed")) {
        establish();assert(!advise(1,1));establish();assert(native_calls[0x48]==3);
    } else if(!strcmp(test,"unknown-advice")) {
        establish();assert(!advise(1,2));establish();assert(native_calls[0x48]==3);
    } else if(!strcmp(test,"malformed-size")||!strcmp(test,"null-data")) {
        establish();uint32_t request[4]={1,0,0,0};
        assert(call(0x48,!strcmp(test,"null-data")?NULL:request,
            !strcmp(test,"null-data")?12:sizeof(request))==EINVAL);
        assert(retained_cache.failed);establish();assert(native_calls[0x48]==4);
    } else if(!strcmp(test,"new")) {
        establish();uint64_t request[2]={4096,0};assert(!call(0x42,request,sizeof(request)));
        establish();assert(native_calls[0x48]==2);
    } else if(!strcmp(test,"map-failure")||!strcmp(test,"unmap-failure")) {
        establish();
        if(!strcmp(test,"map-failure"))assert(redwood_drm_map(0,1,4096)==(void *)-1);
        else redwood_drm_unmap(0,1,(void *)(uintptr_t)0x1000);
        assert(retained_cache.failed);establish();assert(native_calls[0x48]==3);
    } else if(!strcmp(test,"close-failure")) {
        establish();close_fail=true;uint32_t request[2]={1,0};assert(call(9,request,sizeof(request))==EINVAL);
        assert(retained_cache.failed);establish();assert(native_calls[0x48]==3);
    } else if(!strcmp(test,"unknown-selector")||!strcmp(test,"surface-import")) {
        establish();uint32_t request=0;assert(!call(!strcmp(test,"surface-import")?0x7e:0x7f,&request,4));
        establish();assert(native_calls[0x48]==2);
    } else if(!strcmp(test,"failure")||!strcmp(test,"short-return")) {
        if(!strcmp(test,"failure"))fail_number=0x48;else short_number=0x48;
        int result=advise(1,0);assert(result==(!strcmp(test,"failure")?-ENOMEM:0));
        fail_number=short_number=0;assert(retained_cache.failed);establish();assert(native_calls[0x48]==3);
    } else if(!strcmp(test,"changed-response")) {
        change_handle=1;assert(!advise(1,0));change_handle=0;assert(retained_cache.failed);
        establish();assert(native_calls[0x48]==3);
    } else if(!strcmp(test,"full")) {
        for(unsigned h=1;h<=PDRC_CAPACITY;h++)assert(!advise(h,0));
        assert(!advise(PDRC_CAPACITY+1,0));assert(!advise(PDRC_CAPACITY+1,0));assert(!advise(1,0));
        assert(native_calls[0x48]==PDRC_CAPACITY+2&&retained_cache.full==2);
    } else if(!strcmp(test,"wait-submit")||!strcmp(test,"fork-during-wait")) {
        establish();block_wait=true;pthread_t waiter;assert(!pthread_create(&waiter,NULL,wait_thread,NULL));
        wait_for(&wait_entered);
        if(!strcmp(test,"fork-during-wait")) {
            pid_t child=fork();assert(child>=0);
            if(!child){assert(!retained_cache.enabled&&retained_cache.inflight==0);_exit(0);}
            int status=0;assert(waitpid(child,&status,0)==child&&WIFEXITED(status)&&!WEXITSTATUS(status));
        }
        /* The WAIT is already inside native IOKit. SUBMIT must reach native
         * without acquiring any mutex held across that WAIT. */
        uint32_t request=0;assert(!call(0x46,&request,4));assert(!pthread_join(waiter,NULL));
        assert(native_calls[0x46]==1&&native_calls[0x47]==1&&retained_cache.inflight==0);
    } else if(!strcmp(test,"close-race")) {
        establish();block_close=true;pthread_t closer,reader;
        assert(!pthread_create(&closer,NULL,close_thread,NULL));wait_for(&close_entered);
        assert(!pthread_create(&reader,NULL,advice_thread,NULL));
        /* Force the native query to finish while CLOSE is still in flight.
         * Its truthful pre-CLOSE retained answer must be invalidated AGAIN
         * when the lifetime operation actually completes. */
        assert(!pthread_join(reader,NULL));assert(advice_result==0);
        release(&release_close);assert(!pthread_join(closer,NULL));
        assert(native_calls[0x48]==2);assert(advise(1,0)==-EINVAL);assert(native_calls[0x48]==3);
        assert(!retained_cache.count);
    } else if(!strcmp(test,"reconnect")) {
        establish();connection=9;retained_connect(0);establish();assert(native_calls[0x48]==2);
    } else if(!strcmp(test,"reconnect-inflight")) {
        establish();block_madvise=true;pthread_t reader;assert(!pthread_create(&reader,NULL,old_query_thread,NULL));
        wait_for(&madvise_entered);connection=9;retained_connect(0);assert(retained_cache.inflight==1);
        release(&release_madvise);assert(!pthread_join(reader,NULL));block_madvise=false;
        assert(!retained_cache.count&&!retained_cache.failed);establish();assert(native_calls[0x48]==3);
    } else if(!strcmp(test,"fork")) {
        establish();pid_t child=fork();assert(child>=0);
        if(!child) {
            assert(!retained_cache.enabled&&retained_cache.inflight==0);establish();assert(native_calls[0x48]==3);_exit(0);
        }
        int status=0;assert(waitpid(child,&status,0)==child&&WIFEXITED(status)&&!WEXITSTATUS(status));
        assert(!advise(1,0)&&native_calls[0x48]==1&&retained_cache.enabled);
    } else {assert(!"unknown fixture");}
    assert(retained_cache.inflight==0);puts("PASS real-shim fixture");return 0;
#else
    assert(!"trial-only fixture requested from default-OFF binary");
#endif
}
