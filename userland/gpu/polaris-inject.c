/* Polaris20H392 window-server EAGL bridge, adapted from HackiOS (MIT;
 * LICENSE.hackios). Actual QuartzCore vtable targets and all457 OpenGLES
 * slots checked against this build. No foreign hardware registers. */
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <objc/runtime.h>
#include <mach/mach.h>
#include <mach/host_info.h>
#include <stdint.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <signal.h>
#include <sys/ucontext.h>
#include <unistd.h>
#include <time.h>
#include "../../tools/polaris-gl-status.h"
extern const void *_dyld_get_shared_cache_range(size_t *);
#define CACHE_BASE              0x180000000UL
#define VT_GLES_CONTEXT         0x1d5b2f6e8UL   /* vtable for CA::OGL::GLESContext */
#define VSLOT(vtable, offset)   ((vtable) + 0x10 + (offset))
#define FN_FUNCTION_SUPPORTED   0x1884b2164UL   /* CA::OGL::GLContext::function_supported() const */
#define FN_FUNCTION_UNIFORM     0x1884b21acUL   /* CA::OGL::GLContext::function_uniform(unsigned, unsigned long, unsigned long, float const*) */

static uintptr_t slide;

static void *
replace_virtual(const char *what, uintptr_t slot, uintptr_t expected, void *replacement)
{
	uintptr_t *entry = (uintptr_t *)(slot + slide);
	vm_address_t page = (vm_address_t)entry & ~(vm_address_t)(vm_page_size - 1);
	void *original;

	if (*entry != expected + slide) {
		fprintf(stderr, "polaris-gl: %s: slot holds %#lx, expected %#lx: left alone\n", what, *entry - slide, expected);
		return NULL;
	}
	if (vm_protect(mach_task_self(), page, vm_page_size, FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) != KERN_SUCCESS) {
		fprintf(stderr, "polaris-gl: %s: table not writable\n", what);
		return NULL;
	}
	original = (void *)*entry;
	*entry = (uintptr_t)replacement;
	vm_protect(mach_task_self(), page, vm_page_size, FALSE, VM_PROT_READ);
	return original;
}

static int (*orig_function_supported)(void *context);
static void (*gl_function_refused)(unsigned function);
static void (*orig_function_uniform)(void *context, unsigned index, size_t components, size_t count, const float *values);
static void (*gl_function_values)(void *context, unsigned function, unsigned index, size_t components, size_t count,
    const float *values);

static unsigned
context_function(void *context)
{
	return *(*(uint8_t **)((char *)context + 0x10) + 0x10);
}

static int
my_function_supported(void *context)
{
	static uint8_t said[256];
	int supported = orig_function_supported(context);
	unsigned function = context_function(context);

	if (!supported) {
		if (gl_function_refused != NULL) {
			gl_function_refused(function);
		}
		if (!said[function & 255]) {
			said[function & 255] = 1;
			fprintf(stderr, "polaris-gl: CoreAnimation's GL renderer has no function %u\n", function);
		}
	}
	return supported;
}

static void
my_function_uniform(void *context, unsigned index, size_t components, size_t count, const float *values)
{
	gl_function_values(context, context_function(context), index, components, count, values);
	orig_function_uniform(context, index, components, count, values);
}

static void
gl_hooks(void *lib)
{
	size_t length = 0;
	const void *cache = _dyld_get_shared_cache_range(&length);

	if (cache == NULL || lib == NULL) {
		return;
	}
	slide = (uintptr_t)cache - CACHE_BASE;
	gl_function_refused = (void (*)(unsigned))dlsym(lib, "redwood_gl_function_refused");
	gl_function_values = (void (*)(void *, unsigned, unsigned, size_t, size_t, const float *))dlsym(lib,
	    "redwood_gl_function_values");
	orig_function_supported = replace_virtual("function_supported", VSLOT(VT_GLES_CONTEXT, 0x378), FN_FUNCTION_SUPPORTED,
	    my_function_supported);
	if (gl_function_values != NULL) {
		orig_function_uniform = replace_virtual("function_uniform", VSLOT(VT_GLES_CONTEXT, 0x388), FN_FUNCTION_UNIFORM,
		    my_function_uniform);
	}
	fprintf(stderr, "polaris-gl: GLESContext hooks: function_supported %s, function_uniform %s\n",
	    orig_function_supported ? "on" : "OFF", orig_function_uniform ? "on" : "OFF");
}

/* First fatal PC/LR survives launchd restarting this process. The handler
 * uses only a fixed stack record and the thin syscall stub: no allocation,
 * stdio, dladdr, frame-pointer dereference or GPU connection/driver locks. */
extern int __mac_syscall(const char *,int,void *);
static struct pgpu_image crash_images[4];
static uint32_t crash_images_ready;
static void
polaris_gl_inject(void);
static void crash_image(unsigned index,unsigned kind,void *symbol)
{
    Dl_info info;
    if(!symbol || !dladdr(symbol,&info) || !info.dli_fbase)return;
    const struct mach_header_64 *h=info.dli_fbase;
    if(h->magic!=MH_MAGIC_64 || h->ncmds>4096 || h->sizeofcmds>1048576)return;
    const char *p=(const char*)(h+1),*end=p+h->sizeofcmds;
    uint64_t lo=UINT64_MAX,hi=0;
    for(unsigned i=0;i<h->ncmds;i++) {
        if((size_t)(end-p)<sizeof(struct load_command))return;
        const struct load_command *lc=(const void*)p;
        if(lc->cmdsize<sizeof(*lc) || lc->cmdsize>(size_t)(end-p))return;
        if(lc->cmd==LC_SEGMENT_64 && lc->cmdsize>=sizeof(struct segment_command_64)) {
            const struct segment_command_64 *s=(const void*)p;
            if(s->vmsize && s->initprot && s->vmaddr<=UINT64_MAX-s->vmsize) {
                if(s->vmaddr<lo)lo=s->vmaddr;
                if(s->vmaddr+s->vmsize>hi)hi=s->vmaddr+s->vmsize;
            }
        }
        p+=lc->cmdsize;
    }
    if(hi>lo) {
        crash_images[index]=(struct pgpu_image){(uintptr_t)h,hi-lo,kind};
        __atomic_fetch_or(&crash_images_ready,1u<<index,__ATOMIC_RELEASE);
    }
}
static void fatal_signal(int sig,siginfo_t *info,void *opaque)
{
    ucontext_t *context=opaque;
    struct pgpu_crash fault={.signal=(unsigned)sig,.code=info?(unsigned)info->si_code:0,
        .address=info?(uintptr_t)info->si_addr:0};
    if(context && context->uc_mcontext) {
        struct pgpu_image images[4]={0};
        uint32_t ready=__atomic_load_n(&crash_images_ready,__ATOMIC_ACQUIRE);
        for(unsigned n=0;n<4;n++)if(ready&(1u<<n))images[n]=crash_images[n];
        fault.pc=pgpu_pc(context->uc_mcontext->__ss.__pc,images,4,&fault.pc_image);
        fault.lr=pgpu_pc(context->uc_mcontext->__ss.__lr,images,4,&fault.lr_image);
    }
    (void)__mac_syscall("AMFI",0x5b,&fault);
    const char line[]="POLARIS GL: fatal signal; first PC/LR saved in GLF rows\n";
    (void)write(STDERR_FILENO,line,sizeof(line)-1);
    /* SA_RESETHAND already restored the default. Do not resume a faulting
     * renderer or attempt to reset/tear down hardware from a signal. */
    (void)kill(getpid(),sig);
}
static void watch_for_faults(void)
{
    size_t bytes=0;const void *base=_dyld_get_shared_cache_range(&bytes);
    crash_images[0]=(struct pgpu_image){(uintptr_t)base,bytes,1};
    __atomic_fetch_or(&crash_images_ready,1,__ATOMIC_RELEASE);
    crash_image(1,2,(void*)polaris_gl_inject);
    struct sigaction action={0};action.sa_sigaction=fatal_signal;
    action.sa_flags=SA_SIGINFO|SA_RESETHAND;
    const int signals[]={SIGSEGV,SIGBUS,SIGABRT,SIGILL,SIGTRAP};
    for(unsigned n=0;n<sizeof(signals)/sizeof(signals[0]);n++)sigaction(signals[n],&action,NULL);
}

static io_connect_t desktop_connection;
static void performance_note(const struct pgpu_perf_notice *notice)
{
    static mach_port_t host;
    static uint32_t before[4];
    static int have_before;
    static uint64_t last_us;
    struct timespec ts;
    if(clock_gettime(CLOCK_MONOTONIC,&ts))return;
    uint64_t now_us=(uint64_t)ts.tv_sec*1000000+(uint64_t)ts.tv_nsec/1000;
    if(last_us && now_us-last_us<1000000)return;
    last_us=now_us;
    if(!host)host=mach_host_self();
    struct pgpu_perf_notice copy=*notice;
    host_cpu_load_info_data_t load;mach_msg_type_number_t count=HOST_CPU_LOAD_INFO_COUNT;
    if(host_statistics(host,HOST_CPU_LOAD_INFO,(host_info_t)&load,&count)==KERN_SUCCESS &&
        count==HOST_CPU_LOAD_INFO_COUNT) {
        if(have_before)copy.cpu_busy=pgpu_perf_cpu(before,load.cpu_ticks);
        memcpy(before,load.cpu_ticks,sizeof(before));have_before=1;
    }else have_before=0;
    host_basic_info_data_t basic;count=HOST_BASIC_INFO_COUNT;
    if(host_info(host,HOST_BASIC_INFO,(host_info_t)&basic,&count)==KERN_SUCCESS &&
        count==HOST_BASIC_INFO_COUNT && basic.avail_cpus>0 && basic.avail_cpus<=8)
        copy.cpus=(uint32_t)basic.avail_cpus;
    size_t bytes=sizeof(copy);
    (void)IOConnectCallStructMethod(desktop_connection,0x79,&copy,sizeof(copy),&copy,&bytes);
}
static void render_note(const struct pgpu_render_notice *notice)
{
    struct pgpu_render_notice copy=*notice;size_t bytes=sizeof(copy);
    (void)IOConnectCallStructMethod(desktop_connection,0x7a,&copy,sizeof(copy),&copy,&bytes);
}
static void loader_note(unsigned stage,unsigned error,unsigned methods)
{
    uint32_t report[3]={stage,error,methods},reply[3];size_t bytes=sizeof(reply);
    kern_return_t kr=IOConnectCallStructMethod(desktop_connection,0x7b,report,sizeof(report),reply,&bytes);
    if(kr || bytes!=sizeof(reply))fprintf(stderr,"POLARIS GL: loader report failed %#x\n",kr);
}
static int real_window_server(void)
{
    char path[1024];uint32_t bytes=sizeof(path);
    const char *tested=getenv("POLARIS_GL_TESTED");
    /* dyld's program name follows executable_path, not our rewritten argv[0].
     * Kernel admission still independently verifies the executable vnode. */
    return tested && !strcmp(tested,"1") && !_NSGetExecutablePath(path,&bytes) &&
        !strcmp(path,"/usr/libexec/polaris-bbd-real");
}
__attribute__((constructor)) static void polaris_gl_inject(void)
{
    if(!real_window_server())return;
    watch_for_faults();
    io_service_t gpu=IOServiceGetMatchingService(0,IOServiceMatching("PolarisGPU"));
    if(!gpu)return;
    kern_return_t kr=IOServiceOpen(gpu,mach_task_self(),0,&desktop_connection);
    IOObjectRelease(gpu);
    if(kr){fprintf(stderr,"POLARIS GL: desktop connection failed %#x\n",kr);return;}
    loader_note(2,0,0);
    /* Mesa reuses this task's one exclusive connection. Never inherit a port
     * from the child selftest and never compete with our own connection. */
    char port[16];snprintf(port,sizeof(port),"%u",desktop_connection);
    if(setenv("POLARIS_GPU_CONNECTION",port,1)) {loader_note(2,1,0);return;}
    loader_note(3,0,0);
    void *gl=dlopen("/usr/lib/libPolarisGL.dylib",RTLD_NOW|RTLD_LOCAL);
    if(!gl){loader_note(3,2,0);fprintf(stderr,"POLARIS GL: bridge load failed: %s\n",dlerror());return;}
    unsigned (*methods)(void)=(unsigned (*)(void))dlsym(gl,"polaris_eagl_methods");
    void (*observe)(void (*)(unsigned,unsigned,unsigned))=
        (void (*)(void (*)(unsigned,unsigned,unsigned)))dlsym(gl,"polaris_eagl_observe");
    if(!methods || !observe){loader_note(4,3,0);return;}
    unsigned mask=methods();
    if(mask!=PGPU_EAGL_METHOD_MASK){loader_note(4,4,mask);return;}
    crash_image(2,3,(void*)methods);
    crash_image(3,4,dlsym(gl,"glFinish"));
    observe(loader_note);
    void (*render_observe)(void (*)(const struct pgpu_render_notice *))=
        (void (*)(void (*)(const struct pgpu_render_notice *)))dlsym(gl,"polaris_eagl_render_observe");
    if(render_observe)render_observe(render_note);
    void (*performance_observe)(void (*)(const struct pgpu_perf_notice *))=
        (void (*)(void (*)(const struct pgpu_perf_notice *)))dlsym(gl,"polaris_eagl_performance_observe");
    if(performance_observe)performance_observe(performance_note);
    gl_hooks(gl);
    fprintf(stderr,"POLARIS GL: all8 EAGL methods installed; desktop submissions still require observation\n");
}
