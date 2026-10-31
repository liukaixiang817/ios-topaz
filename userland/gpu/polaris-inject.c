/* Polaris exact-build window-server EAGL bridge, adapted from HackiOS (MIT;
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
#include <mach/mach_time.h>
#include <mach/host_info.h>
#include <stdint.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <signal.h>
#include <sys/ucontext.h>
#include <unistd.h>
#include <time.h>
#include "../../tools/polaris-gl-status.h"
#include "../../tools/polaris-compositor-clock.h"
extern const void *_dyld_get_shared_cache_range(size_t *);
#define CACHE_BASE              0x180000000UL
#define VT_GLES_CONTEXT         PGPU_QC_GLES_VTABLE
#define VSLOT(vtable, offset)   ((vtable) + 0x10 + (offset))
#define FN_FUNCTION_SUPPORTED   PGPU_QC_FUNCTION_SUPPORTED
#define FN_FUNCTION_UNIFORM     PGPU_QC_FUNCTION_UNIFORM

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
static const uint64_t *clock_once;
static const uint8_t *clock_choice;
static mach_timebase_info_data_t clock_timebase;
static unsigned clock_trial_mode;
static int clock_target_prepare(void)
{
    clock_once=NULL;clock_choice=NULL;clock_trial_mode=0;
    const char *mode=getenv(PCC_ENV);
    if(!mode)return 0; /* original path: no new cache reads */
    if(strcmp(mode,"0") && strcmp(mode,"1"))return -1;
    clock_trial_mode=mode[0]=='1'?1:2;
    size_t cache_bytes=0;const void *cache=_dyld_get_shared_cache_range(&cache_bytes);
    if(!cache || (uintptr_t)cache<CACHE_BASE)return -2;
    uint64_t base=(uintptr_t)cache,offset=base-CACHE_BASE;
    const uint64_t targets[]={PCC_TEXT_BASE,PCC_BLOCK,PCC_STRING,PCC_STATE,PCC_ONCE};
    const size_t spans[]={32,32,15,1,8};
    for(unsigned i=0;i<5;i++)
        if(targets[i]>UINT64_MAX-offset || !pcc_span(targets[i]+offset,spans[i],base,cache_bytes))return -3;
    const struct mach_header_64 *header=NULL;
    uint32_t images=_dyld_image_count();if(images>2048)return -4;
    for(uint32_t i=0;i<images;i++) {
        const char *name=_dyld_get_image_name(i);
        if(name && !strcmp(name,"/System/Library/Frameworks/QuartzCore.framework/QuartzCore")) {
            if(header)return -5;
            header=(const void*)_dyld_get_image_header(i);
        }
    }
    if((uintptr_t)header!=PCC_TEXT_BASE+offset || !header || header->sizeofcmds>65536 ||
        !pcc_span((uintptr_t)header,32+header->sizeofcmds,base,cache_bytes) ||
        !pcc_layout(header,32+header->sizeofcmds))return -6;
    static const uint8_t code[32]=PCC_BLOCK_CODE;
    if(memcmp((const void*)(uintptr_t)(PCC_BLOCK+offset),code,sizeof(code)) ||
        memcmp((const void*)(uintptr_t)(PCC_STRING+offset),PCC_FORCE,sizeof(PCC_FORCE)))return -7;
    if(mach_timebase_info(&clock_timebase)!=KERN_SUCCESS || !clock_timebase.numer || !clock_timebase.denom)return -8;
    clock_once=(const void*)(uintptr_t)(PCC_ONCE+offset);
    clock_choice=(const void*)(uintptr_t)(PCC_STATE+offset);
    return 1;
}
static void clock_note(unsigned frames)
{
    if(!clock_once || !clock_choice)return;
    uint64_t before=__atomic_load_n(clock_once,__ATOMIC_ACQUIRE);
    unsigned choice=__atomic_load_n(clock_choice,__ATOMIC_ACQUIRE);
    uint64_t after=__atomic_load_n(clock_once,__ATOMIC_ACQUIRE);
    unsigned ready=before==UINT64_MAX && after==UINT64_MAX && choice<=1;
    uint64_t ticks=mach_absolute_time();
    if(ticks>UINT64_MAX/clock_timebase.numer)return;
    uint64_t us=ticks*clock_timebase.numer/clock_timebase.denom/1000;
    fprintf(stderr,"POLARIS CA CLOCK: us=%llu mode=%u ready=%u choice=%u window_frames=%u; choice not hardware Hz\n",
        us,clock_trial_mode,ready,choice,frames);
}
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
    clock_note(notice->frames); /* existing >=1s observer, no extra IPC */
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
#if defined(PGPU_USERLAND_20F66)
    extern int polaris_media_compat_entry(void);
    if(polaris_media_compat_entry())return;
    extern int polaris_poster_preview_entry(void);
    if(polaris_poster_preview_entry())return;
#endif
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
    int clock=clock_target_prepare();
    if(clock)fprintf(stderr,"POLARIS CA CLOCK TARGET: status=%d mode=%u; exact%s read-only\n",clock,clock_trial_mode,PGPU_USERLAND_BUILD);
    fprintf(stderr,"POLARIS GL: all8 EAGL methods installed; desktop submissions still require observation\n");
}
