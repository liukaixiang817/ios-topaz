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
#include <stdint.h>
#include <mach-o/dyld.h>
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

/* Where a crash happened, printed to stderr (the console): image + offset + symbol. */

static io_connect_t desktop_connection;
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
    if(mask!=0x7f){loader_note(4,4,mask);return;}
    observe(loader_note);
    gl_hooks(gl);
    fprintf(stderr,"POLARIS GL: all7 EAGL methods installed; desktop submissions still require observation\n");
}
