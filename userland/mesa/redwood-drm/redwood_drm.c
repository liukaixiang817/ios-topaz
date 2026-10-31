/*
 * The libdrm of xf86drm.h (see there): Linux's DRM requests to the kernel's GPU driver as calls
 * of its IOKit user client. A request's number (the low byte of the ioctl code) is the call's
 * selector, its structure goes in and comes back as it is; a buffer's memory is the client
 * memory of the type that is the buffer's handle.
 *
 * freedreno knows its device by a file descriptor. It gets one that means nothing (/dev/null):
 * there is one GPU and one connection to it in a process.
 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <IOKit/IOKitLib.h>

#include "xf86drm.h"

/* Compile-time default OFF. A trial build additionally needs exact runtime
 * intent and a normal task-owned Polaris connection. No reference shortcut
 * that answers for every arbitrary handle is used. */
#ifndef POLARIS_DRM_RETAIN_CACHE_TRIAL
#define POLARIS_DRM_RETAIN_CACHE_TRIAL 0
#endif
#if POLARIS_DRM_RETAIN_CACHE_TRIAL
#include <pthread.h>
#include <stdatomic.h>
#include "polaris-retained-cache.h"
#endif

#ifndef REDWOOD_GPU_SERVICE
#define REDWOOD_GPU_SERVICE     "RedwoodGPU"
#endif
#define REDWOOD_GPU_SURFACE     0x7e            /* the request that is not Linux's */
#define REDWOOD_GPU_DESCRIBE    0xffffffffu     /* ... asked only what the buffer would be like */

#if POLARIS_DRM_RETAIN_CACHE_TRIAL
static _Atomic(io_connect_t) connection;
static _Atomic(int) connection_fd = -1;
#else
static io_connect_t connection;
static int connection_fd = -1;
#endif

#if POLARIS_DRM_RETAIN_CACHE_TRIAL
static struct pdrc_state retained_cache;
static pthread_mutex_t retained_mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t retained_once=PTHREAD_ONCE_INIT;
static int retained_fork_ready;
static void retained_fork_prepare(void){pthread_mutex_lock(&retained_mutex);}
static void retained_fork_parent(void){pthread_mutex_unlock(&retained_mutex);}
static void retained_fork_child(void)
{
    pdrc_failed(&retained_cache);
    retained_cache.inflight=0;
    pthread_mutex_unlock(&retained_mutex);
}
static void retained_register_fork(void)
{retained_fork_ready=pthread_atfork(retained_fork_prepare,retained_fork_parent,retained_fork_child)==0;}
static void retained_connect(int inherited)
{
    pthread_once(&retained_once,retained_register_fork);
    const char *intent=getenv("POLARIS_DRM_RETAIN_CACHE");
    bool eligible=retained_fork_ready&&!inherited&&connection_fd>=0&&
        !strcmp(REDWOOD_GPU_SERVICE,"PolarisGPU")&&intent&&!strcmp(intent,"1");
    pthread_mutex_lock(&retained_mutex);
    pdrc_connect(&retained_cache,(uint64_t)getpid(),connection,eligible);
    pthread_mutex_unlock(&retained_mutex);
}
static void retained_external_begin(io_connect_t port,struct pdrc_ticket *ticket)
{
    pthread_mutex_lock(&retained_mutex);
    (void)pdrc_before(&retained_cache,(uint64_t)getpid(),port,UINT32_MAX,NULL,0,ticket);
    pthread_mutex_unlock(&retained_mutex);
}
static void retained_external_end(io_connect_t port,kern_return_t result,const struct pdrc_ticket *ticket)
{
    pthread_mutex_lock(&retained_mutex);
    if(port!=connection)port=0; /* A completion from an old connection cannot bless a new one. */
    pdrc_after(&retained_cache,(uint64_t)getpid(),port,UINT32_MAX,NULL,0,result,0,ticket);
    pthread_mutex_unlock(&retained_mutex);
}
#endif

int
drmOpenWithType(const char *name, const char *busid, int type)
{
	io_service_t service;

	(void)busid;
	(void)type;
	if (strcmp(name, "msm") != 0) {
		return -1;
	}
	if (connection_fd >= 0) {
		return dup(connection_fd);
	}
	/* The Polaris acceptance program owns this task's connection so it can
	 * report each actual shader/surface phase through the SAME user client.
	 * Normal window-server use still opens its own connection below. */
	const char *inherited = getenv("POLARIS_GPU_CONNECTION");
	if (strcmp(REDWOOD_GPU_SERVICE, "PolarisGPU") == 0 && inherited != NULL) {
		char *end = NULL;
		unsigned long port = strtoul(inherited, &end, 10);
		if (!port || port > UINT32_MAX || !end || *end) return -1;
		connection = (io_connect_t)port;
		connection_fd = open("/dev/null", O_RDWR);
#if POLARIS_DRM_RETAIN_CACHE_TRIAL
        retained_connect(1);
#endif
		return connection_fd < 0 ? -1 : dup(connection_fd);
	}
	service = IOServiceGetMatchingService(0, IOServiceMatching(REDWOOD_GPU_SERVICE));
	if (service == 0) {
		return -1;
	}
#if POLARIS_DRM_RETAIN_CACHE_TRIAL
    io_connect_t opened_connection=0;
    if (IOServiceOpen(service, mach_task_self(), 0, &opened_connection) != 0) {
#else
	if (IOServiceOpen(service, mach_task_self(), 0, &connection) != 0) {
#endif
		IOObjectRelease(service);
		return -1;
	}
#if POLARIS_DRM_RETAIN_CACHE_TRIAL
    connection=opened_connection;
#endif
	IOObjectRelease(service);
	connection_fd = open("/dev/null", O_RDWR);
#if POLARIS_DRM_RETAIN_CACHE_TRIAL
    retained_connect(0);
#endif
	return dup(connection_fd);
}

static int
call(unsigned number, void *data, size_t size)
{
	size_t returned = size;
#if POLARIS_DRM_RETAIN_CACHE_TRIAL
    io_connect_t call_connection=connection;
    struct pdrc_ticket ticket;
    pthread_mutex_lock(&retained_mutex);
    if(pdrc_before(&retained_cache,(uint64_t)getpid(),call_connection,number,data,size,&ticket)) {
        pthread_mutex_unlock(&retained_mutex);return 0;
    }
    pthread_mutex_unlock(&retained_mutex);
    /* Never hold the cache mutex across IOKit. In particular a WAIT may need
     * another thread's SUBMIT to complete. Inflight + generation bind any
     * candidate retained answer after the original native request returns. */
    kern_return_t result = IOConnectCallStructMethod(call_connection, number, data, size, data, &returned);
#else
	kern_return_t result = IOConnectCallStructMethod(connection, number, data, size, data, &returned);
#endif
#if POLARIS_DRM_RETAIN_CACHE_TRIAL
    pthread_mutex_lock(&retained_mutex);
    pdrc_after(&retained_cache,(uint64_t)getpid(),connection,number,data,size,result,returned,&ticket);
    pthread_mutex_unlock(&retained_mutex);
#endif

	switch (result) {
	case 0:
		return 0;
	case kIOReturnNoMemory:
		return ENOMEM;
	case kIOReturnBadArgument:
		return EINVAL;
	case kIOReturnTimeout:
		return ETIMEDOUT;
	case kIOReturnBusy:
		return EBUSY;
	case kIOReturnNotFound:
		return ENOENT;
	case kIOReturnUnsupported:
		return ENOSYS;
	default:
		return EIO;
	}
}

int
drmIoctl(int fd, unsigned long request, void *arg)
{
	int error = call((unsigned)(request & 0xff), arg, IOCPARM_LEN(request));

	(void)fd;
	if (error != 0) {
		errno = error;
		return -1;
	}
	return 0;
}

int
drmCommandWrite(int fd, unsigned long index, const void *data, unsigned long size)
{
	(void)fd;
	return -call((unsigned)(DRM_COMMAND_BASE + index), (void *)(uintptr_t)data, size);
}

int
drmCommandWriteRead(int fd, unsigned long index, void *data, unsigned long size)
{
	(void)fd;
	return -call((unsigned)(DRM_COMMAND_BASE + index), data, size);
}

/*
 * The driver calls itself what Linux's is called, and is of the version whose interface it has:
 * 1.7, buffers at addresses the kernel chooses and tells ("softpin"), nothing newer.
 */
drmVersionPtr
drmGetVersion(int fd)
{
	drmVersionPtr version = calloc(1, sizeof(*version));

	(void)fd;
	if (version != NULL) {
		version->version_major = 1;
		version->version_minor = 7;
		version->name = strdup("msm");
		version->name_len = 3;
		version->date = strdup("");
		version->desc = strdup("Adreno on Darwin");
		version->desc_len = (int)strlen(version->desc);
	}
	return version;
}

void
drmFreeVersion(drmVersionPtr version)
{
	if (version != NULL) {
		free(version->name);
		free(version->date);
		free(version->desc);
		free(version);
	}
}

int
drmGetCap(int fd, uint64_t capability, uint64_t *value)
{
	(void)fd;
	(void)capability;
	*value = 0;
	return 0;
}

void *
redwood_drm_map(int fd, uint32_t handle, uint64_t size)
{
	mach_vm_address_t address = 0;
	mach_vm_size_t mapped = 0;

	(void)fd;
	(void)size;
	/*
	 * Linux gives freedreno its buffers write-combined, with no cache of this processor's between
	 * the program and the memory the GPU sees. So does the kernel's driver here: the memory is
	 * made that way, and this mapping is as the memory is.
	 */
#if POLARIS_DRM_RETAIN_CACHE_TRIAL
    io_connect_t port=connection;struct pdrc_ticket ticket;retained_external_begin(port,&ticket);
    kern_return_t result=IOConnectMapMemory64(port,handle,mach_task_self(),&address,&mapped,kIOMapAnywhere);
    retained_external_end(port,result,&ticket);
    if(result!=0) {
#else
	if (IOConnectMapMemory64(connection, handle, mach_task_self(), &address, &mapped, kIOMapAnywhere) != 0) {
#endif
		return (void *)-1;              /* mmap()'s MAP_FAILED */
	}
	return (void *)(uintptr_t)address;
}

void
redwood_drm_unmap(int fd, uint32_t handle, void *address)
{
	(void)fd;
#if POLARIS_DRM_RETAIN_CACHE_TRIAL
    io_connect_t port=connection;struct pdrc_ticket ticket;retained_external_begin(port,&ticket);
    kern_return_t result=IOConnectUnmapMemory64(port,handle,mach_task_self(),(mach_vm_address_t)(uintptr_t)address);
    retained_external_end(port,result,&ticket);
#else
	IOConnectUnmapMemory64(connection, handle, mach_task_self(), (mach_vm_address_t)(uintptr_t)address);
#endif
}

int
redwood_drm_surface(int fd, struct redwood_drm_surface *surface)
{
	int error;

	(void)fd;
	surface->handle = REDWOOD_GPU_DESCRIBE;
	error = call(REDWOOD_GPU_SURFACE, surface, sizeof(*surface));
	if (error != 0) {
		errno = error;
		return -1;
	}
	return 0;
}

int
drmPrimeFDToHandle(int fd, int surface, uint32_t *handle)
{
	struct redwood_drm_surface request = { .surface = (uint32_t)surface };
	int error = call(REDWOOD_GPU_SURFACE, &request, sizeof(request));

	(void)fd;
	if (error != 0) {
		errno = error;
		return -1;
	}
	*handle = request.handle;
	return 0;
}

static int
none(void)
{
	errno = ENOSYS;
	return -1;
}

/* Buffers and fences as file descriptors, for handing them to other programs and drivers: none of that here. */
#define NONE(name, ...) int name(__VA_ARGS__) { return none(); }
NONE(drmPrimeHandleToFD, __attribute__((unused)) int fd, __attribute__((unused)) uint32_t handle,
    __attribute__((unused)) uint32_t flags, __attribute__((unused)) int *prime_fd)
NONE(drmSyncobjCreate, __attribute__((unused)) int fd, __attribute__((unused)) uint32_t flags,
    __attribute__((unused)) uint32_t *handle)
NONE(drmSyncobjDestroy, __attribute__((unused)) int fd, __attribute__((unused)) uint32_t handle)
NONE(drmSyncobjReset, __attribute__((unused)) int fd, __attribute__((unused)) const uint32_t *handles,
    __attribute__((unused)) uint32_t count)
NONE(drmSyncobjFDToHandle, __attribute__((unused)) int fd, __attribute__((unused)) int obj_fd,
    __attribute__((unused)) uint32_t *handle)
NONE(drmSyncobjHandleToFD, __attribute__((unused)) int fd, __attribute__((unused)) uint32_t handle,
    __attribute__((unused)) int *obj_fd)
NONE(drmSyncobjImportSyncFile, __attribute__((unused)) int fd, __attribute__((unused)) uint32_t handle,
    __attribute__((unused)) int sync_file_fd)
NONE(drmSyncobjExportSyncFile, __attribute__((unused)) int fd, __attribute__((unused)) uint32_t handle,
    __attribute__((unused)) int *sync_file_fd)
