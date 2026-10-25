/* Polaris A630 resident BO/submission service. Linux MSM 1.7 wire protocol;
 * informed by HackiOS RedwoodGPU (d82c64a3, MIT, userland/gpu/LICENSE.hackios).
 *
 * First integration deliberately admits ONE privileged writer. No claim of
 * per-process GPU isolation. Submit is synchronous: flush/idle/halt precede
 * every successful reply, so CPU readers and display see completed surfaces.
 * On any uncertain DMA state the client, descriptors and all mappings are
 * retained permanently, the service is poisoned and no replacement opens.
 */
#include <IOKit/IOLib.h>
#include <IOKit/IOLocks.h>
#include <IOKit/IOKitKeys.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IOService.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <sys/systm.h>
#include <mach/vm_param.h>
#include <kern/thread.h>
#include "SweetSurface.h"
#include "polaris_gpu.h"
#include "polaris_gpu_abi.h"

#if defined(POLARIS_RAM_ONLY)
#define GPU_BUFFERS 4096u
#define GPU_MAX_BO (128u << 20)
#define GPU_MAX_BYTES (384ull << 20)
#define GPU_VA_FIRST 0x20000000ull
#define GPU_VA_END 0x40000000ull
#define GPU_CMDS 128u
#define GPU_BOS 4096u
#define GPU_READONLY 2u

static IOLock *gpuLock;
static bool gpuOpened, gpuQuarantined;
static uint32_t gpuSubmissions, gpuSurfaces;
static uint32_t gpuPublished,gpuOpenStatus,gpuFaultStatus;
static uint32_t gpuAppStage,gpuAppError;
/* Loading evidence is independent of the shader/pixel acceptance result.
 * These cached words never read GPU registers from the display timer. */
static uint32_t gpuLoaderStage,gpuLoaderError,gpuLoaderMethods;
extern "C" void polaris_gpu_loader_policy(int error)
{
    uint32_t expected=0;
    if(__atomic_compare_exchange_n(&gpuLoaderStage,&expected,1,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))
        __atomic_store_n(&gpuLoaderError,(uint32_t)error,__ATOMIC_RELEASE);
}
static bool polaris_gpu_loader_report(uint32_t kind,uint32_t stage,uint32_t error,uint32_t methods)
{
    if(kind!=2 || stage<2 || stage>6 || error>6 || (methods&~0x7fu))return false;
    __atomic_store_n(&gpuLoaderError,error,__ATOMIC_RELEASE);
    __atomic_store_n(&gpuLoaderMethods,methods,__ATOMIC_RELEASE);
    __atomic_store_n(&gpuLoaderStage,stage,__ATOMIC_RELEASE);
    IOLog("POLARIS GL: desktop loader L%u X%x M%x; submissions=%u imports=%u\n",
        stage,error,methods,gpuSubmissions,gpuSurfaces);
    return true;
}
extern "C" uint32_t polaris_gpu_client_line(char *out,uint32_t capacity)
{
    if(!out || !capacity || !__atomic_load_n(&gpuPublished,__ATOMIC_ACQUIRE))return 0;
    return (uint32_t)snprintf(out,capacity,"GA O%u S%x I%x T%u E%u D%u R%u L%u X%x M%x",
        __atomic_load_n(&gpuOpenStatus,__ATOMIC_ACQUIRE),
        __atomic_load_n(&gpuSubmissions,__ATOMIC_ACQUIRE),
        __atomic_load_n(&gpuSurfaces,__ATOMIC_ACQUIRE),
        __atomic_load_n(&gpuAppStage,__ATOMIC_ACQUIRE),
        __atomic_load_n(&gpuAppError,__ATOMIC_ACQUIRE),
        __atomic_load_n(&gpuFaultStatus,__ATOMIC_ACQUIRE),polaris_gpu_ready()?1:0,
        __atomic_load_n(&gpuLoaderStage,__ATOMIC_ACQUIRE),
        __atomic_load_n(&gpuLoaderError,__ATOMIC_ACQUIRE),
        __atomic_load_n(&gpuLoaderMethods,__ATOMIC_ACQUIRE));
}
struct PolarisBO {
    IOMemoryDescriptor *memory;
    SweetSurface *surface;
    IOMemoryMap *map;
    uint64_t address, size;
    uint32_t flags;
};
class PolarisGPUUserClient : public IOUserClient {
    OSDeclareDefaultStructors(PolarisGPUUserClient);
    typedef IOUserClient super;
    PolarisBO *buffers;
    uint64_t bytes;
    uint32_t nextHandle, lastFence, queues;
    bool closed, quarantined;
    task_t ownerTask;
    PolarisBO *buffer(uint32_t h) {return h && h<=GPU_BUFFERS && buffers[h-1].memory ? &buffers[h-1] : NULL;}
    void poison();
    IOReturn make(IOMemoryDescriptor *,SweetSurface *,uint64_t,uint32_t,uint32_t *);
    bool drop(uint32_t);
    IOReturn submit(msm_gem_submit *);
    IOReturn surface(redwood_surface *);
public:
    bool initWithTask(task_t,void *,UInt32,OSDictionary *) APPLE_KEXT_OVERRIDE;
    IOReturn clientClose() APPLE_KEXT_OVERRIDE;
    void free() APPLE_KEXT_OVERRIDE;
    IOReturn clientMemoryForType(UInt32,IOOptionBits *,IOMemoryDescriptor **) APPLE_KEXT_OVERRIDE;
    IOReturn externalMethod(uint32_t,IOExternalMethodArguments *,IOExternalMethodDispatch *,OSObject *,void *) APPLE_KEXT_OVERRIDE;
};
class PolarisGPU : public IOService {
    OSDeclareDefaultStructors(PolarisGPU);
public:
    IOReturn newUserClient(task_t,void *,UInt32,OSDictionary *,IOUserClient **) APPLE_KEXT_OVERRIDE;
};
OSDefineMetaClassAndStructors(PolarisGPU,IOService);
OSDefineMetaClassAndStructors(PolarisGPUUserClient,IOUserClient);

void PolarisGPUUserClient::poison()
{
    gpuQuarantined=true;polaris_gpu_quarantine();
    __atomic_store_n(&gpuFaultStatus,1,__ATOMIC_RELEASE);
    if (!quarantined) {quarantined=true;retain();} /* DMA ownership survives task death */
}
bool PolarisGPUUserClient::initWithTask(task_t task,void *security,UInt32 type,OSDictionary *props)
{
    if (!super::initWithTask(task,security,type,props)) return false;
    ownerTask=task;
    buffers=IONewZero(PolarisBO,GPU_BUFFERS);
    return buffers!=NULL;
}
IOReturn PolarisGPU::newUserClient(task_t task,void *security,UInt32 type,OSDictionary *props,IOUserClient **out)
{
    if (type || !out) return kIOReturnBadArgument;
    /* A shared address space cannot safely accept arbitrary app shaders.
     * The genuine window server is mobile, so authenticate its executable
     * vnode rather than root UID or a caller-provided process name. */
    if(task!=current_task() || !polaris_gpu_caller_allowed())return kIOReturnNotPrivileged;
    IOLockLock(gpuLock);
    IOReturn result=kIOReturnBusy;
    if (!gpuOpened && !gpuQuarantined && polaris_gpu_ready()) {
        PolarisGPUUserClient *c=new PolarisGPUUserClient;
        if (c && c->initWithTask(task,security,type,props) && c->attach(this) && c->start(this)) {
            gpuOpened=true;__atomic_store_n(&gpuOpenStatus,1,__ATOMIC_RELEASE);*out=c;result=kIOReturnSuccess;
        } else {if(c)c->release();result=kIOReturnNoMemory;}
    }
    IOLockUnlock(gpuLock);
    return result;
}
/* First fit with an unmapped 16KiB guard after every BO. Bounded by live
 * handles, no dynamically growing metadata and no wrap/overlapping reuse. */
IOReturn PolarisGPUUserClient::make(IOMemoryDescriptor *memory,SweetSurface *s,
    uint64_t size,uint32_t flags,uint32_t *handle)
{
    if (!size || size>GPU_MAX_BO || (size&PAGE_MASK) || bytes>GPU_MAX_BYTES-size)
        return kIOReturnNoMemory;
    unsigned h=GPU_BUFFERS;
    for(unsigned n=0;n<GPU_BUFFERS;n++) {
        unsigned at=(nextHandle+n)%GPU_BUFFERS;
        if (!buffers[at].memory) {h=at;break;}
    }
    if(h==GPU_BUFFERS || !polaris_gpu_quiescent()) return kIOReturnNotReady;
    uint64_t address=GPU_VA_FIRST;
    for(unsigned pass=0;pass<=GPU_BUFFERS;pass++) {
        bool moved=false;
        if(size+PAGE_SIZE>GPU_VA_END-address) return kIOReturnNoMemory;
        for(unsigned n=0;n<GPU_BUFFERS;n++) if(buffers[n].memory) {
            PolarisBO *b=&buffers[n];
            if(address<b->address+b->size+PAGE_SIZE && address+size+PAGE_SIZE>b->address) {
                address=b->address+b->size+PAGE_SIZE;moved=true;break;
            }
        }
        if(!moved) break;
        if(pass==GPU_BUFFERS) return kIOReturnNoMemory;
    }
    /* Retain before installing ANY PTE: even failed TLBSYNC may retain DMA. */
    PolarisBO *b=&buffers[h];memory->retain();if(s)s->retain();
    *b=(PolarisBO){memory,s,NULL,address,size,flags};bytes+=size;
    if(memory->prepare(kIODirectionInOut)!=kIOReturnSuccess) {
        b->memory=NULL;memory->release();if(s)s->release();bytes-=size;return kIOReturnNoMemory;
    }
    bool mapped=true;
    for(uint64_t off=0;off<size;off+=4096) {
        IOByteCount length=0;
        addr64_t pa=memory->getPhysicalSegment(off,&length,kIOMemoryMapperNone);
        if (!pa || (pa&4095) || length<4096 ||
            !polaris_gpu_map(address+off,pa,(flags&GPU_READONLY)!=0,true)) {mapped=false;break;}
    }
    if(!mapped) {
        if(!drop(h+1))poison();
        return kIOReturnNoMemory;
    }
    if(!polaris_gpu_commit()) {poison();return kIOReturnNotReady;}
    *handle=h+1;nextHandle=h+1;
    return kIOReturnSuccess;
}
bool PolarisGPUUserClient::drop(uint32_t handle)
{
    PolarisBO *b=buffer(handle);
    if(!b) return false;
    if(!polaris_gpu_unmap(b->address,b->size)) {poison();return false;}
    b->memory->complete(kIODirectionInOut);
    OSSafeReleaseNULL(b->map);OSSafeReleaseNULL(b->memory);OSSafeReleaseNULL(b->surface);
    bytes-=b->size;*b=(PolarisBO){};
    return true;
}
IOReturn PolarisGPUUserClient::surface(redwood_surface *r)
{
    SweetSurface *s=sweet_surface_copy(r->surface);
    if(!s) return kIOReturnNotFound;
    /* Ordinary wired surfaces only; never map the physical panel/MMIO. Own
     * SweetSurface pixels start at byte ZERO (reference MiniIOSurface +PAGE
     * is a different ABI). Keep the exact allocation/offset/row geometry. */
    IOReturn result=kIOReturnUnsupported;
    if(OSDynamicCast(IOBufferMemoryDescriptor,s->memory) && s->mapCache==kIOMapDefaultCache && !s->planeCount && s->allocSize &&
        !(s->allocSize&PAGE_MASK) && s->offset<s->allocSize) {
        uint32_t handle=0;
        r->size=s->allocSize;r->offset=s->offset;r->rowBytes=s->bytesPerRow;
        r->width=s->width;r->height=s->height;r->pixelFormat=s->pixelFormat;r->planes=s->planeCount;
        if(r->handle==UINT32_MAX) {r->handle=0;result=kIOReturnSuccess;}
        else {
            for(unsigned n=0;n<GPU_BUFFERS;n++) if(buffers[n].surface==s) {handle=n+1;break;}
            result=handle?kIOReturnSuccess:make(s->memory,s,s->allocSize,0,&handle);
            if(result==kIOReturnSuccess) {r->handle=handle;__atomic_fetch_add(&gpuSurfaces,1,__ATOMIC_RELEASE);}
        }
    }
    s->release();return result;
}
IOReturn PolarisGPUUserClient::submit(msm_gem_submit *r)
{
    if(!r->nr_cmds || r->nr_cmds>GPU_CMDS || !r->nr_bos || r->nr_bos>GPU_BOS ||
        r->queueid>queues || !r->queueid || r->in_syncobjs || r->out_syncobjs ||
        r->nr_in_syncobjs || r->nr_out_syncobjs || r->pad ||
        (r->flags & ~(0x10u|0x80000000u))) return kIOReturnBadArgument;
    msm_gem_submit_bo *bos=IONew(msm_gem_submit_bo,r->nr_bos);
    msm_gem_submit_cmd *cmds=IONew(msm_gem_submit_cmd,r->nr_cmds);
    IOReturn result=kIOReturnBadArgument;
    if(!bos || !cmds) {result=kIOReturnNoMemory;goto out;}
    if(copyin(r->bos,bos,r->nr_bos*sizeof(*bos)) || copyin(r->cmds,cmds,r->nr_cmds*sizeof(*cmds))) {
        result=kIOReturnVMError;goto out;
    }
    {
        uint64_t addresses[GPU_CMDS];uint32_t words[GPU_CMDS],count=0;
        for(unsigned n=0;n<r->nr_bos;n++)
            if(!buffer(bos[n].handle) || !(bos[n].flags&3u) || (bos[n].flags&~15u)) goto out;
        for(unsigned n=0;n<r->nr_cmds;n++) {
            const msm_gem_submit_cmd *c=&cmds[n];
            if(c->submit_idx>=r->nr_bos)goto out;
            PolarisBO *b=buffer(bos[c->submit_idx].handle);
            /* relocs is unused/unspecified when nr_relocs==0 (Mesa25.0.7
             * msm_ringbuffer_sp leaves that field uninitialized). */
            if(!b || c->type!=1 || c->nr_relocs || c->pad || !c->size ||
                ((c->submit_offset|c->size)&3) || c->submit_offset>b->size || c->size>b->size-c->submit_offset ||
                c->size/4>0xfffff) goto out;
            addresses[count]=b->address+c->submit_offset;words[count++]=c->size/4;
        }
        /* Kernel map every referenced BO before release; keep cached CPU and
         * SMMU attributes identical. All CPU aliases are cleaned before DMA,
         * invalidated after the observed GPU flush/fence/idle/halt. */
        for(unsigned n=0;n<r->nr_bos;n++) {
            PolarisBO *b=buffer(bos[n].handle);
            if(!b->map)b->map=b->memory->createMappingInTask(kernel_task,0,kIOMapAnywhere|kIOMapDefaultCache,0,b->size);
            if(!b->map) {result=kIOReturnNoMemory;goto out;}
            polaris_gpu_cache((void*)b->map->getVirtualAddress(),b->size);
        }
        for(unsigned n=0;n<r->nr_bos;n++) {
            PolarisBO *b=buffer(bos[n].handle);
            if(b->surface)__atomic_store_n(&b->surface->polarisGPUBusy,1,__ATOMIC_RELEASE);
        }
        if(!polaris_gpu_submit(addresses,words,count,&r->fence)) {poison();result=kIOReturnTimeout;goto out;}
        lastFence=r->fence;
        for(unsigned n=0;n<r->nr_bos;n++) {
            PolarisBO *b=buffer(bos[n].handle);
            polaris_gpu_cache((void*)b->map->getVirtualAddress(),b->size);
        }
        for(unsigned n=0;n<r->nr_bos;n++) {
            PolarisBO *b=buffer(bos[n].handle);
            if(b->surface)__atomic_store_n(&b->surface->polarisGPUBusy,0,__ATOMIC_RELEASE);
        }
        __atomic_fetch_add(&gpuSubmissions,1,__ATOMIC_RELEASE);
        if(gpuSubmissions<=4 || !(gpuSubmissions%256))
            IOLog("POLARIS GPU: completed submission %u, IBs=%u BOs=%u surfaces=%u; GPU fence+idle+halt\n",
                r->fence,count,r->nr_bos,gpuSurfaces);
        result=kIOReturnSuccess;
    }
out:
    if(bos)IODelete(bos,msm_gem_submit_bo,r->nr_bos);
    if(cmds)IODelete(cmds,msm_gem_submit_cmd,r->nr_cmds);
    return result;
}
IOReturn PolarisGPUUserClient::clientMemoryForType(UInt32 type,IOOptionBits *options,IOMemoryDescriptor **memory)
{
    if(current_task()!=ownerTask || !polaris_gpu_caller_allowed())return kIOReturnNotPrivileged;
    IOLockLock(gpuLock);
    PolarisBO *b=closed?NULL:buffer(type);
    IOReturn result=kIOReturnNotFound;
    if(b && polaris_gpu_ready()) {*options=kIOMapAnywhere|kIOMapDefaultCache;b->memory->retain();*memory=b->memory;result=0;}
    IOLockUnlock(gpuLock);return result;
}
IOReturn PolarisGPUUserClient::externalMethod(uint32_t selector,IOExternalMethodArguments *a,
    IOExternalMethodDispatch *,OSObject *,void *)
{
    if(current_task()!=ownerTask || !polaris_gpu_caller_allowed())return kIOReturnNotPrivileged;
    union {msm_param param;msm_gem_new make;msm_gem_info info;msm_gem_cpu_prep prep;
        msm_gem_submit submit;msm_wait_fence wait;msm_gem_madvise madvise;
        msm_submitqueue queue;msm_submitqueue_query query;drm_gem_close close;redwood_surface surface;
        struct {uint32_t stage,error;} report;
        struct {uint32_t stage,error,methods;} loader;} r;
    size_t size=0;
    switch(selector) {
        case 0x40:case 0x41:size=sizeof(r.param);break;
        case 0x42:size=sizeof(r.make);break;case 0x43:size=sizeof(r.info);break;
        case 0x44:size=sizeof(r.prep);break;case 0x45:case 0x4b:size=4;break;
        case 0x46:size=sizeof(r.submit);break;case 0x47:size=sizeof(r.wait);break;
        case 0x48:size=sizeof(r.madvise);break;case 0x4a:size=sizeof(r.queue);break;
        case 0x4c:size=sizeof(r.query);break;case 0x09:size=sizeof(r.close);break;
        case 0x7e:size=sizeof(r.surface);break;default:return kIOReturnUnsupported;
        case 0x7c:size=sizeof(r.report);break;
        case 0x7b:size=sizeof(r.loader);break;
    }
    if(!a || !a->structureInput || a->structureInputDescriptor || a->structureOutputDescriptor ||
        a->scalarInputCount || a->scalarOutputCount || a->structureInputSize!=size ||
        !a->structureOutput || a->structureOutputSize<size) return kIOReturnBadArgument;
    bzero(&r,sizeof(r));memcpy(&r,a->structureInput,size);
    IOLockLock(gpuLock);
    IOReturn result=kIOReturnBadArgument;
    if(closed || (selector!=0x7c && selector!=0x7b && !polaris_gpu_ready())) {result=kIOReturnNotReady;goto done;}
    switch(selector) {
        case 0x40:
            if(r.param.pipe!=0x10 || r.param.len || r.param.pad)break;
            switch(r.param.param) {
                case 1:r.param.value=630;break;case 2:r.param.value=0x100000;break;
                case 3:r.param.value=0x06030001;break;case 4:r.param.value=257000000;break;
                case 5:if(!polaris_gpu_timestamp(&r.param.value))goto done;break;case 6:r.param.value=0;break;
                case 7:r.param.value=1;break;case 9:r.param.value=0;break;
                case 0x10:r.param.value=15;break;default:goto done;
            }
            result=0;break;
        case 0x41:result=0;break; /* diagnostic process name; no hardware change */
        case 0x42: {
            if(!r.make.size || r.make.size>GPU_MAX_BO || (r.make.flags&~0x000f0003u))break;
            if((r.make.flags&0x000f0000u)!=0x00010000u &&
               (r.make.flags&0x000f0000u)!=0x00020000u &&
               (r.make.flags&0x000f0000u)!=0x00040000u) {result=kIOReturnUnsupported;break;}
            uint64_t length=(r.make.size+PAGE_MASK)&~(uint64_t)PAGE_MASK;
            IOBufferMemoryDescriptor *m=IOBufferMemoryDescriptor::inTaskWithOptions(kernel_task,
                kIODirectionInOut|kIOMemoryKernelUserShared,(vm_size_t)length,PAGE_SIZE);
            if(!m){result=kIOReturnNoMemory;break;}
            bzero(m->getBytesNoCopy(),length);
            result=make(m,NULL,length,r.make.flags,&r.make.handle);m->release();break;
        }
        case 0x43: {
            PolarisBO *b=buffer(r.info.handle);if(!b || r.info.pad)break;
            if(r.info.info==0)r.info.value=(uint64_t)r.info.handle<<PAGE_SHIFT;
            else if(r.info.info==1)r.info.value=b->address;
            else if(r.info.info==2) {result=0;break;} /* SET_NAME */
            else if(r.info.info==5)r.info.value=b->flags;
            else break;
            result=0;break;
        }
        case 0x44:result=buffer(r.prep.handle)?0:kIOReturnNotFound;break;
        case 0x45:result=0;break;
        case 0x46:result=submit(&r.submit);break;
        case 0x47:
            if(r.wait.queueid && r.wait.queueid<=queues && !(r.wait.flags&~1u) &&
                r.wait.fence && lastFence && (int32_t)(lastFence-r.wait.fence)>=0)result=0;
            else result=kIOReturnTimeout;break;
        case 0x48:if(buffer(r.madvise.handle)){r.madvise.retained=1;result=0;}break;
        case 0x4a:if(!r.queue.flags && !r.queue.prio && queues<1024){r.queue.id=++queues;result=0;}break;
        case 0x4b:result=0;break;
        case 0x4c: {
            if(!r.query.id || r.query.id>queues || r.query.param || r.query.pad ||
                r.query.len!=sizeof(uint64_t) || !r.query.data)break;
            uint64_t faults=0; /* ready synchronous backend has no unreported reset */
            result=copyout(&faults,r.query.data,sizeof(faults))?kIOReturnVMError:kIOReturnSuccess;
            break;
        }
        case 0x09:if(!r.close.pad)result=drop(r.close.handle)?0:kIOReturnNotFound;break;
        case 0x7e:result=surface(&r.surface);break;
        case 0x7b:
            /* Only the real server may report loading. This is diagnostic
             * evidence, never GPU readiness or a successful submission. */
            if(polaris_gpu_loader_report(polaris_gpu_caller_kind(),r.loader.stage,r.loader.error,r.loader.methods))result=0;
            break;
        case 0x7c:
            if(r.report.stage>6 || r.report.error>255 ||
                (r.report.stage==6 && !r.report.error && (!gpuSubmissions || !gpuSurfaces)))break;
            __atomic_store_n(&gpuAppStage,r.report.stage,__ATOMIC_RELEASE);
            __atomic_store_n(&gpuAppError,r.report.error,__ATOMIC_RELEASE);
            IOLog("POLARIS GL: acceptance stage%u error%u, completed=%u surfaces=%u\n",
                r.report.stage,r.report.error,gpuSubmissions,gpuSurfaces);
            result=0;break;
    }
done:
    if(result==0){memcpy(a->structureOutput,&r,size);a->structureOutputSize=size;}
    IOLockUnlock(gpuLock);return result;
}
IOReturn PolarisGPUUserClient::clientClose()
{
    IOLockLock(gpuLock);
    if(!closed) {
        closed=true;
        if(!polaris_gpu_quiescent())poison();
        for(unsigned n=0;!quarantined && n<GPU_BUFFERS;n++)if(buffers[n].memory)drop(n+1);
        if(!quarantined){gpuOpened=false;__atomic_store_n(&gpuOpenStatus,0,__ATOMIC_RELEASE);}
    }
    IOLockUnlock(gpuLock);terminate();return 0;
}
void PolarisGPUUserClient::free()
{
    /* Normal close has drained and removed every GPU mapping. A quarantined
     * client has a permanent retain and must never arrive here. */
    if(buffers)IODelete(buffers,PolarisBO,GPU_BUFFERS);
    super::free();
}
extern "C" void PolarisGPUStart(void)
{
    if(!polaris_gpu_ready() || gpuLock)return;
    gpuLock=IOLockAlloc();if(!gpuLock)return;
    PolarisGPU *s=new PolarisGPU;
    if(s && s->init() && s->attach(IOService::getPlatform()) && s->start(IOService::getPlatform())) {
        s->setName("PolarisGPU");s->setProperty(kIOUserClientClassKey,"PolarisGPUUserClient");
        s->setProperty("A630NativeProof",true);s->setProperty("ExclusiveVerifiedWriter",true);
        s->registerService();
        __atomic_store_n(&gpuPublished,1,__ATOMIC_RELEASE);
        IOLog("POLARIS GPU: resident MSM1.7 service available; native proof passed, desktop backend still requires Mesa/EAGL\n");
    }else if(s)s->release();
}
#endif
