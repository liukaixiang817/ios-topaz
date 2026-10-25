/* Install only hash-checked, fixed-path files into the verified volatile
 * HFS RAM COW root before PID1. No raw disk operation or persistent writer.
 * Until every new file is staged, the Apple launchd/backboardd stay intact.
 * The small PID1 helper later activates the wrapper with POSIX rename and
 * immediately execs Apple's /sbin/launchd. Failure keeps CPU bootstrap.
 */
#if defined(POLARIS_RAM_ONLY)
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/vnode.h>
#include <sys/vnode_internal.h>
#include <sys/fcntl.h>
#include <sys/proc.h>
#include <kern/thread.h>
#include <kern/clock.h>
#include <kern/sched_prim.h>
#include <sys/uio.h>
#include <sys/mount_internal.h>
#include <pexpert/pexpert.h>
#include <pexpert/device_tree.h>
#include <pexpert/arm64/boot.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha2.h>
#include <arm/machine_routines.h>
#include "polaris_gpu_bundle.h"
#include "polaris_gpu.h"

extern bool polaris_ram_overlay_allowed(void);
bool polaris_gpu_overlay_stage(void);
bool polaris_gpu_overlay_ready(void);
bool polaris_gpu_caller_allowed(void);
uint32_t polaris_gpu_caller_kind(void);
static uint32_t pgpu_started,pgpu_ready;
static int pgpu_wait;
static const char *const pgpu_paths[PGPU_FILES]={
    "/usr/lib/libPolarisMesa.dylib", "/usr/lib/libPolarisGL.dylib",
    "/usr/lib/libPolarisInject.dylib", "/usr/libexec/polaris-bbd-wrapper",
    "/usr/libexec/polaris-gl-test", "/usr/libexec/polaris-init"
};
static bool pgpu_digest(const void *data,size_t bytes,const uint8_t *expected)
{
    /* Same built-in SHA256 provider as the proven firmware validator.
     * The one-shot ccdigest() wrapper is not linked in this kernel. */
    uint8_t hash[32];const struct ccdigest_info *di=&ccsha256_ltc_di;
    ccdigest_di_decl(di,context);ccdigest_init(di,context);
    ccdigest_update(di,context,bytes,data);ccdigest_final(di,context,hash);
    ccdigest_di_clear(di,context);
    return !memcmp(hash,expected,32);
}
bool polaris_gpu_overlay_ready(void)
{return __atomic_load_n(&pgpu_ready,__ATOMIC_ACQUIRE)!=0;}
uint32_t polaris_gpu_caller_kind(void)
{
    /* backboardd runs as mobile on20H392. UID/admin checks alone either
     * refuse it or admit every app with that UID. Bind to the actual
     * executable vnode of one of our TWO fixed, root-owned, validated
     * images instead, and recheck on each method/mapping after exec. */
    if(!polaris_gpu_overlay_ready() || !polaris_ram_overlay_allowed())return false;
    vnode_t image=proc_getexecutablevnode(current_proc());
    if(!image)return false;
    struct vnode_attr attr;VATTR_INIT(&attr);VATTR_WANTED(&attr,va_uid);VATTR_WANTED(&attr,va_mode);
    bool ok=vnode_isreg(image) && (vfs_flags(vnode_mount(image))&MNT_ROOTFS) &&
        !vnode_getattr(image,&attr,vfs_context_kernel()) &&
        VATTR_IS_SUPPORTED(&attr,va_uid) && VATTR_IS_SUPPORTED(&attr,va_mode) &&
        attr.va_uid==0 && !(attr.va_mode&022);
    const char *const paths[]={"/usr/libexec/polaris-gl-test","/usr/libexec/polaris-bbd-real"};
    uint32_t found=0;
    for(unsigned n=0;ok && n<2;n++) {
        vnode_t expected=NULLVP;
        if(!vnode_lookup(paths[n],VNODE_LOOKUP_NOFOLLOW|VNODE_LOOKUP_NOCROSSMOUNT,&expected,vfs_context_kernel())) {
            found=expected==image?n+1:0;vnode_put(expected);if(found)break;
        }
    }
    vnode_put(image);return ok?found:0;
}
bool polaris_gpu_caller_allowed(void) {return polaris_gpu_caller_kind()!=0;}
static int pgpu_write(unsigned kind,const struct pgpu_file *file)
{
    /* Recheck at every VFS write; the block layer still refuses UFS WRITE,
     * UNMAP and SYNC CDBs. O_EXCL prevents touching any existing file. */
    if(kind>=PGPU_FILES || !polaris_ram_overlay_allowed())return EPERM;
    vfs_context_t ctx=vfs_context_kernel();vnode_t vp=NULLVP;
    int flags=FWRITE|O_CREAT|O_EXCL|O_NOFOLLOW;
    int error=vnode_open(pgpu_paths[kind],flags,kind<3?0644:0755,0,&vp,ctx);
    if(error)return error;
    if(!vnode_isreg(vp) || !(vfs_flags(vnode_mount(vp))&MNT_ROOTFS))error=EPERM;
    int resid=0;
    if(!error) error=vn_rdwr(UIO_WRITE,vp,(caddr_t)file->data,(int)file->bytes,0,UIO_SYSSPACE,
        IO_NODELOCKED,vfs_context_ucred(ctx),&resid,vfs_context_proc(ctx));
    if(!error && resid)error=EIO;
    off_t length=0;
    if(!error) error=vnode_size(vp,&length,ctx);
    if(!error && length!=file->bytes)error=EIO;
    int closed=vnode_close(vp,FWRITE,ctx);
    return error?error:closed;
}
bool polaris_gpu_overlay_stage(void)
{
    unsigned enable=0;PE_parse_boot_argn("polarisgl",&enable,sizeof(enable));
    if(enable!=1 || !polaris_ram_overlay_allowed())return false;
    if(__atomic_exchange_n(&pgpu_started,1,__ATOMIC_ACQ_REL))return polaris_gpu_overlay_ready();
    /* On CPU1 let the proven native bootstrap finish before allocating and
     * writing the overlay. Do not consume its10s hardware deadline with VFS
     * work. A failed native proof goes straight to the original CPU boot. */
    for(unsigned n=0;n<120 && !polaris_gpu_ready() && polaris_gpu_boot_pending();n++) {
        uint64_t deadline;clock_interval_to_deadline(100,NSEC_PER_MSEC,&deadline);
        (void)assert_wait_deadline(&pgpu_wait,THREAD_UNINT,deadline);thread_block(THREAD_CONTINUE_NULL);
    }
    if(!polaris_gpu_ready()){printf("POLARIS GL RAM overlay: native proof not ready; original CPU bootstrap\n");return false;}
    DTEntry node;const void *reg,*sha,*version;unsigned rn,sn,vn;
    if(SecureDTLookupEntry(NULL,"/polaris-gpu-userland",&node)!=kSuccess ||
        SecureDTGetProperty(node,"reg",&reg,&rn)!=kSuccess || rn!=16 ||
        SecureDTGetProperty(node,"sha256",&sha,&sn)!=kSuccess || sn!=32 ||
        SecureDTGetProperty(node,"ios-build",&version,&vn)!=kSuccess || vn!=7 || memcmp(version,"20H392",7))return false;
    uint64_t physical=pgpu_u64(reg),bytes=pgpu_u64((const uint8_t*)reg+8);
    const boot_args *args=PE_state.bootArgs;
    /* The blob must be a reserved, statically mapped kernel-data span, not
     * MMIO or arbitrary RAM named by an ADT property. No ml_io_map on DRAM. */
    if(!args || (physical&0x3fff) || bytes<PGPU_HEADER || bytes>PGPU_MAX ||
        physical<args->physBase || physical>=args->topOfKernelData ||
        bytes>args->topOfKernelData-physical || physical-args->physBase>args->memSize ||
        bytes>args->memSize-(physical-args->physBase))return false;
    const void *data=(const void*)ml_static_ptovirt((vm_offset_t)physical);
    struct pgpu_file files[PGPU_FILES];
    if(!pgpu_digest(data,(size_t)bytes,sha) || !pgpu_parse(data,(size_t)bytes,files,pgpu_digest))return false;
    for(unsigned n=0;n<PGPU_FILES;n++) {
        int error=pgpu_write(n,&files[n]);
        if(error) {printf("POLARIS GL RAM overlay: stage%u failed %d; Apple bootstrap unchanged\n",n,error);return false;}
    }
    __atomic_store_n(&pgpu_ready,1,__ATOMIC_RELEASE);
    printf("POLARIS GL RAM overlay: six verified files staged, %llu bytes; UFS base READ ONLY\n",bytes);
    return true;
}
#endif
