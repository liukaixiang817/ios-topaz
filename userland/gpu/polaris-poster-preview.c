/* A real UIKit/CoreGraphics snapshot for one exact PosterBoard preview method
 * when its requested Metal queue is unavailable. No Metal device emulation,
 * GPU registry/hardware changes, empty placeholder, or native display writes.
 * UIKit is resolved only in PosterBoard; backboardd gains no UIKit dependency.
 */
#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CGGeometry.h>
#include <CoreGraphics/CGContext.h>
#include <CommonCrypto/CommonDigest.h>
#include <dispatch/dispatch.h>
#include <objc/runtime.h>
#include <objc/message.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../tools/polaris-poster-preview.h"
extern const void *_dyld_get_shared_cache_range(size_t *);

static id (*original_preview)(id,SEL,id);
static id (*metal_device)(void);
static void (*begin_image)(CGSize,BOOL,CGFloat);
static CGContextRef (*image_context)(void);
static id (*get_image)(void);
static void (*end_image)(void);
static void (*translate_context)(CGContextRef,CGFloat,CGFloat);
static size_t (*image_width)(const void *),(*image_height)(const void *);
static unsigned preview_calls;

static id snapshot_preview(id self,SEL cmd,id view)
{
    /* Retain the genuine Apple path if a real Metal queue becomes available. */
    id device=metal_device();
    int device_present=device!=NULL;
    id queue=((id(*)(id,SEL))objc_msgSend)(device,sel_registerName("newCommandQueue"));
    ((void(*)(id,SEL))objc_msgSend)(device,sel_registerName("release"));
    if(queue) {
        ((void(*)(id,SEL))objc_msgSend)(queue,sel_registerName("release"));
        return original_preview(self,cmd,view);
    }
    id layer=((id(*)(id,SEL))objc_msgSend)(view,sel_registerName("layer"));
    if(!view || !layer) {
        fprintf(stderr,"POLARIS POSTER PREVIEW: missing real view/layer; no placeholder\n");return NULL;
    }
    CGRect bounds=((CGRect(*)(id,SEL))objc_msgSend)(layer,sel_registerName("bounds"));
    CGFloat scale=((CGFloat(*)(id,SEL))objc_msgSend)(layer,sel_registerName("contentsScale"));
    uint32_t pw=0,ph=0;
    if(!ppp_dimensions(bounds.size.width,bounds.size.height,scale,&pw,&ph) ||
       !isfinite(bounds.origin.x) || !isfinite(bounds.origin.y) ||
       fabs(bounds.origin.x)>16384 || fabs(bounds.origin.y)>16384) {
        fprintf(stderr,"POLARIS POSTER PREVIEW: invalid real bounds=(%g,%g %gx%g) scale=%g; no placeholder\n",
            (double)bounds.origin.x,(double)bounds.origin.y,(double)bounds.size.width,
            (double)bounds.size.height,(double)scale);return NULL;
    }
    /* Match Apple's truncated pixel dimensions and UIImage scale1 return.
     * UIKit supplies the actual bitmap context and CALayer renders this real
     * view's contents. All image/context ownership stays inside this task. */
    begin_image((CGSize){pw/scale,ph/scale},NO,scale);
    CGContextRef context=image_context();
    id result=NULL;
    if(context) {
        translate_context(context,-bounds.origin.x,-bounds.origin.y);
        ((void(*)(id,SEL,CGContextRef))objc_msgSend)(layer,sel_registerName("renderInContext:"),context);
        id image=get_image();
        const void *cg=((const void *(*)(id,SEL))objc_msgSend)(image,sel_registerName("CGImage"));
        if(cg && image_width(cg)==pw && image_height(cg)==ph)
            result=((id(*)(id,SEL,const void *))objc_msgSend)((id)objc_getClass("UIImage"),
                sel_registerName("imageWithCGImage:"),cg);
    }
    end_image();
    if(preview_calls++<16 || !result)
        fprintf(stderr,"POLARIS POSTER PREVIEW: real layer %ux%u scale=%g UIKit bitmap=%s; Metal device=%d queue absent\n",
            pw,ph,(double)scale,result?"created":"FAILED",device_present);
    return result;
}

static int span(uintptr_t p,size_t n,uintptr_t base,size_t bytes)
{
    return n<=bytes && p>=base && p-base<=bytes-n;
}

static int exact_method(Method method)
{
    if(!method)return -1;
    if(method_getNumberOfArguments(method)!=3)return -2;
    char *ret=method_copyReturnType(method),*a=method_copyArgumentType(method,0),
         *b=method_copyArgumentType(method,1),*c=method_copyArgumentType(method,2);
    int types=ret && ret[0]=='@' && a && a[0]=='@' && b && !strcmp(b,":") && c && c[0]=='@';
    free(ret);free(a);free(b);free(c);
    if(!types)return -3;
    size_t bytes=0;uintptr_t base=(uintptr_t)_dyld_get_shared_cache_range(&bytes);
    if(base<UINT64_C(0x180000000) || bytes<PPP_METHOD_BYTES)return -4;
    uintptr_t offset=base-UINT64_C(0x180000000);
    if(PPP_TEXT>UINTPTR_MAX-offset || PPP_METHOD>UINTPTR_MAX-offset)return -5;
    const struct mach_header_64 *header=NULL;
    uint32_t count=_dyld_image_count();if(count>2048)return -6;
    for(uint32_t i=0;i<count;i++) {
        const char *name=_dyld_get_image_name(i);
        if(name && !strcmp(name,"/System/Library/PrivateFrameworks/PosterBoard.framework/PosterBoard")) {
            if(header)return -7;
            header=(const void *)_dyld_get_image_header(i);
        }
    }
    if((uintptr_t)header!=PPP_TEXT+offset || !span((uintptr_t)header,sizeof(*header),base,bytes) ||
       header->magic!=MH_MAGIC_64 || header->cputype!=CPU_TYPE_ARM64 ||
       header->ncmds>128 || header->sizeofcmds>65536 ||
       !span((uintptr_t)header,sizeof(*header)+header->sizeofcmds,base,bytes))return -8;
    const uint8_t uuid[16]=PPP_UUID;
    const uint8_t *p=(const uint8_t *)(header+1),*end=p+header->sizeofcmds;
    unsigned seen=0;
    for(uint32_t i=0;i<header->ncmds;i++) {
        if((size_t)(end-p)<sizeof(struct load_command))return -9;
        const struct load_command *lc=(const void *)p;
        if(lc->cmdsize<sizeof(*lc) || lc->cmdsize>(size_t)(end-p))return -9;
        if(lc->cmd==LC_UUID) {
            if(lc->cmdsize!=24 || seen++ || memcmp(p+8,uuid,16))return -10;
        }
        p+=lc->cmdsize;
    }
    uintptr_t imp=(uintptr_t)method_getImplementation(method);
    if(seen!=1 || p!=end || imp!=PPP_METHOD+offset || !span(imp,PPP_METHOD_BYTES,base,bytes))return -11;
    const uint8_t expected[32]=PPP_SHA;uint8_t actual[32];
    return CC_SHA256((const void *)imp,PPP_METHOD_BYTES,actual) && !memcmp(actual,expected,32)?1:-12;
}

static void install_preview(void *unused)
{
    (void)unused;
    Class cls=objc_getClass("PBFHomeScreenPreviewImageBuilder");
    Method method=cls?class_getInstanceMethod(cls,sel_registerName("_imageForView:")):NULL;
    int identity=exact_method(method);
    if(identity!=1) {
        fprintf(stderr,"POLARIS POSTER PREVIEW: exact20F66 identity status=%d; unchanged\n",identity);return;
    }
    metal_device=(void *)dlsym(RTLD_DEFAULT,"MTLCreateSystemDefaultDevice");
    begin_image=(void *)dlsym(RTLD_DEFAULT,"UIGraphicsBeginImageContextWithOptions");
    image_context=(void *)dlsym(RTLD_DEFAULT,"UIGraphicsGetCurrentContext");
    get_image=(void *)dlsym(RTLD_DEFAULT,"UIGraphicsGetImageFromCurrentImageContext");
    end_image=(void *)dlsym(RTLD_DEFAULT,"UIGraphicsEndImageContext");
    translate_context=(void *)dlsym(RTLD_DEFAULT,"CGContextTranslateCTM");
    image_width=(void *)dlsym(RTLD_DEFAULT,"CGImageGetWidth");
    image_height=(void *)dlsym(RTLD_DEFAULT,"CGImageGetHeight");
    if(!metal_device || !begin_image || !image_context || !get_image || !end_image ||
       !translate_context || !image_width || !image_height || !objc_getClass("UIImage")) {
        unsigned mask=(metal_device?1:0)|(begin_image?2:0)|(image_context?4:0)|(get_image?8:0)|
            (end_image?16:0)|(translate_context?32:0)|(image_width?64:0)|(image_height?128:0)|
            (objc_getClass("UIImage")?256:0);
        fprintf(stderr,"POLARIS POSTER PREVIEW: UIKit bitmap API mask=%x/1ff; unchanged\n",mask);return;
    }
    original_preview=(void *)method_getImplementation(method);
    IMP previous=method_setImplementation(method,(IMP)snapshot_preview);
    if(previous!=(IMP)original_preview) {
        method_setImplementation(method,previous);original_preview=NULL;
        fprintf(stderr,"POLARIS POSTER PREVIEW: concurrent method change; restored, refused\n");return;
    }
    fprintf(stderr,"POLARIS POSTER PREVIEW: exact20F66 method installed; real UIKit fallback only when Metal queue absent\n");
}

int polaris_poster_preview_entry(void)
{
    char path[1024];uint32_t bytes=sizeof(path);
    const char *wanted=getenv("POLARIS_POSTER_PREVIEW");
    if(!wanted || strcmp(wanted,"1") || _NSGetExecutablePath(path,&bytes) ||
       strcmp(path,"/Applications/PosterBoard.app/PosterBoard"))return 0;
    /* The original failure is on a main-queue preview block. Queue this once
     * from the constructor before UIApplicationMain schedules that work. */
    fprintf(stderr,"POLARIS POSTER PREVIEW: scoped20F66 constructor; main-queue identity check scheduled\n");
    dispatch_async_f(dispatch_get_main_queue(),NULL,install_preview);
    return 1;
}
