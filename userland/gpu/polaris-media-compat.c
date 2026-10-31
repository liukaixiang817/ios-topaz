/* Exact20F66 media-server compatibility derived from pinned HackiOS
 * inject_media.c (MIT, LICENSE.hackios). This phone has no capture driver:
 * skip only the verified portrait-filter GPU prewarm. Leave VideoToolbox's
 * genuine software HEVC decoder, callbacks and errors intact. No fake codec,
 * camera/audio device, Metal device, hardware register or file replacement.
 */
#include <CommonCrypto/CommonDigest.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <objc/runtime.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../tools/polaris-media-compat.h"
extern const void *_dyld_get_shared_cache_range(size_t *);

static int attempted;
static void skip_portrait_prewarm(id self,SEL command,unsigned version,BOOL styles)
{
    (void)self;(void)command;
    static unsigned reports;
    if(reports++<4)
        fprintf(stderr,"POLARIS MEDIA: portrait-only GPU prewarm skipped version=%u styles=%d; software decoder unchanged\n",version,styles);
}

static int within(uintptr_t p,size_t n,uintptr_t base,size_t length)
{return n<=length && p>=base && p-base<=length-n;}

static int exact_prewarm(Method method)
{
    if(!method || method_getNumberOfArguments(method)!=4)return -1;
    char *ret=method_copyReturnType(method),*a=method_copyArgumentType(method,0),
        *b=method_copyArgumentType(method,1),*c=method_copyArgumentType(method,2),
        *d=method_copyArgumentType(method,3);
    int types=ret && !strcmp(ret,"v") && a && !strcmp(a,"@") && b && !strcmp(b,":") &&
        c && !strcmp(c,"I") && d && !strcmp(d,"B");
    free(ret);free(a);free(b);free(c);free(d);
    if(!types)return -2;
    size_t length=0;uintptr_t base=(uintptr_t)_dyld_get_shared_cache_range(&length);
    if(base<UINT64_C(0x180000000) || length<PMC_METHOD_BYTES)return -3;
    uintptr_t slide=base-UINT64_C(0x180000000);
    if(PMC_TEXT>UINTPTR_MAX-slide || PMC_METHOD>UINTPTR_MAX-slide)return -4;
    const struct mach_header_64 *header=NULL;
    uint32_t count=_dyld_image_count();if(count>2048)return -5;
    for(uint32_t i=0;i<count;i++) {
        const char *name=_dyld_get_image_name(i);
        if(name && !strcmp(name,"/System/Library/PrivateFrameworks/CMCapture.framework/CMCapture")) {
            if(header)return -6;
            header=(const void *)_dyld_get_image_header(i);
        }
    }
    if((uintptr_t)header!=PMC_TEXT+slide || !within((uintptr_t)header,sizeof(*header),base,length) ||
       header->magic!=MH_MAGIC_64 || header->cputype!=CPU_TYPE_ARM64 || header->ncmds>128 ||
       header->sizeofcmds>65536 || !within((uintptr_t)header,sizeof(*header)+header->sizeofcmds,base,length))return -7;
    const uint8_t uuid[16]=PMC_UUID;
    const uint8_t *p=(const uint8_t *)(header+1),*end=p+header->sizeofcmds;
    unsigned seen=0;
    for(uint32_t i=0;i<header->ncmds;i++) {
        if((size_t)(end-p)<sizeof(struct load_command))return -8;
        const struct load_command *lc=(const void *)p;
        if(lc->cmdsize<sizeof(*lc) || lc->cmdsize>(size_t)(end-p))return -8;
        if(lc->cmd==LC_UUID && (lc->cmdsize!=24 || seen++ || memcmp(p+8,uuid,16)))return -9;
        p+=lc->cmdsize;
    }
    uintptr_t imp=(uintptr_t)method_getImplementation(method);
    if(seen!=1 || p!=end || imp!=PMC_METHOD+slide || !within(imp,PMC_METHOD_BYTES,base,length))return -10;
    const uint8_t wanted[32]=PMC_SHA;uint8_t actual[32];
    return CC_SHA256((const void *)imp,PMC_METHOD_BYTES,actual) && !memcmp(wanted,actual,32)?1:-11;
}

static void media_image(const struct mach_header *header,intptr_t slide)
{
    (void)header;(void)slide;
    if(attempted)return;
    Class cls=objc_getClass("BWCoreImageFilterRenderer");if(!cls)return;
    attempted=1;
    Method method=class_getClassMethod(cls,sel_registerName("prewarmPortraitFilterVersion:semanticStyleFilters:"));
    int identity=exact_prewarm(method);
    if(identity!=1) {
        fprintf(stderr,"POLARIS MEDIA: exact20F66 portrait identity status=%d; unchanged\n",identity);return;
    }
    IMP original=method_getImplementation(method);
    IMP previous=method_setImplementation(method,(IMP)skip_portrait_prewarm);
    if(previous!=original) {
        method_setImplementation(method,previous);
        fprintf(stderr,"POLARIS MEDIA: concurrent method change; restored, refused\n");return;
    }
    fprintf(stderr,"POLARIS MEDIA: exact20F66 portrait-only prewarm compatibility installed; HEVC service unchanged\n");
}

int polaris_media_compat_entry(void)
{
    char path[1024];uint32_t bytes=sizeof(path);
    const char *wanted=getenv("POLARIS_MEDIA_COMPAT");
    if(!wanted || strcmp(wanted,"1") || _NSGetExecutablePath(path,&bytes) ||
       strcmp(path,"/usr/sbin/mediaserverd"))return 0;
    fprintf(stderr,"POLARIS MEDIA: scoped20F66 constructor; genuine media server, no decoder emulation\n");
    _dyld_register_func_for_add_image(media_image);
    return 1;
}
