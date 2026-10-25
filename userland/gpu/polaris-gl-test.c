/* Actual iOS/A630 acceptance, run in its own task before the window server.
 * Reject a software renderer. Compile/link GLSL, draw a full64x64 surface,
 * wait, then compare ALL4096 pixels through the CPU's IOSurface mapping.
 */
#include <CoreFoundation/CoreFoundation.h>
#include <IOSurface/IOSurfaceRef.h>
#include <IOKit/IOKitLib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <mach/mach.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/ucontext.h>
#include <mach-o/loader.h>
#include <mach-o/dyld.h>
#include <objc/runtime.h>
#include <objc/message.h>
#include "../../tools/polaris-gl-status.h"
#include "../../tools/polaris-gpu-abi.h"
#include <OpenGLES/ES3/gl.h>
#include <OpenGLES/ES3/glext.h>
typedef void *OSMesaContext;
extern OSMesaContext OSMesaCreateContextAttribs(const int *,OSMesaContext);
extern int OSMesaMakeCurrent(OSMesaContext,void *,unsigned,int,int);
extern void OSMesaDestroyContext(OSMesaContext);
extern void (*OSMesaGetProcAddress(const char *))(void);
/* Private exports/signatures and selector6/7/27 wires verified on20H392. */
extern IOSurfaceRef IOSurfaceWrapClientImage(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t,void *);
extern IOSurfaceRef IOSurfaceWrapClientMemory(void *,size_t);
extern kern_return_t IOSurfaceGetBulkAttachments(IOSurfaceRef,void *,size_t *);
extern kern_return_t IOSurfaceSetBulkAttachments(IOSurfaceRef,const void *,size_t,uint32_t);
extern int __mac_syscall(const char *,int,void *);
extern const void *_dyld_get_shared_cache_range(size_t *);
static uint64_t test_started_ms;
static uint64_t test_milliseconds(void)
{
    struct timespec now={0};if(clock_gettime(CLOCK_MONOTONIC,&now))return 0;
    return (uint64_t)now.tv_sec*1000u+(uint64_t)now.tv_nsec/1000000u;
}
static void test_step(unsigned n)
{
    uint64_t ms=test_milliseconds()-test_started_ms;
    struct pgpu_test_notice notice={PGPU_TEST_STEP,n,(uint32_t)(ms>600000?600000:ms),0};
    (void)__mac_syscall("AMFI",0x5c,&notice);
}
static struct pgpu_image test_images[4]; /* each slot immutable before use */
static void test_image(unsigned slot,unsigned kind,void *symbol)
{
    Dl_info info;if(!dladdr(symbol,&info)||!info.dli_fbase)return;
    const struct mach_header_64 *h=info.dli_fbase;
    if(h->magic!=MH_MAGIC_64 || h->ncmds>4096 || h->sizeofcmds>1048576)return;
    const char *p=(const char*)(h+1),*end=p+h->sizeofcmds;uint64_t lo=UINT64_MAX,hi=0;
    for(unsigned i=0;i<h->ncmds;i++) {
        if((size_t)(end-p)<sizeof(struct load_command))return;
        const struct load_command *lc=(const void*)p;
        if(lc->cmdsize<sizeof(*lc)||lc->cmdsize>(size_t)(end-p))return;
        if(lc->cmd==LC_SEGMENT_64 && lc->cmdsize>=sizeof(struct segment_command_64)) {
            const struct segment_command_64 *s=(const void*)p;
            if(s->initprot && s->vmsize && s->vmaddr<=UINT64_MAX-s->vmsize) {
                if(s->vmaddr<lo)lo=s->vmaddr;if(s->vmaddr+s->vmsize>hi)hi=s->vmaddr+s->vmsize;
            }
        }
        p+=lc->cmdsize;
    }
    if(hi>lo)test_images[slot]=(struct pgpu_image){(uintptr_t)h,hi-lo,kind};
}
static void test_fatal(int sig,siginfo_t *info,void *opaque)
{
    ucontext_t *context=opaque;
    struct pgpu_crash fault={.signal=(unsigned)sig,.code=info?(unsigned)info->si_code:0,
        .address=info?(uintptr_t)info->si_addr:0};
    if(context && context->uc_mcontext) {
        fault.pc=pgpu_pc(context->uc_mcontext->__ss.__pc,test_images,4,&fault.pc_image);
        fault.lr=pgpu_pc(context->uc_mcontext->__ss.__lr,test_images,4,&fault.lr_image);
    }
    (void)__mac_syscall("AMFI",0x5b,&fault);
    const char line[]="POLARIS GL: selftest fatal; first PC/LR saved\n";
    (void)write(STDERR_FILENO,line,sizeof(line)-1);(void)kill(getpid(),sig);
}
static void watch_test_faults(void)
{
    size_t bytes=0;const void *base=_dyld_get_shared_cache_range(&bytes);
    test_images[0]=(struct pgpu_image){(uintptr_t)base,bytes,1};
    test_image(1,2,(void*)watch_test_faults);test_image(2,4,(void*)OSMesaCreateContextAttribs);
    struct sigaction action={0};action.sa_sigaction=test_fatal;action.sa_flags=SA_SIGINFO|SA_RESETHAND;
    const int signals[]={SIGSEGV,SIGBUS,SIGABRT,SIGILL,SIGTRAP};
    for(unsigned i=0;i<sizeof(signals)/sizeof(signals[0]);i++)sigaction(signals[i],&action,NULL);
}
static io_connect_t connection;
static unsigned phase;
static void report(unsigned stage,unsigned error)
{
    phase=stage;
    uint32_t data[2]={stage,error};size_t bytes=sizeof(data);
    IOConnectCallStructMethod(connection,0x7c,data,sizeof(data),data,&bytes);
}
static int fail(unsigned error)
{report(phase,error);if(connection)IOServiceClose(connection);return (int)error;}
static GLuint shader(GLenum kind,const char *text)
{
    unsigned step=kind==GL_VERTEX_SHADER?22:26;
    test_step(step);GLuint id=glCreateShader(kind);GLint ok=0;
    test_step(step+1);glShaderSource(id,1,&text,NULL);
    test_step(step+2);glCompileShader(id);test_step(step+3);glGetShaderiv(id,GL_COMPILE_STATUS,&ok);
    if(!ok) {char log[1024]={0};glGetShaderInfoLog(id,sizeof(log),NULL,log);fprintf(stderr,"POLARIS GL shader: %s\n",log);return 0;}
    return id;
}
static void number(CFMutableDictionaryRef d,CFStringRef key,int value)
{
    CFNumberRef n=CFNumberCreate(NULL,kCFNumberIntType,&value);CFDictionarySetValue(d,key,n);CFRelease(n);
}
/* Exercise the exact shared-state getter that crashed the real desktop,
 * around the original task's memory, before admitting any EAGL trial.
 * Also check live aliasing, metadata, cached lookup and release lifetime. */
static int surface_contract(void)
{
    void *allocation=NULL;
    if(posix_memalign(&allocation,16384,32768))return 30;
    uint8_t *p=(uint8_t*)allocation;memset(p,0xa5,32768);
    IOSurfaceRef image=IOSurfaceWrapClientImage(13,8,0x42475241,64,500,p+16384);
    if(!image)return 31;
    uint8_t bulk[0x70]={0};size_t bytes=sizeof(bulk);
    if(IOSurfaceGetBulkAttachments(image,bulk,&bytes) || bytes!=sizeof(bulk) ||
        IOSurfaceGetWidth(image)!=13 || IOSurfaceGetHeight(image)!=8 ||
        IOSurfaceGetBytesPerRow(image)!=64 || IOSurfaceGetAllocSize(image)!=500)return 32;
    for(unsigned n=0;n<32;n++)bulk[n]=(uint8_t)(n+1);
    if(IOSurfaceSetBulkAttachments(image,bulk,sizeof(bulk),1))return 33;
    uint8_t readback[0x70]={0};bytes=sizeof(readback);
    if(IOSurfaceGetBulkAttachments(image,readback,&bytes) || memcmp(readback,bulk,32))return 34;
    p[16384+71]=0x6d;
    const uint8_t *image_base=IOSurfaceGetBaseAddress(image);
    if(!image_base || image_base[71]!=0x6d)return 35;
    mach_port_t port=IOSurfaceCreateMachPort(image);
    IOSurfaceRef lookup=port?IOSurfaceLookupFromMachPort(port):NULL;
    if(!lookup || IOSurfaceGetID(lookup)!=IOSurfaceGetID(image))return 36;
    CFRelease(lookup);mach_port_deallocate(mach_task_self(),port);
    bytes=sizeof(readback);
    if(IOSurfaceGetBulkAttachments(image,readback,&bytes) || memcmp(readback,bulk,32))return 37;
    CFRelease(image);
    IOSurfaceRef memory=IOSurfaceWrapClientMemory(p+37,1234);
    if(!memory || IOSurfaceGetAllocSize(memory)!=1234 || !IOSurfaceGetID(memory))return 38;
    bytes=sizeof(readback);
    const uint8_t *memory_base=IOSurfaceGetBaseAddress(memory);
    if(IOSurfaceGetBulkAttachments(memory,readback,&bytes) || !memory_base || memory_base[3]!=p[40])return 39;
    p[40]=0x73;
    if(memory_base[3]!=0x73)return 40;
    CFRelease(memory);free(allocation);
    fprintf(stderr,"POLARIS GL: PASS wrapped IOSurface state/alias/metadata/lookup/release\n");
    return 0;
}
/* Exercise the path missing from the original solid-colour test: UCHE
 * texture reads of GMEM, including restoration of the previous render pass.
 * Force GMEM only in this separate acceptance task, never in backboardd.
 * Four full-surface inversions must all reach the original CPU alias. */
static unsigned gmem_fetch_contract(GLuint vertex,IOSurfaceRef surface)
{
    GLint extensions=0;bool fetch=false;
    glGetIntegerv(GL_NUM_EXTENSIONS,&extensions);
    for(GLint n=0;n<extensions;n++) {
        const char *name=(const char*)glGetStringi(GL_EXTENSIONS,(GLuint)n);
        if(name && !strcmp(name,"GL_EXT_shader_framebuffer_fetch"))fetch=true;
    }
    if(!fetch)return 41;
    test_step(43);
    const char *source="#version 300 es\n#extension GL_EXT_shader_framebuffer_fetch : require\n"
        "precision highp float;layout(location=0) inout vec4 c;"
        "void main(){c=vec4(vec3(1.0)-c.rgb,1.0);}";
    GLuint fragment=shader(GL_FRAGMENT_SHADER,source);if(!fragment)return 42;
    GLuint program=glCreateProgram();glAttachShader(program,vertex);glAttachShader(program,fragment);
    glLinkProgram(program);GLint linked=0;glGetProgramiv(program,GL_LINK_STATUS,&linked);
    if(!linked)return 43;
    for(unsigned round=0;round<4;round++) {
        test_step(44+round);glUseProgram(program);glDrawArrays(GL_TRIANGLES,0,3);glFinish();
        if(glGetError())return 44;
        if(IOSurfaceLock(surface,kIOSurfaceLockReadOnly,NULL))return 45;
        const uint8_t *pixels=IOSurfaceGetBaseAddress(surface);
        const int original[4]={191,128,64,255};bool correct=pixels!=NULL;
        for(unsigned n=0;correct && n<4096;n++)for(unsigned k=0;k<4;k++) {
            int expected=(round&1)||k==3?original[k]:255-original[k];
            if(abs((int)pixels[4*n+k]-expected)>1){correct=false;break;}
        }
        IOSurfaceUnlock(surface,kIOSurfaceLockReadOnly,NULL);
        if(!correct)return 46;
    }
    glDeleteProgram(program);glDeleteShader(fragment);test_step(48);
    fprintf(stderr,"POLARIS GL: PASS forced GMEM framebuffer fetch/restore ALL4096 pixels x4\n");
    return 0;
}
static IOSurfaceRef addressed_surface(void *pixels,uint32_t format)
{
    CFMutableDictionaryRef d=CFDictionaryCreateMutable(NULL,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    number(d,CFSTR("IOSurfaceWidth"),16);number(d,CFSTR("IOSurfaceHeight"),16);
    number(d,CFSTR("IOSurfaceBytesPerRow"),64);number(d,CFSTR("IOSurfaceBytesPerElement"),4);
    number(d,CFSTR("IOSurfaceAllocSize"),1024);number(d,CFSTR("IOSurfacePixelFormat"),(int)format);
    int64_t address=(int64_t)(uintptr_t)pixels;
    CFNumberRef n=CFNumberCreate(NULL,kCFNumberSInt64Type,&address);
    CFDictionarySetValue(d,CFSTR("IOSurfaceAddress"),n);CFRelease(n);
    IOSurfaceRef surface=IOSurfaceCreate(d);CFRelease(d);return surface;
}
/* Exercise the actual EAGL image methods used by the desktop, rather than
 * importing only an empty render target directly through Mesa. Verify both
 * colour and alpha, plus an update to the SAME caller-owned pixels. */
static unsigned icon_texture_contract(void)
{
    test_step(49);
    if(!dlopen("/System/Library/Frameworks/OpenGLES.framework/OpenGLES",RTLD_NOW|RTLD_LOCAL))return 49;
    void *lib=dlopen("/usr/lib/libPolarisGL.dylib",RTLD_NOW|RTLD_LOCAL);if(!lib)return 50;
    unsigned(*methods)(void)=(unsigned(*)(void))dlsym(lib,"polaris_eagl_methods");
    if(!methods || methods()!=PGPU_EAGL_METHOD_MASK)return 51;
    test_image(3,3,(void*)methods);
    id object=((id(*)(id,SEL))objc_msgSend)((id)objc_getClass("EAGLContext"),sel_registerName("alloc"));
    object=((id(*)(id,SEL,unsigned long,id))objc_msgSend)(object,sel_registerName("initWithAPI:properties:"),3,nil);
    if(!object)return 52;
    void **table=((void**(*)(id,SEL))objc_msgSend)(object,sel_registerName("getMacroContextPrivate"));
    if(!table || !table[0])return 53;
    void(*bind)(void*,GLenum,GLuint)=(void(*)(void*,GLenum,GLuint))table[0x30/8];
    void(*use)(void*,GLuint)=(void(*)(void*,GLuint))table[0x12c8/8];
    void(*draw)(void*,GLenum,GLint,GLsizei)=(void(*)(void*,GLenum,GLint,GLsizei))table[0x210/8];
    void(*finish)(void*)=(void(*)(void*))table[0x2d0/8];
    GLuint vertex=shader(GL_VERTEX_SHADER,"#version 300 es\nlayout(location=0) in vec2 p;out vec2 uv;void main(){uv=(p+1.0)*0.5;gl_Position=vec4(p,0,1);}");
    GLuint fragment=shader(GL_FRAGMENT_SHADER,"#version 300 es\nprecision highp float;in vec2 uv;uniform sampler2D image;out vec4 c;void main(){c=texture(image,uv);}");
    if(!vertex || !fragment)return 54;
    GLuint program=glCreateProgram();glAttachShader(program,vertex);glAttachShader(program,fragment);glLinkProgram(program);
    GLint linked=0;glGetProgramiv(program,GL_LINK_STATUS,&linked);if(!linked)return 55;
    use(table[0],program);glUniform1i(glGetUniformLocation(program,"image"),0);
    GLuint vao,positions,output,fb;glGenVertexArrays(1,&vao);glBindVertexArray(vao);
    glGenBuffers(1,&positions);glBindBuffer(GL_ARRAY_BUFFER,positions);
    const GLfloat points[]={-1,-1,3,-1,-1,3};glBufferData(GL_ARRAY_BUFFER,sizeof(points),points,GL_STATIC_DRAW);
    glVertexAttribPointer(0,2,GL_FLOAT,GL_FALSE,0,0);glEnableVertexAttribArray(0);
    glGenTextures(1,&output);glBindTexture(GL_TEXTURE_2D,output);
    glTexImage2D(GL_TEXTURE_2D,0,GL_RGBA,64,64,0,GL_RGBA,GL_UNSIGNED_BYTE,NULL);
    glGenFramebuffers(1,&fb);glBindFramebuffer(GL_FRAMEBUFFER,fb);
    glFramebufferTexture2D(GL_FRAMEBUFFER,GL_COLOR_ATTACHMENT0,GL_TEXTURE_2D,output,0);
    if(glCheckFramebufferStatus(GL_FRAMEBUFFER)!=GL_FRAMEBUFFER_COMPLETE)return 56;
    glViewport(0,0,64,64);glDisable(GL_BLEND);glDisable(GL_SCISSOR_TEST);
    uint8_t *allocation=NULL;if(posix_memalign((void**)&allocation,16384,32768))return 57;
    uint8_t *pixels=allocation+37;uint8_t readback[64*64*4];
    for(unsigned route=0;route<2;route++) {
        /* Untyped wrapped pictures use the reference bridge's ABGR bytes;
         * ordinary BGRA pictures use the texImageIOSurface source method. */
        IOSurfaceRef surface=addressed_surface(pixels,route?0:0x42475241);
        if(!surface || IOSurfaceGetAllocSize(surface)!=1024)return 58;
        GLuint texture;glGenTextures(1,&texture);
        for(unsigned round=0;round<2;round++) {
            test_step(50+route*2+round);
            for(unsigned y=0;y<16;y++)for(unsigned x=0;x<16;x++) {
                uint8_t rgba[4]={(uint8_t)(round?80:24),(uint8_t)(x<8?48:96),
                    (uint8_t)(y<8?16:64),(uint8_t)(x<8?128:255)};
                uint8_t *p=pixels+(y*16+x)*4;
                if(route){p[0]=rgba[3];p[1]=rgba[2];p[2]=rgba[1];p[3]=rgba[0];}
                else{p[0]=rgba[2];p[1]=rgba[1];p[2]=rgba[0];p[3]=rgba[3];}
            }
            const uint8_t *alias=IOSurfaceGetBaseAddress(surface);
            if(!alias || memcmp(alias,pixels,1024))return 59;
            bind(table[0],GL_TEXTURE_2D,texture);
            if(!round) {
                BOOL ok=route?
                    ((BOOL(*)(id,SEL,unsigned long,IOSurfaceRef,BOOL))objc_msgSend)(object,sel_registerName("attachImage:toCoreSurface:invertedRender:"),GL_TEXTURE_2D,surface,NO):
                    ((BOOL(*)(id,SEL,IOSurfaceRef,unsigned long,unsigned long,GLsizei,GLsizei,unsigned long,unsigned long,uint32_t,BOOL))objc_msgSend)(object,sel_registerName("texImageIOSurface:target:internalFormat:width:height:format:type:plane:invert:"),surface,GL_TEXTURE_2D,GL_RGBA,16,16,GL_BGRA,GL_UNSIGNED_BYTE,0,NO);
                if(!ok)return 60;
                glTexParameteri(GL_TEXTURE_2D,GL_TEXTURE_MIN_FILTER,GL_NEAREST);glTexParameteri(GL_TEXTURE_2D,GL_TEXTURE_MAG_FILTER,GL_NEAREST);
                glTexParameteri(GL_TEXTURE_2D,GL_TEXTURE_WRAP_S,GL_CLAMP_TO_EDGE);glTexParameteri(GL_TEXTURE_2D,GL_TEXTURE_WRAP_T,GL_CLAMP_TO_EDGE);
            }
            draw(table[0],GL_TRIANGLES,0,3);finish(table[0]);
            glReadPixels(0,0,64,64,GL_RGBA,GL_UNSIGNED_BYTE,readback);if(glGetError())return 61;
            for(unsigned y=0;y<64;y++)for(unsigned x=0;x<64;x++) {
                int expected[4]={round?80:24,x<32?48:96,y<32?16:64,x<32?128:255};
                for(unsigned k=0;k<4;k++)if(abs((int)readback[(y*64+x)*4+k]-expected[k])>1)return 62;
            }
        }
        /* The bridge retains each source until its context is released. */
        CFRelease(surface);
    }
    ((void(*)(id,SEL))objc_msgSend)(object,sel_registerName("release"));free(allocation);
    test_step(54);fprintf(stderr,"POLARIS GL: PASS EAGL icon BGRA/ABGR alpha + live caller pixels ALL4096 x4\n");
    return 0;
}
int main(void)
{
    test_started_ms=test_milliseconds();watch_test_faults();test_step(1);
    io_service_t service=IOServiceGetMatchingService(0,IOServiceMatching("PolarisGPU"));
    if(!service)return 20;
    kern_return_t opened=IOServiceOpen(service,mach_task_self(),0,&connection);IOObjectRelease(service);
    if(opened)return 21;
    char port[32];snprintf(port,sizeof(port),"%u",connection);setenv("POLARIS_GPU_CONNECTION",port,1);
    report(1,0);
    /* Reject a mismatched native GMEM window before issuing any draw. */
    struct msm_param gmem={.pipe=0x10,.param=6};size_t gmem_bytes=sizeof(gmem);
    if(IOConnectCallStructMethod(connection,0x40,&gmem,sizeof(gmem),&gmem,&gmem_bytes) ||
        gmem_bytes!=sizeof(gmem) || gmem.value!=0x100000)return fail(47);
    if(setenv("FD_MESA_DEBUG","gmem",1))return fail(48);
    test_step(10);unsigned contract=surface_contract();if(contract)return fail(contract);test_step(11);
    int attrs[]={0x22,GL_RGBA,0x33,0x38,0x36,3,0x37,0,0};
    test_step(20);uint8_t window[16*16*4];OSMesaContext c=OSMesaCreateContextAttribs(attrs,NULL);
    if(!c || !OSMesaMakeCurrent(c,window,GL_UNSIGNED_BYTE,16,16))return fail(10);
    const char *renderer=(const char*)glGetString(GL_RENDERER);
    fprintf(stderr,"POLARIS GL: renderer %s\n",renderer?renderer:"NULL");
    if(!renderer || !strstr(renderer,"630") || strstr(renderer,"softpipe") || strstr(renderer,"llvmpipe"))return fail(11);
    report(2,0);test_step(21);
    const char *vs="#version 300 es\nlayout(location=0) in vec2 p;void main(){gl_Position=vec4(p,0,1);}";
    const char *fs="#version 300 es\nprecision highp float;out vec4 c;void main(){c=vec4(0.25,0.5,0.75,1);}";
    test_step(30);GLuint v=shader(GL_VERTEX_SHADER,vs);test_step(31);
    GLuint f=shader(GL_FRAGMENT_SHADER,fs);test_step(32);if(!v||!f)return fail(12);
    GLuint program=glCreateProgram();glAttachShader(program,v);glAttachShader(program,f);test_step(33);glLinkProgram(program);test_step(34);
    GLint linked=0;glGetProgramiv(program,GL_LINK_STATUS,&linked);if(!linked)return fail(13);
    report(3,0);test_step(35);
    CFMutableDictionaryRef d=CFDictionaryCreateMutable(NULL,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    number(d,CFSTR("IOSurfaceWidth"),64);number(d,CFSTR("IOSurfaceHeight"),64);
    number(d,CFSTR("IOSurfaceBytesPerRow"),256);number(d,CFSTR("IOSurfaceBytesPerElement"),4);
    number(d,CFSTR("IOSurfaceAllocSize"),16384);number(d,CFSTR("IOSurfacePixelFormat"),0x42475241);
    IOSurfaceRef s=IOSurfaceCreate(d);CFRelease(d);if(!s)return fail(14);
    GLuint texture=0,fb=0;glGenTextures(1,&texture);glBindTexture(GL_TEXTURE_2D,texture);
    void (*import)(GLenum,void*)=(void(*)(GLenum,void*))OSMesaGetProcAddress("glEGLImageTargetTexture2DOES");
    if(!import)return fail(15);
    import(GL_TEXTURE_2D,(void*)(uintptr_t)IOSurfaceGetID(s));
    glGenFramebuffers(1,&fb);glBindFramebuffer(GL_FRAMEBUFFER,fb);
    glFramebufferTexture2D(GL_FRAMEBUFFER,GL_COLOR_ATTACHMENT0,GL_TEXTURE_2D,texture,0);
    if(glCheckFramebufferStatus(GL_FRAMEBUFFER)!=GL_FRAMEBUFFER_COMPLETE || glGetError())return fail(16);
    report(4,0);test_step(40);
    const GLfloat points[]={-1,-1,3,-1,-1,3};GLuint array=0,bo=0;
    glGenVertexArrays(1,&array);glBindVertexArray(array);glGenBuffers(1,&bo);glBindBuffer(GL_ARRAY_BUFFER,bo);
    glBufferData(GL_ARRAY_BUFFER,sizeof(points),points,GL_STATIC_DRAW);
    glVertexAttribPointer(0,2,GL_FLOAT,GL_FALSE,0,0);glEnableVertexAttribArray(0);
    glViewport(0,0,64,64);glUseProgram(program);glDrawArrays(GL_TRIANGLES,0,3);glFinish();
    if(glGetError())return fail(17);
    report(5,0);test_step(41);
    if(IOSurfaceLock(s,kIOSurfaceLockReadOnly,NULL))return fail(18);
    const uint8_t *p=IOSurfaceGetBaseAddress(s);unsigned passed=0;
    const int expected[4]={191,128,64,255};
    for(unsigned n=0;n<4096;n++) {
        for(unsigned k=0;k<4;k++)if(abs((int)p[4*n+k]-expected[k])>1) {
            fprintf(stderr,"POLARIS GL: pixel%u channel%u expected%d actual%u\n",n,k,expected[k],p[4*n+k]);return fail(19);
        }
        passed++;
    }
    IOSurfaceUnlock(s,kIOSurfaceLockReadOnly,NULL);
    fprintf(stderr,"POLARIS GL: PASS GPU GLSL + shared IOSurface ALL%u pixels\n",passed);
    test_step(42);
    unsigned gmem_error=gmem_fetch_contract(v,s);if(gmem_error)return fail(gmem_error);
    unsigned icon_error=icon_texture_contract();if(icon_error)return fail(icon_error);
    report(6,0);OSMesaDestroyContext(c);CFRelease(s);IOServiceClose(connection);return 0;
}
