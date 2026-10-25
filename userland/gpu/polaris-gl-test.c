/* Actual iOS/A630 acceptance, run in its own task before the window server.
 * Reject a software renderer. Compile/link GLSL, draw a full64x64 surface,
 * wait, then compare ALL4096 pixels through the CPU's IOSurface mapping.
 */
#include <CoreFoundation/CoreFoundation.h>
#include <IOSurface/IOSurfaceRef.h>
#include <IOKit/IOKitLib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <OpenGLES/ES3/gl.h>
#include <OpenGLES/ES3/glext.h>
typedef void *OSMesaContext;
extern OSMesaContext OSMesaCreateContextAttribs(const int *,OSMesaContext);
extern int OSMesaMakeCurrent(OSMesaContext,void *,unsigned,int,int);
extern void OSMesaDestroyContext(OSMesaContext);
extern void (*OSMesaGetProcAddress(const char *))(void);
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
    GLuint id=glCreateShader(kind);GLint ok=0;
    glShaderSource(id,1,&text,NULL);glCompileShader(id);glGetShaderiv(id,GL_COMPILE_STATUS,&ok);
    if(!ok) {char log[1024]={0};glGetShaderInfoLog(id,sizeof(log),NULL,log);fprintf(stderr,"POLARIS GL shader: %s\n",log);return 0;}
    return id;
}
static void number(CFMutableDictionaryRef d,CFStringRef key,int value)
{
    CFNumberRef n=CFNumberCreate(NULL,kCFNumberIntType,&value);CFDictionarySetValue(d,key,n);CFRelease(n);
}
int main(void)
{
    io_service_t service=IOServiceGetMatchingService(0,IOServiceMatching("PolarisGPU"));
    if(!service)return 20;
    kern_return_t opened=IOServiceOpen(service,mach_task_self(),0,&connection);IOObjectRelease(service);
    if(opened)return 21;
    char port[32];snprintf(port,sizeof(port),"%u",connection);setenv("POLARIS_GPU_CONNECTION",port,1);
    report(1,0);
    int attrs[]={0x22,GL_RGBA,0x33,0x38,0x36,3,0x37,0,0};
    uint8_t window[16*16*4];OSMesaContext c=OSMesaCreateContextAttribs(attrs,NULL);
    if(!c || !OSMesaMakeCurrent(c,window,GL_UNSIGNED_BYTE,16,16))return fail(10);
    const char *renderer=(const char*)glGetString(GL_RENDERER);
    fprintf(stderr,"POLARIS GL: renderer %s\n",renderer?renderer:"NULL");
    if(!renderer || !strstr(renderer,"630") || strstr(renderer,"softpipe") || strstr(renderer,"llvmpipe"))return fail(11);
    report(2,0);
    const char *vs="#version 300 es\nlayout(location=0) in vec2 p;void main(){gl_Position=vec4(p,0,1);}";
    const char *fs="#version 300 es\nprecision highp float;out vec4 c;void main(){c=vec4(0.25,0.5,0.75,1);}";
    GLuint v=shader(GL_VERTEX_SHADER,vs),f=shader(GL_FRAGMENT_SHADER,fs);if(!v||!f)return fail(12);
    GLuint program=glCreateProgram();glAttachShader(program,v);glAttachShader(program,f);glLinkProgram(program);
    GLint linked=0;glGetProgramiv(program,GL_LINK_STATUS,&linked);if(!linked)return fail(13);
    report(3,0);
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
    report(4,0);
    const GLfloat points[]={-1,-1,3,-1,-1,3};GLuint array=0,bo=0;
    glGenVertexArrays(1,&array);glBindVertexArray(array);glGenBuffers(1,&bo);glBindBuffer(GL_ARRAY_BUFFER,bo);
    glBufferData(GL_ARRAY_BUFFER,sizeof(points),points,GL_STATIC_DRAW);
    glVertexAttribPointer(0,2,GL_FLOAT,GL_FALSE,0,0);glEnableVertexAttribArray(0);
    glViewport(0,0,64,64);glUseProgram(program);glDrawArrays(GL_TRIANGLES,0,3);glFinish();
    if(glGetError())return fail(17);
    report(5,0);
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
    report(6,0);OSMesaDestroyContext(c);CFRelease(s);IOServiceClose(connection);return 0;
}
