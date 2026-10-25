"""Execute actual loading guards, Objective-C method transaction and reports.
Mocked platform boundaries are not physical desktop GPU evidence.
"""
from pathlib import Path
import unittest
from .test_polaris_gpu_lifetime import function
from .test_polaris_gpu_bootstrap import run
ROOT=Path(__file__).resolve().parents[2]

class GPULoaderTests(unittest.TestCase):
    def test_actual_constructor_reuses_one_task_connection_and_reports_load_failures(self):
        code=function((ROOT/'userland/gpu/polaris-inject.c').read_text(),'static void polaris_gl_inject(')
        run('#include "'+str(ROOT/'tools/polaris-gl-status.h')+'"\n' + r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
typedef unsigned io_service_t;typedef int kern_return_t;
#define RTLD_NOW 2
#define RTLD_LOCAL 4
static unsigned desktop_connection,stage,error,methods,admitted,service,opens,open_error;
static unsigned alias_set,env_error,load_error,symbol_error,mask,observed,hooks;
static void loader_note(unsigned s,unsigned e,unsigned m){stage=s;error=e;methods=m;}
static int real_window_server(void){return admitted;}
static void *IOServiceMatching(const char*n){assert(!strcmp(n,"PolarisGPU"));return (void*)1;}
static io_service_t IOServiceGetMatchingService(unsigned p,void*m){assert(!p&&m==(void*)1);return service;}
static unsigned mach_task_self(void){return 99;}
static int IOServiceOpen(unsigned s,unsigned t,unsigned y,unsigned*out){assert(s==1&&t==99&&!y);opens++;*out=23;return open_error;}
static void IOObjectRelease(unsigned s){assert(s==1);}
static int env_(const char*n,const char*v,int overwrite){assert(!strcmp(n,"POLARIS_GPU_CONNECTION")&&!strcmp(v,"23")&&overwrite);alias_set++;return env_error;}
#define setenv env_
static void *dlopen(const char*p,int flags){assert(alias_set==1&&!strcmp(p,"/usr/lib/libPolarisGL.dylib")&&flags==6);return load_error?0:(void*)2;}
static const char*dlerror(void){return "modeled failure";}
static unsigned methods_(void){return mask;}
static void observe_(void(*note)(unsigned,unsigned,unsigned)){observed++;note(4,0,mask);}
static void*dlsym(void*h,const char*n){assert(h==(void*)2);if(symbol_error)return 0;
 if(!strcmp(n,"polaris_eagl_methods"))return (void*)methods_;
 if(!strcmp(n,"glFinish"))return (void*)methods_;
 if(!strcmp(n,"polaris_eagl_render_observe") || !strcmp(n,"polaris_eagl_performance_observe"))return 0;assert(!strcmp(n,"polaris_eagl_observe"));return (void*)observe_;}
static void watch_for_faults(void){}
static void crash_image(unsigned i,unsigned k,void*p){assert(i<4&&k<5&&p);}
static void render_note(const struct pgpu_render_notice*p){(void)p;assert(0);}
static void performance_note(const struct pgpu_perf_notice*p){(void)p;assert(0);}
static void gl_hooks(void*h){assert(h==(void*)2);hooks++;}
static void reset(void){stage=error=methods=opens=open_error=alias_set=env_error=load_error=symbol_error=observed=hooks=0;admitted=service=1;mask=255;}
''' + code + r'''
int main(void){reset();admitted=0;polaris_gl_inject();assert(!opens&&!stage);
 reset();service=0;polaris_gl_inject();assert(!opens&&!stage);
 reset();open_error=1;polaris_gl_inject();assert(opens==1&&!stage&&!alias_set);
 reset();env_error=1;polaris_gl_inject();assert(stage==2&&error==1&&!hooks);
 reset();load_error=1;polaris_gl_inject();assert(stage==3&&error==2&&!hooks);
 reset();symbol_error=1;polaris_gl_inject();assert(stage==4&&error==3&&!hooks);
 reset();mask=63;polaris_gl_inject();assert(stage==4&&error==4&&methods==63&&!hooks);
 reset();polaris_gl_inject();assert(opens==1&&alias_set==1&&observed==1&&hooks==1&&stage==4&&!error&&methods==255);return 0;}
''')

    def test_actual_path_guard_ignores_rewritten_program_name_and_refuses_other_images(self):
        code=function((ROOT/'userland/gpu/polaris-inject.c').read_text(),'static int real_window_server(')
        run('#include "'+str(ROOT/'tools/polaris-gl-status.h')+'"\n' + r'''
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
static const char *path,*tested;static int path_error;
static char *env_(const char *name){assert(!strcmp(name,"POLARIS_GL_TESTED"));return (char*)tested;}
#define getenv env_
static int _NSGetExecutablePath(char*out,uint32_t*bytes){assert(*bytes==1024);if(path_error)return -1;strcpy(out,path);return 0;}
''' + code + r'''
int main(void){path="/usr/libexec/polaris-bbd-real";tested="1";assert(real_window_server());
 tested=0;assert(!real_window_server());tested="0";assert(!real_window_server());
 tested="1";path="/usr/libexec/backboardd";assert(!real_window_server());
 path="/usr/libexec/polaris-gl-test";assert(!real_window_server());
 path="/usr/libexec/polaris-bbd-real.extra";assert(!real_window_server());
 path="/usr/libexec/polaris-bbd-real";path_error=1;assert(!real_window_server());return 0;}
''')

    def test_actual_method_preflight_and_rollback_preserve_originals_on_failure(self):
        code=function((ROOT/'userland/gpu/eagl.c').read_text(),'static unsigned polaris_install_methods(')
        run('#include "'+str(ROOT/'tools/polaris-gl-status.h')+'"\n' + r'''
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <stdbool.h>
typedef int Class;typedef unsigned SEL;typedef void(*IMP)(void);
struct method{IMP imp;};typedef struct method*Method;
#define Nil 0
static struct method own[8],parent[8];static const char*names[8];
static unsigned name_count,mutations,missing,fail_at;static bool inherited[8],added[8];
static void original(void){}
static void my_initWithAPI(void){} static void my_API(void){} static void my_sharegroup(void){} static void my_setParameter(void){}
static void my_getMacroContextPrivate(void){} static void my_texImageIOSurface(void){}
static void my_attachImage(void){} static void my_dealloc(void){}
static SEL sel_registerName(const char*n){for(unsigned i=0;i<name_count;i++)if(!strcmp(n,names[i]))return i;
 assert(name_count<8);names[name_count]=n;return name_count++;}
static Class class_getSuperclass(Class c){assert(c==1);return 2;}
static Method class_getInstanceMethod(Class c,SEL s){assert(s<8);if(s+1==missing)return 0;
 return c==2?&parent[s]:(inherited[s]&&!added[s]?&parent[s]:&own[s]);}
static IMP method_getImplementation(Method m){assert(m);return m->imp;}
static const char *method_getTypeEncoding(Method m){assert(m);return "v@:";}
static IMP method_setImplementation(Method m,IMP i){assert(m);IMP old=m->imp;
 mutations++;if(mutations!=fail_at)m->imp=i;return old;}
static bool class_addMethod(Class c,SEL s,IMP i,const char*t){assert(c==1&&!strcmp(t,"v@:"));
 mutations++;if(mutations==fail_at)return false;own[s].imp=i;added[s]=true;return true;}
static void reset(void){mutations=missing=fail_at=0;for(unsigned i=0;i<8;i++){
 own[i].imp=parent[i].imp=original;inherited[i]=(i==7);added[i]=false;}}
''' + code + r'''
int main(void){reset();assert(!polaris_install_methods(Nil)&&!mutations);
 for(unsigned i=1;i<=8;i++){reset();missing=i;assert(!polaris_install_methods(1)&&!mutations);}
 for(unsigned i=1;i<=8;i++){reset();fail_at=i;assert(!polaris_install_methods(1));
  for(unsigned j=0;j<8;j++){assert(method_getImplementation(class_getInstanceMethod(1,j))==original);assert(parent[j].imp==original);}}
 reset();assert(polaris_install_methods(1)==0xff&&mutations==8);
 for(unsigned j=0;j<8;j++){assert(method_getImplementation(class_getInstanceMethod(1,j))!=original);assert(parent[j].imp==original);}
 return 0;}
''')

    def test_actual_loader_report_cannot_forge_selftest_or_submission_counters(self):
        text=(ROOT/'tools/PolarisGPU.cpp').read_text()
        code=function(text,'static bool polaris_gpu_loader_report(')
        run('#include "'+str(ROOT/'tools/polaris-gl-status.h')+'"\n' + r'''
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#define IOLog(...) ((void)0)
static uint32_t gpuLoaderStage=1,gpuLoaderError,gpuLoaderMethods;
static uint32_t gpuSubmissions=1,gpuSurfaces=1,gpuAppStage=6,gpuAppError;
''' + code + r'''
int main(void){
 assert(!polaris_gpu_loader_report(1,4,0,255));assert(!polaris_gpu_loader_report(0,4,0,255));
 assert(!polaris_gpu_loader_report(2,1,0,255));assert(!polaris_gpu_loader_report(2,7,0,255));
 assert(!polaris_gpu_loader_report(2,4,7,255));assert(!polaris_gpu_loader_report(2,4,0,256));
 assert(gpuLoaderStage==1&&!gpuLoaderError&&!gpuLoaderMethods);
 for(unsigned s=2;s<=6;s++)assert(polaris_gpu_loader_report(2,s,0,255));
 assert(gpuLoaderStage==6&&!gpuLoaderError&&gpuLoaderMethods==255);
 assert(gpuSubmissions==1&&gpuSurfaces==1&&gpuAppStage==6&&!gpuAppError);return 0;}
''')

    def test_actual_context_observer_is_not_called_per_frame_or_repeated_success(self):
        text=(ROOT/'userland/gpu/eagl.c').read_text()
        code=''.join(function(text,n) for n in ['void polaris_eagl_observe(', 'static void polaris_context_note('])
        run('#include "'+str(ROOT/'tools/polaris-gl-status.h')+'"\n' + r'''
#include <assert.h>
static unsigned polaris_method_mask=255,notes,last_stage,last_error,polaris_context_stage,polaris_context_error;
static void(*polaris_observer)(unsigned,unsigned,unsigned);
static void note(unsigned s,unsigned e,unsigned m){assert(m==255);notes++;last_stage=s;last_error=e;}
''' + code + r'''
int main(void){
 polaris_context_note(5,0);polaris_context_note(6,0);assert(!notes);
 polaris_eagl_observe(note);assert(notes==1&&last_stage==6&&!last_error);
 for(unsigned i=0;i<100;i++){polaris_context_note(5,0);polaris_context_note(6,0);}
 assert(notes==1&&last_stage==6&&!last_error);
 polaris_context_note(5,6);assert(notes==2&&last_stage==5&&last_error==6);return 0;}
''')
