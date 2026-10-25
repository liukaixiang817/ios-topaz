"""Real crash/report/log adapters and wrapper restart containment with mocked OS boundaries."""
from pathlib import Path
import unittest
from .test_polaris_gpu_lifetime import function
from .test_polaris_gpu_bootstrap import run
ROOT=Path(__file__).resolve().parents[2]
HEADER='#include "'+str(ROOT/'tools/polaris-gl-status.h')+'"\n'

class GPURestartTests(unittest.TestCase):
    def test_sharegroup_never_dereferences_the_uninitialized_Apple_private_context(self):
        code=function((ROOT/'userland/gpu/eagl.c').read_text(),'static id my_sharegroup(')
        run(r'''
#include <assert.h>
#include <stdint.h>
typedef void*id;typedef void*SEL;
#define nil ((void*)0)
''' + code + r'''
int main(void){assert(my_sharegroup((void*)(uintptr_t)1,0)==nil);assert(my_sharegroup(0,(void*)8)==nil);return 0;}
''')

    def test_first_fatal_snapshot_survives_restarts_and_reports_do_not_change_GPU_proof(self):
        text=(ROOT/'tools/PolarisGPU.cpp').read_text()
        code=''.join(function(text,n).replace('extern "C" ','') for n in ['extern "C" bool polaris_gpu_record_crash(', 'extern "C" uint32_t polaris_gpu_crash_line('])
        run(HEADER+r'''
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
static struct pgpu_crash gpuFirstCrash;
static uint32_t gpuCrashPublished,gpuCrashPID;
''' + code + r'''
int main(void){char line[68];struct pgpu_crash a={.signal=11,.code=1,.pc=0x1d3f51890,.lr=0x188400000,.address=8,.pc_image=1,.lr_image=1};
 assert(!polaris_gpu_crash_line(0,line,sizeof(line)));assert(!polaris_gpu_record_crash(0,42));
 struct pgpu_crash bad=a;bad.signal=9;assert(!polaris_gpu_record_crash(&bad,42));bad=a;bad.pc_image=5;assert(!polaris_gpu_record_crash(&bad,42));
 assert(!gpuCrashPublished);assert(polaris_gpu_record_crash(&a,370));assert(gpuCrashPublished==2&&gpuCrashPID==370);
 bad=a;bad.pc=0x1234;assert(polaris_gpu_record_crash(&bad,380));assert(gpuFirstCrash.pc==a.pc&&gpuCrashPID==370);
 for(unsigned i=0;i<3;i++){unsigned n=polaris_gpu_crash_line(i,line,sizeof(line));assert(n==strlen(line)&&n<=67);}
 assert(!polaris_gpu_crash_line(3,line,sizeof(line))&&!polaris_gpu_crash_line(0,0,sizeof(line)));
 struct pgpu_image ranges[]={{0x700000000,0x10000,1},{0x900000000,0x1000,3}};uint32_t kind;
 assert(pgpu_pc(0x700001890,ranges,2,&kind)==0x180001890&&kind==1);
 assert(pgpu_pc(0x900000080,ranges,2,&kind)==0x80&&kind==3);
 assert(pgpu_pc(0x900001000,ranges,2,&kind)==0x900001000&&kind==0);
 assert(pgpu_desktop_allowed(2,0)&&!pgpu_desktop_allowed(2,1)&&pgpu_desktop_allowed(1,1));return 0;}
''')

    def test_successful_runtime_CB0_accesses_stop_scrolling_but_bootstrap_and_atomic_progress_remain(self):
        text=(ROOT/'tools/polaris-a630.c').read_text()
        code=''.join(function(text,n) for n in ['static void a630_access_begin(', 'static void a630_access_end('])
        run(r'''
#include <stdint.h>
#include <stdarg.h>
#include <assert.h>
static uint32_t a630_mode=9,a630_published;
static uint64_t a630_progress_access,a630_last_cb_access;
static unsigned messages;
static int print_(const char*f,...){assert(f);messages++;return 0;}
#define printf print_
''' + code + r'''
int main(void){a630_access_begin(1,3,0x8000);assert(messages==1&&(a630_progress_access>>63));a630_access_end();
 assert(!(a630_progress_access>>63));a630_access_begin(1,3,0x8000);assert(messages==1);
 a630_access_begin(2,3,0x8000);assert(messages==2);a630_published=1;
 for(unsigned i=0;i<10000;i++){a630_access_begin(i%4,3,0x8000+(i%8)*4);a630_access_end();}
 assert(messages==2&&!(a630_progress_access>>63));a630_mode=0;a630_access_begin(1,3,0x8008);assert(messages==2);return 0;}
''')

    def test_real_wrapper_skips_acceptance_and_injection_after_first_desktop_attempt(self):
        code=function((ROOT/'userland/gpu/polaris-bbd-wrapper.c').read_text(),'int main(').replace('int main(','static int wrapper_main(')
        run(r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/wait.h>
typedef int io_service_t;typedef void*CFTypeRef;
#define CFSTR(s) (s)
#define kCFAllocatorDefault 0
#define kCFBooleanTrue ((void*)1)
#define STDERR_FILENO 2
static unsigned attempted,spawned,executed;
static int open_(const char*p,int f){assert(!strcmp(p,"/dev/console")&&f==O_WRONLY);return -1;}
#define open open_
static int dup2(int a,int b){(void)a;(void)b;return 0;}
static int close(int fd){(void)fd;return 0;}
static int sysctlbyname(const char*n,void*out,size_t*b,void*in,size_t bytes){assert(!strcmp(n,"kern.bootargs")&&*b>=12&&!in&&!bytes);strcpy(out,"polarisgl=1");return 0;}
static void*IOServiceMatching(const char*n){assert(!strcmp(n,"PolarisGPU"));return (void*)2;}
static int IOServiceGetMatchingService(int p,void*m){assert(!p&&m==(void*)2);return 3;}
static void*IORegistryEntryCreateCFProperty(int s,const char*k,int a,int z){assert(s==3&&!strcmp(k,"PolarisDesktopAttempted")&&!a&&!z);return attempted?kCFBooleanTrue:0;}
static void CFRelease(void*p){assert(p==kCFBooleanTrue);}
static void IOObjectRelease(int s){assert(s==3);}
static int spawn_(pid_t*p,const char*name,void*a,void*b,char*const argv[],char*const env[]){assert(!strcmp(name,"/usr/libexec/polaris-gl-test")&&!a&&!b&&argv&&env);spawned++;*p=7;return 0;}
#define posix_spawn spawn_
static pid_t wait_(pid_t p,int*s,int flags){assert(p==7&&(flags==WNOHANG||!flags));*s=0;return p;}
#define waitpid wait_
static int usleep(unsigned t){assert(t==100000);return 0;}
static int execv(const char*p,char*const argv[]){assert(!strcmp(p,"/usr/libexec/polaris-bbd-real")&&!strcmp(argv[0],"backboardd"));executed++;return -1;}
extern char **environ;
''' + code + r'''
int main(void){char*argv[]={"wrapper",0};assert(wrapper_main(1,argv)==127&&spawned==1&&executed==1);
 assert(getenv("DYLD_INSERT_LIBRARIES")&&getenv("POLARIS_GL_TESTED"));
 attempted=1;assert(wrapper_main(1,argv)==127&&spawned==1&&executed==2);
 assert(!getenv("DYLD_INSERT_LIBRARIES")&&!getenv("POLARIS_GL_TESTED")&&!getenv("POLARIS_GPU_CONNECTION"));return 0;}
''')
