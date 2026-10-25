"""Run actual cold-start deadline, reporter, and fatal paths with mocked OS boundaries."""
from pathlib import Path
import unittest
from .test_polaris_gpu_lifetime import function
from .test_polaris_gpu_bootstrap import run
ROOT=Path(__file__).resolve().parents[2]
HEADER='#include "'+str(ROOT/'tools/polaris-gl-status.h')+'"\n'
class AcceptanceTests(unittest.TestCase):
    def test_actual_reporter_role_bounds_and_first_terminal_retention(self):
        t=(ROOT/'tools/PolarisGPU.cpp').read_text()
        c=''.join(function(t,n).replace('extern "C" ','') for n in ['extern "C" bool polaris_gpu_record_test(', 'static uint32_t polaris_gpu_test_line('])
        run(HEADER+r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
static uint32_t gpuTestBegan,gpuTestEndPublished;
static uint64_t gpuTestProgress;
static struct pgpu_test_notice gpuTestEnd;
'''+c+r'''
int main(void){char s[68];struct pgpu_test_notice p={PGPU_TEST_BEGIN,0,0,0};
 assert(sizeof(p)==16&&!polaris_gpu_test_line(s,sizeof(s)));
 assert(!polaris_gpu_record_test(1,&p)&&!polaris_gpu_record_test(2,&p));
 assert(polaris_gpu_record_test(3,&p));p=(struct pgpu_test_notice){PGPU_TEST_STEP,30,27000,0};
 assert(polaris_gpu_record_test(1,&p)&&!polaris_gpu_record_test(3,&p));
 assert(polaris_gpu_test_line(s,sizeof(s))&&strstr(s,"R1 V0 P30 MS27000"));
 p=(struct pgpu_test_notice){PGPU_TEST_TIMEOUT,9,30000,0};assert(!polaris_gpu_record_test(3,&p));
 p.elapsed_ms=180000;assert(polaris_gpu_record_test(3,&p)&&gpuTestEndPublished==2);
 assert(polaris_gpu_test_line(s,sizeof(s))&&strstr(s,"R4 V9 P30 MS180000"));
 p=(struct pgpu_test_notice){PGPU_TEST_EXIT,0,180001,0};assert(polaris_gpu_record_test(3,&p));
 assert(gpuTestEnd.event==PGPU_TEST_TIMEOUT);p.reserved=1;assert(!pgpu_test_notice_valid(3,&p));
 p.reserved=0;p.elapsed_ms=600001;assert(!pgpu_test_notice_valid(3,&p));
 return 0;}
''')
    def test_actual_wall_clock_deadline_exit_signal_and_errors(self):
        t=(ROOT/'userland/gpu/polaris-bbd-wrapper.c').read_text()
        c=''.join(function(t,n) for n in ['static uint64_t test_milliseconds(', 'static void test_notice(', 'static int run_acceptance('])
        run(HEADER+r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>
static unsigned mode,polls,kills,reaps,exits;
static uint64_t ms=1000;
static struct pgpu_test_notice saved;
static int clock_(clockid_t id,struct timespec*out){assert(id==CLOCK_MONOTONIC);if(mode==7)return -1;out->tv_sec=ms/1000;out->tv_nsec=(ms%1000)*1000000;return 0;}
#define clock_gettime clock_
static int sleep_(unsigned n){assert(n==100000);ms+=1000;return 0;}
#define usleep sleep_
static int __mac_syscall(const char*n,int call,void*p){assert(!strcmp(n,"AMFI")&&call==0x5c);saved=*(struct pgpu_test_notice*)p;assert(pgpu_test_notice_valid(3,&saved));return 0;}
static char *env[]={0};static char **environ=env;
static int spawn_(pid_t*id,const char*n,void*a,void*b,char*const av[],char*const ev[]){assert(!strcmp(n,"/usr/libexec/polaris-gl-test")&&!a&&!b&&av&&ev);*id=7;return mode==4?ENOENT:0;}
#define posix_spawn spawn_
static pid_t wait_(pid_t id,int*status,int flags){assert(id==7);if(!flags){reaps++;*status=SIGKILL;return id;}
 polls++;if(mode==5){errno=ECHILD;return -1;}if(mode==6&&polls==1){errno=EINTR;return -1;}
 if(mode==3)return 0;
 if(mode==8&&ms<170000)return 0;
 *status=mode==1?(12<<8):mode==2?SIGSEGV:0;exits++;return id;}
#define waitpid wait_
static int kill_(pid_t id,int sig){assert(id==7&&sig==SIGKILL);kills++;return 0;}
#define kill kill_
'''+c+r'''
static void reset(unsigned m){mode=m;polls=kills=reaps=exits=0;ms=1000;memset(&saved,0,sizeof(saved));}
int main(void){reset(0);assert(run_acceptance()&&saved.event==PGPU_TEST_EXIT&&!saved.value&&!kills);
 reset(1);assert(!run_acceptance()&&saved.event==PGPU_TEST_EXIT&&saved.value==12);
 reset(2);assert(!run_acceptance()&&saved.event==PGPU_TEST_SIGNAL&&saved.value==SIGSEGV);
 reset(3);assert(!run_acceptance()&&saved.event==PGPU_TEST_TIMEOUT&&saved.elapsed_ms==180000&&kills==1&&reaps==1);
 reset(4);assert(!run_acceptance()&&saved.event==PGPU_TEST_SPAWN_ERROR&&saved.value==ENOENT&&!polls);
 reset(5);assert(!run_acceptance()&&saved.event==PGPU_TEST_WAIT_ERROR&&saved.value==ECHILD&&!kills);
 reset(6);assert(run_acceptance()&&polls==2&&!kills);
 reset(7);assert(!run_acceptance()&&saved.event==PGPU_TEST_WAIT_ERROR&&saved.value==EIO&&!polls);
 reset(8);assert(run_acceptance()&&saved.elapsed_ms>=169000&&!kills);return 0;}
''')
    def test_actual_child_fatal_records_PC_without_GPU_or_loader_calls(self):
        t=(ROOT/'userland/gpu/polaris-gl-test.c').read_text();c=function(t,'static void test_fatal(')
        run(HEADER+r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#define STDERR_FILENO 2
struct regs{uint64_t __pc,__lr;};struct mc{struct regs __ss;};typedef struct{struct mc*uc_mcontext;}ucontext_t;
typedef struct{int si_code;void*si_addr;}siginfo_t;
static struct pgpu_image test_images[3]={{0x700000000,0x10000,1},{0x900000000,0x10000,2},{0xa00000000,0x10000,4}};
static struct pgpu_crash captured;static unsigned writes,kills;
static int __mac_syscall(const char*n,int cmd,void*p){assert(!strcmp(n,"AMFI")&&cmd==0x5b);captured=*(struct pgpu_crash*)p;return 0;}
static int write(int fd,const void*p,size_t n){assert(fd==2&&p&&n);writes++;return (int)n;}
static int getpid(void){return 42;}
static int kill(int pid,int sig){assert(pid==42&&sig==11);kills++;return 0;}
'''+c+r'''
int main(void){struct mc m={{0xa00000120,0x700001800}};ucontext_t u={&m};siginfo_t i={2,(void*)0x30};
 test_fatal(11,&i,&u);assert(writes==1&&kills==1&&pgpu_crash_valid(&captured));
 assert(captured.pc==0x120&&captured.pc_image==4&&captured.lr==0x180001800&&captured.lr_image==1&&captured.address==0x30);return 0;}
''')
    def test_wrapper_reporter_identity_never_becomes_a_GPU_caller(self):
        code=function((ROOT/'tools/polaris-gpu-overlay.c').read_text(),'bool polaris_gpu_wrapper_allowed(')
        run(r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
typedef int vnode_t;
#define NULLVP 0
#define MNT_ROOTFS 1
#define VNODE_LOOKUP_NOFOLLOW 2
#define VNODE_LOOKUP_NOCROSSMOUNT 4
struct vnode_attr{unsigned va_uid,va_mode;};
#define VATTR_INIT(a) memset(a,0,sizeof(*(a)))
#define VATTR_WANTED(a,b) ((void)(a))
#define VATTR_IS_SUPPORTED(a,b) ((void)(a),true)
static unsigned ready=1,allowed=1,image=9,uid=0,mode=0755,expected=9,original=8,rootfs=1,refs,puts;
static bool polaris_gpu_overlay_ready(void){return ready;}
static bool polaris_ram_overlay_allowed(void){return allowed;}
static int current_proc(void){return 1;}
static int proc_getexecutablevnode(int p){assert(p==1);if(image)refs++;return image;}
static bool vnode_isreg(int v){assert(v==(int)image);return true;}
static int vnode_mount(int v){assert(v==(int)image);return 2;}
static int vfs_flags(int m){assert(m==2);return rootfs;}
static int vfs_context_kernel(void){return 3;}
static int vnode_getattr(int v,struct vnode_attr*a,int c){assert(v==(int)image&&c==3);a->va_uid=uid;a->va_mode=mode;return 0;}
static int vnode_lookup(const char*p,int f,int*out,int c){assert(f==6&&c==3);
 if(!strcmp(p,"/usr/libexec/backboardd"))*out=expected;else{assert(!strcmp(p,"/usr/libexec/polaris-bbd-real"));*out=original;}
 if(*out)refs++;return *out?0:1;}
static void vnode_put(int v){assert(v>0);puts++;}
'''+code+r'''
int main(void){assert(polaris_gpu_wrapper_allowed()&&refs==puts);
 image=8;assert(!polaris_gpu_wrapper_allowed()&&refs==puts);image=9;
 original=9;assert(!polaris_gpu_wrapper_allowed()&&refs==puts);original=8;
 uid=501;assert(!polaris_gpu_wrapper_allowed()&&refs==puts);uid=0;
 mode=0775;assert(!polaris_gpu_wrapper_allowed()&&refs==puts);mode=0755;
 rootfs=0;assert(!polaris_gpu_wrapper_allowed()&&refs==puts);rootfs=1;
 original=0;assert(!polaris_gpu_wrapper_allowed()&&refs==puts);original=8;
 allowed=0;assert(!polaris_gpu_wrapper_allowed()&&refs==puts);allowed=1;
 ready=0;assert(!polaris_gpu_wrapper_allowed()&&refs==puts);return 0;}
''')
