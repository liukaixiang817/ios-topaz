"""Compile the real mode9 scheduler, deadline and progress adapters.
These tests prove host control flow, never GPU or secure-world execution.
"""
from pathlib import Path
import unittest
try:
    from .test_polaris_a630_core import run
except ImportError:
    from test_polaris_a630_core import run
ROOT=Path(__file__).resolve().parents[2]
def body(start):
    text=(ROOT/'tools/polaris-a630.c').read_text()
    at=text.index(start)
    left=text.index('{',at);depth=1;right=left+1
    while depth:
        if text[right]=='{':depth+=1
        if text[right]=='}':depth-=1
        right+=1
    return text[at:right]+'\n' 
class A630WorkerTests(unittest.TestCase):
    def test_real_mode9_init_returns_without_running_hardware(self):
        worker=body('static void a630_worker(void *arg __unused,wait_result_t wr __unused)')
        init=body('void polaris_a630_init(void)\n{')
        run(r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <assert.h>
#define THREAD_UNINT 0
#define THREAD_CONTINUE_NULL 0
#define NSEC_PER_MSEC 1000000
#define KERN_SUCCESS 0
typedef int wait_result_t,kern_return_t,thread_t;
static uint32_t a630_started,a630_mode,a630_worker_state;
static unsigned selected=9,queued,runs,created,dropped,slept,terminated,stages,fail_create;
static int a630_worker_wait;
static void(*job)(void*,wait_result_t);
static void PE_parse_boot_argn(const char*k,unsigned*v,unsigned n){(void)k;assert(n==4);*v=selected;}
static void a630_stage(uint32_t n,const char*s){assert(n==1&&s);stages++;}
static void clock_interval_to_deadline(unsigned n,unsigned scale,uint64_t*out){assert(n==50&&scale==NSEC_PER_MSEC);*out=50000000;}
static int assert_wait_deadline(void*event,unsigned mode,uint64_t end){assert(event==&a630_worker_wait&&mode==THREAD_UNINT&&end==50000000);slept++;return 0;}
static void thread_block(unsigned c){assert(c==THREAD_CONTINUE_NULL&&slept==1);}
static void a630_run(unsigned mode){assert(mode==a630_mode);if(mode==9)assert(a630_worker_state==2&&slept==1);runs++;}
static int current_thread(void){return 17;}
static void thread_terminate(int t){assert(t==17&&a630_worker_state==3);terminated++;}
static int kernel_thread_start(void(*fn)(void*,wait_result_t),void*arg,int*out){assert(!arg&&runs==0);created++;job=fn;if(fail_create)return 5;*out=18;queued++;return 0;}
static void thread_deallocate(int t){assert(t==18);dropped++;}
'''+worker+init+r'''
int main(void){
 polaris_a630_init();assert(queued==1&&created==1&&runs==0&&dropped==1&&a630_worker_state==1);
 /* This point is reachable by BSD init/USB with the GPU job still pending. */
 unsigned USB_init_can_continue=1;assert(USB_init_can_continue&&runs==0);
 polaris_a630_init();assert(queued==1&&created==1&&runs==0);
 job(NULL,0);assert(runs==1&&terminated==1&&a630_worker_state==3);
 a630_started=0;selected=0;polaris_a630_init();assert(created==1&&runs==1);
 selected=10;polaris_a630_init();assert(created==1&&runs==1);
 a630_started=0;selected=8;polaris_a630_init();assert(created==1&&runs==2);
 a630_started=0;selected=9;fail_create=1;runs=0;polaris_a630_init();assert(created==2&&runs==0&&a630_worker_state==4&&queued==1);
 return 0;}
''')
    def test_real_deadline_stops_polls_and_forbids_resource_release(self):
        budget=body('static bool a630_budget_ok(struct a630_io *io)')
        owned=body('static bool a630_runtime_owned(void *opaque)')
        resources=body('static bool a630_resources_can_stop(void *opaque)')
        run(r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <assert.h>
struct a630_io {bool gmu_lease,runtime_lease,can_stop;uint64_t deadline;};
static uint64_t now;static uint32_t a630_budget_expired;static unsigned logged;
static void clock_get_uptime(uint64_t*out){*out=now;}
static uint32_t a630_pending_format(char*out,uint32_t n){assert(n>=2);out[0]='X';out[1]=0;return 1;}
static int capture(const char*f,const char*s){assert(f&&s[0]=='X');logged++;return 0;}
#define printf capture
'''+budget+owned+resources+r'''
int main(void){
 struct a630_io io={.gmu_lease=true,.runtime_lease=true,.can_stop=true,.deadline=100};
 now=99;assert(a630_budget_ok(&io)&&a630_runtime_owned(&io)&&io.can_stop&&!logged);
 now=100;assert(!a630_runtime_owned(&io)&&!io.can_stop&&a630_budget_expired==1&&logged==1);
 for(unsigned n=0;n<100;n++)assert(!a630_budget_ok(&io));assert(logged==1&&!io.can_stop);
 assert(io.gmu_lease&&io.runtime_lease); /* expiry is not proof of DMA drain */
 io.can_stop=true;assert(!a630_resources_can_stop(&io)&&!io.can_stop); /* cleanup cannot re-admit teardown after expiry */
 io.deadline=0;now=UINT64_MAX;assert(a630_runtime_owned(&io)); /* legacy modes unchanged */
 io.gmu_lease=false;assert(!a630_runtime_owned(&io));return 0;}
''')
    def test_progress_is_armed_before_announcing_new_cb0_access(self):
        begin=body('static void a630_access_begin(unsigned op,unsigned bank,uint32_t offset)')
        end=body('static void a630_access_end(void)')
        run(r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <assert.h>
static unsigned a630_mode=9,logs;static uint64_t a630_progress_access,a630_last_cb_access;
static int capture(const char*f,unsigned op,unsigned off){
 assert(f&&((a630_progress_access>>63)==1)&&((a630_progress_access>>56)&15)==op&&(unsigned)a630_progress_access==off);logs++;return 0;}
#define printf capture
'''+begin+end+r'''
int main(void){
 a630_access_begin(1,3,0x87f4);assert(logs==1&&(a630_progress_access>>63)==1);a630_access_end();assert(!(a630_progress_access>>63));
 for(unsigned n=0;n<1000;n++){a630_access_begin(1,1,0x111c);a630_access_end();a630_access_begin(1,3,0x87f4);a630_access_end();}
 assert(logs==1); /* no per-TLB-poll console flood despite lease reads */
 a630_access_begin(4,3,0x8020);assert(logs==2&&(unsigned)a630_progress_access==0x8020);a630_access_end();
 a630_mode=8;uint64_t before=a630_progress_access;a630_access_begin(1,3,0x8000);assert(a630_progress_access==before&&logs==2);return 0;}
''')
if __name__=='__main__':unittest.main()
