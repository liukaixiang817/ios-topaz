"""Actual bootstrap adapters with instrumented VFS/policy/diagnostic calls.
These tests do not execute HFS, the phone or the GPU.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest
from .test_polaris_gpu_lifetime import function

ROOT = Path(__file__).resolve().parents[2]


def run(text):
    with tempfile.TemporaryDirectory() as directory:
        p = Path(directory)
        (p / 'test.c').write_text(text)
        subprocess.run(['/usr/bin/clang', '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', str(p / 'test.c'), '-o', str(p / 'test')], check=True)
        subprocess.run([str(p / 'test')], check=True)


class GPUBootstrapTests(unittest.TestCase):
    def test_repeated_diagnostics_preserve_first_snapshot_and_new_faults_without_repainting_immutable_rows(self):
        actual = function((ROOT / 'tools/polaris-gpu-diagnostics.h').read_text(), 'static bool\npolaris_diag_report(')
        run(r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#define POLARIS_DIAG_SLOTS 16
#define POLARIS_DIAG_BYTES 240
static unsigned touch,usb_reports,gpu_reports,gpu_status,usb_status,enabled=1,faults,heartbeats;
static int polaris_diag_lock,sweet_ufs_lock;
static char polaris_diag_lines[16][240];
static struct{unsigned used,limit;uint64_t dirty_blocks,written_blocks;}polaris_root_cow={1043,32768,4110,4250};
static struct{uint64_t size;}polaris_root_arena={512ull<<20};
static uint64_t polaris_cow_failures,polaris_base_calls=4140,polaris_ram_reads=3,polaris_ram_merges=9,polaris_full_writes=110;
static bool polaris_ram_cow_enabled=true,polaris_io_failed;
static bool polaris_diag_enabled(void){return enabled;}
static void lck_spin_lock(int*p){assert(p==&polaris_diag_lock);}
static void lck_spin_unlock(int*p){assert(p==&polaris_diag_lock);}
static bool lck_mtx_try_lock(int*p){assert(p==&sweet_ufs_lock);return true;}
static void lck_mtx_unlock(int*p){assert(p==&sweet_ufs_lock);}
void polaris_touch_report(void){touch++;}
void polaris_usb_report(void){usb_reports++;}
uint32_t polaris_usb_status(char*out,uint32_t n){return snprintf(out,n,"USB %u",usb_status);}
void polaris_a630_report(void){gpu_reports++;}
uint32_t polaris_a630_status(void){return gpu_status;}
uint32_t polaris_a630_details(char*out,uint32_t n){return snprintf(out,n,"pending");}
uint32_t polaris_gpu_overlay_line(char*out,uint32_t n){return snprintf(out,n,"GLB S4 F0");}
uint32_t polaris_gpu_client_line(char*out,uint32_t n){return snprintf(out,n,"GA O0 S0");}
static int log_(const char*format,...){char line[512];va_list ap;va_start(ap,format);int n=vsnprintf(line,sizeof(line),format,ap);va_end(ap);
 if(strstr(line,"fault one")||strstr(line,"fault two"))faults++;
 if(strstr(line,"D GL BOOT:"))heartbeats++;return n;}
#define printf log_
''' + actual + r'''
int main(void){strcpy(polaris_diag_lines[0],"fault one");
 assert(polaris_diag_report()&&gpu_reports==1&&usb_reports==1&&faults==1);
 for(unsigned n=0;n<100;n++)assert(polaris_diag_report());
 assert(gpu_reports==1&&usb_reports==1&&faults==1&&heartbeats==101);
 gpu_status=0x300;usb_status=12;strcpy(polaris_diag_lines[1],"fault two");
 assert(polaris_diag_report()&&gpu_reports==2&&usb_reports==2&&faults==2);
 for(unsigned n=0;n<100;n++)assert(polaris_diag_report());
 assert(gpu_reports==2&&usb_reports==2&&faults==2&&heartbeats==202);
 assert(polaris_root_cow.used==1043&&polaris_base_calls==4140&&polaris_root_cow.written_blocks==4250);
 enabled=0;unsigned before=touch;assert(!polaris_diag_report()&&touch==before);return 0;}
''')

    def test_real_writer_chunks_sync_and_stops_on_short_write_or_lost_COW_guard(self):
        actual = function((ROOT / 'tools/polaris-gpu-overlay.c').read_text(), 'static int pgpu_write(')
        run(r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <assert.h>
typedef long off_t;typedef char *caddr_t;typedef int vfs_context_t,vnode_t;
#define PGPU_FILES 6
#define NULLVP 0
#define EPERM 1
#define EIO 5
#define FWRITE 2
#define O_CREAT 4
#define O_EXCL 8
#define O_NOFOLLOW 16
#define MNT_ROOTFS 32
#define UIO_WRITE 1
#define UIO_SYSSPACE 2
#define IO_SYNC 64
#define MIN(a,b) ((a)<(b)?(a):(b))
static const char *pgpu_paths[6]={"mesa","gl","inject","wrapper","test","init"};
struct pgpu_file {const uint8_t *data,*sha;uint32_t bytes,kind;};
static unsigned guard,writes,closed,opened,size_queries,short_at,deny_after,last_step,last_error;
static uint32_t offset,maximum;static int close_error;
static bool polaris_ram_overlay_allowed(void){guard++;return !deny_after||guard<=deny_after;}
static int vfs_context_kernel(void){return 7;}
static int vnode_open(const char*p,int flags,int mode,int v,vnode_t*out,int ctx){
 assert(p==pgpu_paths[0]&&flags==(FWRITE|O_CREAT|O_EXCL|O_NOFOLLOW)&&mode==0644&&!v&&ctx==7);opened++;*out=9;return 0;}
static bool vnode_isreg(int v){assert(v==9);return true;}
static int vnode_mount(int v){assert(v==9);return 10;}
static int vfs_flags(int m){assert(m==10);return MNT_ROOTFS;}
static int vfs_context_ucred(int c){assert(c==7);return 11;}
static int vfs_context_proc(int c){assert(c==7);return 12;}
static void pgpu_note(unsigned s,unsigned f,uint32_t d,uint32_t t,int e,bool p){
 (void)p;assert(f==0&&d<=t);last_step=s;last_error=e;}
static int vn_rdwr(int rw,int v,caddr_t p,int bytes,off_t at,int seg,int flags,int cred,int*resid,int proc){
 assert(rw==UIO_WRITE&&v==9&&p&&bytes>0&&bytes<=128*1024&&at==offset&&seg==UIO_SYSSPACE&&flags==IO_SYNC&&cred==11&&proc==12);
 writes++;if((unsigned)bytes>maximum)maximum=(unsigned)bytes;
 *resid=writes==short_at?1:0;offset+=(uint32_t)bytes;return 0;}
static int vnode_size(int v,off_t*out,int ctx){assert(v==9&&ctx==7);size_queries++;*out=offset;return 0;}
static int vnode_close(int v,int flags,int ctx){assert(v==9&&flags==FWRITE&&ctx==7);closed++;return close_error;}
''' + actual + r'''
int main(void){
 static uint8_t data[300001];struct pgpu_file file={data,0,sizeof(data),0};
 assert(!pgpu_write(0,&file));assert(writes==3&&maximum==131072&&offset==sizeof(data)&&closed==1&&size_queries==1&&last_step==6&&!last_error);
 guard=writes=closed=opened=size_queries=offset=0;short_at=2;
 assert(pgpu_write(0,&file)==EIO);assert(writes==2&&closed==1&&!size_queries&&last_error==EIO);
 guard=writes=closed=opened=size_queries=offset=short_at=0;deny_after=2;
 assert(pgpu_write(0,&file)==EPERM);assert(writes==1&&closed==1&&!size_queries&&last_error==EPERM);
 guard=writes=closed=opened=size_queries=offset=deny_after=0;close_error=19;
 assert(pgpu_write(0,&file)==19&&closed==1&&last_error==19);
 assert(pgpu_write(PGPU_FILES,&file)==EPERM);
 return 0;}
''')

    def test_real_progress_reader_is_bounded_consistent_and_never_waits(self):
        text = (ROOT / 'tools/polaris-gpu-overlay.c').read_text()
        state = text[text.index('static uint32_t pgpu_progress_seq;'):text.index('static int pgpu_wait;')]
        actual = function(text, 'uint32_t polaris_gpu_overlay_line(')
        run(r'''
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
''' + state + actual + r'''
int main(void){char text[68];assert(!polaris_gpu_overlay_line(0,68)&&!polaris_gpu_overlay_line(text,0));
 assert(!polaris_gpu_overlay_line(text,68));memset(&pgpu_progress,0xff,sizeof(pgpu_progress));
 pgpu_progress_seq=1;assert(!polaris_gpu_overlay_line(text,68));
 pgpu_progress_seq=2;unsigned n=polaris_gpu_overlay_line(text,68);assert(n==strlen(text)&&n<=67);
 assert(strstr(text,"GLB S")&&strstr(text," Bffffffff/ffffffff"));return 0;}
''')

    def test_non_target_AMFI_preserves_absent_policy_result_and_PID1_never_looks_up_files(self):
        # Public patch contains the complete small policy callback; reconstruct
        # its resulting text from the staged patch rather than private XNU.
        patch = (ROOT / 'xnu/profiles/polaris/0856-polaris-eagl-crash-containment-and-quiet-runtime.patch').read_text()
        lines = [l[1:] for l in patch.splitlines() if l.startswith((' ', '+')) and not l.startswith('+++')]
        actual = function('\n'.join(lines), 'static int polaris_gl_dyld_policy(')
        run('#include "'+str(ROOT/'tools/polaris-gl-status.h')+'"\n' + r'''
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <assert.h>
typedef uintptr_t user_addr_t;
#define ENOPOLICY 103
#define EINVAL 22
struct proc{bool init;};
static unsigned ready,kind,lookups,inputs,outputs,bad_in,policy_notes,crash_notes;
static unsigned proc_pid(struct proc*p){(void)p;return 42;}
static bool polaris_gpu_record_crash(const struct pgpu_crash*p,unsigned pid){assert(pid==42);crash_notes++;return pgpu_crash_valid(p);}
static int policy_error;
static void polaris_gpu_loader_policy(int e){policy_notes++;policy_error=e;}
static bool proc_isinitproc(struct proc*p){return p->init;}
static bool polaris_gpu_overlay_ready(void){return ready;}
static unsigned polaris_gpu_caller_kind(void){lookups++;return kind;}
static int copyin(user_addr_t at,void*out,size_t bytes){assert(at==1);inputs++;if(bytes==40){*(struct pgpu_crash*)out=(struct pgpu_crash){.signal=11,.pc=8};}else{assert(bytes==16);((uint64_t*)out)[1]=2;}return bad_in?14:0;}
static int copyout(const void*in,user_addr_t at,size_t bytes){assert(*(const uint64_t*)in==255&&at==2&&bytes==8);outputs++;return 0;}
''' + actual + r'''
int main(void){struct proc p={true};ready=1;kind=2;
 assert(polaris_gl_dyld_policy(&p,0x5a,1)==ENOPOLICY&&!lookups&&!inputs&&!outputs);
 p.init=false;assert(polaris_gl_dyld_policy(&p,1,1)==ENOPOLICY&&!lookups);
 ready=0;assert(polaris_gl_dyld_policy(&p,0x5a,1)==ENOPOLICY&&!lookups);
 ready=1;kind=1;assert(polaris_gl_dyld_policy(&p,0x5a,1)==ENOPOLICY&&lookups==1&&!inputs);
 kind=2;assert(!polaris_gl_dyld_policy(&p,0x5a,1)&&inputs==1&&outputs==1);
 bad_in=1;assert(polaris_gl_dyld_policy(&p,0x5a,1)==14&&outputs==1);
 assert(policy_notes==2&&policy_error==14);bad_in=0;
 assert(!polaris_gl_dyld_policy(&p,0x5b,1)&&crash_notes==1&&policy_notes==2);return 0;}
''')
