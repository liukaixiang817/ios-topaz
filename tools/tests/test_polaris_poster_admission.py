"""Actual narrow PosterBoard decisions with mocked VFS/copy boundaries.

These are host checks, not proof of dyld loading or rendering on the phone.
"""
from pathlib import Path
import unittest
from .test_polaris_gpu_lifetime import function
from .test_polaris_gpu_bootstrap import run

ROOT = Path(__file__).resolve().parents[2]
PATCH = ROOT / 'xnu/profiles/polaris/0900-polaris-exact-PosterBoard-preview-loader.patch'


def additions():
    return '\n'.join(line[1:] for line in PATCH.read_text().splitlines()
                     if line.startswith('+') and not line.startswith('+++'))


class PosterAdmissionTests(unittest.TestCase):
    def test_real_executable_requires_exact_overlay_root_vnode_and_owner(self):
        code = function(additions(), 'bool polaris_poster_preview_allowed(void)\n{')
        run(r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
typedef int vnode_t;
#define NULLVP 0
#define MNT_ROOTFS 1
#define VNODE_LOOKUP_NOFOLLOW 2
#define VNODE_LOOKUP_NOCROSSMOUNT 4
struct vnode_attr{unsigned va_uid,va_mode;};
#define VATTR_INIT(a) memset(a,0,sizeof(*(a)))
#define VATTR_WANTED(a,b) ((void)(a))
#define VATTR_IS_SUPPORTED(a,b) ((void)(a),supported)
static uint32_t pgpu_poster_preview=1;
static unsigned ready=1,allowed=1,image=9,expected=9,uid,mode=0755,rootfs=1;
static unsigned refs,releases,regular=1,supported=1,attr_error,lookup_error;
static const char *process_name="PosterBoard";
static bool polaris_gpu_overlay_ready(void){return ready;}
static bool polaris_ram_overlay_allowed(void){return allowed;}
static int current_proc(void){return 1;}
static int proc_pid(int p){assert(p==1);return 42;}
static void proc_name(int p,char*out,size_t n){assert(p==42);size_t z=strlen(process_name);assert(n>z);memcpy(out,process_name,z+1);}
static int proc_getexecutablevnode(int p){assert(p==1);if(image)refs++;return image;}
static bool vnode_isreg(int v){assert(v==(int)image);return regular;}
static int vnode_mount(int v){assert(v==(int)image);return 2;}
static int vfs_flags(int m){assert(m==2);return rootfs;}
static int vfs_context_kernel(void){return 3;}
static int vnode_getattr(int v,struct vnode_attr*a,int c){assert(v==(int)image&&c==3);a->va_uid=uid;a->va_mode=mode;return attr_error;}
static int vnode_lookup(const char*p,int f,int*out,int c){assert(!strcmp(p,"/Applications/PosterBoard.app/PosterBoard")&&f==6&&c==3);if(lookup_error)return 1;*out=expected;if(*out)refs++;return *out?0:1;}
static void vnode_put(int v){assert(v>0);releases++;}
''' + code + r'''
#define CHECK(want) do{assert(polaris_poster_preview_allowed()==(want));assert(refs==releases);}while(0)
int main(void){CHECK(true);
 expected=8;CHECK(false);expected=9;
 image=8;CHECK(false);image=9;
 uid=501;CHECK(false);uid=0;
 mode=0775;CHECK(false);mode=0755;
 rootfs=0;CHECK(false);rootfs=1;
 regular=0;CHECK(false);regular=1;
 supported=0;CHECK(false);supported=1;
 attr_error=1;CHECK(false);attr_error=0;
 lookup_error=1;CHECK(false);lookup_error=0;
 image=0;CHECK(false);image=9;
 process_name="SpringBoard";CHECK(false);process_name="PosterBoard";
 pgpu_poster_preview=0;CHECK(false);pgpu_poster_preview=1;
 allowed=0;CHECK(false);allowed=1;
 ready=0;CHECK(false);ready=1;CHECK(true);return 0;}
''')

    def test_policy_only_returns_path_variable_bit_and_preserves_copy_errors(self):
        code = function(additions(), 'static int polaris_poster_dyld_policy(')
        run(r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#define user_addr_t uintptr_t
static unsigned in_error,out_error,in_calls,out_calls,logs;
static int copyin(user_addr_t a,void*out,size_t n){in_calls++;assert(n==16);if(in_error)return 14;memcpy(out,(void*)a,n);return 0;}
static int copyout(const void*in,user_addr_t out,size_t n){out_calls++;assert(n==8);if(out_error)return 14;memcpy((void*)out,in,n);return 0;}
static int log_(const char*fmt,...){assert(fmt);logs++;return 0;}
#define printf log_
''' + code + r'''
int main(void){uint64_t out=0xdead,request[]={0,(uintptr_t)&out};
 assert(!polaris_poster_dyld_policy((uintptr_t)request)&&out==2&&in_calls==1&&out_calls==1);
 out=0xdead;in_error=1;assert(polaris_poster_dyld_policy((uintptr_t)request)==14&&out==0xdead&&out_calls==1);in_error=0;
 out_error=1;assert(polaris_poster_dyld_policy((uintptr_t)request)==14&&out==0xdead);out_error=0;
 for(unsigned i=0;i<20;i++)assert(!polaris_poster_dyld_policy((uintptr_t)request)&&out==2);
 assert(logs==8);return 0;}
''')


if __name__ == '__main__':
    unittest.main()
