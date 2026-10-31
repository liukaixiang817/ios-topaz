"""Actual narrow mediaserverd decisions with mocked VFS/copy boundaries.

These are host checks, not proof of media service loading or HEVC decoding.
"""
from pathlib import Path
import unittest
from .test_polaris_gpu_lifetime import function
from .test_polaris_gpu_bootstrap import run

ROOT = Path(__file__).resolve().parents[2]
PATCH = ROOT / 'xnu/profiles/polaris/0902-polaris-exact-media-portrait-loader.patch'


def additions():
    return '\n'.join(line[1:] for line in PATCH.read_text().splitlines()
                     if line.startswith(('+',' ')) and not line.startswith('+++'))


class MediaAdmissionTests(unittest.TestCase):
    def test_real_executable_requires_exact_overlay_root_vnode_and_owner(self):
        code = function(additions(), 'bool polaris_media_compat_allowed(void)\n{')
        run(r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
typedef int vnode_t,vfs_context_t;
#define caddr_t char*
#define Z_WAITOK 1
#define UIO_READ 1
#define UIO_SYSSPACE 2
#define NULLVP 0
#define MNT_ROOTFS 1
#define VNODE_LOOKUP_NOFOLLOW 2
#define VNODE_LOOKUP_NOCROSSMOUNT 4
struct vnode_attr{unsigned va_uid,va_gid,va_mode;uint64_t va_data_size;};
#define VATTR_INIT(a) memset(a,0,sizeof(*(a)))
#define VATTR_WANTED(a,b) ((void)(a))
#define VATTR_IS_SUPPORTED(a,b) ((void)(a),supported)
static uint32_t pgpu_poster_preview=1;
static unsigned ready=1,allowed=1,image=9,expected=9,uid,gid=0,mode=0755,rootfs=1;
static uint64_t bytes=188112;
static unsigned allocations,frees,allocation_error,read_error,short_read,digest_good=1;
static unsigned refs,releases,regular=1,supported=1,attr_error,lookup_error;
static const char *process_name="mediaserverd";
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
static int vnode_getattr(int v,struct vnode_attr*a,int c){assert(v==(int)image&&c==3);a->va_uid=uid;a->va_gid=gid;a->va_mode=mode;a->va_data_size=bytes;return attr_error;}
static int vnode_lookup(const char*p,int f,int*out,int c){assert(!strcmp(p,"/usr/sbin/mediaserverd")&&f==6&&c==3);if(lookup_error)return 1;*out=expected;if(*out)refs++;return *out?0:1;}
static void vnode_put(int v){assert(v>0);releases++;}
static void *kalloc_data(size_t n,int f){assert(n==188112&&f==Z_WAITOK);if(allocation_error)return NULL;allocations++;return malloc(n);}
static void kfree_data(void*p,size_t n){assert(p&&n==188112);frees++;free(p);}
static int vfs_context_ucred(int c){assert(c==3);return 4;}
static int vfs_context_proc(int c){assert(c==3);return 5;}
static int vn_rdwr(int rw,int v,char*p,int n,long long at,int seg,int flags,int cred,int*resid,int proc){assert(rw==UIO_READ&&v==(int)image&&p&&n==188112&&!at&&seg==UIO_SYSSPACE&&!flags&&cred==4&&proc==5);*resid=short_read?1:0;if(read_error)return 14;memset(p,0xab,n);return 0;}
static bool pgpu_digest(const void*p,size_t n,const uint8_t*h){assert(p&&n==188112&&h[0]==0x35&&h[31]==0x20&&((const uint8_t*)p)[n-1]==0xab);return digest_good;}
static int log_(const char*format,...){assert(format);return 0;}
#define printf log_
''' + code + r'''
#define CHECK(want) do{assert(polaris_media_compat_allowed()==(want));assert(refs==releases);assert(allocations==frees);}while(0)
int main(void){CHECK(true);
 expected=8;CHECK(false);expected=9;
 image=8;CHECK(false);image=9;
 uid=501;CHECK(false);uid=0;
 mode=0777;CHECK(false);mode=0755;
 gid=501;CHECK(false);gid=0;
 bytes=188111;CHECK(false);bytes=188112;
 allocation_error=1;CHECK(false);allocation_error=0;
 read_error=1;CHECK(false);read_error=0;
 short_read=1;CHECK(false);short_read=0;
 digest_good=0;CHECK(false);digest_good=1;
 rootfs=0;CHECK(false);rootfs=1;
 regular=0;CHECK(false);regular=1;
 supported=0;CHECK(false);supported=1;
 attr_error=1;CHECK(false);attr_error=0;
 lookup_error=1;CHECK(false);lookup_error=0;
 image=0;CHECK(false);image=9;
 process_name="SpringBoard";CHECK(false);process_name="mediaserverd";
 pgpu_poster_preview=0;CHECK(false);pgpu_poster_preview=1;
 allowed=0;CHECK(false);allowed=1;
 ready=0;CHECK(false);ready=1;CHECK(true);return 0;}
''')

    def test_policy_only_returns_path_variable_bit_and_preserves_copy_errors(self):
        code = function(additions(), 'static int polaris_media_dyld_policy(')
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
 assert(!polaris_media_dyld_policy((uintptr_t)request)&&out==2&&in_calls==1&&out_calls==1);
 out=0xdead;in_error=1;assert(polaris_media_dyld_policy((uintptr_t)request)==14&&out==0xdead&&out_calls==1);in_error=0;
 out_error=1;assert(polaris_media_dyld_policy((uintptr_t)request)==14&&out==0xdead);out_error=0;
 for(unsigned i=0;i<20;i++)assert(!polaris_media_dyld_policy((uintptr_t)request)&&out==2);
 assert(logs==8);return 0;}
''')


if __name__ == '__main__':
    unittest.main()
