"""Actual original-table checks and info-query ABI with mocked host boundaries."""
from pathlib import Path
import unittest
from .test_polaris_gpu_lifetime import function
from .test_polaris_gpu_bootstrap import run

ROOT = Path(__file__).resolve().parents[2]
PATCH = ROOT / 'xnu/profiles/polaris/0901-polaris-verified-original-extension-table-state.patch'


def additions():
    return '\n'.join(x[1:] for x in PATCH.read_text().splitlines()
                     if x.startswith('+') and not x.startswith('+++'))


class ExtensionStateTests(unittest.TestCase):
    def test_original_table_requires_full_read_hash_metadata_and_root(self):
        actual = function(additions(), 'static bool pgpu_verify_extension_table(')
        run(r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
typedef int vnode_t,vfs_context_t;
#define NULLVP 0
#define MNT_ROOTFS 1
#define VNODE_LOOKUP_NOFOLLOW 2
#define VNODE_LOOKUP_NOCROSSMOUNT 4
#define Z_WAITOK 1
#define UIO_READ 1
#define UIO_SYSSPACE 2
#define caddr_t char*
struct vnode_attr{unsigned va_uid,va_gid,va_mode;uint64_t va_data_size;};
#define VATTR_INIT(a) memset(a,0,sizeof(*(a)))
#define VATTR_WANTED(a,b) ((void)(a))
#define VATTR_IS_SUPPORTED(a,b) ((void)(a),supported)
static unsigned allowed=1,regular=1,rootfs=1,supported=1,lookup_error,attr_error;
static unsigned uid,gid=80,mode=0644,alloc_error,read_error,short_read,digest_good=1;
static unsigned refs,puts_,allocations,frees,lose_root;
static uint64_t bytes=104731;
static bool polaris_ram_overlay_allowed(void){return allowed;}
static int vfs_context_kernel(void){return 3;}
static int vnode_lookup(const char*p,int f,int*out,int c){assert(!strcmp(p,"/System/Library/xpc/extensions.plist")&&f==6&&c==3);if(lookup_error)return 1;*out=9;refs++;return 0;}
static bool vnode_isreg(int v){assert(v==9);return regular;}
static int vnode_mount(int v){assert(v==9);return 2;}
static int vfs_flags(int v){assert(v==2);return rootfs;}
static int vnode_getattr(int v,struct vnode_attr*a,int c){assert(v==9&&c==3);a->va_uid=uid;a->va_gid=gid;a->va_mode=mode;a->va_data_size=bytes;return attr_error;}
static void vnode_put(int v){assert(v==9);puts_++;}
static void*kalloc_data(size_t n,int f){assert(n==104731&&f==1);if(alloc_error)return NULL;allocations++;return malloc(n);}
static void kfree_data(void*p,size_t n){assert(p&&n==104731);frees++;free(p);}
static int vfs_context_ucred(int c){assert(c==3);return 4;}
static int vfs_context_proc(int c){assert(c==3);return 5;}
static int vn_rdwr(int rw,int vp,char*p,int n,long long at,int seg,int flags,int cred,int*resid,int proc){assert(rw==1&&vp==9&&p&&n==104731&&!at&&seg==2&&!flags&&cred==4&&proc==5);*resid=short_read?1:0;if(read_error)return 14;memset(p,0xab,n);if(lose_root)allowed=0;return 0;}
static bool pgpu_digest(const void*p,size_t n,const uint8_t*h){assert(n==104731&&h[0]==0xe9&&h[31]==0xa4&&((const uint8_t*)p)[n-1]==0xab);return digest_good;}
static int log_(const char*f,...){assert(f);return 0;}
#define printf log_
''' + actual + r'''
#define CHECK(want) do{assert(pgpu_verify_extension_table()==(want));assert(refs==puts_&&allocations==frees);}while(0)
int main(void){CHECK(true);
 uid=501;CHECK(false);uid=0;gid=501;CHECK(false);gid=80;
 mode=0664;CHECK(false);mode=0644;bytes=104730;CHECK(false);bytes=104731;
 regular=0;CHECK(false);regular=1;rootfs=0;CHECK(false);rootfs=1;
 supported=0;CHECK(false);supported=1;attr_error=1;CHECK(false);attr_error=0;
 lookup_error=1;CHECK(false);lookup_error=0;alloc_error=1;CHECK(false);alloc_error=0;
 read_error=1;CHECK(false);read_error=0;short_read=1;CHECK(false);short_read=0;
 digest_good=0;CHECK(false);digest_good=1;lose_root=1;CHECK(false);lose_root=0;allowed=1;
 allowed=0;CHECK(false);allowed=1;CHECK(true);return 0;}
''')

    def test_info_query_has_verified_root_gate_preserves_PID1_and_copy_errors(self):
        text = additions()
        code = function(text, 'bool polaris_extension_table_verified(void)\n{')
        code += function(text, 'static int polaris_extension_boot_state(')
        run(r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#define user_addr_t uintptr_t
#define ENOPOLICY 103
struct proc{bool init;};
static uint32_t pgpu_extension_table;
static unsigned ready=1,allowed=1,out_error,copies,logs,root_checks;
static bool proc_isinitproc(struct proc*p){return p->init;}
static bool polaris_gpu_overlay_ready(void){return ready;}
static bool polaris_ram_overlay_allowed(void){root_checks++;return allowed;}
static int copyout(const void*p,user_addr_t out,size_t n){assert(n==8);copies++;if(out_error)return 14;memcpy((void*)out,p,n);return 0;}
static int proc_pid(struct proc*p){assert(p);return 42;}
static void proc_name(int p,char*out,size_t n){assert(p==42&&n>4);memcpy(out,"pkd",4);}
static int log_(const char*f,...){assert(f);logs++;return 0;}
#define printf log_
''' + code + r'''
int main(void){struct proc p={0};uint64_t out=0xdead;
 assert(polaris_extension_boot_state(&p,(uintptr_t)&out)==ENOPOLICY&&out==0xdead&&!copies);
 pgpu_extension_table=1;p.init=1;assert(polaris_extension_boot_state(&p,(uintptr_t)&out)==ENOPOLICY&&!copies&&!root_checks);p.init=0;
 allowed=0;assert(polaris_extension_boot_state(&p,(uintptr_t)&out)==ENOPOLICY&&!copies);allowed=1;
 ready=0;assert(polaris_extension_boot_state(&p,(uintptr_t)&out)==ENOPOLICY&&!copies);ready=1;
 assert(!polaris_extension_boot_state(&p,(uintptr_t)&out)&&out==0x86&&copies==1);
 out=0xdead;out_error=1;assert(polaris_extension_boot_state(&p,(uintptr_t)&out)==14&&out==0xdead);out_error=0;
 for(unsigned n=0;n<40;n++)assert(!polaris_extension_boot_state(&p,(uintptr_t)&out)&&out==0x86);
 assert(logs==16);return 0;}
''')


if __name__ == '__main__':
    unittest.main()
