"""Actual exec environment/diagnostic boundaries; host only, no media decode."""
from pathlib import Path
import unittest
from .test_polaris_gpu_lifetime import function
from .test_polaris_gpu_bootstrap import run
ROOT=Path(__file__).resolve().parents[2]
PATCH=ROOT/'xnu/profiles/polaris/0903-polaris-exact-media-exec-and-bounded-diagnostics.patch'
def postimage():
    return '\n'.join(x[1:] for x in PATCH.read_text().splitlines()
                     if x.startswith(('+',' ')) and not x.startswith('+++'))
class MediaExecTests(unittest.TestCase):
    def test_actual_exec_preserves_argv_environment_and_ncargs_accounting(self):
        code=function(postimage(),'exec_polaris_media_environment(')
        run(r'''
#define _DARWIN_C_SOURCE
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#define IMGPF_IS_64BIT_ADDR 8
#define IMGPF_INTERPRET 1
#define UIO_SYSSPACE 2
#define TRUE 1
#undef CAST_USER_ADDR_T
#define CAST_USER_ADDR_T(s) ((uintptr_t)(s))
struct componentname{unsigned cn_namelen;const char*cn_nameptr;};
struct nameidata{struct componentname ni_cnd;};
struct image_params{int ip_vfs_context,ip_flags,ip_vp,ip_envc,ip_argspace,ip_strspace;struct nameidata*ip_ndp;char*ip_endargv,*ip_strendp;};
static unsigned pid1,ready=1,identity=1,add_error,calls,lookups,logs;
static int vfs_context_proc(int x){assert(x==2);return 3;}
static bool proc_isinitproc(int p){assert(p==3);return pid1;}
static bool polaris_gpu_overlay_ready(void){return ready;}
static bool polaris_media_image_allowed(int v){assert(v==9);lookups++;return identity;}
static int exec_add_user_string(struct image_params*p,uintptr_t s,int segment,int ncargs){assert(segment==2&&ncargs==1);calls++;if(add_error)return EFAULT;size_t n=strlen((char*)s)+1;assert(p->ip_strspace>=(int)n&&p->ip_argspace>=(int)n);memcpy(p->ip_strendp,(char*)s,n);p->ip_strendp+=n;p->ip_strspace-=n;p->ip_argspace-=n;return 0;}
static int log_(const char*f,...){assert(f);logs++;return 0;}
#define printf log_
''' + 'static int '+code+r'''
static char area[4096];static struct nameidata nd={{12,"mediaserverd"}};static struct image_params p;
static void reset(void){memset(area,0xaa,sizeof(area));memcpy(area,"argv-original",14);memcpy(area+14,"KEEP=value",11);p=(struct image_params){2,8,9,1,3000,3000,&nd,area+14,area+25};pid1=0;ready=identity=1;add_error=calls=lookups=0;}
static void append(const char*s){size_t n=strlen(s)+1;memcpy(p.ip_strendp,s,n);p.ip_strendp+=n;p.ip_envc++;}
int main(void){reset();int before=p.ip_argspace;assert(!exec_polaris_media_environment(&p,8));
 assert(calls==2&&p.ip_envc==3&&lookups==1&&!memcmp(area,"argv-original",14)&&!strcmp(area+14,"KEEP=value"));
 assert(strstr(area+25,"DYLD_INSERT_LIBRARIES=/usr/lib/libPolarisInject.dylib"));
 assert(p.ip_argspace==before-(int)(p.ip_strendp-(area+25))-16);
 calls=0;before=p.ip_argspace;assert(!exec_polaris_media_environment(&p,8)&&!calls&&p.ip_argspace==before);
 reset();append("POLARIS_MEDIA_COMPAT=1");assert(!exec_polaris_media_environment(&p,8)&&calls==1&&p.ip_envc==3);
 reset();append("DYLD_INSERT_LIBRARIES=/foreign");before=p.ip_envc;assert(exec_polaris_media_environment(&p,8)==EINVAL&&!calls&&p.ip_envc==before);
 reset();append("POLARIS_MEDIA_COMPAT=1");append("POLARIS_MEDIA_COMPAT=1");assert(exec_polaris_media_environment(&p,8)==EINVAL&&!calls);
 reset();append("POLARIS_MEDIA_COMPAT=0");assert(exec_polaris_media_environment(&p,8)==EINVAL&&!calls);
 reset();p.ip_argspace=8;assert(exec_polaris_media_environment(&p,8)==E2BIG&&!calls);
 reset();p.ip_strspace=1;assert(exec_polaris_media_environment(&p,8)==E2BIG&&!calls);
 reset();add_error=1;assert(exec_polaris_media_environment(&p,8)==EFAULT&&calls==1&&p.ip_envc==1);
 reset();p.ip_strendp--;assert(exec_polaris_media_environment(&p,8)==EINVAL&&!calls);
 reset();p.ip_envc=513;assert(exec_polaris_media_environment(&p,8)==E2BIG&&!calls);
 reset();pid1=1;assert(!exec_polaris_media_environment(&p,8)&&!calls&&!lookups);
 reset();identity=0;assert(!exec_polaris_media_environment(&p,8)&&!calls&&lookups==1);
 reset();ready=0;assert(!exec_polaris_media_environment(&p,8)&&!calls&&!lookups);
 reset();nd.ni_cnd.cn_nameptr="other-target";assert(!exec_polaris_media_environment(&p,8)&&!calls&&!lookups);nd.ni_cnd.cn_nameptr="mediaserverd";
 reset();p.ip_flags|=IMGPF_INTERPRET;assert(!exec_polaris_media_environment(&p,8)&&!calls&&!lookups);
 reset();assert(!exec_polaris_media_environment(&p,4)&&!calls&&!lookups);return 0;}
''')
    def test_actual_notice_rejects_unknown_short_kernel_pointers_and_retains_errors(self):
        code=function(postimage(),'static int polaris_media_diagnostic(')
        run('#include "'+str(ROOT/'tools/polaris-media-status.h')+'"\n'+r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#define user_addr_t uintptr_t
static unsigned in_error,logs;
static int copyin(uintptr_t p,void*out,size_t n){if(in_error)return EFAULT;memcpy(out,(void*)p,n);return 0;}
static int log_(const char*f,...){assert(f);logs++;return 0;}
#define printf log_
'''+code+r'''
int main(void){struct polaris_media_notice n={.magic=PMD_MAGIC,.bytes=sizeof(n),.kind=PMD_ENTRY};
 assert(!polaris_media_diagnostic((uintptr_t)&n)&&logs==1);
 in_error=1;assert(polaris_media_diagnostic((uintptr_t)&n)==EFAULT&&logs==1);in_error=0;
 n.bytes--;assert(polaris_media_diagnostic((uintptr_t)&n)==EINVAL);n.bytes++;
 n.kind=99;assert(polaris_media_diagnostic((uintptr_t)&n)==EINVAL);n.kind=PMD_THREAD;
 n.index=1u<<16;n.detail=8;assert(!polaris_media_diagnostic((uintptr_t)&n));
 n.detail=9;assert(polaris_media_diagnostic((uintptr_t)&n)==EINVAL);n.detail=8;
 n.index=(1u<<16)|64;assert(polaris_media_diagnostic((uintptr_t)&n)==EINVAL);n.index=1u<<16;
 n.pc[1]=UINT64_MAX;assert(polaris_media_diagnostic((uintptr_t)&n)==EINVAL);n.pc[1]=0;
 for(unsigned i=2;i<PMD_LIMIT;i++)assert(!polaris_media_diagnostic((uintptr_t)&n));
 assert(logs==PMD_LIMIT&&polaris_media_diagnostic((uintptr_t)&n)==EAGAIN&&logs==PMD_LIMIT);return 0;}
''')
if __name__=='__main__':unittest.main()
