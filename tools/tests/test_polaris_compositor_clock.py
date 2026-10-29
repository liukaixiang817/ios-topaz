"""Scoped environment and bounded read-only ABI checks, not CA/SD845 emulation."""
from pathlib import Path
import unittest
from .test_polaris_gpu_bootstrap import run
from .test_polaris_gpu_lifetime import function

ROOT = Path(__file__).resolve().parents[2]
HEADER = '#include "' + str(ROOT / 'tools/polaris-compositor-clock.h') + '"\n'
LAYOUT = r'''
static void put32(unsigned char*p,unsigned n){memcpy(p,&n,4);}
static void put64(unsigned char*p,uint64_t n){memcpy(p,&n,8);}
static void layout(unsigned char*p){memset(p,0,200);put32(p,0xfeedfacf);put32(p+4,0x100000c);put32(p+12,6);put32(p+16,3);put32(p+20,168);
 put32(p+32,0x1b);put32(p+36,24);const unsigned char u[]={0x9e,0x40,0xb2,0xeb,0x26,0x0c,0x3a,0xf1,0xae,0x45,0xa1,0xa5,0x51,0xa8,0xc1,0xb9};memcpy(p+40,u,16);
 put32(p+56,0x19);put32(p+60,72);put64(p+80,PCC_TEXT_BASE);put64(p+88,0x34d000);put32(p+116,1);
 put32(p+128,0x19);put32(p+132,72);put64(p+152,0x1e1df4a00);put64(p+160,0x3f38);put32(p+188,1);}
'''


class CompositorClockTests(unittest.TestCase):
    def test_exact_bounded_unique_tokens_and_real_POSIX_environment_scope(self):
        run(HEADER + r'''
#include <assert.h>
#include <stdlib.h>
int main(void){unsetenv(PCC_FORCE);unsetenv(PCC_ENV);
 assert(!pcc_request("",1));assert(pcc_request(0,1)<0);
 assert(pcc_request("ca_vbl=1",8)<0);assert(pcc_request("ca_vbl=1",9)==1);
 assert(pcc_request("x=ca_vbl=1",12)==0);assert(pcc_request("ca_vbl=10",10)<0);
 assert(pcc_request("ca_vbl=1 ca_vbl=0",20)<0);assert(pcc_request("ca_vbl=1 ca_vbl=x",20)<0);
 assert(pcc_request("\tca_vbl=0\n",16)==2);
 assert(!pcc_environment("ca_vbl=1",9,0,getenv,setenv,unsetenv));assert(!getenv(PCC_FORCE)&&!getenv(PCC_ENV));
 assert(!pcc_environment("polarisgl=1",12,1,getenv,setenv,unsetenv));
 assert(pcc_environment("ca_vbl=1",9,1,getenv,setenv,unsetenv)==1);
 assert(!strcmp(getenv(PCC_FORCE),"1")&&!strcmp(getenv(PCC_ENV),"1"));
 assert(pcc_environment("ca_vbl=0",9,1,getenv,setenv,unsetenv)==-2);assert(!strcmp(getenv(PCC_FORCE),"1"));
 unsetenv(PCC_FORCE);unsetenv(PCC_ENV);assert(pcc_environment("ca_vbl=0",9,1,getenv,setenv,unsetenv)==2);
 assert(!getenv(PCC_FORCE)&&!strcmp(getenv(PCC_ENV),"0"));unsetenv(PCC_ENV);
 setenv(PCC_FORCE,"existing",1);assert(pcc_environment("ca_vbl=1",9,1,getenv,setenv,unsetenv)==-2);assert(!strcmp(getenv(PCC_FORCE),"existing"));
 return 0;}
''')

    def test_failed_environment_changes_roll_back_or_refuse_exec(self):
        run(HEADER + r'''
#include <assert.h>
static char force[8],marker[8];static unsigned call,fail,unset_fail,bad_read;
static char*get_(const char*n){char*p=!strcmp(n,PCC_FORCE)?force:marker;return *p?(bad_read&&!strcmp(n,PCC_ENV)?"bad":p):0;}
static int set_(const char*n,const char*v,int overwrite){assert(overwrite);if(++call==fail)return -1;strcpy(!strcmp(n,PCC_FORCE)?force:marker,v);return 0;}
static int unset_(const char*n){if(unset_fail)return -1;*(!strcmp(n,PCC_FORCE)?force:marker)=0;return 0;}
static void reset(void){*force=*marker=0;call=fail=unset_fail=bad_read=0;}
int main(void){reset();fail=1;assert(pcc_environment("ca_vbl=1",9,1,get_,set_,unset_)==-3);assert(!*force&&!*marker);
 reset();fail=2;assert(pcc_environment("ca_vbl=1",9,1,get_,set_,unset_)==-3);assert(!*force&&!*marker);
 reset();bad_read=1;assert(pcc_environment("ca_vbl=1",9,1,get_,set_,unset_)==-3);assert(!*force&&!*marker);
 reset();fail=2;unset_fail=1;assert(pcc_environment("ca_vbl=1",9,1,get_,set_,unset_)==-4);assert(*force);
 reset();assert(pcc_environment("ca_vbl=1 ca_vbl=1",20,1,get_,set_,unset_)<0);assert(!call&&!*force&&!*marker);return 0;}
''')

    def test_layout_rejects_truncation_wrong_UUID_overlap_permissions_and_mutations(self):
        run(HEADER + '#include <assert.h>\n' + LAYOUT + r'''
int main(void){unsigned char a[200],b[200];layout(a);assert(pcc_layout(a,200));
 for(unsigned n=0;n<200;n++)assert(!pcc_layout(a,n));
 memcpy(b,a,200);b[40]^=1;assert(!pcc_layout(b,200));
 memcpy(b,a,200);put32(b+188,0);assert(!pcc_layout(b,200));
 memcpy(b,a,200);put64(b+160,0x100);assert(!pcc_layout(b,200));
 memcpy(b,a,200);put64(b+80,0);put64(b+88,UINT64_MAX);assert(!pcc_layout(b,200));
 memcpy(b,a,200);put32(b+36,23);assert(!pcc_layout(b,200));
 memcpy(b,a,200);put32(b+16,256);assert(!pcc_layout(b,200));
 uint32_t x=123;for(unsigned i=0;i<10000;i++){memcpy(b,a,200);x=x*1664525+1013904223;unsigned n=x%200;b[n]^=(unsigned char)(1+(x>>24));(void)pcc_layout(b,200);}
 assert(!pcc_span(UINT64_MAX,8,0,UINT64_MAX));assert(pcc_span(20,8,16,12));assert(!pcc_span(20,8,16,11));return 0;}
''')

    def test_actual_readonly_target_adapter_checks_signature_before_sampling_choice(self):
        text = (ROOT / 'userland/gpu/polaris-inject.c').read_text()
        code = function(text, 'static int clock_target_prepare(') + function(text, 'static void clock_note(')
        run(HEADER + r'''
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <mach-o/loader.h>
#define CACHE_BASE 0x180000000ULL
static void*cache;static size_t cache_bytes;static struct mach_header_64 *image;
static const char *image_name;static const uint64_t *clock_once;static const uint8_t *clock_choice;
static mach_timebase_info_data_t clock_timebase;static unsigned clock_trial_mode,bad_base;
static char line[1024];
static const void*range(size_t*n){*n=cache_bytes;return cache;}
static uint32_t fake_images(void){return 1;}
static const char*fake_name(uint32_t n){assert(!n);return image_name;}
static const struct mach_header*fake_header(uint32_t n){assert(!n);return (void*)image;}
static int timebase(mach_timebase_info_t p){p->numer=125;p->denom=bad_base?0:3;return 0;}
static uint64_t fake_ticks(void){return 24000000;}
static int print_(FILE*f,const char*s,...){(void)f;va_list a;va_start(a,s);int n=vsnprintf(line,sizeof(line),s,a);va_end(a);return n;}
#define _dyld_get_shared_cache_range range
#define _dyld_image_count fake_images
#define _dyld_get_image_name fake_name
#define _dyld_get_image_header fake_header
#define mach_timebase_info timebase
#define mach_absolute_time fake_ticks
#define fprintf print_
''' + LAYOUT + code + r'''
int main(void){unsetenv(PCC_ENV);assert(!clock_target_prepare()&&!clock_once);
 cache_bytes=0x70000000;cache=mmap(0,cache_bytes,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);assert(cache!=MAP_FAILED);
 uintptr_t delta=(uintptr_t)cache-CACHE_BASE;
 image=(void*)(uintptr_t)(PCC_TEXT_BASE+delta);layout((void*)image);
 image_name="/System/Library/Frameworks/QuartzCore.framework/QuartzCore";
 const unsigned char bytes[]={0xfd,0x7b,0xbf,0xa9,0xfd,0x03,0x00,0x91,0x40,0x11,0x00,0xd0,0x00,0xd0,0x3e,0x91,0x8d,0x7f,0x61,0x95,0x60,0x00,0x00,0xb4,0x62,0x94,0x07,0x94,0xe0,0x00,0x00,0x35};
 memcpy((void*)(uintptr_t)(PCC_BLOCK+delta),bytes,32);memcpy((void*)(uintptr_t)(PCC_STRING+delta),PCC_FORCE,15);
 setenv(PCC_ENV,"0",1);assert(clock_target_prepare()==1&&clock_trial_mode==2);
 clock_note(12);assert(strstr(line,"ready=0 choice=0 window_frames=12"));
 *(uint64_t*)(uintptr_t)clock_once=UINT64_MAX;clock_note(13);assert(strstr(line,"us=1000000 mode=2 ready=1 choice=0 window_frames=13"));
 *(uint8_t*)(uintptr_t)clock_choice=1;setenv(PCC_ENV,"1",1);assert(clock_target_prepare()==1);clock_note(14);assert(strstr(line,"mode=1 ready=1 choice=1"));
 bad_base=1;assert(clock_target_prepare()==-8&&!clock_once);bad_base=0;
 ((unsigned char*)image)[40]^=1;assert(clock_target_prepare()==-6&&!clock_once);((unsigned char*)image)[40]^=1;
 ((unsigned char*)(uintptr_t)(PCC_BLOCK+delta))[0]^=1;assert(clock_target_prepare()==-7&&!clock_once);
 assert(!munmap(cache,cache_bytes));return 0;}
''')


if __name__ == '__main__':
    unittest.main()
