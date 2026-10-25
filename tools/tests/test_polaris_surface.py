"""20H392 wrapper ABI and real new kernel entry points, ASan/UBSan.
No device/GPU is emulated as proven; actual iOS framework selftest is separate.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest
from tools.tests.test_polaris_gpu_lifetime import function
ROOT=Path(__file__).resolve().parents[2]

def run(code):
    with tempfile.TemporaryDirectory() as d:
        p=Path(d);(p/'test.cpp').write_text(code)
        subprocess.run(['/usr/bin/clang++','-std=c++17','-O1','-g','-Wall','-Wextra','-Werror',
                        '-fsanitize=address,undefined','-I',str(ROOT/'tools'),str(p/'test.cpp'),'-o',str(p/'test')],check=True)
        subprocess.run([str(p/'test')],check=True)

class SurfaceTests(unittest.TestCase):
    def test_wire_geometry_and_transactional_metadata(self):
        run(r'''
#include "polaris-surface.h"
#include <assert.h>
int main(){
 static_assert(sizeof(pgpu_surface_image)==32,"20H392 wire");
 pgpu_surface_image p={0x12345025,16,8,0x42475241,4,64,512};
 assert(pgpu_surface_image_valid(&p));p.bytes=511;assert(!pgpu_surface_image_valid(&p));
 p.width=13;p.bytes=500;assert(pgpu_surface_image_valid(&p));
 p.bytes=499;assert(!pgpu_surface_image_valid(&p));p.width=16;
 p.bytes=512;p.row=63;assert(!pgpu_surface_image_valid(&p));p.row=64;
 p.address=UINT64_MAX-511;assert(!pgpu_surface_image_valid(&p));p.address=1;
 p.width=16385;assert(!pgpu_surface_image_valid(&p));p.width=16;
 p.height=0;assert(!pgpu_surface_image_valid(&p));p.height=8;
 p.element=17;assert(!pgpu_surface_image_valid(&p));p.element=4;
 assert(!pgpu_surface_range(0,1)&&!pgpu_surface_range(1,0)&&!pgpu_surface_range(1,PGPU_SURFACE_MAX_BYTES+1ull));
 assert(pgpu_surface_range(37,1234));
 uint8_t a[0x72],b[0x70],old[0x72];memset(a,0xa5,sizeof(a));
 for(unsigned i=0;i<sizeof(b);i++)b[i]=(uint8_t)i;
 assert(pgpu_surface_bulk_apply(a+1,b,sizeof(b),0x7fff));
 assert(a[0]==0xa5&&a[0x71]==0xa5&&!memcmp(a+1,b,0x65));
 assert(a[0x66]==0xa5);memcpy(old,a,sizeof(a));
 assert(!pgpu_surface_bulk_apply(a+1,b,31,1)&&!memcmp(old,a,sizeof(a)));
 assert(!pgpu_surface_bulk_apply(a+1,b,0x71,1)&&!memcmp(old,a,sizeof(a)));
 assert(!pgpu_surface_bulk_apply(a+1,b,sizeof(b),0x8000)&&!memcmp(old,a,sizeof(a)));
 memset(a+1,0,0x70);assert(pgpu_surface_bulk_apply(a+1,b,0x65,0x4000));
 assert(a[0x65]==0x64&&a[0x64]==0);return 0;
}
''')

    def test_actual_wrap_pins_original_memory_and_unwinds_every_failure(self):
        patch=(ROOT/'xnu/profiles/polaris/0857-polaris-wrapped-surface-state.patch').read_text()
        added=''.join(l[1:]+'\n' for l in patch.splitlines() if l.startswith('+') and not l.startswith('+++'))
        actual=function(added,'IOSurfaceRootUserClient::wrap(')
        after=''.join(l[1:]+'\n' for l in patch.splitlines() if l[:1] in ('+',' ') and not l.startswith('+++'))
        destructor=function(after,'SweetSurface::free(')
        run(r'''
#include "polaris-surface.h"
#include <assert.h>
#include <stdlib.h>
typedef int IOReturn;typedef long long SInt64;
#define kIOReturnSuccess 0
#define kIOReturnBadArgument 1
#define kIOReturnNoMemory 2
#define kIOReturnVMError 3
#define kIOReturnNoResources 4
#define kSweetSurfaceWrapImage 6
#define kSweetSurfaceWrapMemory 7
#define kIOMapDefaultCache 0
#define kIOMapReadOnly 0x100
#define kIODirectionInOut 3
#define kIODirectionOut 1
#define SWEET_SURFACE_WIRED_MAX (1536ull<<20)
#define OSSafeReleaseNULL(p) do{if(p){p->release();p=nullptr;}}while(0)
static uint64_t sweet_surface_wired,seen_address,seen_size;
static unsigned attempts,pins,unpins,descriptors,surfaces,returned,readonly;
static bool fail_alloc,fail_descriptor,fail_prepare,fail_publish,fail_output,read_only;
static long long OSAddAtomic64(long long n,volatile long long*p){long long old=*p;*p+=n;return old;}
struct IOMemoryDescriptor{
 bool prepared=false;
 static IOMemoryDescriptor*withAddressRange(uint64_t a,uint64_t b,int dir,int task){
  assert(task==7);seen_address=a;seen_size=b;attempts++;
  if(fail_descriptor)return nullptr;descriptors++;auto*p=new IOMemoryDescriptor;p->direction=dir;return p;
 }
 int direction=0;
 int prepare(){if(fail_prepare || (read_only&&direction==3))return 1;prepared=true;pins++;return 0;}
 void complete(){assert(prepared);prepared=false;unpins++;}
 void release(){assert(!prepared);descriptors--;delete this;}
};
struct OSObject{void free(){}};
struct SweetSurface:OSObject{
 uint32_t width=0,height=0,pixelFormat=0,bytesPerRow=0,allocSize=0,mapCache=0;
 uint16_t bytesPerElement=0;uint8_t elementWidth=0,elementHeight=0;
 bool externalPrepared=false,wiredAccounted=false;IOMemoryDescriptor *memory=nullptr,*kernelMap=nullptr,*state=nullptr;
 void free();
 void release(){
  free();surfaces--;delete this;
 }
};
static SweetSurface *kept;
static SweetSurface*sweet_surface_alloc(){if(fail_alloc)return nullptr;surfaces++;return new SweetSurface;}
static bool sweet_surface_publish(SweetSurface*){return !fail_publish;}
static void sweet_surf_log_once(const char*,uint32_t){}
struct IOExternalMethodArguments{
 unsigned scalarInputCount=0,structureInputSize=0;void*structureInputDescriptor=nullptr;
 void*structureInput=nullptr;uint64_t scalarInput[2]={};
};
struct IOSurfaceRootUserClient{
 int fTask=7;
 int returnSurface(SweetSurface*s,IOExternalMethodArguments*){
  returned++;assert(s->memory&&s->externalPrepared&&s->wiredAccounted);
  readonly=s->mapCache&kIOMapReadOnly;
  /* Keep a separate observation of the live descriptor; method drops its own surface ref. */
  kept=s;return fail_output?5:0;
 }
 IOReturn wrap(uint32_t,IOExternalMethodArguments*);
};
''' + 'void\n'+destructor+'IOReturn\n'+actual+r'''
static void clean(){assert(!pins||pins==unpins);assert(!sweet_surface_wired&&!descriptors&&!surfaces);}
int main(){IOSurfaceRootUserClient c;IOExternalMethodArguments a;
 pgpu_surface_image p={0x12345025,16,8,0x42475241,4,64,512};
 a.structureInput=&p;a.structureInputSize=32;
 assert(c.wrap(6,&a)==0&&seen_address==p.address&&seen_size==512&&returned==1);clean();
 p.bytes=511;unsigned n=attempts;assert(c.wrap(6,&a)==1&&attempts==n);clean();p.bytes=512;
 a.structureInputSize=31;assert(c.wrap(6,&a)==1);a.structureInputSize=32;
 fail_alloc=true;assert(c.wrap(6,&a)==2);fail_alloc=false;clean();
 fail_descriptor=true;assert(c.wrap(6,&a)==3);fail_descriptor=false;clean();
 fail_prepare=true;assert(c.wrap(6,&a)==3);fail_prepare=false;clean();
 fail_publish=true;assert(c.wrap(6,&a)==4);fail_publish=false;clean();
 fail_output=true;assert(c.wrap(6,&a)==5);fail_output=false;clean();
 sweet_surface_wired=SWEET_SURFACE_WIRED_MAX;n=attempts;
 assert(c.wrap(6,&a)==2&&attempts==n&&sweet_surface_wired==SWEET_SURFACE_WIRED_MAX);
 sweet_surface_wired=0;clean();
 a={};a.scalarInputCount=2;a.scalarInput[0]=37;a.scalarInput[1]=1234;
 assert(c.wrap(7,&a)==0&&seen_address==37&&seen_size==1234);clean();
 read_only=true;assert(c.wrap(7,&a)==0&&readonly==kIOMapReadOnly);read_only=false;clean();
 a.scalarInput[1]=UINT64_MAX;assert(c.wrap(7,&a)==1);clean();return 0;
}
''')

    def test_actual_bulk_entry_requires_owned_id_and_complete_input(self):
        patch=(ROOT/'xnu/profiles/polaris/0857-polaris-wrapped-surface-state.patch').read_text()
        added=''.join(l[1:]+'\n' for l in patch.splitlines() if l.startswith('+') and not l.startswith('+++'))
        after=''.join(l[1:]+'\n' for l in patch.splitlines() if l[:1] in ('+',' ') and not l.startswith('+++'))
        actual=function(after,'IOSurfaceRootUserClient::setBulk(')
        run(r'''
#include "polaris-surface.h"
#include <assert.h>
#define kIOReturnSuccess 0
#define kIOReturnBadArgument 1
#define kIOReturnNotFound 2
typedef int IOReturn;
static unsigned locks;
static void IOLockLock(int){assert(!locks++);}
static void IOLockUnlock(int){assert(locks--==1);}
struct Descriptor{uint8_t data[0x88]={};size_t size=0x88;bool short_read=false;
 size_t getLength(){return size;}
 size_t readBytes(size_t off,void*out,size_t n){assert(!off&&n==0x88);if(short_read)return n-1;memcpy(out,data,n);return n;}
};
struct State{uint8_t data[0x100]={};void*getBytesNoCopy(){return data;}};
struct SweetSurface{State*state;};struct SweetSurfaceRef{SweetSurface*surface;};
struct IOExternalMethodArguments{unsigned scalarInputCount=0,structureInputSize=0;
 Descriptor*structureInputDescriptor=nullptr;void*structureInput=nullptr;};
struct IOSurfaceRootUserClient{int fLock=1;State state;SweetSurface surface={&state};SweetSurfaceRef ref={&surface};
 SweetSurfaceRef*findRef(uint32_t id,void*){assert(locks==1);return id==7?&ref:nullptr;}
 IOReturn setBulk(IOExternalMethodArguments*);
};
'''+'IOReturn\n'+actual+r'''
int main(){IOSurfaceRootUserClient c;IOExternalMethodArguments a;Descriptor d;
 uint64_t bytes=0x70,mask=1;uint32_t id=7;
 memcpy(d.data+0x70,&bytes,8);memcpy(d.data+0x78,&mask,8);memcpy(d.data+0x80,&id,4);
 memset(d.data,0x4a,32);a.structureInputDescriptor=&d;
 assert(!c.setBulk(&a)&&!locks&&!memcmp(c.state.data+0x30,d.data,32));
 d.short_read=true;assert(c.setBulk(&a)==1&&!locks);d.short_read=false;
 d.size--;assert(c.setBulk(&a)==1&&!locks);d.size++;
 id=8;memcpy(d.data+0x80,&id,4);assert(c.setBulk(&a)==2&&!locks);id=7;memcpy(d.data+0x80,&id,4);
 bytes=31;memcpy(d.data+0x70,&bytes,8);assert(c.setBulk(&a)==1&&!locks);
 a.structureInputDescriptor=nullptr;a.structureInput=d.data;a.structureInputSize=0x88;
 bytes=0x70;memcpy(d.data+0x70,&bytes,8);assert(!c.setBulk(&a)&&!locks);
 a.scalarInputCount=1;assert(c.setBulk(&a)==1&&!locks);return 0;}
''')
