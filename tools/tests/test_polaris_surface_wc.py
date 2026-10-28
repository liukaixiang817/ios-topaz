"""Execute actual native surface allocation/dispatch with faulting descriptors.

These test ownership, cache selection and failure cleanup, not native pmap or
GPU pixels. Those require the actual EFI/XNU and phone trials separately.
"""
from pathlib import Path
import unittest
from tools.tests.test_polaris_gpu_lifetime import function
from tools.tests.test_polaris_surface import run

ROOT = Path(__file__).resolve().parents[2]


class SurfaceWCTests(unittest.TestCase):
    def test_actual_allocation_dispatch_cache_modes_and_failure_retention(self):
        patch = (ROOT / 'xnu/profiles/polaris/0879-polaris-owned-BGRA-surface-WC-trial.patch').read_text()
        actual = ''.join(line[1:] + '\n' for line in patch.splitlines()
                         if line[:1] in ('+', ' ') and not line.startswith('+++'))
        methods = ''.join(kind + '\n' + function(actual, name) for kind, name in [
            ('static bool', 'sweet_surface_wc_requested('),
            ('static IOReturn', 'sweet_surface_owned_backing('),
            ('static IOReturn', 'sweet_surface_backing(')])
        run(r'''
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#define POLARIS_RAM_ONLY 1
typedef int IOReturn,task_t;typedef long long SInt64;
#define kIOReturnSuccess 0
#define kIOReturnNoMemory 1
#define kIOReturnUnsupported 2
#define kIOReturnBadArgument 3
#define kIOReturnVMError 4
#define kIODirectionInOut 3
#define kIODirectionOut 1
#define kIOMemoryKernelUserShared 0x10
#define kIOMapAnywhere 0x100
#define kIOMapDefaultCache 0
#define kIOMapWriteCombineCache 0x200
#define kIOMapReadOnly 0x400
#define SWEET_SURFACE_WIRED_MAX (1536ull<<20)
#define OSDynamicCast(type,p) dynamic_cast<type*>(p)
#define OSSafeReleaseNULL(p) do{if(p){(p)->release();(p)=nullptr;}}while(0)
static const int kernel_task=1,page_size=16384;
static uint64_t sweet_surface_wired;
static unsigned allocations,mappings,zeroes,descriptors,maps,pins,unpins;
static bool fail_alloc,fail_map,fail_pin,fail_descriptor,have_flag;
static uint32_t enabled;
static unsigned opts_seen;
static bool PE_parse_boot_argn(const char*name,void*out,int bytes){
 assert(!strcmp(name,"polarisgpusurfacewc")&&bytes==4);
 memcpy(out,&enabled,4);return have_flag;
}
static SInt64 OSAddAtomic64(SInt64 n,volatile SInt64*p){auto old=*p;*p+=n;return old;}
static bool pgpu_surface_range(uint64_t a,uint64_t n){return a&&n&&n<=(256u<<20)&&a<=UINT64_MAX-n;}
struct OSObject{virtual ~OSObject()=default;};
struct OSNumber:OSObject{uint64_t n;explicit OSNumber(uint64_t v):n(v){} uint64_t unsigned64BitValue(){return n;}};
struct OSDictionary{OSObject*entry=nullptr;OSObject*getObject(const char*n){assert(!strcmp(n,"IOSurfaceAddress"));return entry;}};
struct IOMemoryMap{void release(){maps--;delete this;}};
struct IOMemoryDescriptor{
 unsigned direction=3;bool pinned=false;
 virtual ~IOMemoryDescriptor()=default;
 static IOMemoryDescriptor*withAddressRange(uint64_t a,uint64_t size,unsigned dir,int task){
  assert(a==0x12345000&&size==16384&&task==7);
  if(fail_descriptor)return nullptr;
  descriptors++;auto*p=new IOMemoryDescriptor;p->direction=dir;return p;
 }
 int prepare(){if(fail_pin)return 1;pinned=true;pins++;return 0;}
 void complete(){assert(pinned);pinned=false;unpins++;}
 void release(){assert(!pinned);descriptors--;delete this;}
};
struct IOBufferMemoryDescriptor:IOMemoryDescriptor{
 uint8_t bytes[16384];
 static IOBufferMemoryDescriptor*inTaskWithOptions(int task,unsigned options,unsigned size,int page){
  allocations++;opts_seen=options;assert(task==1&&size==16384&&page==16384);
  if(fail_alloc)return nullptr;
  descriptors++;auto*p=new IOBufferMemoryDescriptor;memset(p->bytes,0xa5,sizeof(p->bytes));return p;
 }
 IOMemoryMap*createMappingInTask(int task,int address,unsigned options,int offset,unsigned size){
  assert(task==1&&!address&&options==(kIOMapAnywhere|kIOMapWriteCombineCache)&&!offset&&size==16384);
  mappings++;if(fail_map)return nullptr;maps++;return new IOMemoryMap;
 }
 void*getBytesNoCopy(){return bytes;}
};
struct SweetSurface{
 uint32_t pixelFormat=0x42475241,planeCount=0,bytesPerElement=4,allocSize=16384,mapCache=0;
 bool wiredAccounted=false,externalPrepared=false;
 IOMemoryDescriptor*memory=nullptr;IOMemoryMap*kernelMap=nullptr;
};
static void zero_(void*p,unsigned n){assert(n==16384);memset(p,0,n);zeroes++;}
#define bzero zero_
''' + methods + r'''
static void cleanup(SweetSurface&s){
 if(s.kernelMap)s.kernelMap->release();
 if(s.externalPrepared)s.memory->complete();
 if(s.memory)s.memory->release();
 if(s.wiredAccounted)sweet_surface_wired-=s.allocSize;
 s={};assert(!descriptors&&!maps&&!sweet_surface_wired&&pins==unpins);
}
int main(){SweetSurface s;OSDictionary props;
 assert(!sweet_surface_wc_requested(&s));have_flag=true;
 for(enabled=0;enabled<4;enabled++)assert(sweet_surface_wc_requested(&s)==(enabled==1));
 enabled=1;s.pixelFormat=0x52474241;assert(!sweet_surface_wc_requested(&s));s.pixelFormat=0x42475241;
 s.planeCount=1;assert(!sweet_surface_wc_requested(&s));s.planeCount=0;
 s.bytesPerElement=3;assert(!sweet_surface_wc_requested(&s));s.bytesPerElement=4;
 assert(!sweet_surface_backing(&s,&props,7)&&s.mapCache==kIOMapWriteCombineCache&&s.kernelMap);
 assert(opts_seen==(kIODirectionInOut|kIOMemoryKernelUserShared|kIOMapWriteCombineCache));
 for(auto x:static_cast<IOBufferMemoryDescriptor*>(s.memory)->bytes)assert(!x);
 assert(zeroes==1);cleanup(s);
 have_flag=false;unsigned oldmap=mappings;
 assert(!sweet_surface_backing(&s,&props,7)&&s.mapCache==kIOMapDefaultCache&&!s.kernelMap);
 assert(mappings==oldmap&&opts_seen==(kIODirectionInOut|kIOMemoryKernelUserShared));cleanup(s);
 have_flag=true;fail_map=true;unsigned oldzero=zeroes;
 assert(sweet_surface_backing(&s,&props,7)==kIOReturnUnsupported&&s.memory&&!s.kernelMap);
 assert(zeroes==oldzero);cleanup(s);fail_map=false;
 fail_alloc=true;assert(sweet_surface_backing(&s,&props,7)==kIOReturnNoMemory&&!s.memory);cleanup(s);fail_alloc=false;
 OSNumber caller(0x12345000);props.entry=&caller;
 unsigned oldalloc=allocations;oldmap=mappings;
 assert(!sweet_surface_backing(&s,&props,7)&&s.externalPrepared&&s.mapCache==kIOMapDefaultCache);
 assert(allocations==oldalloc&&mappings==oldmap);cleanup(s);
 fail_pin=true;assert(sweet_surface_backing(&s,&props,7)==kIOReturnVMError&&!s.memory);
 assert(allocations==oldalloc&&mappings==oldmap);cleanup(s);fail_pin=false;
 OSObject bad;props.entry=&bad;
 assert(sweet_surface_backing(&s,&props,7)==kIOReturnBadArgument&&!s.memory&&!s.wiredAccounted);
 caller.n=0;props.entry=&caller;assert(sweet_surface_backing(&s,&props,7)==kIOReturnBadArgument);
 return 0;
}
''')
