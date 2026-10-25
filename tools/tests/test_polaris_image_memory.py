"""Real allocation/layout paths against instrumented task descriptors; no GPU proof."""
from pathlib import Path
import unittest
from .test_polaris_gpu_lifetime import function
from .test_polaris_surface import run
ROOT=Path(__file__).resolve().parents[2]
class ImageMemoryTests(unittest.TestCase):
 def test_actual_layout_and_backing_preserve_caller_pixels_and_unwind(self):
  patch=(ROOT/'xnu/profiles/polaris/0861-polaris-existing-image-memory-and-gpu-presentation.patch').read_text()
  after=''.join(l[1:]+'\n' for l in patch.splitlines() if l[:1] in ('+',' ') and not l.startswith('+++'))
  code=''.join(function(after,n) for n in ['sweet_surface_layout(', 'sweet_surface_backing('])
  run(r'''
#include "polaris-surface.h"
#include <assert.h>
#include <map>
#include <string>
#include <vector>
#include <stdlib.h>
typedef int IOReturn,task_t;typedef long long SInt64;
#define kIOReturnSuccess 0
#define kIOReturnBadArgument 1
#define kIOReturnNoMemory 2
#define kIOReturnUnsupported 3
#define kIOReturnVMError 4
#define SWEET_SURFACE_MAX_DIM 16384
#define SWEET_SURFACE_MAX_PLANES 4
#define SWEET_SURFACE_MAX_ALLOC (256u<<20)
#define SWEET_SURFACE_WIRED_MAX (1536ull<<20)
#define kIOMapDefaultCache 0
#define kIOMapReadOnly 0x100
#define kIODirectionInOut 3
#define kIODirectionOut 1
#define kIOMemoryKernelUserShared 8
#define OSDynamicCast(T,p) dynamic_cast<T*>(p)
#define OSSafeReleaseNULL(p) do{if(p){p->release();p=nullptr;}}while(0)
#define round_page(x) (((x)+16383)&~16383ull)
static unsigned attempts,pins,unpins,refs,buffers,alloc_fail,pin_fail,read_only;
static uint64_t address_seen,bytes_seen,sweet_surface_wired;
static unsigned kernel_task=99,page_size=16384;
static SInt64 OSAddAtomic64(SInt64 x,volatile SInt64*p){SInt64 old=*p;*p+=x;return old;}
struct OSObject{virtual ~OSObject(){};};
struct OSNumber:OSObject{uint64_t v;explicit OSNumber(uint64_t a):v(a){}uint64_t unsigned64BitValue(){return v;}uint32_t unsigned32BitValue(){return (uint32_t)v;}};
struct OSDictionary:OSObject{std::map<std::string,OSObject*>v;OSObject*getObject(const char*k){auto i=v.find(k);return i==v.end()?nullptr:i->second;}};
struct OSArray:OSObject{std::vector<OSObject*>v;size_t getCount(){return v.size();}OSObject*getObject(unsigned i){return v.at(i);}};
static uint32_t sweet_dict_u32(OSDictionary*d,const char*k,uint32_t def){auto*n=OSDynamicCast(OSNumber,d->getObject(k));return n?n->unsigned32BitValue():def;}
static uint32_t sweet_div_up(uint32_t a,uint32_t b){return b>1?(a+b-1)/b:a;}
static uint32_t sweet_row_bytes(uint32_t w,uint32_t ew,uint32_t bpe){return (sweet_div_up(w,ew)*bpe+63)&~63u;}
struct IOMemoryDescriptor{
 bool prepared=false;unsigned direction;virtual ~IOMemoryDescriptor(){};
 static IOMemoryDescriptor*withAddressRange(uint64_t a,uint64_t b,unsigned d,task_t task){
  assert(task==7);attempts++;address_seen=a;bytes_seen=b;if(alloc_fail)return nullptr;
  auto*p=new IOMemoryDescriptor;p->direction=d;refs++;return p;
 }
 int prepare(){if(pin_fail||(read_only&&direction==3))return 1;prepared=true;pins++;return 0;}
 void complete(){assert(prepared);prepared=false;unpins++;}
 virtual void release(){assert(!prepared);refs--;delete this;}
};
struct IOBufferMemoryDescriptor:IOMemoryDescriptor{
 char data[32768]={};
 static IOBufferMemoryDescriptor*inTaskWithOptions(unsigned task,unsigned flags,unsigned size,unsigned align){
  assert(task==99&&flags==11&&size<=32768&&align==16384);buffers++;if(alloc_fail)return nullptr;refs++;return new IOBufferMemoryDescriptor;
 }
 void*getBytesNoCopy(){return data;}
};
struct sweet_surface_plane{uint32_t width,height,bytesPerRow,offset,size;uint16_t bytesPerElement;uint8_t elementWidth,elementHeight;};
struct SweetSurface{
 uint32_t width=0,height=0,bytesPerRow=0,pixelFormat=0,cacheMode=0,offset=0,planeCount=0,allocSize=0,mapCache=0;
 uint16_t bytesPerElement=0;uint8_t elementWidth=0,elementHeight=0;struct sweet_surface_plane planes[4]={};
 bool wiredAccounted=false,externalPrepared=false;IOMemoryDescriptor*memory=nullptr;
 ~SweetSurface(){if(externalPrepared)memory->complete();if(memory)memory->release();if(wiredAccounted)sweet_surface_wired-=allocSize;}
};
'''+'static IOReturn\n'+code.replace('}\nsweet_surface_backing','}\nstatic IOReturn\nsweet_surface_backing')+r'''
int main(){
 OSNumber width(13),height(8),row(64),bpe(4),alloc(500),address(0x12345025),format(0x42475241);OSObject wrong;
 OSDictionary d;d.v={{"IOSurfaceWidth",&width},{"IOSurfaceHeight",&height},{"IOSurfaceBytesPerRow",&row},{"IOSurfaceBytesPerElement",&bpe},{"IOSurfaceAllocSize",&alloc},{"IOSurfaceAddress",&address},{"IOSurfacePixelFormat",&format}};
 {SweetSurface s;assert(!sweet_surface_layout(&s,&d)&&s.allocSize==500);assert(!sweet_surface_backing(&s,&d,7));
  assert(s.externalPrepared&&s.wiredAccounted&&address_seen==0x12345025&&bytes_seen==500&&!buffers);}
 assert(!sweet_surface_wired&&!refs&&pins==unpins);
 for(unsigned mode=1;mode<4;mode++){
  alloc_fail=mode==1;pin_fail=mode==2;read_only=mode==3;
  {SweetSurface s;assert(!sweet_surface_layout(&s,&d));int r=sweet_surface_backing(&s,&d,7);
   assert(r==(mode==3?0:4));if(mode==3)assert(s.mapCache==kIOMapReadOnly);}
  assert(!sweet_surface_wired&&!refs&&pins==unpins);
 }alloc_fail=pin_fail=read_only=0;
 {SweetSurface s;alloc.v=499;assert(sweet_surface_layout(&s,&d)==1);alloc.v=500;}
 {SweetSurface s;d.v["IOSurfaceAddress"]=&wrong;assert(sweet_surface_layout(&s,&d)==1);d.v["IOSurfaceAddress"]=&address;}
 {SweetSurface s;address.v=UINT64_MAX-499;assert(sweet_surface_layout(&s,&d)==1);address.v=0x12345025;}
 {SweetSurface s;d.v["IOSurfaceAddressRanges"]=&wrong;assert(sweet_surface_layout(&s,&d)==3);d.v.erase("IOSurfaceAddressRanges");}
 {SweetSurface s;assert(!sweet_surface_layout(&s,&d));sweet_surface_wired=SWEET_SURFACE_WIRED_MAX;
  unsigned n=attempts;assert(sweet_surface_backing(&s,&d,7)==2&&attempts==n);}
 assert(sweet_surface_wired==SWEET_SURFACE_WIRED_MAX);sweet_surface_wired=0;
 d.v.erase("IOSurfaceAddress");
 {SweetSurface s;assert(!sweet_surface_layout(&s,&d)&&s.allocSize==16384);assert(!sweet_surface_backing(&s,&d,7));assert(!s.externalPrepared&&buffers==1);}
 assert(!sweet_surface_wired&&!refs&&pins==unpins);return 0;}
''')
