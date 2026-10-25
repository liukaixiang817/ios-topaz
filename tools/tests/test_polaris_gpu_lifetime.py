"""Compile actual C++ BO methods with instrumented descriptors/backend.
Only hardware completion is modeled; these are lifetime tests, not GPU proof.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


def function(text, name):
    start = text.index(name)
    left = text.index('{', start)
    at, depth = left + 1, 1
    while depth:
        depth += (text[at] == '{') - (text[at] == '}')
        at += 1
    return text[start:at] + '\n'


class GPULifetimeTests(unittest.TestCase):
    def test_actual_application_status_formatter_is_bounded_and_read_only(self):
        code = (ROOT / 'tools/PolarisGPU.cpp').read_text()
        actual = function(code, 'extern "C" uint32_t polaris_gpu_client_line(')
        source = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
static uint32_t gpuPublished,gpuOpenStatus=1,gpuSubmissions=0xffffffff,gpuSurfaces=0xffffffff;
static uint32_t gpuAppStage=6,gpuAppError=255,gpuFaultStatus=1;
static uint32_t gpuLoaderStage=6,gpuLoaderError=0xffffffff,gpuLoaderMethods=0xff,gpuDesktopSubmissions=0xffffffff;
static bool ready;
static bool polaris_gpu_ready(){return ready;}
''' + actual + r'''
int main(){char b[68];memset(b,0xa5,sizeof(b));
 assert(!polaris_gpu_client_line(0,68)&&!polaris_gpu_client_line(b,0));
 assert(!polaris_gpu_client_line(b,68));gpuPublished=1;
 unsigned n=polaris_gpu_client_line(b,68);assert(n==strlen(b)&&n<=67);
 assert(strstr(b,"T6 E255 D1 R0"));ready=true;
 assert(polaris_gpu_client_line(b,68)==n&&strstr(b,"R1"));
 return 0;}
'''
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory)
            (p / 'test.cpp').write_text(source)
            subprocess.run(['/usr/bin/clang++', '-std=c++17', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', str(p / 'test.cpp'), '-o', str(p / 'test')], check=True)
            subprocess.run([str(p / 'test')], check=True)

    def test_actual_bo_release_partial_map_and_unknown_dma_retention(self):
        code = (ROOT / 'tools/PolarisGPU.cpp').read_text()
        actual = ''.join(function(code, name) for name in [
            'void PolarisGPUUserClient::poison()',
            'IOReturn PolarisGPUUserClient::make(',
            'bool PolarisGPUUserClient::drop('])
        source = r'''
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <stddef.h>
#include <string.h>
typedef int IOReturn;typedef uint64_t IOByteCount,addr64_t;
#define kIOReturnNoMemory 1
#define kIOReturnNotReady 2
#define kIOReturnSuccess 0
#define kIODirectionInOut 3
#define kIOMemoryMapperNone 0
#define PAGE_SIZE 16384u
#define PAGE_MASK 16383u
#define GPU_BUFFERS 4096u
#define GPU_MAX_BO (128u<<20)
#define GPU_MAX_BYTES (384ull<<20)
#define GPU_VA_FIRST 0x20000000ull
#define GPU_VA_END 0x40000000ull
#define GPU_READONLY 2u
#define OSSafeReleaseNULL(p) do{if(p){(p)->release();(p)=nullptr;}}while(0)
static unsigned maps,unmaps,commits,fail_map,failed_commit,dead,completes,releases;
static bool gpuQuarantined;static uint32_t gpuFaultStatus;
static bool polaris_gpu_quiescent(){return !dead;}
static bool polaris_gpu_map(uint64_t va,uint64_t pa,bool ro,bool cached){
 assert(va>=0x20000000&&pa>=0x180000000ull&&cached);(void)ro;
 maps++;return !fail_map||maps!=fail_map;}
static bool polaris_gpu_commit(){commits++;if(failed_commit){dead=1;return false;}return true;}
static bool polaris_gpu_unmap(uint64_t a,uint64_t s){assert(a>=0x20000000&&s&&!(s&16383));
 assert(!dead);unmaps++;return true;}
static void polaris_gpu_quarantine(){dead=1;}
struct IOMemoryMap {void release(){releases++;}};
struct SweetSurface {unsigned refs=1;void retain(){refs++;}void release(){assert(refs);refs--;}};
struct IOMemoryDescriptor {
 unsigned refs=1,prepared=0,done=0;uint64_t size;
 explicit IOMemoryDescriptor(uint64_t s):size(s){}
 void retain(){refs++;}void release(){assert(refs);refs--;releases++;}
 int prepare(int){assert(!prepared);prepared=1;return 0;}
 void complete(int){assert(!dead&&prepared&&!done);done=1;completes++;}
 addr64_t getPhysicalSegment(uint64_t off,IOByteCount*len,int){assert(off<size);*len=size-off;return 0x180000000ull+off;}
};
struct PolarisBO {IOMemoryDescriptor*memory;SweetSurface*surface;IOMemoryMap*map;uint64_t address,size;uint32_t flags;};
class PolarisGPUUserClient {public:
 PolarisBO buffers[GPU_BUFFERS]={};uint64_t bytes=0;uint32_t nextHandle=0;bool quarantined=false;unsigned retained=0;
 void retain(){retained++;}void poison();
 PolarisBO*buffer(uint32_t h){return h&&h<=GPU_BUFFERS&&buffers[h-1].memory?&buffers[h-1]:nullptr;}
 IOReturn make(IOMemoryDescriptor*,SweetSurface*,uint64_t,uint32_t,uint32_t*);bool drop(uint32_t);
};
''' + actual + r'''
int main(){
 PolarisGPUUserClient c;IOMemoryDescriptor first(16384),second(32768);SweetSurface surface;
 uint32_t a=0,b=0;assert(c.make(&first,&surface,16384,0,&a)==0);
 assert(a==1&&first.refs==2&&surface.refs==2&&maps==4&&commits==1);
 assert(c.make(&second,nullptr,32768,2,&b)==0&&b==2);
 assert(c.buffers[1].address==c.buffers[0].address+32768&&c.bytes==49152);
 assert(c.drop(a)&&first.done&&first.refs==1&&surface.refs==1&&unmaps==1);
 assert(c.drop(b)&&second.done&&second.refs==1&&c.bytes==0&&unmaps==2);
 /* Partial PTE construction is undone before prepare's pin is dropped. */
 IOMemoryDescriptor partial(32768);maps=0;fail_map=3;
 assert(c.make(&partial,nullptr,32768,0,&a)==kIOReturnNoMemory);
 assert(partial.done&&partial.refs==1&&unmaps==3&&!c.quarantined&&!c.bytes);
 /* A failed TLBSYNC is NOT successful DMA containment, even if CP was
  * halted beforehand. Descriptors + client stay retained without complete. */
 fail_map=0;failed_commit=1;IOMemoryDescriptor unknown(16384);
 unsigned before=completes,unmapped=unmaps;
 assert(c.make(&unknown,&surface,16384,0,&a)==kIOReturnNotReady);
 assert(c.quarantined&&c.retained==1&&gpuQuarantined&&gpuFaultStatus&&dead);
 assert(unknown.refs==2&&!unknown.done&&surface.refs==2&&completes==before&&unmaps==unmapped);
 unknown.release();assert(unknown.refs==1); /* original allocator may release its own ref */
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory)
            (p / 'test.cpp').write_text(source)
            subprocess.run(['/usr/bin/clang++', '-std=c++17', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', str(p / 'test.cpp'), '-o', str(p / 'test')], check=True)
            subprocess.run([str(p / 'test')], check=True)

    def test_actual_pid1_activation_failure_rolls_back_before_apple_exec(self):
        code = (ROOT / 'userland/gpu/polaris-init.c').read_text()
        code = code[code.index('int main(void)'):].replace('int main(void)', 'static int activate(void)', 1)
        source = r'''
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <setjmp.h>
#include <unistd.h>
static jmp_buf done;
static unsigned scenario,calls,restored,activated,apple_original;
static int exists(const char*p,int how){(void)how;return strstr(p,"wrapper")?0:-1;}
static int move_(const char*a,const char*b){
 calls++;
 if(!strcmp(a,"/usr/libexec/backboardd")) {assert(strstr(b,"real"));if(scenario==1)return -1;apple_original=0;return 0;}
 if(strstr(a,"wrapper")){assert(!strcmp(b,"/usr/libexec/backboardd"));if(scenario==2)return -1;activated=1;return 0;}
 assert(strstr(a,"real")&&!strcmp(b,"/usr/libexec/backboardd"));restored=1;apple_original=1;return 0;}
static int exec_(const char*p,char*const argv[]){assert(!strcmp(p,"/sbin/launchd")&&!strcmp(argv[0],p)&&!argv[1]);longjmp(done,1);}
#define access exists
#define rename move_
#define execv exec_
''' + code + r'''
int main(void){
 for(scenario=0;scenario<3;scenario++){
  calls=restored=activated=0;apple_original=1;
  if(!setjmp(done))activate();
  if(!scenario)assert(calls==2&&activated&&!restored);
  if(scenario==1)assert(calls==1&&!activated&&apple_original);
  if(scenario==2)assert(calls==3&&!activated&&restored&&apple_original);
 }
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory)
            (p / 'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang', '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', str(p / 'test.c'), '-o', str(p / 'test')], check=True)
            subprocess.run([str(p / 'test')], check=True)


if __name__ == '__main__':
    unittest.main()
