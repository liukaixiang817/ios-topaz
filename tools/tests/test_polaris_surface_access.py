"""Actual native presenter/submit methods with an instrumented host backend.
ASan/UBSan and concurrent ownership tests are not physical GPU/DPU validation.
"""
from pathlib import Path
import hashlib
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


def function(text, name):
    start = text.index(name)
    at = text.index('{', start) + 1
    depth = 1
    while depth:
        depth += (text[at] == '{') - (text[at] == '}')
        at += 1
    return text[start:at] + '\n'


def reconstruct_framebuffer(destination):
    """Replay actual public profile patches for this one native source."""
    relative = 'iokit/Kernel/arm/SweetFramebuffer.cpp'
    patches = [p for p in sorted((ROOT / 'xnu/patches').glob('*.patch')) if int(p.name[:4]) <= 79]
    patches += sorted((ROOT / 'xnu/profiles/polaris').glob('*.patch'))
    baseline = None
    for patch in patches:
        if patch.name.startswith('0912-'):
            baseline = (destination / relative).read_text()
        pieces = re.split(r'(?=^--- (?:a/|/dev/null))', patch.read_text(encoding='latin1'), flags=re.M)
        for piece in pieces:
            match = re.match(r'--- (?:a/[^\n]*|/dev/null)\n\+\+\+ b/([^\n]+)\n', piece)
            if not match or match[1] != relative:
                continue
            piece = piece.split('\ndiff --git ')[0] + '\n'
            applied = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1'], input=piece,
                                     cwd=destination, capture_output=True, text=True, encoding='latin1')
            if applied.returncode or 'offset' in applied.stdout.lower() or 'fuzz' in applied.stdout.lower():
                raise AssertionError(patch.name + ': ' + applied.stdout + applied.stderr)
    assert baseline is not None
    return baseline, (destination / relative).read_text()


class SurfaceAccessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.path = Path(cls.directory.name)
        cls.baseline, cls.framebuffer = reconstruct_framebuffer(cls.path)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def run_actual(self, stem, source):
        path = self.path / (stem + '.cpp')
        path.write_text(source)
        command = ['/usr/bin/clang++', '-std=c++17', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                   '-Wno-unused-variable', '-Wno-unused-function', '-fsanitize=address,undefined',
                   '-fno-omit-frame-pointer', '-I' + str(ROOT / 'tools'), str(path), '-o', str(self.path / stem)]
        compiled = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
        actual = subprocess.run([str(self.path / stem)], capture_output=True, text=True, timeout=30)
        self.assertEqual(actual.returncode, 0, actual.stdout + actual.stderr)

    def test_shipped_private_header_and_exact_iig_binding(self):
        patch = (ROOT / 'xnu/profiles/polaris/0913-polaris-atomic-whole-frame-surface-pins.patch').read_text()
        part = patch.split('+++ b/iokit/Kernel/arm/polaris_surface_access.h\n')[1]
        shipped = '\n'.join(line[1:] for line in part.splitlines() if line.startswith('+')) + '\n'
        header = (ROOT / 'tools/polaris-surface-access.h').read_text()
        self.assertEqual(shipped, header)
        self.assertIn(hashlib.sha256(header.encode()).hexdigest(), (ROOT / 'tools/xnu-iig-cache.py').read_text())

    def test_non_polaris_presenter_tokens_unchanged(self):
        texts = []
        for body in [self.baseline, self.framebuffer]:
            result = subprocess.run(['/usr/bin/clang++', '-E', '-P', '-x', 'c++', '-UPOLARIS_RAM_ONLY', '-'],
                                    input=function(body, 'void\nAppleCLCD::present('), capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            texts.append(re.sub(r'\s+', '', result.stdout))
        self.assertEqual(*texts)

    def test_actual_whole_presenter_rejection_wled_margins_and_concurrency(self):
        actual = ''.join(function(self.framebuffer, name) for name in [
            'static bool polaris_frame_layer_valid(', 'static bool polaris_frame_release(',
            'void\nAppleCLCD::present('])
        actual = actual.replace('__asm__ volatile("dsb sy":::"memory");', 'host_dsb();')
        self.run_actual('presenter', PRESENTER_PRE + actual + PRESENTER_MAIN)

    def test_actual_submit_failure_contention_and_unknown_dma(self):
        source = (ROOT / 'tools/PolarisGPU.cpp').read_text()
        self.run_actual('submit', SUBMIT_PRE + function(source, 'IOReturn PolarisGPUUserClient::submit(') + SUBMIT_MAIN)


PRESENTER_PRE = r"""
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <thread>
#include <atomic>
#include "polaris-surface-access.h"
#include "polaris-display-blit.h"
#include "polaris-display-staged.h"
#include "polaris-wled-native.h"
#define POLARIS_RAM_ONLY 1
#define SWEET_FB_LAYERS 4
#define IOLog(...) ((void)0)
#define OSSafeReleaseNULL(s) do{if(s){(s)->release();s=nullptr;}}while(0)
static uint32_t get32(const uint8_t*p,size_t n){uint32_t v;memcpy(&v,p+n,4);return v;}
static void put32(uint8_t*p,size_t n,uint32_t v){memcpy(p+n,&v,4);}
static unsigned barriers,blocked,quarantined;
extern "C" void polaris_gpu_display_fault(void){quarantined++;}
static bool try_writer;
static void host_dsb(){__atomic_thread_fence(__ATOMIC_SEQ_CST);barriers++;}
static int sweet_console_muted;
static int PE_parse_boot_argn(const char*,void*p,size_t){*(int*)p=1;return 1;}
static void IOLockLock(void*){}static void IOLockUnlock(void*){}
struct Memory {size_t bytes;size_t getLength(){return bytes;}};
struct SweetSurface {
 unsigned id=0,refs=1,width=8,height=8,bytesPerRow=32,offset=0,bytesPerElement=4,elementWidth=1,elementHeight=1,pixelFormat=0,polarisGPUBusy=0;
 std::vector<uint8_t> pixels=std::vector<uint8_t>(256);Memory mem={256};Memory*memory=&mem;
 void retain(){refs++;}void release(){assert(refs>1);refs--;}
 uintptr_t kernelAddress(){if(try_writer){assert(!pfs_acquire(&polarisGPUBusy,PFS_GPU));blocked++;}return(uintptr_t)pixels.data();}
};
static SweetSurface *registry[8];
static SweetSurface*sweet_surface_copy(unsigned id){if(id>=8 || !registry[id])return nullptr;registry[id]->retain();return registry[id];}
static bool polaris_gpu_desktop_active(){return !quarantined;}
static unsigned sweet_fb_swaps_logged=16;
static uint64_t polaris_fb_presents,polaris_fb_pixels;
struct AppleCLCD {
 bool fPolarisWledCopied=false,fConsolePaused=false,fDirty=false;
 uint32_t fWidth=10,fHeight=8,fRowBytes=40,fLogicalW=8,fLogicalH=8;
 int fOffX=0,fOffY=0;uintptr_t fPixels;SweetSurface*fSurface=nullptr;void*fLock=nullptr;
 uint32_t fPolarisColumns[1080],fPolarisRow[1080];polaris_wled_native_adapter fPolarisWled={};
 void present(const uint8_t*);
};
"""

PRESENTER_MAIN = r"""
static void layer(uint8_t*r,unsigned n,unsigned id,int dy=0,int h=8){put32(r,0x104,get32(r,0x104)|(1u<<n));put32(r,0x54+4*n,id);
 size_t a=0x64+16*n,b=0xc4+16*n;put32(r,a,0);put32(r,a+4,0);put32(r,a+8,8);put32(r,a+12,h);
 put32(r,b,0);put32(r,b+4,dy);put32(r,b+8,8);put32(r,b+12,h);}
int main(){
 std::vector<uint8_t> panel(320,0x76);AppleCLCD f;f.fPixels=(uintptr_t)panel.data();SweetSurface a,b;a.id=1;b.id=2;registry[1]=&a;registry[2]=&b;
 memset(a.pixels.data(),0x11,256);memset(b.pixels.data(),0x22,256);uint8_t rec[0x46c]={};
 f.fPolarisWled.enabled=true;f.fPolarisWled.state.cookie=1;f.fPolarisWled.state.desired_on=true;
 layer(rec,0,1);layer(rec,1,2);put32(rec,0x64+16+8,9);auto before=panel;
 f.present(rec);assert(panel==before&&!polaris_fb_pixels&&!f.fPolarisWledCopied&&a.refs==1&&b.refs==1&&!a.polarisGPUBusy&&!b.polarisGPUBusy);
 put32(rec,0x64+16+8,8);b.polarisGPUBusy=PFS_GPU;f.present(rec);assert(panel==before&&f.fDirty&&!f.fPolarisWledCopied&&!a.polarisGPUBusy&&b.polarisGPUBusy==PFS_GPU);
 assert(!pfs_acquire(&b.polarisGPUBusy,PFS_PANEL));b.polarisGPUBusy=0;f.fDirty=false;
 put32(rec,0x54+4,7);f.present(rec);assert(panel==before&&!f.fDirty&&!a.polarisGPUBusy&&a.refs==1);
 put32(rec,0x54+4,1);try_writer=true;f.present(rec);try_writer=false;
 assert(blocked==4 && f.fPolarisWledCopied && barriers>=2 && a.refs==1 && !a.polarisGPUBusy);
 assert(pfs_acquire(&a.polarisGPUBusy,PFS_GPU)&&pfs_release(&a.polarisGPUBusy,PFS_GPU));
 for(unsigned y=0;y<8;y++)for(unsigned x=0;x<10;x++)for(unsigned c=0;c<4;c++)assert(panel[y*40+x*4+c]==(x==0||x==9?0:0x11));
 /* A late console glyph in either margin is cleared by the next actual partial update. */
 panel[0]=0xff;panel[39]=0xff;memset(rec,0,sizeof(rec));layer(rec,0,1,0,4);layer(rec,1,2,4,4);
 f.present(rec);assert(!f.fPolarisWledCopied&&panel[0]==0&&panel[39]==0);
 /* Atomic ownership excludes writers throughout a read, including concurrent contenders. */
 uint32_t state=0;unsigned data[64]={};std::atomic<bool> done{false};
 std::thread writer([&]{for(unsigned n=1;n<=20000;n++){while(!pfs_acquire(&state,PFS_GPU))std::this_thread::yield();
 for(auto&v:data)v=n;assert(pfs_release(&state,PFS_GPU));}done=true;});
 unsigned samples=0;while(!done){if(pfs_acquire(&state,PFS_PANEL)){unsigned v=data[0];for(auto x:data)assert(x==v);samples++;assert(pfs_release(&state,PFS_PANEL));}}
 writer.join();printf("samples=%u\n",samples);assert(!state);state=99;assert(!pfs_release(&state,PFS_GPU)&&state==99&&!pfs_acquire(&state,PFS_PANEL));
 /* Unexpected ownership is retained and quarantined, never silently freed. */
 a.retain();a.polarisGPUBusy=99;SweetSurface*bad[4]={&a,nullptr,nullptr,nullptr};
 assert(!polaris_frame_release(bad)&&a.refs==2&&a.polarisGPUBusy==99&&quarantined==1);
 puts("PASS actual presenter: invalid/missing/busy final layer makes zero panel writes; duplicate pins; WLED full-single-layer; late margins; concurrent exclusion");return 0;}
"""

SUBMIT_PRE = r"""
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "polaris-surface-access.h"
#include "polaris-gpu-abi.h"
#define GPU_CMDS 128u
#define GPU_BOS 4096u
#define kIOReturnSuccess 0
#define kIOReturnBadArgument 1
#define kIOReturnNoMemory 2
#define kIOReturnVMError 3
#define kIOReturnNotReady 4
#define kIOReturnBusy 5
#define kIOReturnTimeout 6
#define IOLog(...) ((void)0)
typedef int IOReturn;
static unsigned allocs,fail_alloc,issued,pre_calls,post_calls,fail_cache;
static bool fail_dma,corrupt_owner;
static uint64_t ticks;
static void*allocate(size_t n){allocs++;return allocs==fail_alloc?nullptr:malloc(n);}
#define IONew(T,N) ((T*)allocate(sizeof(T)*(N)))
#define IODelete(P,T,N) free(P)
static int copyin(uint64_t a,void*b,size_t n){memcpy(b,(void*)a,n);return 0;}
static void clock_get_uptime(uint64_t*p){*p=(ticks+=1000);}
static uint64_t polaris_gpu_elapsed_us(uint64_t a,uint64_t b){return b-a;}
static void IOSleep(unsigned){}
static bool polaris_gpu_desktop_demand(unsigned){return true;}
static bool gpuMethodPerformance;static unsigned gpuSubmissions,gpuDesktopSubmissions,gpuSurfaces;
struct PolarisStageMeter{};static PolarisStageMeter gpuStageMeter;
static bool polaris_gpu_last_submit_us(uint32_t,uint64_t*){return true;}
struct PolarisCacheTally{uint64_t before,after,readonlySkipped,wcBefore,wcAfter;};
static void polaris_gpu_stage_record(PolarisStageMeter*,uint64_t*,uint64_t*,bool,PolarisCacheTally*){}
struct SweetSurface{uint32_t polarisGPUBusy=0;};
struct PolarisBO{SweetSurface*surface=nullptr;uint64_t address=4096,size=4096;};
static SweetSurface*hardware_surfaces[2];
static bool polaris_gpu_submit(uint64_t*,uint32_t*,uint32_t,uint32_t*f){issued++;for(auto p:hardware_surfaces)assert(p->polarisGPUBusy==PFS_GPU);
 if(fail_dma)return false;if(corrupt_owner)hardware_surfaces[0]->polarisGPUBusy=99;*f=1;return true;}
struct PolarisGPUUserClient {
 PolarisBO buffers[2];uint32_t queues=1,lastFence=0,callerKind=2;bool poisoned=false;
 PolarisBO*buffer(uint32_t h){return h&&h<=2?&buffers[h-1]:nullptr;}
 void poison(){poisoned=true;}
 bool cacheBefore(const msm_gem_submit_bo*,uint32_t,PolarisCacheTally*){pre_calls++;for(auto p:hardware_surfaces)assert(p->polarisGPUBusy==PFS_GPU);return !fail_cache;}
 void cacheAfter(const msm_gem_submit_bo*,uint32_t,PolarisCacheTally*){post_calls++;for(auto p:hardware_surfaces)assert(p->polarisGPUBusy==PFS_GPU||corrupt_owner);}
 IOReturn submit(msm_gem_submit*);
};
"""

SUBMIT_MAIN = r"""
int main(){
 for(unsigned scenario=0;scenario<7;scenario++){
 allocs=issued=pre_calls=post_calls=fail_alloc=fail_cache=0;fail_dma=corrupt_owner=false;ticks=0;
 PolarisGPUUserClient c;SweetSurface a,b;c.buffers[0].surface=&a;c.buffers[1].surface=&b;hardware_surfaces[0]=&a;hardware_surfaces[1]=&b;
 msm_gem_submit_bo bos[3]={{1,1,0},{1,2,0},{1,1,0}};msm_gem_submit_cmd cmd={1,0,0,16,0,0,0};
 msm_gem_submit r={};r.nr_bos=3;r.nr_cmds=1;r.queueid=1;r.bos=(uintptr_t)bos;r.cmds=(uintptr_t)&cmd;
 if(scenario==1)b.polarisGPUBusy=PFS_PANEL;
 if(scenario==2)fail_alloc=3;
 if(scenario==3)fail_cache=1;
 if(scenario==4)fail_dma=true;
 if(scenario==5)cmd.submit_idx=4;
 if(scenario==6)corrupt_owner=true;
 int result=c.submit(&r);
 if(scenario==0)assert(result==0&&issued==1&&pre_calls==1&&post_calls==1&&!a.polarisGPUBusy&&!b.polarisGPUBusy&&!c.poisoned);
 if(scenario==1)assert(result==kIOReturnBusy&&!issued&&!pre_calls&&!a.polarisGPUBusy&&b.polarisGPUBusy==PFS_PANEL&&!c.poisoned);
 if(scenario==2)assert(result==kIOReturnNoMemory&&!issued&&!pre_calls&&!a.polarisGPUBusy&&!b.polarisGPUBusy&&!c.poisoned);
 if(scenario==3)assert(result==kIOReturnNoMemory&&!issued&&pre_calls==1&&!post_calls&&!a.polarisGPUBusy&&!b.polarisGPUBusy&&!c.poisoned);
 if(scenario==4)assert(result==kIOReturnTimeout&&issued==1&&pre_calls==1&&!post_calls&&a.polarisGPUBusy==PFS_GPU&&b.polarisGPUBusy==PFS_GPU&&c.poisoned);
 if(scenario==5)assert(result==kIOReturnBadArgument&&!issued&&!pre_calls&&!a.polarisGPUBusy&&!b.polarisGPUBusy&&!c.poisoned);
 if(scenario==6)assert(result==kIOReturnNotReady&&issued==1&&post_calls==1&&a.polarisGPUBusy==99&&!b.polarisGPUBusy&&c.poisoned);
 }
 puts("PASS actual submit: dedup/cache ordering; bounded contention; allocation/map failure; validation; failed-DMA quarantine; ownership-corruption retention");return 0;}
"""

if __name__ == "__main__":
    unittest.main()
