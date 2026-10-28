"""Actual cache methods and timed PM4 runner; offline, never phone GPU proof."""
from pathlib import Path
import tempfile
import subprocess
import unittest
from .test_polaris_gpu_lifetime import function

ROOT = Path(__file__).resolve().parents[2]


class CacheProfile(unittest.TestCase):
    def test_wc_requires_explicit_trial_and_WC_allocation_request(self):
        text=(ROOT/'tools/PolarisGPU.cpp').read_text()
        actual=function(text,'static bool polaris_gpu_use_wc(')
        source='#include <stdint.h>\n#include <assert.h>\nstatic bool gpuWriteCombined;\n'+actual+r'''
int main(){
 for(unsigned flag=0;flag<0x50000;flag+=0x10000){
  gpuWriteCombined=false;assert(!polaris_gpu_use_wc(flag));
  gpuWriteCombined=true;assert(polaris_gpu_use_wc(flag)==(flag==0x10000));
 }
 assert(polaris_gpu_use_wc(0x10002));return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'test.cpp').write_text(source)
            subprocess.run(['/usr/bin/clang++','-std=c++17','-Wall','-Wextra','-Werror',
                            '-fsanitize=address,undefined',str(p/'test.cpp'),'-o',str(p/'test')],check=True)
            subprocess.run([str(p/'test')],check=True)

    def test_actual_cache_passes_only_skip_SMMU_readonly_allocations_after_completion(self):
        text = (ROOT / 'tools/PolarisGPU.cpp').read_text()
        actual = ''.join(function(text, name) for name in [
            'bool PolarisGPUUserClient::cacheBefore(', 'void PolarisGPUUserClient::cacheAfter('])
        source = r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#define GPU_READONLY 2u
#define kIOMapAnywhere 1
#define kIOMapDefaultCache 2
static void *kernel_task;
static unsigned caches,mapped,fail_mapping,barriers;
static void polaris_gpu_memory_order(){barriers++;}
#define kIOMapWriteCombineCache 4
static void *addresses[16];static uint64_t sizes[16];
static void polaris_gpu_cache(void *p,uint64_t n){assert(caches<16);addresses[caches]=p;sizes[caches++]=n;}
struct IOMemoryMap {uintptr_t address;uintptr_t getVirtualAddress(){return address;}};
struct Memory {IOMemoryMap *map;IOMemoryMap *createMappingInTask(void*,int,int,int,uint64_t){mapped++;return mapped==fail_mapping?NULL:map;}};
struct msm_gem_submit_bo {uint32_t flags,handle;};
struct PolarisBO {Memory *memory;IOMemoryMap *map;uint64_t size;uint32_t flags;bool writeCombined;};
struct PolarisCacheTally {uint64_t before,after,readonlySkipped,wcBefore,wcAfter;};
class PolarisGPUUserClient {public:
 PolarisBO bo[4];PolarisBO *buffer(unsigned h){assert(h&&h<=4);return &bo[h-1];}
 bool cacheBefore(const msm_gem_submit_bo*,uint32_t,PolarisCacheTally*);
 void cacheAfter(const msm_gem_submit_bo*,uint32_t,PolarisCacheTally*);
};
''' + actual + r'''
int main(){
 IOMemoryMap maps[4]={{0x1000},{0x2000},{0x3000},{0x4000}};
 Memory memory[4]={{maps},{maps+1},{maps+2},{maps+3}};
 PolarisGPUUserClient c;
 for(unsigned i=0;i<4;i++)c.bo[i]={memory+i,NULL,(i+1)*16384ull,i==0?GPU_READONLY:0u,false};
 /* Submit READ alone is NOT proof of GPU-write-protected allocation.
  * Mutable read-only references and output surfaces still get post sync. */
 msm_gem_submit_bo refs[4]={{1,1},{1,2},{2,3},{3,4}};
 PolarisCacheTally tally={0,0,0,0,0};
 assert(c.cacheBefore(refs,4,&tally)&&mapped==4&&caches==4&&tally.before==163840);
 for(unsigned i=0;i<4;i++)assert(addresses[i]==(void*)maps[i].address&&sizes[i]==(i+1)*16384ull);
 c.cacheAfter(refs,4,&tally);assert(caches==7&&tally.after==147456&&tally.readonlySkipped==16384);
 assert(barriers==2&&!tally.wcBefore&&!tally.wcAfter);
 for(unsigned i=1;i<4;i++)assert(addresses[3+i]==(void*)maps[i].address&&sizes[3+i]==(i+1)*16384ull);
 /* A CPU edit to read-only GPU commands is cleaned AGAIN before the next
  * submit; skipping post invalidation never skips the pre-submit barrier. */
 caches=0;assert(c.cacheBefore(refs,4,&tally)&&mapped==4&&caches==4);
 /* Mapping failure stops before that BO or any later BO can be touched. */
 for(unsigned i=0;i<4;i++)c.bo[i].map=NULL;
 mapped=caches=0;fail_mapping=2;tally={0,0,0,0,0};
 assert(!c.cacheBefore(refs,4,&tally)&&mapped==2&&caches==1&&tally.before==16384);
 /* Only a BO admitted by make() with actual WC attributes may skip sweeps;
  * cached mutable READ references and writable shared surfaces still sync. */
 fail_mapping=0;mapped=caches=barriers=0;tally={0,0,0,0,0};
 c.bo[0].writeCombined=true;c.bo[2].writeCombined=true;
 assert(c.cacheBefore(refs,4,&tally));c.cacheAfter(refs,4,&tally);
 assert(caches==4&&barriers==2&&tally.before==98304&&tally.after==98304);
 assert(tally.wcBefore==65536&&tally.wcAfter==65536&&!tally.readonlySkipped);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory)
            (p/'test.cpp').write_text(source)
            subprocess.run(['/usr/bin/clang++', '-std=c++17', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', str(p/'test.cpp'), '-o', str(p/'test')], check=True)
            subprocess.run([str(p/'test')], check=True)
        # Completion failure must retain/quarantine before the cache-after
        # path or any surface busy flag is released, in the real method.
        submit = function(text, 'IOReturn PolarisGPUUserClient::submit(')
        self.assertLess(submit.index('if(!polaris_gpu_submit('), submit.index('cacheAfter('))
        self.assertLess(submit.index('poison();result=kIOReturnTimeout;goto out;'), submit.index('cacheAfter('))

    def test_timing_does_not_change_actual_command_order_or_failure_containment(self):
        # Reuse the real packet decoder/failure scenarios and add the clock
        # to the SAME calls. This executes the actual modified inline C.
        base = (ROOT/'tools/tests/test_polaris_a630_submit.py').read_text()
        start = base.index("run(r'''", base.index('def test_completion_wrap_and_ambiguous_dma_quarantine')) + len("run(r'''")
        end = base.index("''')", start)
        source = base[start:end]
        source = source.replace('int main(void){', r'''
static uint64_t ticks;static unsigned backwards;
static uint64_t clock_(void *p){assert(p==&ticks);if(backwards){ticks=ticks?ticks-1:20;return ticks;}return ticks+=10;}
int main(void){''')
        source = source.replace('a630_submit_run(&r,&io,m.ring,m.scratch,&ib,1)',
                                'a630_submit_profiled(&r,&io,m.ring,m.scratch,&ib,1,clock_,&ticks)')
        source = source.replace('assert(r.completed==501&&r.count==501);', r'''
 assert(r.completed==501&&r.count==501&&r.timing_mask==31&&r.timing_polls>=2);
 for(unsigned n=0;n<5;n++)assert(r.timing[n]==10);
 assert(m.writes==501*3&&m.syncs==501*5); /* Same hardware operations. */
 backwards=1;ticks=100;
 assert(a630_submit_profiled(&r,&io,m.ring,m.scratch,&ib,1,clock_,&ticks));
 assert(!r.timing_mask&&!r.poisoned&&r.completed==502);backwards=0;
''')
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory)
            (p/'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang', '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', '-I'+str(ROOT/'tools'), str(p/'test.c'),
                            '-o', str(p/'test')], check=True)
            subprocess.run([str(p/'test')], check=True)


if __name__ == '__main__': unittest.main()
