"""Actual native input/first-submit demand; policy is not a hardware FPS test."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from .test_polaris_gpu_lifetime import function
from .test_polaris_gpu_bootstrap import run
ROOT=Path(__file__).resolve().parents[2]


def patched_touch():
    # Reconstruct the real source from the shipped profile, including every
    # prior lifecycle patch. No private buildtree or textual model of pk_poll.
    with tempfile.TemporaryDirectory() as directory:
        d=Path(directory);(d/'bsd/dev').mkdir(parents=True)
        for p in sorted((ROOT/'xnu/profiles/polaris').glob('*.patch')):
            parts=re.split(r'(?m)(?=^--- )',p.read_text())
            selected=[x for x in parts if '\n+++ b/bsd/dev/polaris_touch.c\n' in x]
            if not selected:continue
            patch=d/'step.patch';patch.write_text(''.join(selected))
            result=subprocess.run(['/usr/bin/patch','--batch','--forward','-p1','-i',str(patch)],cwd=d,capture_output=True,text=True)
            if result.returncode or 'fuzz' in result.stdout or 'offset' in result.stdout:
                raise AssertionError(p.name+': '+result.stdout+result.stderr)
        return (d/'bsd/dev/polaris_touch.c').read_text()


class InputDemand(unittest.TestCase):
    def test_actual_edges_hint_before_HID_without_hints_for_fault_or_shutdown(self):
        code=patched_touch()
        native=function(code,'static void pk_deliver(')+'\n'+function(code,'static void pk_poll(')
        run('#include "'+str(ROOT/'tools/polaris-uefi-buttons.h')+'"\n'+r'''
#include <assert.h>
#include <string.h>
#define printf(...) ((void)0)
static struct polaris_uefi_button_slot polaris_uefi_buttons;
static struct polaris_button_consumer pk_consumer;
static bool pk_enabled=true;static uint64_t ns=100000;static unsigned edges,hints,current;
static int polaris_hid_buttons_ready(void){return 1;}
static uint64_t mach_absolute_time(void){return ns;}
static void absolutetime_to_nanoseconds(uint64_t a,uint64_t*b){*b=a;}
static void pi_cache(uint64_t a,bool clean){assert(a==(uintptr_t)&polaris_uefi_buttons+(clean?128:0));}
static void polaris_cpu_input_activity(void){hints++;}
static void polaris_gpu_input_activity(void){assert(hints==edges+1);}
static void sweet_hid_key(int key,int down){assert(key==0);assert(hints==edges+1||pk_consumer.error);current=down;edges++;}
'''+native+r'''
int main(void){pk_poll(false);struct polaris_uefi_button_slot*s=&polaris_uefi_buttons;
 s->request=1;s->sampled_us=1;ns+=100000;pk_poll(false);assert(!hints&&!edges);
 s->request=2;s->sampled_us=2;s->pressed=1;ns+=100000;pk_poll(false);assert(hints==1&&edges==1&&current);
 s->request=3;s->sampled_us=3;s->pressed=1;ns+=100000;pk_poll(false);assert(hints==1&&edges==1);
 s->request=4;s->sampled_us=4;s->pressed=0;ns+=100000;pk_poll(false);assert(hints==2&&edges==2&&!current);
 s->request=5;s->sampled_us=5;s->pressed=1;ns+=100000;pk_poll(false);assert(hints==3&&edges==3&&current);
 ns+=750000000;pk_poll(false);assert(hints==3&&edges==4&&!current&&s->error==3);
 pk_poll(true);assert(hints==3);
 memset(s,0,sizeof(*s));memset(&pk_consumer,0,sizeof(pk_consumer));hints=edges=0;
 ns+=100000;pk_poll(false);s->request=1;s->sampled_us=1;ns+=100000;pk_poll(false);
 s->request=2;s->sampled_us=2;s->pressed=1;ns+=100000;pk_poll(false);assert(hints==1&&current);
 pk_poll(true);assert(hints==1&&edges==2&&!current&&s->error==4);return 0;}
''')

    def test_actual_first_submit_demand_refuses_failure_and_ignores_foreign_clients(self):
        source=(ROOT/'tools/PolarisGPU.cpp').read_text()
        body=function(source,'static bool polaris_gpu_desktop_demand(')
        body=body.replace('__atomic_load_n','__atomic_load_n')
        run(r'''
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
static bool gpuStockEnabled,pass;static uint64_t gpuStockActivity,now=100;
static unsigned ticks;
static uint64_t polaris_gpu_stock_now(void){return now;}
static bool polaris_gpu_performance_tick(uint64_t n,uint64_t a){assert(n==now&&a==n&&gpuStockActivity==n);ticks++;return pass;}
'''+body+r'''
int main(void){assert(polaris_gpu_desktop_demand(2)&&!ticks&&!gpuStockActivity);
 gpuStockEnabled=true;assert(polaris_gpu_desktop_demand(1)&&!ticks&&!gpuStockActivity);
 pass=true;assert(polaris_gpu_desktop_demand(2)&&ticks==1&&gpuStockActivity==100);
 now=200;pass=false;assert(!polaris_gpu_desktop_demand(2)&&ticks==2&&!gpuStockEnabled);
 assert(polaris_gpu_desktop_demand(2)&&ticks==2);return 0;}
''')
        submit=function(source,'IOReturn PolarisGPUUserClient::submit(')
        self.assertLess(submit.index('for(unsigned n=0;n<r->nr_cmds;n++)'),submit.index('polaris_gpu_desktop_demand(callerKind)'))
        self.assertLess(submit.index('polaris_gpu_desktop_demand(callerKind)'),submit.index('cacheBefore(bos'))
        self.assertIn('poison();result=kIOReturnNotReady;goto out;',submit)


if __name__=='__main__':unittest.main()
