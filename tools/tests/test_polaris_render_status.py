"""Actual diagnostic reporters and presentation admission, never GPU execution proof."""
from pathlib import Path
import unittest
from .test_polaris_gpu_lifetime import function
from .test_polaris_gpu_bootstrap import run
ROOT=Path(__file__).resolve().parents[2]
H='#include "'+str(ROOT/'tools/polaris-gl-status.h')+'"\n'
class RenderStatusTests(unittest.TestCase):
 def test_actual_snapshot_is_desktop_only_bounded_and_read_only(self):
  t=(ROOT/'tools/PolarisGPU.cpp').read_text()
  code=''.join(function(t,n).replace('extern "C" ','') for n in ['static uint32_t polaris_gpu_performance_line(', 'static bool polaris_gpu_render_report(', 'extern "C" uint32_t polaris_gpu_render_line('])
  run(H+r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
static uint32_t gpuRender[8],gpuRenderPublished,gpuPerformance[10],gpuPerformancePublished;
'''+code+r'''
int main(void){char b[68];struct pgpu_render_notice p={100,2,3,4,5,2,0x41424752,0x970};
 _Static_assert(sizeof(p)==32,"render diagnostic ABI");
 assert(!polaris_gpu_render_report(1,&p)&&!polaris_gpu_render_report(0,&p));
 assert(!polaris_gpu_render_report(2,0)&&!gpuRenderPublished);
 assert(polaris_gpu_render_report(2,&p));assert(gpuRenderPublished==2);
 assert(polaris_gpu_render_line(0,b,sizeof(b))&&strstr(b,"GLR F64 E2 S3 I4 M5"));
 assert(polaris_gpu_render_line(1,b,sizeof(b))&&strstr(b,"GLX K2 A41424752 @970"));
 p.kind=7;assert(!polaris_gpu_render_report(2,&p)&&gpuRenderPublished==2);p.kind=0;p.slot=0x2200;
 assert(!polaris_gpu_render_report(2,&p));
 for(unsigned i=0;i<8;i++)gpuRender[i]=0xffffffff;
 for(unsigned i=0;i<2;i++){unsigned n=polaris_gpu_render_line(i,b,sizeof(b));assert(n==strlen(b)&&n<=67);}
 gpuRenderPublished=3;assert(!polaris_gpu_render_line(0,b,sizeof(b)));
 assert(!polaris_gpu_render_line(2,b,sizeof(b))&&!polaris_gpu_render_line(0,0,sizeof(b)));
 return 0;}
''')
  entry=function(t,'IOReturn PolarisGPUUserClient::externalMethod(')
  self.assertIn('case 0x7a:size=sizeof(r.render)',entry)
  self.assertIn('polaris_gpu_render_report(callerKind,&r.render)',entry)
  self.assertIn('current_task()!=ownerTask || !polaris_gpu_caller_allowed()',entry)
 def test_actual_first_render_failure_survives_later_errors(self):
  t=(ROOT/'userland/gpu/eagl.c').read_text()
  code=''.join(function(t,n) for n in ['void polaris_eagl_render_observe(', 'static void polaris_render_fault('])
  run(H+r'''
#include <assert.h>
#include <stdbool.h>
static struct pgpu_render_notice polaris_render,got;
static void(*polaris_render_observer)(const struct pgpu_render_notice*);
static unsigned reports;
static void note(const struct pgpu_render_notice*p){got=*p;reports++;}
'''+code+r'''
int main(void){polaris_render_fault(2,0x41424752,0x970);
 assert(polaris_render.images==1&&polaris_render.kind==2&&!reports);
 polaris_eagl_render_observe(note);assert(reports==1&&got.arg==0x41424752);
 polaris_render_fault(1,0x502,0x970);polaris_render_fault(4,7,0x12a8);polaris_render_fault(5,8,0x12c0);polaris_render_fault(6,0xe80,0xe80);
 assert(polaris_render.errors==1&&polaris_render.shaders==2&&polaris_render.missing==1&&polaris_render.images==1);
 assert(polaris_render.kind==2&&polaris_render.arg==0x41424752&&reports==1);
 polaris_eagl_render_observe(note);assert(reports==2&&got.errors==1&&got.shaders==2);return 0;}
''')
 def test_fast_presentation_requires_live_real_desktop_submission(self):
  code=function((ROOT/'tools/PolarisGPU.cpp').read_text(),'extern "C" bool polaris_gpu_desktop_active(').replace('extern "C" ','')
  run(r'''
#include <assert.h>
#include <stdbool.h>
#include <stdbool.h>
#include <stdint.h>
static uint32_t gpuDesktopSubmissions,gpuOpenStatus;static bool ready;
static bool polaris_gpu_ready(void){return ready;}
'''+code+r'''
int main(void){ready=true;gpuOpenStatus=1;assert(!polaris_gpu_desktop_active());
 gpuDesktopSubmissions=1;assert(polaris_gpu_desktop_active());ready=false;assert(!polaris_gpu_desktop_active());
 ready=true;gpuOpenStatus=0;assert(!polaris_gpu_desktop_active());return 0;}
''')
