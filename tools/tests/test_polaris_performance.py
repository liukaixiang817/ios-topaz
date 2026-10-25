"""Actual deadline/diagnostic code; synthetic results are not phone FPS."""
from pathlib import Path
import unittest
from .test_polaris_gpu_lifetime import function
from .test_polaris_gpu_bootstrap import run
ROOT=Path(__file__).resolve().parents[2]
H='#include "'+str(ROOT/'tools/polaris-performance.h')+'"\n'

class PerformanceTests(unittest.TestCase):
 def test_window_average_idle_and_cpu_counter_wrap(self):
  run(H+r'''
#include <assert.h>
int main(void){struct pgpu_perf_window w={0};struct pgpu_perf_notice p={0};
 assert(!pgpu_perf_add(&w,20,10,1,2,3,4,&p)&&!w.frames);
 assert(!pgpu_perf_add(&w,100,10100,100,50,60,70,&p));
 assert(pgpu_perf_add(&w,1000100,1010100,200,100,120,140,&p));
 assert(p.frames==2&&p.window_us==1010000&&p.frame_us==10000);
 assert(p.wait_us==150&&p.readback_us==75&&p.upload_us==90&&p.hash_us==105);
 assert(!w.frames&&p.cpu_busy==10001&&!p.cpus&&!p.reserved);
 uint32_t b[4]={UINT32_MAX-10,0,UINT32_MAX-10,0},a[4]={9,20,9,0};
 assert(pgpu_perf_cpu(b,a)==6666);assert(pgpu_perf_cpu(a,a)==10001);
 a[0]=b[0];a[1]=0;assert(pgpu_perf_cpu(b,a)==0);
 assert(pgpu_perf_u32(UINT64_MAX)==UINT32_MAX);
 return 0;}
''')

 def test_independent_deadlines_reproduce_then_remove_extra_tick(self):
  run('#include "'+str(ROOT/'tools/polaris-display-cadence.h')+'"\n'+r'''
#include <assert.h>
static unsigned simulate(int fixed,unsigned cost,unsigned *notifies){
 uint64_t now=1,vsync=0,present=0;unsigned frames=0;*notifies=0;
 while(now<1000001){uint64_t started=now;
  if(!vsync||now>=vsync){(*notifies)++;vsync=polaris_fb_next_vsync_us(now,vsync);}
  if(now>=present){frames++;present=now+polaris_fb_gpu_interval_us(60,cost);now+=cost;}
  unsigned delay=fixed?polaris_fb_deadline_delay_us(now,vsync,present,0):polaris_fb_gpu_tick_us((uint32_t)(now-started));
  assert(delay>=1000);now+=delay;
 }return frames;
}
int main(void){unsigned oldN,newN;unsigned old=simulate(0,10636,&oldN),fresh=simulate(1,10636,&newN);
 assert(old==30&&fresh>=46&&fresh<=48);assert(newN<=61&&oldN<=61);
 for(unsigned cost=0;cost<=200000;cost+=997){unsigned n;simulate(1,cost,&n);assert(n<=61);}
 assert(polaris_fb_next_vsync_us(100000,1)==100003);
 assert(polaris_fb_deadline_delay_us(16668,33335,21273,0)==4605);
 assert(polaris_fb_deadline_delay_us(22000,33335,21273,0)==11335);
 assert(polaris_fb_deadline_delay_us(22000,33335,21273,1)==1000);
 assert(polaris_fb_deadline_delay_us(0,16667,0,0)==16667);
 return 0;}
''')

 def test_actual_report_refuses_other_callers_and_preserves_first_error(self):
  t=(ROOT/'tools/PolarisGPU.cpp').read_text()
  code=''.join(function(t,n).replace('extern "C" ','') for n in [
   'static bool polaris_gpu_performance_report(', 'static uint32_t polaris_gpu_performance_line(',
   'static bool polaris_gpu_render_report(', 'extern "C" uint32_t polaris_gpu_render_line('])
  run('#include "'+str(ROOT/'tools/polaris-gl-status.h')+'"\n'+r'''
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
static uint32_t gpuPerformance[10],gpuPerformancePublished,gpuRender[8],gpuRenderPublished;
'''+code+r'''
int main(void){char b[68];struct pgpu_perf_notice p={60,1000000,10000,1000,500,200,20,9900,1,0};
 assert(!polaris_gpu_performance_report(1,&p)&&!polaris_gpu_performance_report(0,&p));
 assert(!polaris_gpu_performance_report(2,0));
 assert(polaris_gpu_performance_report(2,&p));
 assert(polaris_gpu_performance_line(b,sizeof(b))&&strstr(b,"F10000 W1000 R500 U200 H20 B9900 N1"));
 p.reserved=1;assert(!polaris_gpu_performance_report(2,&p));p.reserved=0;p.cpus=9;
 assert(!polaris_gpu_performance_report(2,&p));p.cpus=1;p.cpu_busy=10002;
 assert(!polaris_gpu_performance_report(2,&p));p.cpu_busy=10001;p.window_us=1;
 assert(!polaris_gpu_performance_report(2,&p));p.window_us=1000000;p.frames=0;
 assert(!polaris_gpu_performance_report(2,&p));
 struct pgpu_render_notice r={0};assert(polaris_gpu_render_report(2,&r));
 assert(polaris_gpu_render_line(1,b,sizeof(b))&&!strncmp(b,"PF ",3));
 r.kind=1;r.arg=0x502;assert(polaris_gpu_render_report(2,&r));
 assert(polaris_gpu_render_line(1,b,sizeof(b))&&strstr(b,"GLX K1 A502"));
 for(unsigned i=2;i<=6;i++)gpuPerformance[i]=UINT32_MAX;
 assert(polaris_gpu_performance_line(b,sizeof(b))<68&&strlen(b)<68);
 gpuPerformancePublished=3;assert(!polaris_gpu_performance_line(b,sizeof(b)));
 return 0;}
''')
  entry=function(t,'IOReturn PolarisGPUUserClient::externalMethod(')
  self.assertIn('case 0x79:size=sizeof(r.performance)',entry)
  self.assertIn('polaris_gpu_performance_report(callerKind,&r.performance)',entry)
  self.assertIn('current_task()!=ownerTask || !polaris_gpu_caller_allowed()',entry)

 def test_actual_compact_panel_keeps_faults_within_pixel_bounds(self):
  p=ROOT/'xnu/profiles/polaris/0862-polaris-render-performance-and-independent-display-deadlines.patch'
  source='\n'.join(l[1:] for l in p.read_text().splitlines() if l.startswith((' ','+')) and not l.startswith('+++'))
  code=function(source,'static void polaris_status_bar(')
  run(r'''
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
typedef struct {unsigned fPolarisFPS10,fPolarisCopyMeanUS,fPolarisGapUS,fPolarisStatusPaintUS;
 unsigned fHeight,fWidth,fRowBytes;uintptr_t fPixels;} AppleCLCD;
static unsigned char iso_font[256*16];static int faults;
static uint32_t polaris_usb_status(char*p,uint32_t n){return snprintf(p,n,"USB");}
static uint32_t polaris_gpu_client_line(char*p,uint32_t n){return snprintf(p,n,"GA");}
static uint32_t polaris_gpu_render_line(unsigned i,char*p,uint32_t n){return snprintf(p,n,"GL%u",i);}
static uint32_t polaris_gpu_fault_line(unsigned i,char*p,uint32_t n){return faults?snprintf(p,n,"GF%u",i):0;}
static uint32_t polaris_gpu_crash_line(unsigned i,char*p,uint32_t n){return (faults||i==2)?snprintf(p,n,"GLF%u",i):0;}
'''+code+r'''
int main(void){for(unsigned h=1;h<=400;h++){
 uint32_t *pixels=malloc(1080*h*4);assert(pixels);
 AppleCLCD f={600,10636,33334,10636,h,1080,4320,(uintptr_t)pixels};
 for(faults=0;faults<2;faults++){
  memset(pixels,0x55,1080*h*4);polaris_status_bar(&f);
  unsigned lines=faults?11:6;if(lines>h/32)lines=h/32;
  for(unsigned i=lines*32*1080;i<h*1080;i++)assert(pixels[i]==0x55555555);
 }free(pixels);
 }return 0;}
''')

if __name__=='__main__':unittest.main()
