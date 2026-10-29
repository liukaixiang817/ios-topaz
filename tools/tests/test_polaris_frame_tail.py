"""Run actual bounded tail accounting, not a model of the phone's GPU/FPS."""
from pathlib import Path
import unittest
from .test_polaris_gpu_bootstrap import run
from .test_polaris_gpu_lifetime import function

ROOT = Path(__file__).resolve().parents[2]
H = '#include "' + str(ROOT / 'tools/polaris-frame-tail.h') + '"\n'


class FrameTailTests(unittest.TestCase):
    def test_cross_window_report_cost_and_actual_wrapper_return_are_not_hidden(self):
        run(H + r'''
#include <assert.h>
int main(void){
 struct pgpu_frame_tail s={0};uint64_t begin=1000;unsigned emitted=0;
 for(unsigned frame=1;frame<=130;frame++){
  assert(pgpu_tail_begin(&s,frame,begin));
  struct pgpu_tail_window w;uint32_t seq=0;uint64_t own=0;
  if(pgpu_tail_take(&s,&w,&seq)){
   emitted++;assert(seq==emitted && w.frames==64 && w.active==64);
   assert(w.last-w.first==63 && w.end_us-w.from_us==w.render+w.gap);
   assert(w.gap==w.tail+w.outside && w.render==64*14000);
   assert(w.observer==64*100 && w.outside==64*2500);
   assert(w.report==(seq==1?0:5000));
   assert(w.log==64*200+w.report && w.tail==64*400+w.report);
   assert(w.over_budget==64);own=5000;
  }
  assert(pgpu_tail_end(&s,frame,begin,begin+14000,begin+14350+own,
                       200+own,100,own));
  assert(pgpu_tail_returned(&s,frame,begin+14400+own));
  begin+=16900+own;
 }
 assert(emitted==2 && !s.fault && sizeof(s)<=384);
 return 0;
}
''')

    def test_bad_clock_sequence_parts_and_overflow_poison_only_diagnostics(self):
        run(H + r'''
#include <assert.h>
static struct pgpu_frame_tail pending(void){struct pgpu_frame_tail s={0};
 assert(pgpu_tail_begin(&s,1,100));assert(pgpu_tail_end(&s,1,100,200,300,40,20,10));return s;}
int main(void){
 struct pgpu_frame_tail s=pending();assert(!pgpu_tail_begin(&s,2,299)&&s.fault==PGT_CLOCK);
 assert(!pgpu_tail_begin(&s,2,400));
 s=pending();assert(!pgpu_tail_begin(&s,3,400)&&s.fault==PGT_SEQUENCE);
 s=pending();assert(!pgpu_tail_returned(&s,2,400)&&s.fault==PGT_SEQUENCE);
 s=(struct pgpu_frame_tail){0};assert(pgpu_tail_begin(&s,1,100));
 assert(!pgpu_tail_end(&s,1,100,200,210,9,2,0)&&s.fault==PGT_PARTS);
 s=(struct pgpu_frame_tail){0};assert(pgpu_tail_begin(&s,1,100));
 assert(!pgpu_tail_end(&s,1,100,200,210,5,1,6)&&s.fault==PGT_PARTS);
 s=pending();s.window.log=UINT64_MAX;struct pgpu_tail_window prior=s.window;
 assert(!pgpu_tail_begin(&s,2,400)&&s.fault==PGT_OVERFLOW);
 assert(!memcmp(&prior,&s.window,sizeof(prior)));
 s=pending();s.sequence=UINT32_MAX;s.window.frames=64;
 struct pgpu_tail_window out={0};uint32_t seq=123;
 assert(!pgpu_tail_take(&s,&out,&seq)&&s.fault==PGT_OVERFLOW&&seq==123);
 s=pending();s.frame=UINT32_MAX;
 assert(!pgpu_tail_begin(&s,1,400)&&s.fault==PGT_SEQUENCE);
 assert(!pgpu_tail_begin(0,1,1));return 0;
}
''')

    def test_random_contiguous_samples_preserve_wall_time_partition_and_idle_counts(self):
        run(H + r'''
#include <assert.h>
int main(void){struct pgpu_frame_tail s={0};uint64_t b=1,rng=7;
 uint64_t render=0,tail=0,gap=0,outside=0,logs=0,obs=0;unsigned active=0,over=0;
 for(unsigned i=1;i<=10000;i++){
  assert(pgpu_tail_begin(&s,i,b));
  if(s.window.frames==64){struct pgpu_tail_window w;uint32_t seq;
   assert(pgpu_tail_take(&s,&w,&seq));
   assert(w.render==render&&w.tail==tail&&w.gap==gap&&w.outside==outside);
   assert(w.log==logs&&w.observer==obs&&w.active==active&&w.over_budget==over);
   assert(w.render+w.gap==w.end_us-w.from_us&&w.gap==w.tail+w.outside);
   render=tail=gap=outside=logs=obs=0;active=over=0;
  }
  rng=rng*6364136223846793005ULL+1;
  uint64_t d=1000+(rng%20000),t=100+(rng%1000),o=10+(rng%10000),l=t/3,c=t/4;
  if(!(i%33))o+=300000;
  assert(pgpu_tail_end(&s,i,b,b+d,b+d+t,l,c,0));
  render+=d;tail+=t;outside+=o;gap+=t+o;logs+=l;obs+=c;
  if(d+t+o<=100000){active++;over+=(d+t+o)>16667;}
  b+=d+t+o;
 }assert(!s.fault);return 0;}
''')

    def test_only_exact_unique_modes_activate_new_diagnostic(self):
        run(H + r'''
#include <assert.h>
int main(void){
 assert(!pgpu_tail_mode(0)&&!pgpu_tail_mode("")&&!pgpu_tail_mode("touch_lat=1"));
 assert(pgpu_tail_mode("a=1 touch_lat=2 b=3")==2);
 assert(pgpu_tail_mode("\ttouch_lat=3\n")==3);
 const char *bad[]={"not_touch_lat=2","touch_lat=20","touch_lat=2x","touch_lat=0",
  "touch_lat=2 touch_lat=2","touch_lat=1 touch_lat=3","touch_lat=3 touch_lat=bad"};
 for(unsigned i=0;i<sizeof(bad)/sizeof(*bad);i++)assert(!pgpu_tail_mode(bad[i]));
 return 0;}
''')

    def test_pre_frame_API_work_and_partial_first_draw_do_not_overlap_render_or_tail(self):
        run(H + r'''
#include <assert.h>
int main(void){struct pgpu_frame_tail s={0};
 assert(pgpu_tail_begin(&s,1,100));
 assert(pgpu_tail_api_enter(&s,120)&&!s.api_open);
 assert(pgpu_tail_end(&s,1,100,200,300,40,20,10));
 assert(pgpu_tail_api_enter(&s,310)&&pgpu_tail_api_leave(&s,330));
 assert(pgpu_tail_api_enter(&s,350)&&pgpu_tail_begin(&s,2,400));
 assert(!s.api_open&&s.window.api==70&&s.window.active_api==70);
 assert(s.window.calls==2&&s.window.active_calls==2&&s.window.outside==100);
 assert(pgpu_tail_api_leave(&s,500)&&s.window.api==70);
 assert(pgpu_tail_end(&s,2,400,600,700,10,20,0));
 assert(!pgpu_tail_api_enter(&s,699)&&s.fault==PGT_CLOCK);
 return 0;}
''')

    def test_actual_six_part_formatter_fits_console_with_maximum_width_fields(self):
        code = function((ROOT / 'userland/gpu/eagl.c').read_text(), 'static void polaris_tail_emit(')
        run(H + r'''
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
static unsigned lines;
static void say(const char *format,...){char row[1024];va_list a;va_start(a,format);
 int n=vsnprintf(row,sizeof(row),format,a);va_end(a);
 assert(n>0&&n<=255&&row[n-1]=='\n');lines++;}
''' + code + r'''
int main(void){struct pgpu_tail_window w;memset(&w,255,sizeof(w));
 polaris_tail_emit(UINT64_MAX,3,UINT32_MAX,&w);assert(lines==6);return 0;}
''')


if __name__ == '__main__':
    unittest.main()
