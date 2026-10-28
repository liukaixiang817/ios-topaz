"""Native fixed-offset read-only clock observer and bounded console records.
Mocks test its callbacks; they are not hardware frequency evidence.
"""
from pathlib import Path
import re,subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[2]
class ClockSnapshot(unittest.TestCase):
 def test_actual_native_function_has_fixed_reads_and_refuses_invalid_state(self):
  text=(ROOT/'tools/polaris-a630-runtime.h').read_text();a=text.index('bool polaris_gpu_clock_snapshot(');b=text.index('\nbool polaris_gpu_submit(',a);function=text[a:b]
  for bad in ['a630_write','a630_store','cache(', 'a630_core_halt','quarantine','__atomic_store']:
   self.assertNotIn(bad,function)
  code=r'''
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#define A630_POST_ACK 0x8ff0u
#define A630_POST_PERF 0x8ff4u
#define A630_POST_BW 0x8ff8u
#define A630_POST_RETURN 0x8ffcu
static unsigned ready=1,begin=1,reads,begins,fail=99;
static int a630_client_io;
static struct {unsigned completed;struct {unsigned idle,halted,keep_live;}live;} a630_client_submit={1,{1,1,0}};
static bool polaris_gpu_ready(void){return ready;}
static bool a630_client_begin(void){begins++;return begin;}
static bool a630_read_register(void*ctx,unsigned bank,uint32_t off,uint32_t*v){
 assert(ctx==&a630_client_io);assert(v);
 static const unsigned gm[]={0x8ff0,0x8ff4,0x8ff8,0x8ffc};
 static const unsigned cc[]={0x101c,0x1020,0,4,0x38,0xc,0x2c};
 unsigned n=reads++;assert(n<18);
 if(n<4){assert(bank==2 && off==gm[n]);}else assert(bank==1 && off==cc[(n-4)%7]);
 if(n==fail)return false;*v=off;return true;
}
''' + function+r'''
int main(void){uint32_t v[20];memset(v,0xa5,sizeof(v));
 assert(!polaris_gpu_clock_snapshot(0,19));assert(!polaris_gpu_clock_snapshot(v,18));assert(reads==0&&begins==0);
 ready=0;assert(!polaris_gpu_clock_snapshot(v,19));ready=1;
 a630_client_submit.completed=0;assert(!polaris_gpu_clock_snapshot(v,19));a630_client_submit.completed=1;
 a630_client_submit.live.idle=0;assert(!polaris_gpu_clock_snapshot(v,19));a630_client_submit.live.idle=1;
 a630_client_submit.live.halted=0;assert(!polaris_gpu_clock_snapshot(v,19));a630_client_submit.live.halted=1;
 a630_client_submit.live.keep_live=1;assert(!polaris_gpu_clock_snapshot(v,19));a630_client_submit.live.keep_live=0;
 assert(reads==0&&begins==0);begin=0;assert(!polaris_gpu_clock_snapshot(v,19));assert(reads==0);begin=1;
 assert(polaris_gpu_clock_snapshot(v,19));assert(reads==18&&v[0]==0x3ffff&&v[19]==0xa5a5a5a5);
 assert(!memcmp(&v[5],&v[12],7*4));
 for(unsigned n=0;n<18;n++){reads=0;fail=n;assert(!polaris_gpu_clock_snapshot(v,19));assert(reads==18);assert(v[0]==(0x3ffffu^(1u<<n)));assert(v[19]==0xa5a5a5a5);}
 return 0;}
'''
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);(p/'test.c').write_text(code)
   subprocess.run(['/usr/bin/clang','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(p/'test.c'),'-o',str(p/'test')],check=True)
   subprocess.run([str(p/'test')],check=True)
 def test_console_format_bound_with_all_integer_maxima(self):
  text=(ROOT/'tools/PolarisGPU.cpp').read_text();formats=re.findall(r'IOLog\("(POLARIS GPU (?:STAGE|METHOD|CLOCK) [^"\n]*)"',text)
  self.assertEqual(len(formats),11)
  for fmt in formats:
   expanded=fmt.replace('\\n','\n').replace('%llu',str(2**64-1)).replace('%u',str(2**32-1)).replace('%x','ffffffff').replace('%s','surface')
   self.assertNotIn('%',expanded);self.assertLessEqual(len(expanded.encode()),255,fmt);self.assertTrue(expanded.endswith('\n'))
if __name__=='__main__':unittest.main()
