"""Original sensor wire decoding/bounded observation; no MMIO or thermal policy."""
from pathlib import Path
import subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[2]

class TsensReadOnly(unittest.TestCase):
    def test_exhaustive_signed_wire_values_and_real_failure_boundaries(self):
        source=r'''
#include "polaris-tsens-readonly.h"
#include <assert.h>
#include <string.h>
struct fake {unsigned reads,fail;uint32_t raw[12];uint64_t times[2];unsigned clocks;};
static bool rd(void *v,uint32_t offset,uint32_t *out) {
 struct fake *s=v;unsigned n=s->reads++;
 assert(n<12&&offset==0xbc+(n%6)*4&&offset+4<=0x1ff);
 if(s->fail==n+1)return false;
 *out=s->raw[n];return true;
}
static uint64_t clock_us(void *v) {struct fake *s=v;assert(s->clocks<2);return s->times[s->clocks++];}
static struct fake valid(void) {
 struct fake s={0};s.times[0]=100;s.times[1]=110;
 for(unsigned n=0;n<12;n++)s.raw[n]=(1u<<21)|(400+(n%6)*10);
 return s;
}
static void rejected(struct fake *s,unsigned expected) {
 struct polaris_tsens_io io={s,rd,clock_us};
 struct polaris_tsens_sample out,old;memset(&out,0xa5,sizeof(out));old=out;
 assert(polaris_tsens_observe(&io,&out)==expected);
 assert(!memcmp(&out,&old,sizeof(out)));assert(s->reads<=12);
}
int main(void) {
 for(unsigned code=0;code<4096;code++) {
  int32_t value=123456,expected=(code>=2048?(int)code-4096:(int)code)*100;
  unsigned e=polaris_tsens_decode((1u<<21)|code,&value);
  assert(e==((expected < -40000||expected > 150000)?PTS_RANGE:PTS_OK));
  assert(value==(e?123456:expected));
  assert(polaris_tsens_decode(code,&value)==PTS_VALID);
 }
 struct fake s=valid();struct polaris_tsens_io io={&s,rd,clock_us};struct polaris_tsens_sample out;
 assert(!polaris_tsens_observe(&io,&out)&&s.reads==12&&s.clocks==2);
 assert(out.max_gold_mC==43000&&out.max_gpu_mC==45000&&out.ended_us==110);
 for(unsigned i=1;i<=12;i++){s=valid();s.fail=i;rejected(&s,PTS_READ);assert(s.reads==i);}
 for(unsigned i=0;i<12;i++){s=valid();s.raw[i]&=~(1u<<21);rejected(&s,PTS_VALID);assert(s.reads==i+1);}
 s=valid();s.raw[6]+=21;rejected(&s,PTS_CHANGED_TOO_FAST);
 s=valid();s.raw[6]-=21;rejected(&s,PTS_CHANGED_TOO_FAST);
 s=valid();s.raw[5]|=1u<<19;rejected(&s,PTS_CRITICAL);
 s=valid();s.times[0]=0;rejected(&s,PTS_TIME);assert(!s.reads);
 s=valid();s.times[1]=99;rejected(&s,PTS_TIME);
 s=valid();s.times[1]=1101;rejected(&s,PTS_TIME);
 assert(polaris_tsens_observe(0,&out)==PTS_ARGUMENT);
 io.read=0;assert(polaris_tsens_observe(&io,&out)==PTS_ARGUMENT);
 return 0;
}'''
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp);(p/'a.c').write_text(source)
            subprocess.run(['/usr/bin/clang','-std=c11','-Wall','-Wextra','-Werror',
                            '-fsanitize=address,undefined','-I'+str(ROOT/'tools'),str(p/'a.c'),'-o',str(p/'a')],check=True)
            subprocess.run([str(p/'a')],check=True)

if __name__=='__main__':unittest.main()
