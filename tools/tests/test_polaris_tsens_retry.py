"""VALID-only status re-read bounds, atomic observations and native binding."""
from pathlib import Path
import subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[2]

class TsensRetry(unittest.TestCase):
    def test_real_error_boundaries_and_random_complete_observations(self):
        source=r'''
#include "polaris-tsens-retry.h"
#include <assert.h>
#include <string.h>
struct fixture {uint32_t raw[36],off[36];unsigned count,reads,clocks,fail;
 uint64_t time[2];};
static bool read_status(void *context,uint32_t offset,uint32_t *out) {
 struct fixture *s=context;unsigned n=s->reads++;
 assert(n<s->count && n<36 && offset==s->off[n]);
 if(n+1==s->fail)return false;
 *out=s->raw[n];return true;
}
static uint64_t clock_us(void *context) {
 struct fixture *s=context;assert(s->clocks<2);return s->time[s->clocks++];
}
static struct fixture setup(const unsigned invalid[12]) {
 struct fixture s={0};s.time[0]=100;s.time[1]=110;
 for(unsigned slot=0;slot<12;slot++) {
  for(unsigned a=0;a<=invalid[slot] && a<3;a++) {
   unsigned n=s.count++;s.off[n]=0xbc+(slot%6)*4;
   s.raw[n]=400+(slot%6)*10;
   if(a==invalid[slot])s.raw[n]|=1u<<21;
  }
  if(invalid[slot]>=3)break;
 }
 return s;
}
static void reject(struct fixture *s,unsigned error) {
 struct polaris_tsens_io io={s,read_status,clock_us};
 struct polaris_tsens_sample out,old;
 struct polaris_tsens_retry_evidence evidence,before;
 memset(&out,0xa5,sizeof(out));old=out;
 memset(&evidence,0xa5,sizeof(evidence));before=evidence;
 assert(polaris_tsens_observe_retry(&io,&out,&evidence)==error);
 assert(!memcmp(&old,&out,sizeof(out)));
 assert(!memcmp(&before,&evidence,sizeof(evidence)));assert(s->reads<=36);
}
static void accept(struct fixture *s,uint32_t mask) {
 struct polaris_tsens_io io={s,read_status,clock_us};
 struct polaris_tsens_sample out;struct polaris_tsens_retry_evidence evidence;
 assert(!polaris_tsens_observe_retry(&io,&out,&evidence));
 assert(s->reads==s->count && evidence.reads==s->count && evidence.retry_mask==mask);
 assert(out.max_gold_mC==43000 && out.max_gpu_mC==45000);
 for(unsigned pass=0;pass<2;pass++)for(unsigned slot=0;slot<6;slot++)
  assert(out.raw[pass][slot]==((1u<<21)|(400+slot*10)));
}
int main(void) {
 unsigned invalid[12]={0};struct fixture s;
 for(unsigned slot=0;slot<12;slot++)for(unsigned bad=0;bad<=3;bad++) {
  memset(invalid,0,sizeof(invalid));invalid[slot]=bad;s=setup(invalid);
  if(bad==3){reject(&s,PTS_VALID);assert(s.reads==slot+3);}
  else accept(&s,bad?1u<<slot:0);
 }
 for(unsigned slot=0;slot<12;slot++) {
  memset(invalid,0,sizeof(invalid));invalid[slot]=1;
  s=setup(invalid);s.raw[slot]|=1u<<19;reject(&s,PTS_CRITICAL);assert(s.reads==slot+1);
  s=setup(invalid);s.raw[slot]=(1u<<21)|1800;reject(&s,PTS_RANGE);assert(s.reads==slot+1);
 }
 for(unsigned slot=0;slot<12;slot++)invalid[slot]=2;
 for(unsigned n=1;n<=36;n++){s=setup(invalid);s.fail=n;reject(&s,PTS_READ);assert(s.reads==n);}
 s=setup(invalid);s.time[1]=1101;reject(&s,PTS_TIME);
 s=setup(invalid);s.time[1]=99;reject(&s,PTS_TIME);
 s=setup(invalid);s.time[0]=0;reject(&s,PTS_TIME);assert(!s.reads);
 s=setup(invalid);s.raw[20]+=21;reject(&s,PTS_CHANGED_TOO_FAST);
 uint32_t random=0x51a7b00d;
 for(unsigned trial=0;trial<10000;trial++) {
  uint32_t mask=0;
  for(unsigned slot=0;slot<12;slot++) {
   random=random*1664525u+1013904223u;invalid[slot]=(random>>16)%3;
   if(invalid[slot])mask|=1u<<slot;
  }
  s=setup(invalid);accept(&s,mask);
 }
 struct polaris_tsens_sample out;struct polaris_tsens_retry_evidence evidence;
 assert(polaris_tsens_observe_retry(0,&out,&evidence)==PTS_ARGUMENT);
 s=setup(invalid);struct polaris_tsens_io io={&s,read_status,clock_us};
 assert(polaris_tsens_observe_retry(&io,&out,0)==PTS_ARGUMENT);
 assert(!s.reads);
 return 0;
}'''
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp);(p/'a.c').write_text(source)
            subprocess.run(['/usr/bin/clang','-std=c11','-Wall','-Wextra','-Werror',
                '-fsanitize=address,undefined','-I'+str(ROOT/'tools'),str(p/'a.c'),'-o',str(p/'a')],check=True)
            subprocess.run([str(p/'a')],check=True)

    def test_exact_native_adapter_and_failure_logs_before_thinning(self):
        patch=ROOT/'xnu/profiles/polaris/0895-polaris-TSENS-valid-only-bounded-retry.patch'
        added='\n'.join(s[1:] for s in patch.read_text().splitlines() if s.startswith('+') and not s.startswith('+++'))
        header=(ROOT/'tools/polaris-tsens-retry.h').read_text().replace(
            '#ifndef POLARIS_TSENS_RETRY_H\n#define POLARIS_TSENS_RETRY_H\n','').replace(
            '#include "polaris-tsens-readonly.h"\n','')[:-7]
        body=added.split('/* BEGIN OWN TSENS VALID RETRY: exact bounded adapter, no invalid fallback. */\n',1)[1].split('\n/* END OWN TSENS VALID RETRY. */',1)[0]
        self.assertEqual(header,body)
        self.assertIn('polaris_tsens_observe_retry(&io,&sample,&retry)',added)
        self.assertIn('!polaris_tsens_retry_vm_probe()',added)
        self.assertIn('error==PTS_VALID && s.reads==3 && !s.slot',added)
        self.assertIn('s.critical=1',added)
        context='\n'.join(s[1:] for s in patch.read_text().splitlines() if s.startswith((' ','+')))
        self.assertLess(context.index('if(error) {'),context.index('if(now<polaris_tsens_report_us)return;'))
        self.assertNotIn('pte_observe(',added) # original admission path and guards unchanged
        self.assertNotRegex(added,r'polaris_tsens_regs\[[^\]]+\]\s*=(?!=)')
        self.assertNotIn('polaris_a630_runtime.h',patch.read_text())

if __name__=='__main__':unittest.main()
