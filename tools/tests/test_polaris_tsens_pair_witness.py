"""Conservative VALID-word witnesses: preserve hottest data and refuse faults."""
from pathlib import Path
import copy
import importlib.util
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


class PairWitness(unittest.TestCase):
    def test_separate_scope_and_policy_tampering_refusal(self):
        builder = load('pair_builder', 'tools/build-polaris-uefi-xnu.py')
        image = load('pair_image', 'tools/polaris-uefi-xnu-image.py')
        tokens = [b'polarispts=1', b'polaristsens=3', b'polarisramcow=1', b'ufsrw=0', b'polarisquiesce=1']
        policy = builder.tsens_pair_witness_intent(tokens, True, True, True, True)
        self.assertEqual(policy['max_physical_reads'], 72)
        self.assertIsNone(builder.tsens_pair_witness_intent([], False, False, False, False))
        for index, value in [(0, tokens + tokens[:1]), (0, tokens[1:]),
                             (0, [b'polarispts=0'] + tokens[1:]), (1, False),
                             (1, 1), (2, False), (3, False), (4, False), (4, 1)]:
            args = [tokens, True, True, True, True]
            args[index] = value
            with self.assertRaises(ValueError):
                builder.tsens_pair_witness_intent(*args)
        for token in tokens[1:]:
            with self.assertRaises(ValueError):
                builder.tsens_pair_witness_intent([x for x in tokens if x != token], True, True, True, True)
        driver = dict(TSENS_pair_witness_trial=True, TSENS_pair_policy=policy)
        vm = dict(driver, checks={'native_TSENS_pair_witness_core': True, 'explicit_TSENS_pair_payload': True})
        image.admit_pair_witness_policy(driver, vm, True, True)
        for key in vm['checks']:
            bad = copy.deepcopy(vm)
            bad['checks'].pop(key)
            with self.assertRaises(ValueError):
                image.admit_pair_witness_policy(driver, bad, True, True)
        for side in ['driver', 'VM']:
            for key, value in [('max_physical_reads', 73), ('max_pair_delta_mC', 2001),
                               ('max_span_us', 1001), ('hottest_word_required', 0),
                               ('actual_words_only', True), ('max_words_per_sensor', 4.0)]:
                d, v = copy.deepcopy(driver), copy.deepcopy(vm)
                (d if side == 'driver' else v)['TSENS_pair_policy'][key] = value
                with self.assertRaises(ValueError):
                    image.admit_pair_witness_policy(d, v, True, True)
        for thermal, extended in [(False, True), (True, False)]:
            with self.assertRaises(ValueError):
                image.admit_pair_witness_policy(driver, vm, thermal, extended)
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / 'must-not-exist'
            p = subprocess.run(['python3', str(ROOT / 'tools/build-polaris-uefi-xnu.py'),
                                '--tsens-pair-witness', '--zig', '/no/zig', '--kernel', '/no/kernel',
                                '--payload', '/no/payload', '--output', str(out)], capture_output=True, text=True)
            self.assertEqual(p.returncode, 2)
            self.assertIn('TSENS', p.stderr)
            self.assertFalse(out.exists())

    def test_exact_native_body_and_guard_before_mapping(self):
        patch = (ROOT / 'xnu/profiles/polaris/0897-polaris-conservative-TSENS-pair-witness.patch').read_text()
        added = '\n'.join(s[1:] for s in patch.splitlines() if s.startswith('+') and not s.startswith('+++'))
        body = added.split('/* BEGIN CONSERVATIVE TSENS PAIR WITNESS: exact tested core. */\n')[1].split('\n/* END CONSERVATIVE TSENS PAIR WITNESS. */')[0]
        expected = (ROOT / 'tools/polaris-tsens-pair-witness.h').read_text().replace(
            '#ifndef POLARIS_TSENS_PAIR_WITNESS_H\n#define POLARIS_TSENS_PAIR_WITNESS_H\n', '').replace(
            '#include "polaris-tsens-readonly.h"\n', '')[:-7]
        self.assertEqual(body, expected)
        self.assertEqual(set(re.findall(r'^\+\+\+ b/(.*)$', patch, re.M)), {'iokit/Kernel/arm/SweetCPU.cpp'})
        self.assertIn('pair!=1 || flag!=3', added)
        self.assertIn('polaris_tsens_observe_retry(&io,&sample,&retry)', added)  # unchanged control
        self.assertIn('!polaris_tsens_pair_vm_probe()', added)
        self.assertIn('gate.hot', added)
        self.assertIn('POLARIS OSM REQUEST: begin_us=%llu end_us=%llu', added)
        self.assertIn('no partial admission', added)
        self.assertNotRegex(added, r'polaris_tsens_regs\[[^\]]+\]\s*=(?!=)')
        self.assertNotIn('a630_ch_write(', added)
        self.assertNotIn('polaris_a630_runtime.h', patch)

    def test_actual_raw_word_peak_preservation_and_faults(self):
        source = r'''
#include "polaris-tsens-pair-witness.h"
#include "polaris-tsens-retry.h"
#include "polaris-thermal-eligibility.h"
#include <assert.h>
#include <string.h>
struct fixture {
 int value[6][4];unsigned cursor[6],attempt[6],invalid,reads,clocks;
 unsigned fail,critical,range;uint64_t time[2];
};
static uint32_t word(int c){return (1u<<21)|((uint32_t)c&0xfff);}
static bool read_status(void *v,uint32_t offset,uint32_t *out) {
 struct fixture *s=v;assert(offset>=0xbc&&offset<=0xd0&&!(offset&3));
 unsigned n=(offset-0xbc)/4;s->reads++;assert(s->reads<=72&&s->cursor[n]<4);
 if(s->reads==s->fail)return false;
 *out=word(s->value[n][s->cursor[n]]);
 if(s->reads==s->critical){*out=1u<<19;return true;}
 if(s->reads==s->range){*out=word(1800);return true;}
 if(s->attempt[n]++<s->invalid){*out&=~(1u<<21);return true;}
 s->attempt[n]=0;s->cursor[n]++;return true;
}
static uint64_t clock_us(void *v) {
 struct fixture *s=v;assert(s->clocks<2);return s->time[s->clocks++];
}
static struct fixture fixture(void) {
 struct fixture s={0};s.time[0]=100;s.time[1]=110;
 for(unsigned n=0;n<6;n++)for(unsigned k=0;k<4;k++)s.value[n][k]=400+10*(int)n;
 return s;
}
static void check_success(const struct fixture *f,const struct polaris_tsens_sample *p,
 const struct polaris_tsens_pair_audit *a) {
 assert(!a->error&&a->physical_reads==f->reads&&a->physical_reads<=72&&a->logical_reads<=24);
 assert(a->began_us==p->began_us&&a->ended_us==p->ended_us);
 assert(pte_sample_valid(p,p->ended_us));
 for(unsigned n=0;n<6;n++) {
  assert(a->count[n]>=2&&a->count[n]<=4&&a->count[n]==f->cursor[n]);
  int maximum=-400;
  for(unsigned k=0;k<a->count[n];k++) {
   assert(a->raw[n][k]==word(f->value[n][k]));
   if(f->value[n][k]>maximum)maximum=f->value[n][k];
  }
  unsigned x=a->selected[n][0],y=a->selected[n][1];assert(x<y&&y<a->count[n]);
  assert(p->raw[0][n]==a->raw[n][x]&&p->raw[1][n]==a->raw[n][y]);
  assert(p->temperature_mC[n]==maximum*100);
  assert(f->value[n][x]-f->value[n][y]<=20&&f->value[n][y]-f->value[n][x]<=20);
 }
}
static unsigned observe(struct fixture *s,struct polaris_tsens_sample *p,
 struct polaris_tsens_pair_audit *a) {
 struct polaris_tsens_io io={s,read_status,clock_us};
 return polaris_tsens_observe_pair_witness(&io,p,a);
}
static void reject(struct fixture *s,unsigned expected) {
 struct polaris_tsens_sample p,old;struct polaris_tsens_pair_audit a;
 memset(&p,0xa5,sizeof(p));old=p;
 assert(observe(s,&p,&a)==expected&&a.error==expected);
 assert(!memcmp(&p,&old,sizeof(p))&&s->reads<=72);
}
int main(void) {
 struct fixture s=fixture(),control=s;
 struct polaris_tsens_sample p,q;struct polaris_tsens_pair_audit a;
 struct polaris_tsens_retry_evidence old_evidence;
 struct polaris_tsens_io control_io={&control,read_status,clock_us};
 assert(!observe(&s,&p,&a));check_success(&s,&p,&a);
 assert(!polaris_tsens_observe_retry(&control_io,&q,&old_evidence));
 assert(!memcmp(&p,&q,sizeof(p))&&!a.repaired_mask&&s.reads==12);
 for(unsigned n=0;n<6;n++) {
  s=fixture();s.value[n][1]=s.value[n][0]+20;
  assert(!observe(&s,&p,&a)&&!a.repaired_mask&&s.reads==12);check_success(&s,&p,&a);
  /* A rising step is corroborated at its higher value, never averaged down. */
  s=fixture();s.value[n][0]=400;s.value[n][1]=450;s.value[n][2]=450;
  assert(!observe(&s,&p,&a)&&a.repaired_mask==(1u<<n)&&s.reads==13);check_success(&s,&p,&a);
  /* A hot first word needs a hot witness. Two or three cold words don't win. */
  s=fixture();s.value[n][0]=800;s.value[n][1]=400;s.value[n][2]=800;
  assert(!observe(&s,&p,&a)&&p.temperature_mC[n]==80000);check_success(&s,&p,&a);
  struct polaris_thermal_eligibility gate={0};assert(pte_observe(&gate,&p,0,p.ended_us)&&gate.hot);
  s=fixture();s.value[n][0]=800;s.value[n][1]=400;s.value[n][2]=400;s.value[n][3]=400;
  reject(&s,PTS_CHANGED_TOO_FAST);assert(s.cursor[n]==4);
  /* A new still-higher peak cannot be ignored for an older cooler pair. */
  s=fixture();s.value[n][0]=400;s.value[n][1]=500;s.value[n][2]=600;s.value[n][3]=600;
  assert(!observe(&s,&p,&a)&&s.reads==14&&p.temperature_mC[n]==60000);check_success(&s,&p,&a);
  s=fixture();s.value[n][0]=400;s.value[n][1]=500;s.value[n][2]=600;s.value[n][3]=500;
  reject(&s,PTS_CHANGED_TOO_FAST);
 }
 /* Exercise the complete72-read bound, and every actual I/O failure position. */
 struct fixture maximum=fixture();maximum.invalid=2;
 for(unsigned n=0;n<6;n++){maximum.value[n][0]=400;maximum.value[n][1]=600;maximum.value[n][2]=800;maximum.value[n][3]=800;}
 s=maximum;assert(!observe(&s,&p,&a)&&s.reads==72&&a.logical_reads==24&&a.retry_mask==0xffffff&&a.repaired_mask==63);check_success(&s,&p,&a);
 for(unsigned i=1;i<=72;i++) {
  s=maximum;s.fail=i;reject(&s,PTS_READ);assert(s.reads==i);
  s=maximum;s.critical=i;reject(&s,PTS_CRITICAL);assert(s.reads==i);
  s=maximum;s.range=i;reject(&s,PTS_RANGE);assert(s.reads==i);
 }
 s=fixture();s.invalid=3;reject(&s,PTS_VALID);assert(s.reads==3);
 s=maximum;s.time[1]=1101;reject(&s,PTS_TIME);
 s=maximum;s.time[1]=99;reject(&s,PTS_TIME);
 s=maximum;s.time[0]=0;reject(&s,PTS_TIME);assert(!s.reads);
 s=fixture();s.time[0]=UINT64_MAX-20;s.time[1]=UINT64_MAX;
 assert(!observe(&s,&p,&a));check_success(&s,&p,&a);
 unsigned seed=0x104630;
 for(unsigned trial=0;trial<20000;trial++) {
  s=fixture();seed=seed*1664525u+1013904223u;s.invalid=(seed>>16)%3;
  for(unsigned n=0;n<6;n++)for(unsigned k=0;k<4;k++) {
   seed=seed*1664525u+1013904223u;s.value[n][k]=(int)((seed>>16)%1901)-400;
  }
  struct polaris_tsens_sample before;memset(&p,0xa5,sizeof(p));before=p;
  unsigned error=observe(&s,&p,&a);
  if(!error)check_success(&s,&p,&a);
  else assert(error==PTS_CHANGED_TOO_FAST&&!memcmp(&p,&before,sizeof(p)));
 }
 assert(polaris_tsens_observe_pair_witness(0,&p,&a)==PTS_ARGUMENT);
 s=fixture();struct polaris_tsens_io io={&s,read_status,clock_us};
 assert(polaris_tsens_observe_pair_witness(&io,0,&a)==PTS_ARGUMENT);
 assert(polaris_tsens_observe_pair_witness(&io,&p,0)==PTS_ARGUMENT&&!s.reads);
 return 0;
}'''
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / 'a.c').write_text(source)
            subprocess.run(['/usr/bin/clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', '-I' + str(ROOT / 'tools'),
                            str(p / 'a.c'), '-o', str(p / 'a')], check=True)
            subprocess.run([str(p / 'a')], check=True)


if __name__ == '__main__':
    unittest.main()
