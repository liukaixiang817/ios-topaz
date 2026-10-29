"""Cross-check actual C accounting/formatter against strict host trace audit."""
from pathlib import Path
import importlib.util
import subprocess
import tempfile
import unittest
from .test_polaris_gpu_lifetime import function

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('tail_latency', ROOT / 'tools/polaris-frame-tail-latency.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class TailLatencyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        emitter = function((ROOT / 'userland/gpu/eagl.c').read_text(), 'static void polaris_tail_emit(')
        source = '#include "' + str(ROOT / 'tools/polaris-frame-tail.h') + '"\n' + r'''
#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
static void say(const char *format,...){va_list a;va_start(a,format);vprintf(format,a);va_end(a);}
''' + emitter + r'''
int main(void){struct pgpu_frame_tail s={0};uint64_t b=1000;
 for(unsigned i=1;i<=129;i++){
  assert(pgpu_tail_begin(&s,i,b));
  printf("tl: g %u began %llu ended %llu 1\n",i,b,b+10000);
  struct pgpu_tail_window w;uint32_t q;
  if(pgpu_tail_take(&s,&w,&q))polaris_tail_emit(0x3800000001ULL,2,q,&w);
  assert(pgpu_tail_end(&s,i,b,b+10000,b+10100,20,30,10));
  b+=13000;
 }return 0;}
'''
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp); (p / 'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang', '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', str(p / 'test.c'), '-o', str(p / 'test')], check=True)
            cls.text = subprocess.check_output([str(p / 'test')], text=True)

    def test_two_real_formatter_windows_match_all_full_frame_timestamps(self):
        d = m.analyze(self.text, 0, 2000000, 2)
        self.assertEqual(d['complete_pairs'], 128)
        self.assertEqual(d['mean_wall_us_per_pair']['tail'], 100)
        self.assertEqual(d['mean_wall_us_per_pair']['outside'], 2900)
        self.assertEqual(d['active_mean_wall_us']['log'], 20)
        self.assertTrue(all(w['full_trace_independently_matched'] for w in d['complete_windows']))
        self.assertFalse(d['outside_is_pure_scheduler_wait'])
        self.assertFalse(d['hardware_scanout_Hz_proven'])
        b = d['full_trace_residual_bounds']
        self.assertEqual(b['all_pairs']['pairs'], 128)
        self.assertEqual(b['period_le_25000_us']['pairs'], 128)
        self.assertEqual(b['all_pairs']['outside_tail_and_API_lower_us']['min'], 2900)
        self.assertFalse(b['individual_tail_or_API_time_proven'])
        self.assertFalse(b['scheduler_wait_proven'])

    def test_missing_duplicate_forged_truncated_and_fault_records_refuse(self):
        text = self.text
        bad = [text.replace('tail=6400', 'tail=6401', 1),
               text.replace('obs=1920', 'obs=9999999', 1),
               text.replace('mode=2', 'mode=3', 1),
               text.replace('q=2', 'q=3'),
               text.replace('first=65', 'first=66'),
               '\n'.join(l for l in text.splitlines() if not l.startswith('tl: g 20 ')),
               '\n'.join(l for l in text.splitlines() if not l.startswith('POLARIS GL TAIL WORK:')),
               text.replace('TOTAL: id=', 'TOTAL: bad_id=', 1),
               text + next(l for l in text.splitlines() if l.startswith('POLARIS GL TAIL TOTAL:')) + '\n',
               text + 'POLARIS GL TAIL FAULT: id=3800000001 error=2; timing disabled, rendering unchanged\n']
        for value in bad:
            with self.subTest(value=value[-300:]):
                with self.assertRaises(ValueError):
                    m.analyze(value, 0, 2000000, 2)

    def test_sparse_mode_retains_partition_without_claiming_full_trace(self):
        text = '\n'.join(l.replace('mode=2', 'mode=3') for l in self.text.splitlines()
                         if not l.startswith('tl: g '))
        d = m.analyze(text, 0, 2000000, 3)
        self.assertEqual(d['complete_pairs'], 128)
        self.assertFalse(any(w['full_trace_independently_matched'] for w in d['complete_windows']))
        self.assertFalse(d['final_unclosed_tail_measured'])
        self.assertIsNone(d['full_trace_residual_bounds'])
        with self.assertRaises(ValueError):
            m.analyze(text, 0, 2000000, 2)

    def test_partial_overlap_and_missing_outside_window_do_not_admit_partial_data(self):
        text = '\n'.join(l for l in self.text.splitlines()
                         if not (l.startswith('POLARIS GL TAIL WORK:') and 'q=1 ' in l))
        d = m.analyze(text, 833000, 2000000, 2)
        self.assertEqual(d['complete_pairs'], 64)
        with self.assertRaises(ValueError):
            m.analyze(text, 0, 2000000, 2)
        with self.assertRaises(ValueError):
            m.analyze(self.text, 2000, 830000, 2)

    def test_residual_uses_conservative_window_maximum_not_an_average(self):
        # Totals alone permit one long tail. Subtract the window maximum
        # from every pair; do not assign the 100us average to each frame.
        text = self.text.replace('maxtail=100 ', 'maxtail=5000 ')
        d = m.analyze(text, 0, 2000000, 2)
        self.assertEqual(d['mean_wall_us_per_pair']['tail'], 100)
        self.assertEqual(d['full_trace_residual_bounds']['all_pairs']
                         ['outside_tail_and_API_lower_us']['max'], 0)
        self.assertTrue(all(v['tail_upper_us'] == 5000 for v in
                            d['full_trace_residual_bounds']['rows']))


if __name__ == '__main__':
    unittest.main()
