import importlib.util,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('latency',Path(__file__).resolve().parents[1]/'polaris-frame-latency.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class FullFrameTrace(unittest.TestCase):
 def trace(self):
  lines=[f'tl: g {n} began {1000000+n*50000} ended {1040000+n*50000} 100' for n in range(1,61)]
  lines+=['POLARIS PANEL PERF: end_us=3000000 span_us=1000000 copies=20 fps10=200 copy_mean_us=15000 maxgap_us=60000 cadence_us=30000']
  lines+=['POLARIS GPU METHOD PERF: end_us=3000000 window_us=2000000 kind=submit calls=100 errors=0 auth_us=2000 dispatch_us=100 lock_us=10 body_us=400000 total_us=402110 max_us=7000']
  return '\n'.join(lines)
 def test_complete_timestamps_and_windows(self):
  r=m.analyze(self.trace(),1000000,5000000);self.assertEqual(r['full_frame_trace_count'],60);self.assertEqual(r['frame_duration_us']['median'],40000);self.assertEqual(r['frame_begin_period_us']['median'],50000);self.assertEqual(r['after_frame_until_next_begin_us']['median'],10000);self.assertEqual(r['panel_copy_rate_per_second'],20);self.assertFalse(r['hardware_scanout_FPS_proven']);self.assertFalse(r['CPU_busy_proven']);self.assertEqual(r['complete_native_method_windows']['submit']['mean_body_us'],4000)
 def test_partial_windows_excluded(self):
  r=m.analyze(self.trace(),2500000,4100000);self.assertEqual(r['complete_panel_windows'],0);self.assertFalse(r['complete_native_method_windows'])
 def test_missing_overlapping_and_multiple_context_records_refused(self):
  for bad in [self.trace().replace('tl: g 4 ','tl: g 8 '),self.trace().replace('began 1200000','began 1100001'),self.trace().replace('ended 1240000','ended 100')]:
   with self.assertRaises(ValueError):m.analyze(bad,1000000,5000000)
 def test_sparse_only_never_claims_whole_rate(self):
  with self.assertRaises(ValueError):m.analyze('redwood-gl: frame20',0,1000000)
if __name__=='__main__':unittest.main()
