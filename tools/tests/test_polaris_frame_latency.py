import importlib.util,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('latency',Path(__file__).resolve().parents[1]/'polaris-frame-latency.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class FullFrameTrace(unittest.TestCase):
 def trace(self):
  lines=[f'tl: g {n} began {1000000+n*50000} ended {1040000+n*50000} 100' for n in range(1,61)]
  lines+=['redwood-gl: frame 20: 100 GL calls; 40000 us (20000 handing on, 12000 waiting, 5 copying out), 0 before it for the IOSurfaces']
  lines+=['POLARIS PANEL PERF: end_us=3000000 span_us=1000000 copies=20 fps10=200 copy_mean_us=15000 maxgap_us=60000 cadence_us=30000']
  lines+=['POLARIS GPU METHOD PERF: end_us=3000000 window_us=2000000 kind=submit calls=100 errors=0 auth_us=2000 dispatch_us=100 lock_us=10 body_us=400000 total_us=402110 max_us=7000']
  return '\n'.join(lines)
 def test_complete_timestamps_and_windows(self):
  r=m.analyze(self.trace(),1000000,5000000);self.assertEqual(r['full_frame_trace_count'],60);self.assertEqual(r['frame_duration_us']['median'],40000);self.assertEqual(r['frame_begin_period_us']['median'],50000);self.assertEqual(r['after_frame_until_next_begin_us']['median'],10000);self.assertEqual(r['panel_copy_rate_per_second'],20);self.assertEqual(r['detailed_phase_us']['other_inside_frame_us']['median'],7995);self.assertFalse(r['hardware_scanout_FPS_proven']);self.assertFalse(r['CPU_busy_proven']);self.assertEqual(r['complete_native_method_windows']['submit']['mean_body_us'],4000)
 def test_partial_windows_excluded(self):
  r=m.analyze(self.trace(),2500000,4100000);self.assertEqual(r['complete_panel_windows'],0);self.assertFalse(r['complete_native_method_windows'])
 def test_missing_overlapping_and_multiple_context_records_refused(self):
  for bad in [self.trace().replace('tl: g 4 ','tl: g 8 '),self.trace().replace('began 1200000','began 1100001'),self.trace().replace('ended 1240000','ended 100')]:
   with self.assertRaises(ValueError):m.analyze(bad,1000000,5000000)
 def test_mismatched_context_phase_not_silently_paired(self):
  with self.assertRaises(ValueError):m.analyze(self.trace().replace('40000 us (','39000 us ('),1000000,5000000)
 def test_native_contacts_exclude_idle_before_the_actual_test(self):
  t='tl: g 1 began 1 ended 2 1\nPOLARIS UEFI INPUT: seq=21 down=1 x=540 y=1500\n'+self.trace()+'\nPOLARIS UEFI INPUT: seq=380 down=0 x=540 y=1500'
  a,b,proof=m.contact_bounds(t,21,380);self.assertEqual(a,1100000);self.assertEqual(b,4040000);self.assertEqual(proof['first_post_contact_completion_excluded'],1)
  with self.assertRaises(ValueError):m.contact_bounds(t,380,21)
  with self.assertRaises(ValueError):m.contact_bounds(t.replace('seq=21','seq=22'),21,380)
  with self.assertRaises(ValueError):m.contact_bounds(t+'\nPOLARIS UEFI INPUT: seq=21 down=1 x=1 y=1',21,380)
 def test_all_submit_phases_match_native_success_and_are_not_added_twice(self):
  line='\nPOLARIS GPU STAGE PERF: end_us=3000000 window_us=2000000 submits=100 rejected=0 core_missing=0 validation_us=50000 cache_pre_us=100000 submit_us=200000 cache_post_us=50000 prior_us=5000 ring_us=5000 execute_idle_us=150000 visibility_us=5000 halt_us=5000 postcheck_us=5000 prebytes=1000000 postbytes=1000000 WCpre=500000 WCpost=500000'
  r=m.analyze(self.trace()+line,1000000,5000000);self.assertEqual(r['complete_all_submit_phase_windows'],1);self.assertEqual(r['all_submit_phase_totals']['submits'],100);self.assertTrue(r['core_phases_are_subset_of_submit_us']);self.assertGreater(r['phase_window_EAGL_completions'],0)
  for bad in [line.replace('submits=100','submits=99'),line.replace('core_missing=0','core_missing=1'),line.replace('execute_idle_us=150000','execute_idle_us=250000')]:
   with self.assertRaises(ValueError):m.analyze(self.trace()+bad,1000000,5000000)
 def test_sparse_only_never_claims_whole_rate(self):
  with self.assertRaises(ValueError):m.analyze('redwood-gl: frame20',0,1000000)
 def test_truncated_and_interleaved_stage_records_fail_explicitly(self):
  short='\nPOLARIS GPU STAGE PERF: end_us=3000000 window_us=2000000 submits=100 rejected=0 core_missing=0 validation_us=50000 cache_pre_us=100000 submit_us=200000 cache_post_us=50000 prior_us=5000 ring_us=5000 execute_idle_us=150000 visibility_us=5000 halt_us=5000 p'
  with self.assertRaisesRegex(ValueError,'truncated or malformed'):
   m.analyze(self.trace()+short,1000000,5000000)
  with self.assertRaisesRegex(ValueError,'duplicate field'):
   m.analyze(self.trace()+short+'POLARIS OSM LOAD RO: end_us=3000010',1000000,5000000)
 def test_split_console_records_require_every_identity_matching_part(self):
  method=self.trace().split('POLARIS GPU METHOD PERF: ')[1]
  f=m.fields(method);end=f['end_us']
  def record(prefix,row):return prefix+': '+' '.join(str(k)+'='+str(v) for k,v in row.items())
  def subset(keys):return {k:f[k] for k in keys.split()}
  top=record('POLARIS GPU METHOD PERF',subset('end_us window_us kind calls errors'))
  auth=record('POLARIS GPU METHOD AUTH',subset('end_us kind auth_us dispatch_us lock_us'))
  work=record('POLARIS GPU METHOD WORK',subset('end_us kind body_us total_us max_us'))
  base=self.trace().split('POLARIS GPU METHOD PERF:')[0]+top+'\n'+auth+'\n'+work
  phase=[
   'POLARIS GPU STAGE PERF: end_us=3000000 window_us=2000000 submits=100 rejected=0 core_missing=0',
   'POLARIS GPU STAGE WORK: end_us=3000000 validation_us=50000 cache_pre_us=100000 submit_us=200000 cache_post_us=50000',
   'POLARIS GPU STAGE EXEC: end_us=3000000 prior_us=5000 ring_us=5000 execute_idle_us=150000',
   'POLARIS GPU STAGE DONE: end_us=3000000 visibility_us=5000 halt_us=5000 postcheck_us=5000',
   'POLARIS GPU STAGE BYTES: end_us=3000000 prebytes=1000000 postbytes=1000000 WCpre=500000 WCpost=500000']
  full=base+'\n'+'\n'.join(phase);r=m.analyze(full,1000000,5000000)
  self.assertEqual(r['all_submit_phase_totals']['submits'],100)
  self.assertEqual(r['complete_native_method_windows']['submit']['mean_body_us'],4000)
  for line in [*phase,auth,work,top]:
   with self.assertRaises(ValueError):m.analyze(full.replace(line,''),1000000,5000000)
  for line in [*phase,auth,work,top]:
   with self.assertRaises(ValueError):m.analyze(full+'\n'+line,1000000,5000000)
  with self.assertRaises(ValueError):m.analyze(full.replace(auth,auth.replace('3000000','3000001')),1000000,5000000)
  with self.assertRaises(ValueError):m.analyze(full.replace(auth,auth.replace('kind=submit','kind=close')),1000000,5000000)
if __name__=='__main__':unittest.main()
