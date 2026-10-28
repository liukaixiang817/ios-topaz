from pathlib import Path
import importlib.util,unittest
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('clock',ROOT/'tools/polaris-gpu-clock.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class ClockDecode(unittest.TestCase):
 def fixture(self,hz=257000000,requested=1):
  pll=hz*2;l,rest=divmod(pll,19200000);frac=(rest*65536+19200000-1)//19200000
  ro=dict(end_us=3000000,ok=1,valid=0x3ffff,ACK=0,PERF=0x30000000|requested,BW=4,RETURN=0)
  c=dict(end_us=3000000,CMD=0,CFG=0x101,MODE=0x80000007,L=l,FRAC=frac,USER=0x100,OP=1)
  return ro,c,dict(c)
 def wire(self,rows):
  return '\n'.join('POLARIS GPU CLOCK '+tag+': '+' '.join(k+'='+str(v) if k in ('end_us','ok') else k+'='+format(v,'x') for k,v in row.items()) for tag,row in zip(('RO','A','B'),rows))
 def test_all_original_factory_rates_and_request_not_execution_proof(self):
  for index,hz in enumerate(m.FACTORY_HZ):
   rows=self.fixture(hz,requested=max(index,1));out=m.decode(*rows)
   self.assertTrue(out['admitted']);self.assertLessEqual(abs(out['reference_graph_rate_Hz']-hz),500)
   self.assertEqual(out['nearest_reference_factory_clock_Hz'],hz);self.assertFalse(out['instantaneous_frequency_proven'])
   self.assertFalse(out['physical_clock_graph_verified']);self.assertIsNone(out['physical_configured_clock_Hz'])
   self.assertFalse(out['GPU_busy_or_scanout_FPS_proven']);self.assertEqual(m.analyze(self.wire(rows))[0],dict(out,raw=dict(zip(('RO','A','B'),rows))))
  out=m.decode(*self.fixture(257000000,requested=4));self.assertFalse(out['request_floor_met_by_register_configuration']);self.assertEqual(out['requested_floor_Hz'],520000000)
 def test_unknown_unstable_or_partial_never_proves_frequency(self):
  mutations=[('RO','ok',0),('RO','valid',0x3fffe),('RO','ACK',1),('RO','RETURN',1),('RO','PERF',0x30000000),('RO','PERF',0x30000008),('RO','BW',13),('RO','BW',0),('RO','PERF',0x40000001),('A','CMD',1),('A','CFG',0x301),('A','MODE',0),('A','L',256),('A','L',0),('A','FRAC',65536),('A','USER',0x200),('A','OP',0),('A','CFG',0x1101)]
  for tag,key,value in mutations:
   rows=list(self.fixture());i=('RO','A','B').index(tag);rows[i][key]=value
   if i==1:rows[2][key]=value
   with self.assertRaises(ValueError):m.decode(*rows)
   out=m.analyze(self.wire(rows))[0];self.assertFalse(out['admitted']);self.assertIn('reason',out)
  rows=list(self.fixture());rows[2]['FRAC']^=1
  with self.assertRaisesRegex(ValueError,'changed'):m.decode(*rows)
  rows=list(self.fixture());rows[2]['end_us']+=1
  with self.assertRaisesRegex(ValueError,'timestamp'):m.decode(*rows)
  with self.assertRaises(ValueError):m.decode(*self.fixture(350000000))
 def test_missing_duplicate_wrong_identity_or_overflow_records_rejected(self):
  wire=self.wire(self.fixture())
  for bad in [wire.rsplit('\n',1)[0],wire+'\n'+wire.splitlines()[0],wire.replace('valid=3ffff','valid=3ffff valid=3ffff'),wire.replace('USER=100','USER=100 extra=0'),wire.replace('USER=100','USER=100000000'),wire.replace('USER=100','USER=-1'),wire.replace('end_us=3000000','end_us=18446744073709551616',1)]:
   with self.assertRaises(ValueError):m.analyze(bad)
  with self.assertRaises(ValueError):m.analyze('no native snapshot')
if __name__=='__main__':unittest.main()
