"""Synthetic diagnostic records only; no actual temperature or thermal policy."""
from pathlib import Path
import importlib.util,unittest
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('thermal_parser',ROOT/'tools/polaris-thermal-observations.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def sample(stamp=110,base=400):
    values=[base+i*10 for i in range(6)];words='/'.join(format((1<<21)|v,'x') for v in values)
    return ('POLARIS TSENS RO: us=%d begin=%d span=10 gold=%d/%d/%d/%d gpu=%d/%d; mC observations, not sensor freshness\n'%
            (stamp,stamp-10,*[v*100 for v in values]))+''.join('POLARIS TSENS RAW: us=%d pass=%d values=%s\n'%(stamp,p,words) for p in (0,1))

class ThermalParser(unittest.TestCase):
    def test_raw_pairs_and_scope_of_observations(self):
        d=m.analyze(sample()+sample(1000110,401));self.assertEqual(d['valid_observations'],2)
        self.assertEqual(d['sensors'][0]['minimum_mC'],40000);self.assertEqual(d['sensors'][-1]['maximum_mC'],45100)
        self.assertEqual(d['sensors'][0]['distinct_values'],2)
        self.assertFalse(d['sensor_freshness_proven']);self.assertFalse(d['continuous_performance_admitted'])

    def test_malformed_partial_repeated_and_wrong_wire_records_refused(self):
        s=sample();cases=[s.splitlines()[0]+'\n',s+s,s.replace('begin=100','begin=101'),s.replace('span=10','span=1001'),
            s.replace('gold=40000','gold=40001'),s.replace('200190','190'),s.replace('200190','280190'),
            s.replace('pass=1','pass=0'),s.replace('us=110 pass=1','us=111 pass=1'),
            s.replace('span=10','span=10 span=10'),s.replace('200190/20019a','200190'),
            s+sample(109),s.replace('40000/41000','40000/41000 truncated')]
        for text in cases:
            with self.subTest(text=text):
                with self.assertRaises(ValueError):m.analyze(text)
        with self.assertRaises(ValueError):m.analyze('POLARIS TSENS RO: REFUSED platform/mode; no MMIO\n')

    def test_error_records_remain_errors_and_do_not_grant_policy(self):
        d=m.analyze(sample()+'POLARIS TSENS RO: us=1000100 error=4 last_offset=cc raw=0; no temperature or policy admission\n')
        self.assertEqual(d['error_observations'][0]['error'],4);self.assertFalse(d['continuous_performance_admitted'])

if __name__=='__main__':unittest.main()
