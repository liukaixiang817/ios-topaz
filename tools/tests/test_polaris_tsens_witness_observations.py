"""Reject forged cooler witnesses, missing parts and malformed native audits."""
from pathlib import Path
import importlib.util
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('witness_parser', ROOT / 'tools/polaris-tsens-witness-observations.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def word(value):
    return format((1 << 21) | value, 'x')


def ordinary():
    words = '/'.join(word(400 + 10 * i) for i in range(6))
    return ('POLARIS TSENS RO: us=110 begin=100 span=10 gold=40000/41000/42000/43000 gpu=44000/45000; mC observations, not sensor freshness\n'
            + ''.join('POLARIS TSENS RAW: us=110 pass=%d values=%s\n' % (i, words) for i in (0, 1)))


def witness():
    return ('POLARIS TSENS PAIR IO: us=210 begin=200 end=210 reads=13 logical=13 valid_retry=0 disagree=1 repaired=1; bounded72 physical reads\n'
            + 'POLARIS TSENS WITNESS: us=210 id=7 count=3 selected=1/2 values=%s/%s/%s/0; hottest observed VALID word retained\n' % (word(400), word(450), word(450)))


class WitnessObservations(unittest.TestCase):
    def test_conservative_authentic_words_and_failure_retention(self):
        d = m.analyze(ordinary() + witness())
        self.assertEqual(d['witness_observations'][0]['sensors'][0]['hottest_mC'], 45000)
        self.assertFalse(d['continuous_performance_admitted'])
        hot = witness().replace(word(450), word(800))
        self.assertTrue(m.analyze(ordinary() + hot)['witness_observations'][0]['sensors'][0]['hot_experiment_limit_reached'])
        failure = ('POLARIS TSENS RO: us=300 error=7 last_offset=bc raw=%s; no temperature or policy admission\n'
                   'POLARIS TSENS PAIR FAIL: us=300 begin=301 end=310 error=7 id=7 count=4 reads=9 raw=%s/%s/%s/%s last=%s; no partial admission\n') % ((word(400),) + (word(800), word(400), word(400), word(400), word(400)))
        d = m.analyze(ordinary() + failure)
        self.assertEqual(d['failed_observations'][0]['error'], 7)
        self.assertFalse(d['failed_observations'][0]['performance_admission'])

    def test_forged_or_partial_recovery_refused(self):
        good = ordinary() + witness()
        bad = [good + witness(), good.replace('selected=1/2', 'selected=0/2'),
               good.replace('count=3', 'count=2'), good.replace('id=7', 'id=13'),
               good.replace('logical=13', 'logical=12'), good.replace('reads=13', 'reads=12'),
               good.replace('begin=200', 'begin=1').replace('end=210', 'end=1010').replace('us=210', 'us=1010'),
               good.replace('valid_retry=0', 'valid_retry=4000'), good.replace('repaired=1', 'repaired=3'),
               good.replace(word(450), '450'), good.replace(word(450), '280190'),
               good.replace('selected=1/2', 'selected=1/1'),
               ordinary() + witness().splitlines()[1] + '\n',
               ordinary() + witness().splitlines()[0] + '\n',
               good.replace('hottest observed VALID word retained', 'truncated')]
        for text in bad:
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    m.analyze(text)
        # A hot outlier cannot be voted away by the two cooler matching words.
        cooler = good.replace(word(400) + '/' + word(450) + '/' + word(450),
                              word(800) + '/' + word(400) + '/' + word(400))
        with self.assertRaises(ValueError):
            m.analyze(cooler)


if __name__ == '__main__':
    unittest.main()
