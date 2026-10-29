from pathlib import Path
import importlib.util
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('clock_observations', ROOT / 'tools/polaris-compositor-clock-observations.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class ClockObservationTests(unittest.TestCase):
    def text(self, mode, choice):
        return (f'POLARIS CA CLOCK ENV: request={mode} status={mode}; no refresh-rate claim\n'
                f'POLARIS CA CLOCK TARGET: status=1 mode={mode}; exact20H392 read-only\n'
                f'POLARIS CA CLOCK: us=100 mode={mode} ready=0 choice=0 window_frames=2; choice not hardware Hz\n'
                f'POLARIS CA CLOCK: us=200 mode={mode} ready=1 choice={choice} window_frames=60; choice not hardware Hz\n'
                f'POLARIS CA CLOCK: us=300 mode={mode} ready=1 choice={choice} window_frames=42; choice not hardware Hz\n')

    def test_control_observes_actual_choice_without_assuming_it_is_zero(self):
        for choice in (0, 1):
            d = m.analyze(self.text(2, choice), 150, 400, 2)
            self.assertEqual(d['observed_choices'], [choice])
            self.assertFalse(d['hardware_refresh_Hz_proven'])
            self.assertFalse(d['window_frames_is_cumulative_sequence'])
        self.assertTrue(m.analyze(self.text(1, 1), 150, 400, 1)['passed'])

    def test_missing_duplicate_failed_uninitialized_malformed_and_wrong_choice_refuse(self):
        text = self.text(1, 1)
        bad = [text.replace('status=1 mode=1', 'status=-7 mode=1'),
               text.replace('request=1 status=1', 'request=1 status=-3'),
               text + text.splitlines()[0], text.replace('window_frames=42', 'window_frames='),
               text.replace('us=300', 'us=200'), self.text(1, 0),
               '\n'.join(text.splitlines()[1:])]
        for value in bad:
            with self.subTest(value=value[-150:]), self.assertRaises(ValueError):
                m.analyze(value, 150, 400, 1)
        with self.assertRaises(ValueError):
            m.analyze(text, 50, 400, 1)


if __name__ == '__main__':
    unittest.main()
