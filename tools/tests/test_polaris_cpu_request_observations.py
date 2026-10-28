from pathlib import Path
import importlib.util
import unittest

spec = importlib.util.spec_from_file_location('cpu_requests', Path(__file__).resolve().parents[1] / 'polaris-cpu-request-observations.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def request(begin, end, index, transitions, error=0):
    return f'POLARIS OSM REQUEST: begin_us={begin} end_us={end} index={index} transitions={transitions} error={error}; request not measured Hz\n'


class CPUObservations(unittest.TestCase):
    def test_real_clock_brackets_exclude_transition_frames_and_end_extrapolation(self):
        text = (request(100, 110, 0, 0) + request(200, 210, 22, 1) + request(400, 410, 22, 1)
                + 'tl: g 1 began 90 ended 120 1\n'
                + 'tl: g 2 began 120 ended 190 1\n'
                + 'tl: g 3 began 190 ended 220 1\n'
                + 'tl: g 4 began 220 ended 390 1\n'
                + 'tl: g 5 began 390 ended 420 1\n'
                + 'tl: g 6 began 420 ended 450 1\n')
        d = m.analyze(text, 0, 500)
        self.assertEqual(d['excluded_frames'], 4)
        self.assertEqual(d['frame_duration_by_last_observed_request']['0']['median'], 70)
        self.assertEqual(d['frame_duration_by_last_observed_request']['22']['median'], 170)
        self.assertFalse(d['continuous_hardware_frequency_proven'])
        self.assertTrue(d['correlation_is_not_isolated_causation'])

    def test_missing_reversed_duplicate_or_malformed_records_refused(self):
        first = request(100, 110, 0, 0)
        for tail in [first, request(109, 120, 0, 0), request(200, 210, 22, 0),
                     request(200, 210, 22, 2), request(220, 210, 22, 1),
                     request(200, 210, 23, 1), request(200, 210, 22, 1).replace('index=22', 'index=22 index=22')]:
            with self.subTest(tail=tail):
                with self.assertRaises(ValueError):
                    m.analyze(first + tail, 0, 1000)
        with self.assertRaises(ValueError):
            m.analyze(first + request(200, 210, 22, 1) + 'tl: g 1 began 120 ended 150 1\ntl: g 3 began 151 ended 160 1\n', 0, 1000)

    def test_exact_legacy_inventory_is_not_a_timed_policy_sample(self):
        legacy = 'POLARIS OSM REQUEST: physical0x400 raw_index=0 effective_index=0 requested_Hz=825600000; request is not measured Hz\n'
        timed = request(100, 110, 0, 0) + request(200, 210, 22, 1)
        d = m.analyze(legacy + timed, 0, 300)
        self.assertEqual(len(d['request_observations']), 2)
        self.assertEqual(len(d['untimed_inventory_excluded']), 1)
        with self.assertRaises(ValueError):
            m.analyze(legacy, 0, 300)
        for bad in [legacy.replace('physical0x400', 'physical0x100'),
                    legacy.replace('raw_index=0', 'raw_index=0x1b'),
                    legacy.replace('requested_Hz=825600000;', 'requested_Hz=825600000'),
                    legacy.replace('raw_index=0', 'raw_index=0 raw_index=0')]:
            with self.assertRaises(ValueError):
                m.analyze(bad + timed, 0, 300)

    def test_missing_startup_records_do_not_admit_frames_in_the_missing_interval(self):
        text = (request(100, 110, 0, 0) + request(200, 210, 0, 2)
                + request(300, 310, 22, 3) + request(400, 410, 22, 3)
                + 'tl: g 1 began 320 ended 390 1\n')
        d = m.analyze(text, 315, 395)
        self.assertEqual(d['out_of_window_request_records_excluded'], 2)
        self.assertEqual(d['frame_duration_by_last_observed_request']['22']['count'], 1)
        with self.assertRaises(ValueError):
            m.analyze(text, 0, 395)

    def test_gap_requires_consecutive_frames_inside_one_unchanged_request_bracket(self):
        text = (request(100, 110, 22, 1) + request(400, 410, 22, 1)
                + 'tl: g 1 began 120 ended 190 1\n'
                + 'tl: g 2 began 200 ended 270 1\n'
                + 'tl: g 3 began 300 ended 390 1\n')
        d = m.analyze(text, 0, 500)
        self.assertEqual(d['interframe_gap_by_same_request_interval']['22']['median'], 20)
        self.assertEqual(d['frame_begin_period_by_same_request_interval']['22']['median'], 90)


if __name__ == '__main__':
    unittest.main()
