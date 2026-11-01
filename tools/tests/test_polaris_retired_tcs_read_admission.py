"""Distinct V2 scope: exactly three new edges and no high-trigger restore."""
import ast
import subprocess
import unittest
from pathlib import Path
from .test_polaris_prepared_power_admission import a, desc


class RetiredTcsReadAdmission(unittest.TestCase):
    def test_exact_V2_source_scope(self):
        p = a.GCD_CLOCK_0167
        self.assertIs(a.original_gcd_policy(desc(p)), p)
        self.assertEqual(len(p['inputs']), 88)
        self.assertEqual(len(p['metadata']), 248)
        self.assertEqual(p['metadata'][a.POWER_PREFIX + 'raw_format'], 'CURRENT_ARC_READ_RAW_V2')

    def test_all_new_lifecycle_fields_exact_and_required(self):
        names = ('current_ARC_retired_single_command_latch',
            'current_ARC_original_FREE_and_request_NULL_required',
            'current_ARC_trigger_low_readback_before_staging',
            'current_ARC_high_trigger_restore_stores_max',
            'current_ARC_three_new_rising_edges',
            'current_ARC_restore_enable_after_final_ACK')
        for name in names:
            key = a.POWER_PREFIX + name
            for value in (None, 'forged'):
                d = desc(a.GCD_CLOCK_0167)
                if value is None:
                    del d[key]
                else:
                    d[key] = value
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    a.original_gcd_policy(d)

    def test_old_raw_or_old_read_engine_cannot_substitute(self):
        d = desc(a.GCD_CLOCK_0167)
        d[a.POWER_PREFIX + 'raw_format'] = 'CURRENT_ARC_READ_RAW_V1'
        with self.assertRaises(ValueError):
            a.original_gcd_policy(d)
        for name in ('tools/polaris-wifi-rsc-read.h', 'shim/polaris/uefi-wifi-rsc-device.h'):
            d = desc(a.GCD_CLOCK_0167)
            d['inputs'][name] = a.GCD_CLOCK_0166['inputs'][name]
            with self.subTest(name=name), self.assertRaises(ValueError):
                a.original_gcd_policy(d)

    def test_no_vote_qualification_deadline_or_unknown_relaxation(self):
        for name, value in [('current_ARC_resource_WRITE_reachable', True),
                ('current_ARC_read_qualified_response_semantics_proven', True),
                ('prepared_original_private_deadline_ticks', 3840001),
                ('unknown_blocks_native_PON_receipt', False)]:
            d = desc(a.GCD_CLOCK_0167)
            d[a.POWER_PREFIX + name] = value
            with self.subTest(name=name), self.assertRaises(ValueError):
                a.original_gcd_policy(d)

    def test_twenty_prior_literals_immutable(self):
        root = Path(__file__).resolve().parents[2]
        old = subprocess.check_output(['git', 'show',
            '53bb6d97fb0e227ff65b34d3420ceac5539de4d2:tools/polaris_wled_runtime_admission.py'],
            cwd=root, text=True)
        def values(source):
            return {n.targets[0].id: ast.dump(n.value, include_attributes=False)
                for n in ast.parse(source).body if isinstance(n, ast.Assign)
                and isinstance(n.targets[0], ast.Name)
                and n.targets[0].id.startswith('GCD_CLOCK_')}
        before, now = values(old), values((root / 'tools/polaris_wled_runtime_admission.py').read_text())
        self.assertEqual(len([n for n in before if n != 'GCD_CLOCK_DISABLED']), 20)
        for key, value in before.items():
            self.assertEqual(now[key], value, key)
