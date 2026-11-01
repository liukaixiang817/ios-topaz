"""The source ABI fix creates a distinct scope, never changes old admission."""
import ast
import subprocess
import unittest
from pathlib import Path
from .test_polaris_prepared_power_admission import a, desc


class RscMapStrideAdmission(unittest.TestCase):
    def test_new_source_exact_same_safety_metadata(self):
        p = a.GCD_CLOCK_0166
        self.assertIs(a.original_gcd_policy(desc(p)), p)
        self.assertEqual(p['metadata'], a.GCD_CLOCK_0165['metadata'])
        self.assertEqual(len(p['inputs']), 88)
        changed = [k for k, v in p['inputs'].items() if a.GCD_CLOCK_0165['inputs'][k] != v]
        self.assertEqual(changed, ['shim/polaris/uefi-wifi-rsc-device.h'])

    def test_missing_or_forged_new_source_rejected(self):
        key = 'shim/polaris/uefi-wifi-rsc-device.h'
        for value in (None, '0' * 64):
            d = desc(a.GCD_CLOCK_0166)
            if value is None:
                del d['inputs'][key]
            else:
                d['inputs'][key] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                a.original_gcd_policy(d)

    def test_read_capture_deadline_and_unknown_gates_exact(self):
        for key, value in [('current_ARC_resource_WRITE_reachable', True),
                ('current_ARC_read_qualified_response_semantics_proven', True),
                ('prepared_original_private_deadline_ticks', 3840001),
                ('unknown_blocks_native_PON_receipt', False)]:
            d = desc(a.GCD_CLOCK_0166)
            d[a.POWER_PREFIX + key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                a.original_gcd_policy(d)

    def test_all_nineteen_prior_literal_profiles_unchanged(self):
        root = Path(__file__).resolve().parents[2]
        old = subprocess.check_output(['git', 'show',
            '2f53d2c17b95f85cb8e0c74acee795f036ff1b9f:tools/polaris_wled_runtime_admission.py'],
            cwd=root, text=True)
        def values(source):
            return {n.targets[0].id: ast.dump(n.value, include_attributes=False)
                for n in ast.parse(source).body if isinstance(n, ast.Assign)
                and isinstance(n.targets[0], ast.Name)
                and n.targets[0].id.startswith('GCD_CLOCK_')}
        before, now = values(old), values((root / 'tools/polaris_wled_runtime_admission.py').read_text())
        self.assertEqual(len([n for n in before if n != 'GCD_CLOCK_DISABLED']), 19)
        for key, value in before.items():
            self.assertEqual(now[key], value, key)
