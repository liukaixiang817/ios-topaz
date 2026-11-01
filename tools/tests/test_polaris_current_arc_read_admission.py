"""The new exact scope admits RAW READ/full restore, never resource WRITE."""
import ast
import copy
import subprocess
import unittest
from pathlib import Path
from .test_polaris_prepared_power_admission import a, desc


class CurrentArcReadAdmission(unittest.TestCase):
    def test_exact_current_source_and_capture_only(self):
        p = a.GCD_CLOCK_0165
        self.assertIs(a.original_gcd_policy(desc(p)), p)
        self.assertEqual(len(p['inputs']), 88)
        self.assertEqual(len(p['metadata']), 242)
        self.assertEqual(len(p['resource_fields']), 94)
        for name, value in [('current_ARC_read_capture_only', True),
                ('current_ARC_resource_WRITE_reachable', False),
                ('current_ARC_resource_WRITE_commands_max', 0),
                ('current_ARC_original_Read_API_calls', 0),
                ('current_ARC_read_qualified_response_semantics_proven', False)]:
            self.assertIs(type(p['metadata'][a.POWER_PREFIX + name]), type(value))
            self.assertEqual(p['metadata'][a.POWER_PREFIX + name], value)

    def test_every_new_read_field_is_exact_and_required(self):
        for key, value in a.GCD_CLOCK_0165['metadata'].items():
            if not key.startswith(a.POWER_PREFIX + 'current_ARC_'):
                continue
            for changed in (None, not value if type(value) is bool else 'forged'):
                d = desc(a.GCD_CLOCK_0165)
                if changed is None:
                    del d[key]
                else:
                    d[key] = changed
                with self.subTest(key=key, changed=changed), self.assertRaises(ValueError):
                    a.original_gcd_policy(d)

    def test_new_read_sources_cannot_be_missing_old_or_disabled(self):
        for name in a.CURRENT_ARC_READ_SOURCE_PATHS:
            for action in ('missing', 'changed'):
                d = desc(a.GCD_CLOCK_0165)
                if action == 'missing':
                    del d['inputs'][name]
                else:
                    d['inputs'][name] = '0' * 64
                with self.subTest(name=name, action=action), self.assertRaises(ValueError):
                    a.original_gcd_policy(d)
            d = copy.deepcopy(a.GCD_CLOCK_DISABLED)
            d['inputs'] = {name: a.GCD_CLOCK_0165['inputs'][name]}
            with self.assertRaises(ValueError):
                a.original_gcd_policy(d)

    def test_old_profile_raw_deadline_or_unsafe_gate_cannot_substitute(self):
        for name in ('shim/polaris/uefi-wifi-rsc-access.h',
                'shim/polaris/uefi-wifi-power-path.h', 'tools/build-polaris-uefi-xnu.py'):
            d = desc(a.GCD_CLOCK_0165)
            d['inputs'][name] = a.GCD_CLOCK_0164['inputs'][name]
            with self.subTest(name=name), self.assertRaises(ValueError):
                a.original_gcd_policy(d)
        for name, value in [('raw_bytes', 1892336), ('access_raw_bytes', 401800),
                ('prepared_original_private_deadline_ticks', 3840001),
                ('unknown_blocks_native_PON_receipt', False)]:
            d = desc(a.GCD_CLOCK_0165)
            d[a.POWER_PREFIX + name] = value
            with self.subTest(name=name), self.assertRaises(ValueError):
                a.original_gcd_policy(d)

    def test_all_eighteen_prior_literals_are_unchanged(self):
        root = Path(__file__).resolve().parents[2]
        old = subprocess.check_output(['git', 'show',
            '88e0c0cb535c11d194e325212bf596feb944ad73:tools/polaris_wled_runtime_admission.py'],
            cwd=root, text=True)
        def values(source):
            return {n.targets[0].id: ast.dump(n.value, include_attributes=False)
                for n in ast.parse(source).body if isinstance(n, ast.Assign)
                and isinstance(n.targets[0], ast.Name)
                and n.targets[0].id.startswith('GCD_CLOCK_')}
        before, now = values(old), values((root / 'tools/polaris_wled_runtime_admission.py').read_text())
        self.assertEqual(len([n for n in before if n != 'GCD_CLOCK_DISABLED']), 18)
        for key, value in before.items():
            self.assertEqual(now[key], value, key)
