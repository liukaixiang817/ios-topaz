"""The finite Core reader and RAW_V2 require an independent exact scope."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import polaris_wled_runtime_admission as a


def descriptor(profile):
    return dict(copy.deepcopy(profile['metadata']), inputs=copy.deepcopy(profile['inputs']),
                kernel_sha256=profile['kernel'], payload_sha256=profile['payload'])


class BoundedCmdDbAdmission(unittest.TestCase):
    def test_distinct_exact_committed_scope_and_old_profiles(self):
        for p in (a.GCD_CLOCK_0157, a.GCD_CLOCK_0156, a.GCD_CLOCK_0155):
            self.assertIs(a.original_gcd_policy(descriptor(p)), p)
        self.assertEqual(len(a.GCD_CLOCK_0157['inputs']), 82)
        self.assertEqual(a.GCD_CLOCK_0157['firmware_source'], '220cdd5e055036f37cf165dd21f4a405984347d1')
        self.assertIn('shim/polaris/uefi-wifi-cmddb-bounded-scope.md', a.GCD_CLOCK_0157['power_scope_review'])

    def test_bound_or_fallback_cannot_be_weakened(self):
        for key, value in [('CmdDb_bounded_GCD', False), ('CmdDb_bounded_GCD', 1),
                ('CmdDb_GCD_namespace_max_nodes', 513), ('CmdDb_GCD_namespace_no_API_fallback', False),
                ('CmdDb_GCD_namespace_no_EFI_status_fabrication', False),
                ('CmdDb_original_GCD_API_calls_max', 1), ('CmdDb_GCD_namespace_lock_or_TPL_calls_max', True)]:
            d = descriptor(a.GCD_CLOCK_0157);d[a.POWER_PREFIX+key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                a.original_gcd_policy(d)

    def test_new_complete_raw_layout_is_exact(self):
        for key, value in [('raw_format', 'RAW_V1'), ('raw_bytes', 1235200),
                ('CmdDb_GCD_namespace_raw_bytes', 183063), ('CmdDb_GCD_namespace_target_guard_bytes', 792),
                ('CmdDb_GCD_namespace_target_guard_count', 64)]:
            d = descriptor(a.GCD_CLOCK_0157);d[a.POWER_PREFIX+key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                a.original_gcd_policy(d)

    def test_old_namespace_cannot_be_laundered_by_new_flag(self):
        for old in (a.GCD_CLOCK_0156, a.GCD_CLOCK_0155):
            d = descriptor(a.GCD_CLOCK_0157);d['inputs'] = copy.deepcopy(old['inputs'])
            with self.assertRaises(ValueError):a.original_gcd_policy(d)
            d = descriptor(old);d[a.POWER_PREFIX+'CmdDb_bounded_GCD'] = True
            with self.assertRaises(ValueError):a.original_gcd_policy(d)

    def test_disabled_metadata_cannot_hide_either_new_source(self):
        for name in a.GCD_NAMESPACE_SOURCE_PATHS:
            with self.subTest(name=name), self.assertRaises(ValueError):
                a.original_gcd_policy({'inputs': {name:'0'*64}})

    def test_source_template_kernel_payload_and_review_cannot_be_substituted(self):
        for name in a.GCD_NAMESPACE_SOURCE_PATHS:
            d = descriptor(a.GCD_CLOCK_0157);d['inputs'][name] = '0'*64
            with self.subTest(name=name), self.assertRaises(ValueError):a.original_gcd_policy(d)
        for key in ('kernel_sha256', 'payload_sha256', a.POWER_PREFIX+'CmdDb_GCD_namespace_template_SHA256'):
            d = descriptor(a.GCD_CLOCK_0157);d[key] = '0'*64
            with self.subTest(key=key), self.assertRaises(ValueError):a.original_gcd_policy(d)

    def test_capture_cannot_enable_cpu_or_writer_or_grant_radio_permission(self):
        for key, value in [('CmdDb_capture_only', False), ('CmdDb_original_Query_calls_max', 1),
                ('CPUcritical_and_RSC_reachable', True), ('guarded_PSCI_calls_max', 14),
                ('steps_max', 256), ('MSS_or_NVserve_or_radio', True), ('candidate_ready', True),
                ('hardware_ownership_independently_qualified', True)]:
            d = descriptor(a.GCD_CLOCK_0157);d[a.POWER_PREFIX+key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):a.original_gcd_policy(d)


if __name__ == '__main__':
    unittest.main()
