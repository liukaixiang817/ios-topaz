"""A completed RO work estimate cannot become a renewed deadline or lease."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import polaris_wled_runtime_admission as a


def descriptor(policy):
    return dict(copy.deepcopy(policy['metadata']), inputs=copy.deepcopy(policy['inputs']),
                kernel_sha256=policy['kernel'], payload_sha256=policy['payload'])


class WorkAdmission(unittest.TestCase):
    def test_new_full_scope_and_old_diagnostics_are_distinct(self):
        for policy in (a.GCD_CLOCK_0160, a.GCD_CLOCK_0158, a.GCD_CLOCK_0157):
            self.assertIs(a.original_gcd_policy(descriptor(policy)), policy)
        self.assertEqual(len(a.GCD_CLOCK_0160['inputs']), 83)
        self.assertIn('shim/polaris/uefi-wifi-cmddb-budget-scope.md', a.GCD_CLOCK_0160['power_scope_review'])

    def test_exact_budget_samples_units_raw_and_tickets(self):
        for key, value in [('work_admission', False), ('work_admission', 1),
                ('work_admission_samples', 2), ('work_admission_checkpoints', 79),
                ('work_admission_reserve_ticks', 479999), ('work_admission_plan_ticks', 3840000),
                ('work_admission_original_fresh_ticks', 3840001), ('work_admission_raw_bytes', 31551),
                ('work_admission_independent_RO_ticket', False), ('work_admission_before_private_Create', False),
                ('work_admission_no_deadline_renewal', False),
                ('work_admission_estimate_not_hardware_authority', False)]:
            d = descriptor(a.GCD_CLOCK_0160); d[a.POWER_PREFIX+'CmdDb_'+key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                a.original_gcd_policy(d)

    def test_no_getter_query_writer_or_UNKNOWN_cleanup(self):
        for key, value in [('CmdDb_work_admission_original_GetMap_calls_max', 3),
                ('CmdDb_work_admission_original_GCD_Query_calls', 1), ('CmdDb_original_Query_calls_max', 1),
                ('CPUcritical_and_RSC_reachable', True), ('MSS_or_NVserve_or_radio', True),
                ('UNKNOWN_no_USB_Console_Stall_or_firmware_return', False),
                ('unknown_blocks_native_PON_receipt', False), ('CmdDb_GCD_namespace_target_guard_count', 65)]:
            d = descriptor(a.GCD_CLOCK_0160); d[a.POWER_PREFIX+key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                a.original_gcd_policy(d)

    def test_old_input_sets_and_extra_partial_flag_rejected(self):
        for policy in (a.GCD_CLOCK_0158, a.GCD_CLOCK_0157):
            d = descriptor(a.GCD_CLOCK_0160); d['inputs'] = copy.deepcopy(policy['inputs'])
            with self.assertRaises(ValueError): a.original_gcd_policy(d)
            d = descriptor(policy); d[a.POWER_PREFIX+'CmdDb_work_admission'] = True
            with self.assertRaises(ValueError): a.original_gcd_policy(d)
        d = descriptor(a.GCD_CLOCK_0160); d[a.POWER_PREFIX+'CmdDb_first_node_stop'] = True
        with self.assertRaises(ValueError): a.original_gcd_policy(d)

    def test_every_actual_new_compiled_input_is_pinned(self):
        for name in ('shim/polaris/gcd-core-identity.h', 'shim/polaris/uefi-wifi-cmddb-budget.h',
                     'shim/polaris/uefi-wifi-power-path.h', 'shim/polaris/uefi-xnu.c',
                     'tools/build-polaris-uefi-xnu.py'):
            d = descriptor(a.GCD_CLOCK_0160); d['inputs'][name] = '0'*64
            with self.subTest(name=name), self.assertRaises(ValueError): a.original_gcd_policy(d)

    def test_budget_source_cannot_hide_behind_disabled_scope(self):
        d = dict(a.GCD_CLOCK_DISABLED, inputs={'shim/polaris/uefi-wifi-cmddb-budget.h': '0'*64})
        with self.assertRaises(ValueError): a.original_gcd_policy(d)


if __name__ == '__main__':
    unittest.main()
