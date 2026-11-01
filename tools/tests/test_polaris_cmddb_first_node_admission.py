"""Explicit partial diagnostic scope cannot be relabelled as full capture."""
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import polaris_wled_runtime_admission as a


def descriptor(p):
    return dict(copy.deepcopy(p['metadata']),inputs=copy.deepcopy(p['inputs']),
                kernel_sha256=p['kernel'],payload_sha256=p['payload'])


class FirstNodeAdmission(unittest.TestCase):
    def test_new_exact_partial_scope_preserves_existing_full_scope(self):
        for p in (a.GCD_CLOCK_0158,a.GCD_CLOCK_0157):
            self.assertIs(a.original_gcd_policy(descriptor(p)),p)
        self.assertEqual(a.GCD_CLOCK_0158['firmware_source'],'0a7ce93b70a002b21c87f5c676d491643cc42e59')
        self.assertIn('shim/polaris/uefi-wifi-cmddb-first-node-scope.md',a.GCD_CLOCK_0158['power_scope_review'])

    def test_budget_raw_refusal_and_no_target_contract_are_exact(self):
        for key,value in [('CmdDb_first_node_stop',False),('CmdDb_first_node_stop',1),
                ('CmdDb_effective_node_budget',2),('CmdDb_namespace_complete_possible',True),
                ('CmdDb_database_target_bytes_max',1),('CmdDb_GCD_namespace_target_guard_count',66),
                ('CmdDb_planned_stop_error',13),('CmdDb_first_node_requires_both_source_checkpoints',False),
                ('CmdDb_first_node_no_UNKNOWN_clearing',False),('raw_bytes',1656239),('raw_format','RAW_V1')]:
            d=descriptor(a.GCD_CLOCK_0158);d[a.POWER_PREFIX+key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):a.original_gcd_policy(d)

    def test_partial_flag_does_not_admit_the_consumed_full_reader(self):
        d=descriptor(a.GCD_CLOCK_0158);d['inputs']=copy.deepcopy(a.GCD_CLOCK_0157['inputs'])
        with self.assertRaises(ValueError):a.original_gcd_policy(d)
        d=descriptor(a.GCD_CLOCK_0157);d[a.POWER_PREFIX+'CmdDb_first_node_stop']=True
        with self.assertRaises(ValueError):a.original_gcd_policy(d)

    def test_partial_diagnostic_does_not_admit_unknown_cleanup_or_power(self):
        for key,value in [('UNKNOWN_no_USB_Console_Stall_or_firmware_return',False),
                ('unknown_blocks_native_PON_receipt',False),('CPUcritical_and_RSC_reachable',True),
                ('CmdDb_original_Query_calls_max',1),('CmdDb_original_GCD_API_calls_max',1),
                ('CmdDb_GCD_namespace_no_API_fallback',False),('MSS_or_NVserve_or_radio',True)]:
            d=descriptor(a.GCD_CLOCK_0158);d[a.POWER_PREFIX+key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):a.original_gcd_policy(d)


if __name__=='__main__':unittest.main()
