"""Staged RO observations cannot acquire a private/writer/renewed-ticket scope."""
import ast
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import polaris_wled_runtime_admission as a


def descriptor(policy):
    return dict(copy.deepcopy(policy['metadata']), inputs=copy.deepcopy(policy['inputs']),
                kernel_sha256=policy['kernel'], payload_sha256=policy['payload'])


class StagedROAdmission(unittest.TestCase):
    def test_distinct_new_and_historical_scopes(self):
        for p in (a.GCD_CLOCK_0161, a.GCD_CLOCK_0160, a.GCD_CLOCK_0158, a.GCD_CLOCK_0157):
            self.assertIs(a.original_gcd_policy(descriptor(p)), p)
        self.assertEqual(len(a.GCD_CLOCK_0161['inputs']), 85)
        self.assertIn('shim/polaris/uefi-wifi-cmddb-staged-scope.md', a.GCD_CLOCK_0161['power_scope_review'])

    def test_phase_raw_size_limits_and_retirement_are_exact(self):
        for key, value in [('staged_RO_prepare', False), ('staged_RO_prepare', 1),
                ('staged_RO_phases', 3), ('staged_RO_bytes_per_phase', 65535),
                ('staged_RO_phase_raw_bytes', 349455), ('staged_RO_original_fresh_ticks', 3840001),
                ('staged_RO_independent_resident_spent_once_tickets', False),
                ('staged_RO_NO_deadline_reset_or_rebase', False),
                ('staged_RO_original_GetMap_calls_max', 9), ('staged_RO_original_LocateProtocol_calls_max', 5),
                ('staged_RO_full_namespace_passes', 7), ('staged_RO_full_database_copies', 1),
                ('GCD_namespace_target_guard_count', 67), ('staged_RO_before_any_private_client', False),
                ('staged_RO_final_native_flag_source_literal', False),
                ('staged_RO_no_continuous_hardware_lease_claim', False)]:
            d = descriptor(a.GCD_CLOCK_0161);d[a.POWER_PREFIX+'CmdDb_'+key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):a.original_gcd_policy(d)

    def test_no_restored_writer_private_or_UNKNOWN_bypass(self):
        for key,value in [('wifi_CPU0_RPMh_private_client', True), ('wifi_CPU0_RPMh_private_API_calls_max', 2),
                ('wifi_CPU0_RPMh_MMIO_or_SMC', True), ('wifi_CPU0_power_raw_bytes', 1660543),
                ('wifi_CPU0_power_raw_format', 'RAW_V2'), ('wifi_CPU0_power_client_raw_bytes', 227104),
                ('wifi_CPU0_power_guarded_PSCI_calls_max', 14), ('wifi_CPU0_power_CPUcritical_and_RSC_reachable', True),
                ('wifi_CPU0_power_MSS_or_NVserve_or_radio', True),
                ('wifi_CPU0_power_UNKNOWN_no_USB_Console_Stall_or_firmware_return', False),
                ('wifi_CPU0_power_unknown_blocks_native_PON_receipt', False)]:
            d = descriptor(a.GCD_CLOCK_0161);d[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):a.original_gcd_policy(d)

    def test_complete_namespace_source_and_decoder_cannot_be_disabled(self):
        for key in ('all_loaded_headers_before_after','cross_phase_namespace_map_source_equal','original_ARC_decoder_reused'):
            d=descriptor(a.GCD_CLOCK_0161);d[a.POWER_PREFIX+'CmdDb_staged_RO_'+key]=False
            with self.subTest(key=key),self.assertRaises(ValueError):a.original_gcd_policy(d)
        for key in ('CmdDb_first_node_stop','CmdDb_work_admission'):
            d=descriptor(a.GCD_CLOCK_0161);d[a.POWER_PREFIX+key]=True
            with self.assertRaises(ValueError):a.original_gcd_policy(d)

    def test_actual_compiled_sources_pinned_and_no_old_input_substitution(self):
        for name in ('shim/polaris/uefi-wifi-cmddb-staged.h','shim/polaris/uefi-wifi-gcd-ro-owner.h',
                'shim/polaris/uefi-wifi-gcd-namespace.h','shim/polaris/uefi-wifi-cmddb-query.h',
                'shim/polaris/uefi-wifi-power-path.h','shim/polaris/uefi-xnu.c','tools/build-polaris-uefi-xnu.py'):
            d=descriptor(a.GCD_CLOCK_0161);d['inputs'][name]='0'*64
            with self.subTest(name=name),self.assertRaises(ValueError):a.original_gcd_policy(d)
        d=descriptor(a.GCD_CLOCK_0161);d['inputs']=copy.deepcopy(a.GCD_CLOCK_0160['inputs'])
        with self.assertRaises(ValueError):a.original_gcd_policy(d)

    def test_disabled_scope_cannot_hide_staged_readers(self):
        for name in a.CMDDB_STAGED_SOURCE_PATHS:
            d=dict(a.GCD_CLOCK_DISABLED,inputs={name:'0'*64})
            with self.assertRaises(ValueError):a.original_gcd_policy(d)

    def test_every_old_literal_profile_is_unchanged(self):
        root=Path(__file__).resolve().parents[2]
        before=__import__('subprocess').check_output(['git','show','d47cfd04798cbb93a5d55b2f17c9db332296b9d0:tools/polaris_wled_runtime_admission.py'],cwd=root,text=True)
        def literals(text):
            return {n.targets[0].id:ast.dump(n.value,include_attributes=False) for n in ast.parse(text).body
                    if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name)
                    and n.targets[0].id.startswith('GCD_CLOCK_')}
        old=literals(before);new=literals((root/'tools/polaris_wled_runtime_admission.py').read_text())
        for name,value in old.items():self.assertEqual(new[name],value,name)


if __name__ == '__main__':unittest.main()
