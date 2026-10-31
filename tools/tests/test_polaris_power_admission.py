"""The conditional power scope cannot inherit or weaken old RAM-only scopes."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from polaris_wled_runtime_admission import (
    GCD_CLOCK_0154, GCD_CLOCK_0150, POWER_PREFIX, POWER_SOURCE_PATHS,
    original_gcd_policy, original_gcd_model_markers)


def descriptor(profile):
    return dict(copy.deepcopy(profile['metadata']), inputs=copy.deepcopy(profile['inputs']),
                kernel_sha256=profile['kernel'], payload_sha256=profile['payload'])


class ConditionalPowerAdmission(unittest.TestCase):
    def test_independent_scope_retains_build_time_absence_of_hardware_proof(self):
        d = descriptor(GCD_CLOCK_0154)
        self.assertIs(original_gcd_policy(d), GCD_CLOCK_0154)
        self.assertFalse(d[POWER_PREFIX+'hardware_ownership_independently_qualified'])
        self.assertFalse(d[POWER_PREFIX+'candidate_ready'])
        self.assertTrue(d[POWER_PREFIX+'unknown_blocks_native_PON_receipt'])
        self.assertIs(original_gcd_policy(descriptor(GCD_CLOCK_0150)), GCD_CLOCK_0150)

    def test_changed_runtime_contract_or_misleading_old_scope_is_rejected(self):
        changes = [('guarded_PSCI_calls_max', 7), ('steps_max', True),
                   ('raw_bytes', 1235199), ('UNKNOWN_no_USB_Console_Stall_or_firmware_return', False),
                   ('exact_local_restore_before_known_Delete', False),
                   ('hardware_ownership_independently_qualified', True),
                   ('candidate_ready', True), ('MSS_or_NVserve_or_radio', True)]
        for key, value in changes:
            d = descriptor(GCD_CLOCK_0154)
            d[POWER_PREFIX+key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                original_gcd_policy(d)
        d = descriptor(GCD_CLOCK_0154)
        d['wifi_CPU0_RPMh_private_vote_commandset_MMIO_SMC_MSS_NVserve_calls'] = 0
        with self.assertRaises(ValueError):
            original_gcd_policy(d)

    def test_sources_kernel_and_payload_are_exact_not_opt_in_booleans(self):
        for change in ['missing-path', 'changed-source', 'kernel', 'payload']:
            d = descriptor(GCD_CLOCK_0154)
            name = sorted(POWER_SOURCE_PATHS)[0]
            if change == 'missing-path':
                del d['inputs'][name]
            elif change == 'changed-source':
                d['inputs'][name] = '0'*64
            elif change == 'kernel':
                d['kernel_sha256'] = '0'*64
            else:
                d['payload_sha256'] = '0'*64
            with self.subTest(change=change), self.assertRaises(ValueError):
                original_gcd_policy(d)

    def test_power_cannot_hide_behind_disabled_or_old_profile(self):
        old = descriptor(GCD_CLOCK_0150)
        old[POWER_PREFIX+'transaction'] = True
        with self.assertRaises(ValueError):
            original_gcd_policy(old)
        with self.assertRaises(ValueError):
            original_gcd_policy({'inputs': {name: '0'*64 for name in POWER_SOURCE_PATHS}})

    def test_each_model_needs_literal_integer_compiledout_evidence(self):
        names = ['ORIGINAL_GCD_SOFTWARE_PHYSICAL_SERVICE_FP_COMPILED_OUT',
                 'AUDIO_CLOCK_GCD_SOFTWARE_PHYSICAL_QUERY_COMPILED_OUT',
                 'WIFI_POWER_SOFTWARE_PHYSICAL_TRANSACTION_COMPILED_OUT']
        original_gcd_model_markers({'raw_fields': {name: 1 for name in names}}, power=True)
        for value in [None, True, False, 0, '1']:
            raw = {name: 1 for name in names}
            raw[names[-1]] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                original_gcd_model_markers({'raw_fields': raw}, power=True)


if __name__ == '__main__':
    unittest.main()
