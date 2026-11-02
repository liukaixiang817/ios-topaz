"""The new exact log bound cannot grant commands or relax old bounds."""
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from polaris_wled_runtime_control import WledRuntimeProtocol

class FourVRMCapacity(unittest.TestCase):
    def test_new_exact_full_snapshot_bound(self):
        client=WledRuntimeProtocol(None,firmware_log_capacity=10747904)
        self.assertEqual(client.limits['logs'],14942208+128)
        self.assertEqual(client.limits['wled-runtime'],980)
        self.assertFalse(client.exit_sent)

    def test_existing_bounds_unchanged(self):
        for capacity in (8388608,10485760,12582912):
            with self.subTest(capacity=capacity):
                self.assertEqual(WledRuntimeProtocol(None,firmware_log_capacity=capacity).limits['logs'],capacity+(4<<20)+128)

    def test_nearby_sizes_and_nonliteral_types_refused(self):
        for capacity in (10747903,10747905,True,10747904.0,-1,0,'10747904',1<<32):
            with self.subTest(capacity=capacity):
                with self.assertRaises(ValueError):
                    WledRuntimeProtocol(None,firmware_log_capacity=capacity)

    def test_new_size_cannot_enable_reset_commands(self):
        client=WledRuntimeProtocol(None,firmware_log_capacity=10747904)
        for command in (b'reboot',b'reboot-bootloader',b'oem drained-reboot:1',b'oem drained-reboot:2'):
            with self.subTest(command=command):
                with self.assertRaises(ValueError):client._control(command)

if __name__=='__main__':unittest.main()
