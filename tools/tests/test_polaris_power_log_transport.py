"""NEW power log capacity: real bounded upload code, SOFTWARE USB only."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from polaris_wled_runtime_control import WledRuntimeProtocol
from polaris_uefi_usb_transport import KernelProtocol, ReadOnlyProtocol


class LogPeer:
    def __init__(self, count):
        self.count = count
        self.left = count
        self.stage = 0
        self.writes = []
        self.body_reads = 0

    def write(self, command):
        self.writes.append(command)

    def read(self, wanted):
        self.stage += 1
        if self.stage == 1:
            return b'DATA'+f'{self.count:08x}'.encode()
        if self.left:
            n = min(wanted, self.left)
            self.left -= n
            self.body_reads += 1
            return b'\xa5'*n
        return b'OKAY'


def prepared(count, capacity=None):
    peer = LogPeer(count)
    client = WledRuntimeProtocol(peer, firmware_log_capacity=capacity)
    client.verified, client.staged = True, 'logs'
    return client, peer


class PowerLogTransport(unittest.TestCase):
    def test_complete_NEW_firmware_plus_native_snapshot_and_exact_bound(self):
        count = (12 << 20)+128
        client, peer = prepared(count, 8 << 20)
        raw = client.upload()
        self.assertEqual(len(raw), count)
        self.assertEqual(raw, b'\xa5'*count)
        self.assertEqual(peer.writes, [b'upload'])
        self.assertIsNone(client.staged)

    def test_over_bound_header_refuses_before_reading_body(self):
        client, peer = prepared((12 << 20)+129, 8 << 20)
        with self.assertRaises(ValueError):
            client.upload()
        self.assertEqual(peer.body_reads, 0)
        self.assertIsNone(client.staged)

    def test_default_and_other_client_bounds_remain_unchanged(self):
        client, peer = prepared((6 << 20)+129)
        with self.assertRaises(ValueError):
            client.upload()
        self.assertEqual(peer.body_reads, 0)
        self.assertEqual(KernelProtocol.limits['logs'], (6 << 20)+128)
        self.assertEqual(WledRuntimeProtocol.limits['logs'], (6 << 20)+128)
        self.assertEqual(ReadOnlyProtocol.limits['logs'], 32768)

    def test_capacity_neither_accepts_arbitrary_values_nor_grants_verification(self):
        for capacity in [True, 8388608.0, '8388608', 0, 8388609, 1 << 30]:
            with self.subTest(capacity=capacity), self.assertRaises(ValueError):
                WledRuntimeProtocol(LogPeer(1), firmware_log_capacity=capacity)
        client = WledRuntimeProtocol(LogPeer(1), firmware_log_capacity=8 << 20)
        with self.assertRaises(ValueError):
            client.stage('logs')

    def test_extended_logs_do_not_enable_generic_reset(self):
        client, peer = prepared(1, 8 << 20)
        with self.assertRaises(ValueError):
            client._control(b'reboot-bootloader')
        self.assertEqual(peer.writes, [])


if __name__ == '__main__':
    unittest.main()
