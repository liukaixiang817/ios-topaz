#!/usr/bin/env python3
"""Exact-wire host checks with deterministic fake clocks, never device I/O."""
import importlib.util
from pathlib import Path
import struct
import sys
import unittest

spec = importlib.util.spec_from_file_location("polaris_clock_host", Path(__file__).with_name("polaris-clock-host.py"))
c = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = c
spec.loader.exec_module(c)
BASE = 1_793_404_800_000_000_000


class Fake:
    verified = True

    def __init__(self):
        self.transport = self
        self.commands = []
        self.sequence = 0
        self.phase = c.READY
        self.actual = self.actual_ticks = self.uncertainty = 0
        self.applied = 0
        self.frequency = c.FREQUENCY
        self.cookie = 17
        self.reserved = 0
        self.unknown = False
        self.pending = False

    def state(self):
        return "kernel-entered"

    def write(self, command):
        self.commands.append(command)

    def read(self, count):
        assert count == 64
        command = self.commands[-1]
        if command == b"oem utc-status":
            return b"OKAY" + struct.pack("<8sQIIIIQQQI", b"PCLSTA01", self.cookie, self.sequence,
                self.phase, 0, self.frequency, self.actual, self.actual_ticks, self.uncertainty, self.applied)
        if command.startswith(b"oem utc-probe:"):
            return b"OKAY" + struct.pack("<8sQIIQQIIIQ", b"PCLPRO01", self.cookie, self.sequence + 1,
                self.frequency, 19_200_000, 19_201_920, self.sequence, self.phase, 0, self.reserved)
        if command.startswith(b"oem utc-set:"):
            seq, utc, anchor, uncertainty = [int(x, 16) for x in command[12:].split(b":")]
            if not self.pending:
                self.sequence = seq
                self.phase = c.APPLIED
                self.actual = utc + 1000
                self.actual_ticks = anchor + 19_200
                self.uncertainty = uncertainty
                self.applied += 1
            if self.unknown:
                raise TimeoutError("fake delivery uncertainty")
            return b"OKAY"
        raise AssertionError(command)


def clocks(*, rtt=10_000_000, step=0, set_step=0):
    realtime = iter([BASE, BASE + rtt + step, BASE + rtt + 1_000_000 + step + set_step])
    mono = iter([1_000_000, 1_001_000, 1_000_000 + rtt, 1_001_000 + rtt,
                 2_000_000 + rtt, 2_001_000 + rtt])
    return dict(realtime_ns=lambda: next(realtime), monotonic_ns=lambda: next(mono), sleep=lambda _: None)


class ClockChecks(unittest.TestCase):
    def test_native_readback_required_and_new_reconnect(self):
        f = Fake()
        out = c.synchronize(f, **clocks())
        self.assertEqual(out["sequence"], 1)
        self.assertEqual(out["source"], "host-UTC")
        self.assertFalse(out["network_time_verified"])
        self.assertEqual([len(x) for x in f.commands], [14, 22, 63, 14])
        self.assertEqual(c.synchronize(f, **clocks())["sequence"], 2)

    def test_host_step_rejected_before_set(self):
        for changes in (dict(step=50_000_000), dict(set_step=50_000_000), dict(rtt=300_000_000)):
            f = Fake()
            with self.assertRaises(c.ClockError):
                c.synchronize(f, **clocks(**changes))
            self.assertFalse(any(x.startswith(b"oem utc-set:") for x in f.commands))

    def test_unknown_ack_does_not_resend(self):
        f = Fake()
        f.unknown = True
        with self.assertRaises(c.DeliveryUnknown) as context:
            c.synchronize(f, **clocks())
        self.assertEqual(context.exception.sequence, 1)
        self.assertEqual(sum(x.startswith(b"oem utc-set:") for x in f.commands), 1)
        self.assertEqual(c.status(f).status, c.APPLIED)  # independent status-only recovery

    def test_native_pending_is_not_sync_success(self):
        f = Fake()
        f.pending = True
        with self.assertRaises(c.DeliveryUnknown):
            c.synchronize(f, **clocks(), max_status_reads=2)
        self.assertEqual(sum(x.startswith(b"oem utc-set:") for x in f.commands), 1)

    def test_identity_range_and_sealed(self):
        for kind in ("unverified", "sealed", "frequency", "reserved"):
            f = Fake()
            if kind == "unverified":
                f.verified = False
            elif kind == "sealed":
                f.phase = c.SEALED
            elif kind == "frequency":
                f.frequency += 1
            else:
                f.reserved = 1
            with self.assertRaises(c.ClockError):
                c.synchronize(f, **clocks())
            self.assertFalse(any(x.startswith(b"oem utc-set:") for x in f.commands))

    def test_short_noncanonical_status(self):
        for raw in (b"", b"PCLSTA01" + bytes(52), bytes(64)):
            with self.assertRaises(c.ClockError):
                c.decode_status(raw)


if __name__ == "__main__":
    unittest.main()
