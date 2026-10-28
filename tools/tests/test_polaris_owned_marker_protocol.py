"""Wire/parser rejection tests; no claim of physical UFS durability."""
import copy
import hashlib
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from polaris_owned_marker_protocol import OwnedMarkerProtocol, admit_manifest


class Wire:
    def __init__(self, replies):
        self.replies = list(replies); self.commands = []; self.chunks = []
    def write(self, data): self.commands.append(data)
    def write_data(self, data): self.chunks.append(data)
    def read(self, count): return self.replies.pop(0)


def manifest():
    return dict(physical_owned_marker_test=True, physical_small_file_write_test=True,
        original_root_writes_volatile=True, raw_reset_requires_durable_SAFE=True,
        durable_guard_generated_after_reset_disabled=True, bounded_input=True,
        RAM_native_shutdown_bridge=True, ready_to_boot_driver=True, phone_compatible=True,
        RAM_only_XNU_loader=False, QEMU_variant=False, storage_write_api=False,
        NVRAM_write_api=False, isolated_QEMU_readonly_UFS_test=False,
        isolated_QEMU_owned_UFS_test=False, controlled_owned_response_short_injection=False,
        controlled_durable_guard_omitted=False, firmware_services_exited=False,
        RAM_host_idle_recovery_seconds=None, kernel_CPU_affinity=0x700,
        kernel_CPU_count=2, RAM_base=0x180000000, RAM_bytes=0xfc8a0000,
        firmware_core_reserved=0)


def status(**change):
    values = dict(cookie=123, sequence=0, mode=0, phase=1, error=0,
                  write_epoch=1, flushed_epoch=0, capabilities=0)
    values.update(change)
    raw = struct.pack('<QIIIIQQI', *values.values()) + bytes(84)
    return [b'OKAY', b'DATA00000080', raw, b'OKAY']


class MarkerTests(unittest.TestCase):
    def test_every_manifest_mode_change_refused(self):
        original = manifest(); admit_manifest(original)
        for key, value in original.items():
            changed = copy.deepcopy(original)
            changed[key] = not value if type(value) is bool else (1800 if value is None else value + 1)
            with self.subTest(key=key), self.assertRaises(ValueError): admit_manifest(changed)

    def test_raw_and_RAM_fallback_never_transmitted(self):
        wire = Wire([b'OKAYpolaris-uefi-diag']); p = OwnedMarkerProtocol(wire, manifest()); p.product()
        for method in [p.reboot, lambda: p.reboot(True), p.reboot_drained,
                       lambda: p._control(b'reboot'), lambda: p._control(b'reboot-bootloader')]:
            with self.assertRaises(RuntimeError): method()
        self.assertEqual(wire.commands, [b'getvar:product'])

    def test_request_ACK_does_not_grant_reset(self):
        wire = Wire([b'OKAYpolaris-uefi-diag', *status(), b'OKAY',
            *status(sequence=1, mode=2, phase=4),
            *status(sequence=1, mode=2, phase=5, flushed_epoch=1, capabilities=0x1f), b'OKAY'])
        p = OwnedMarkerProtocol(wire, manifest()); p.product(); p.request_shutdown()
        with self.assertRaises(RuntimeError): p.reboot_safe()
        self.assertNotIn(b'oem drained-reboot:2', wire.commands)
        self.assertEqual(p.reboot_safe()['capabilities'], 0x1f)
        self.assertEqual(wire.commands[-1], b'oem drained-reboot:2')

    def test_rejected_download_recovery_requires_unstarted_state(self):
        for state in ('validated', 'prepared', 'AP-start-pending', 'kernel-entered',
                      'receiving', 'AP-early-fault', 'unknown'):
            wire = Wire([b'OKAYpolaris-uefi-diag', b'OKAY' + state.encode()])
            p = OwnedMarkerProtocol(wire, manifest()); p.product()
            with self.subTest(state=state), self.assertRaises((RuntimeError, ValueError)):
                p.recover_unstarted_fastboot()
            self.assertNotIn(b'reboot-bootloader', wire.commands)
        wire = Wire([b'OKAYpolaris-uefi-diag', b'OKAYwaiting-payload', b'FAILreset unavailable'])
        p = OwnedMarkerProtocol(wire, manifest()); p.product()
        with self.assertRaises(RuntimeError): p.recover_unstarted_fastboot()
        wire = Wire([b'OKAYpolaris-uefi-diag', b'OKAYwaiting-payload', b'OKAY'])
        p = OwnedMarkerProtocol(wire, manifest()); p.product(); p.recover_unstarted_fastboot()
        self.assertEqual(wire.commands[-1], b'reboot-bootloader')

    def test_every_non_safe_field_refuses_reset(self):
        for change in [dict(cookie=124), dict(sequence=2), dict(mode=1), dict(phase=6),
                       dict(error=5), dict(write_epoch=0), dict(write_epoch=2),
                       dict(flushed_epoch=0), dict(capabilities=0x80000003), dict(capabilities=0)]:
            final = dict(sequence=1, mode=2, phase=5, flushed_epoch=1, capabilities=0x1f)
            final.update(change)
            wire = Wire([b'OKAYpolaris-uefi-diag', *status(), b'OKAY', *status(**final)])
            p = OwnedMarkerProtocol(wire, manifest()); p.product(); p.request_shutdown()
            with self.subTest(change=change), self.assertRaises(RuntimeError): p.reboot_safe()
            self.assertNotIn(b'oem drained-reboot:2', wire.commands)

    def test_RAM_unknown_owner_and_wrong_epoch_refuse_request(self):
        for change in [dict(cookie=0), dict(phase=0), dict(phase=6), dict(error=5),
                       dict(write_epoch=0), dict(write_epoch=2), dict(flushed_epoch=1),
                       dict(capabilities=0x80000000), dict(mode=2), dict(sequence=1)]:
            wire = Wire([b'OKAYpolaris-uefi-diag', *status(**change)])
            p = OwnedMarkerProtocol(wire, manifest()); p.product()
            with self.subTest(change=change), self.assertRaises(RuntimeError): p.request_shutdown()
            self.assertNotIn(b'oem shutdown:2', wire.commands)

    def test_payload_exact_binding_and_one_kernel_only(self):
        data = b'x' * 70000; m = manifest()
        m.update(payload_bytes=len(data), payload_sha256=hashlib.sha256(data).hexdigest())
        wire = Wire([b'OKAYpolaris-uefi-diag', b'OKAYwaiting-payload', b'DATA00011170',
                     b'OKAY', b'OKAYvalidated', b'OKAYvalidated', b'OKAY'])
        p = OwnedMarkerProtocol(wire, m); p.product(); p.stage_payload(data, m); p.boot()
        self.assertEqual(b''.join(wire.chunks), data)
        self.assertEqual(wire.commands[-1], b'oem boot')
        bad = copy.deepcopy(m); bad['payload_sha256'] = '0' * 64
        with self.assertRaises(ValueError): p.stage_payload(data, bad)


if __name__ == '__main__': unittest.main()
