"""Host controls for the separately admitted physical 8MiB marker trial.

This client grants neither image admission nor file ownership. The resident
firmware independently checks the real native shutdown mailbox. A reset ACK
still requires an independent FASTBOOT query and recovery readback afterward.
The ordinary RAM client and its RAM_DRAINED approval remain unchanged.
"""
import copy
import hashlib

from polaris_uefi_usb_transport import KernelProtocol


def admit_manifest(manifest):
    required_true = ('physical_owned_marker_test', 'physical_small_file_write_test',
                     'original_root_writes_volatile', 'raw_reset_requires_durable_SAFE',
                     'durable_guard_generated_after_reset_disabled', 'bounded_input',
                     'RAM_native_shutdown_bridge', 'ready_to_boot_driver', 'phone_compatible')
    required_false = ('RAM_only_XNU_loader', 'QEMU_variant', 'storage_write_api',
                      'NVRAM_write_api', 'isolated_QEMU_readonly_UFS_test',
                      'isolated_QEMU_owned_UFS_test', 'controlled_owned_response_short_injection',
                      'controlled_durable_guard_omitted', 'firmware_services_exited')
    if (not all(manifest.get(k) is True for k in required_true) or
            not all(manifest.get(k) is False for k in required_false) or
            manifest.get('RAM_host_idle_recovery_seconds', 1800) is not None or
            manifest.get('kernel_CPU_affinity') != 0x700 or manifest.get('kernel_CPU_count') != 2 or
            manifest.get('RAM_base') != 0x180000000 or manifest.get('RAM_bytes') != 0xfc8a0000 or
            manifest.get('firmware_core_reserved') != 0):
        raise ValueError('explicit physical marker guard manifest required')


class OwnedMarkerProtocol(KernelProtocol):
    """A marker-specific session, with no raw-reset or RAM-drain fallback."""
    def __init__(self, transport, manifest):
        admit_manifest(manifest)
        super().__init__(transport)
        self.marker_manifest = copy.deepcopy(manifest)

    def _control(self, command):
        if command in (b'reboot', b'reboot-bootloader'):
            raise RuntimeError('raw reset is unavailable in the owned marker session')
        return super()._control(command)

    def stage_payload(self, data, manifest):
        admit_manifest(manifest)
        if (manifest != self.marker_manifest or manifest.get('payload_bytes') != len(data) or
                not 0 < len(data) <= 128 << 20 or
                hashlib.sha256(data).hexdigest() != manifest.get('payload_sha256')):
            raise ValueError('marker payload differs from its bound manifest')
        if self.state() != 'waiting-payload':
            raise ValueError('cannot replace a running or previously validated kernel')
        command = f'download:{len(data):08x}'.encode()
        self.transport.write(command)
        if self.transport.read(64) != b'DATA' + command[9:]:
            raise ValueError('marker RAM download size was not admitted')
        for at in range(0, len(data), 65536):
            self.transport.write_data(data[at:at + 65536])
        if self.transport.read(64) != b'OKAY' or self.state() != 'validated':
            raise ValueError('marker payload validation failed')

    def reboot(self, bootloader=False):
        raise RuntimeError('raw reset is unavailable; native durable SAFE is required')

    def recover_unstarted_fastboot(self):
        """Recover a rejected download before any kernel was prepared/started.

        The firmware independently checks load_state again in prepare_reset;
        after CPU_ON it still requires durable SAFE. A host state string alone
        never grants reset permission for a running marker kernel.
        """
        if self.shutdown_token is not None or self.state() != 'waiting-payload':
            raise RuntimeError('unstarted recovery requires a rejected, unprepared payload')
        if KernelProtocol._control(self, b'reboot-bootloader'):
            raise ValueError('invalid unstarted recovery acknowledgement')

    def request_shutdown(self, bootloader=True):
        if type(bootloader) is not bool or self.shutdown_token is not None:
            raise ValueError('one explicit native shutdown target per marker session')
        before = self.shutdown_status()
        # This trial performs exactly one 4KiB marker WRITE. A different epoch,
        # RAM-only capability, failed owner, or partially sealed state is refused.
        if (not before['cookie'] or before['phase'] != 1 or before['sequence'] or
                before['mode'] or before['error'] or before['write_epoch'] != 1 or
                before['flushed_epoch'] or before['capabilities']):
            raise RuntimeError('native marker is not ready for its durable shutdown')
        mode = 2 if bootloader else 1
        if self._control(f'oem shutdown:{mode}'.encode()):
            raise ValueError('invalid marker shutdown acknowledgement')
        self.shutdown_token = (before['cookie'], 1, mode)
        return self.shutdown_token

    def reboot_drained(self):
        raise RuntimeError('RAM_DRAINED cannot authorize a marker reset; use reboot_safe')

    def reboot_safe(self):
        if self.shutdown_token is None:
            raise RuntimeError('no session-bound marker shutdown request')
        status = self.shutdown_status()
        cookie, sequence, mode = self.shutdown_token
        if (status['cookie'] != cookie or status['sequence'] != sequence or
                status['mode'] != mode or status['phase'] != 5 or status['error'] or
                status['write_epoch'] != 1 or status['flushed_epoch'] != 1 or
                status['capabilities'] != 0x1f):
            raise RuntimeError('durable marker SAFE not proven; reset refused')
        if self._control(f'oem drained-reboot:{mode}'.encode()):
            raise ValueError('invalid durable reset acknowledgement')
        return status  # Not proof of the resulting mode or physical readback.
