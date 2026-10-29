"""The read hold must never become a kernel, setter or installation permit."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'tools' / (name + '.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


image = load('polaris-uefi-wled-image')
observe = load('polaris-wled-observations')
control = load('polaris-uefi-wled')


def fixture():
    d = dict(WLED_readonly_inventory_only=True, kernel_CPU_ON_compiled_out=True,
             kernel_handoff=False, PMIC_write_api=False, storage_write_api=False,
             NVRAM_write_api=False, physical_buttons=True, probe_only=True,
             holds_before_OS_start=True, kernel_CPU_affinity=0x700, kernel_CPU_count=4,
             QEMU_variant=False, phone_compatible=True, controlled_WLED_read_refusal=False,
             physical_owned_marker_test=False, selected_application=False,
             disk_payload_read_only=False, chain_app=None, ready_to_boot_driver=True,
             payload_C_admission=True, rebased_kernel_bytes_match=True,
             RAM_host_idle_recovery_seconds=1800, inputs={'source': 'digest'}, kernel_sha256='kernel')
    models = [dict(passed=True, WLED_readonly_inventory_only=True,
                   release_handoff_admitted=False, actual_phone_or_PMIC_emulated=False,
                   kernel_CPU_started=False, PMIC_power_control_tested=False,
                   inputs=d['inputs'].copy(), kernel_sha256='kernel',
                   checks={k: True for k in image.MODEL_CHECKS}, controlled_read_refusal=v,
                   raw_fields=dict(WLED_MOCK_BACKEND=1, WLED_KERNEL_AP_STAGE=0,
                                   WLED_READ_COMMANDS=4 if v else 32, WLED_SNAPSHOT_FORMAT=2, WLED_READONLY_RESULT=6 if v else 0),
                   actual_guest_memory=dict(actual_AP_stage='synthetic VM', actual_kernel_log_total='synthetic VM'))
              for v in (False, True)]
    return d, models


def inventory():
    values = dict(WLED_READONLY_VERSION=0x50000000, WLED_CTRL_APID_OWNER=7 << 32,
                  WLED_SINK_APID_OWNER=9 << 32, WLED_CTRL_MAPPING=0x3d800,
                  WLED_SINK_MAPPING=0x3d900, WLED_READ_COMMANDS=28,
                  WLED_CTRL_REVISION=0x01020304, WLED_SINK_REVISION=0x01020304,
                  WLED_DISPLAY_READY_ENABLE=0x800000, WLED_FAULT_RT=0,
                  WLED_SINK_CONFIG=0, WLED_READONLY_RESULT=0, WLED_KERNEL_AP_STAGE=0)
    lines = [f'{k}=0x{v:016x}' for k, v in values.items()]
    for n in range(4):
        lines.extend([f'WLED_STRING_INDEX=0x{n:016x}', 'WLED_STRING_CONFIG=0x0000000000000000',
                      'WLED_STRING_LEVEL=0x00000000000007ff'])
    return '\n'.join(lines + ['WLED_INVENTORY_HOLD: NO_CPU_ON NO_PMIC_WRITE'])


class Scope(unittest.TestCase):
    def test_source_bound_models_only_read_scope(self):
        d, m = fixture(); image.admit(d, m)
        for key, value in [('kernel_handoff', True), ('kernel_CPU_ON_compiled_out', False),
                           ('PMIC_write_api', True), ('storage_write_api', True),
                           ('NVRAM_write_api', True), ('kernel_CPU_affinity', 7),
                           ('QEMU_variant', True), ('selected_application', True),
                           ('RAM_host_idle_recovery_seconds', 0), ('PMIC_write_api', 0)]:
            altered = dict(d, **{key: value})
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                image.admit(altered, m)

    def test_missing_stale_or_promoted_model_refused(self):
        d, models = fixture()
        for key, value in [('inputs', {}), ('kernel_CPU_started', True),
                           ('release_handoff_admitted', True), ('checks', {}),
                           ('actual_guest_memory', {}), ('kernel_sha256', 'other')]:
            m = copy.deepcopy(models); m[0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): image.admit(d, m)
        with self.assertRaises(ValueError): image.admit(d, [models[0], models[0]])

    def test_phone_hold_binding_is_not_ios_binding(self):
        d, _ = fixture(); d['sha256'] = 'driver'
        i = dict(d, sha256='image', driver_sha256='driver')
        b = dict(state='temporary_WLED_inventory_boot_command_succeeded', image_sha256='image', sent_utc='now')
        control.binding(b, i, d)
        for bad in [dict(b, state='temporary_UEFI_XNU_boot_command_succeeded'), dict(b, image_sha256='other')]:
            with self.assertRaises(ValueError): control.binding(bad, i, d)
        with self.assertRaises(ValueError): control.binding(b, dict(i, kernel_handoff=True), d)

    def test_inventory_is_not_power_permission(self):
        result = observe.parse(inventory())
        self.assertTrue(result['complete_inventory'])
        self.assertFalse(result['writer_permission_or_identity_admitted'])
        self.assertFalse(result['backlight_off_or_on_proven'])

    def test_mock_duplicate_short_foreign_and_running_os_refused(self):
        text = inventory()
        bad = [text + '\nWLED_MOCK_BACKEND=0x0000000000000001',
               text + '\nWLED_READONLY_RESULT=0x0000000000000000',
               text.replace('WLED_SINK_MAPPING=0x000000000003d900', 'WLED_SINK_MAPPING=0x000000000003da00'),
               text.replace('WLED_STRING_INDEX=0x0000000000000002', 'WLED_STRING_INDEX=0x0000000000000003'),
               text.replace('WLED_KERNEL_AP_STAGE=0x0000000000000000', 'WLED_KERNEL_AP_STAGE=0x0000000000000001'),
               text + '\nDarwin Kernel Version', text + '\nKERNEL_PSCI_STATUS=0x0000000000000000',
               text.replace('WLED_READ_COMMANDS=0x000000000000001c', 'WLED_READ_COMMANDS=0x000000000000001b')]
        for value in bad:
            with self.subTest(value=value[-80:]), self.assertRaises(ValueError): observe.parse(value)
        for n in range(len(text)):
            with self.assertRaises(ValueError): observe.parse(text[:n])


    def test_v2_requires_psm_irq_and_32_reads_but_keeps_old_records_readable(self):
        old = inventory(); self.assertEqual(observe.parse(old)['snapshot_format'], 1)
        new = old.replace('WLED_READ_COMMANDS=0x000000000000001c', 'WLED_READ_COMMANDS=0x0000000000000020')
        new += '\nWLED_SNAPSHOT_FORMAT=0x0000000000000002\nWLED_PSM_CONFIG=0x0000000000000000\nWLED_IRQ_ENABLE=0x0000000000000000'
        self.assertEqual(observe.parse(new)['snapshot_format'], 2)
        for key in ['WLED_PSM_CONFIG', 'WLED_IRQ_ENABLE', 'WLED_READ_COMMANDS']:
            with self.assertRaises(ValueError): observe.parse('\n'.join(l for l in new.splitlines() if not l.startswith(key+'=')))

    def test_hardware_read_refusal_is_preserved_not_power_success(self):
        result = observe.parse('WLED_READONLY_RESULT=0x0000000000000006\nWLED_KERNEL_AP_STAGE=0x0000000000000000\nWLED_INVENTORY_HOLD: NO_CPU_ON NO_PMIC_WRITE')
        self.assertFalse(result['complete_inventory']); self.assertEqual(result['readonly_result'], 6)
        self.assertFalse(result['PMIC_writes'])


if __name__ == '__main__':
    unittest.main()
