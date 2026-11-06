"""Exercise actual one-shot command ordering with software host transports."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
spec = importlib.util.spec_from_file_location('native_boot', TOOLS/'polaris-wifi-native-boot.py')
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)


class NativeBootOrder(unittest.TestCase):
    def scenario(self, fault='', execute=True, watchdog=False):
        calls = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            case = root/'research/case'
            (case/'payload-0001').mkdir(parents=True)
            (case/'payload-0001/payload.bin').write_bytes(b'payload')
            serial = root/'device'
            serial.write_text('software-device')
            output = case/'attempt'
            image = dict(sha256='image', artifact='image.bin')
            driver = dict(sha256='driver')
            if watchdog:driver.update(UEFI_watchdog_status_before_native_required=True,RAM_idle_reboot_enabled=False)
            review = dict(fastboot_sha256='hash', libusb_sha256='hash')

            def consume(*_):
                calls.append('consume')
                return dict(consumed=True)

            def run(command, **_):
                action = 'product' if 'getvar' in command else 'send'
                calls.append(action)
                if action == 'send':
                    self.assertEqual(calls[:3], ['product', 'consume', 'send'])
                return SimpleNamespace(returncode=1 if fault == action else 0,
                                       stdout='product: polaris\n' if action == 'product' else 'OKAY\n', stderr='')

            class Transport:
                def __init__(self, *_):
                    calls.append('transport')

                def open_target(self):
                    return True

                def close(self):
                    calls.append('close')

            class Protocol:
                def __init__(self, *_):
                    pass

                def product(self):
                    calls.append('UEFI-product')
                    return 'polaris-uefi-diag'

                def stage_payload(self, data, manifest):
                    calls.append('stage')
                    if fault == 'stage':
                        raise RuntimeError('software stage failure')
                    self.payload_stage = dict(validation_ACK=True)

                def stage(self, what):
                    calls.append('prestart-logs')
                    assert what=='logs'

                def upload(self):
                    calls.append('upload')
                    status=7 if fault=='watchdog' else 0
                    return (f'UEFI_WATCHDOG_DISABLE_STATUS=0x{status:016x}\r\n'
                            'RAM_IDLE_AUTO_RESET_SECONDS=0x0000000000000000\r\n').encode()

                def boot(self, **_):
                    calls.append('start')
                    if fault == 'start':
                        raise RuntimeError('software unknown ACK')

            argv = ['boot', '--review', str(root/'review'), '--serial-file', str(serial),
                    '--fastboot', str(root/'fastboot'), '--libusb', str(root/'libusb'), '--output', str(output)]
            if execute:
                argv.append('--boot-once')
            with patch.object(boot, 'ROOT', root), patch.object(boot, 'sha', return_value='hash'), \
                 patch.object(boot, 'validate', return_value=(review, case, image, driver, SimpleNamespace(consume=consume))), \
                 patch.object(boot.subprocess, 'run', side_effect=run), \
                 patch.object(boot, 'LibusbTransport', Transport), patch.object(boot, 'KernelProtocol', Protocol), \
                 patch.object(sys, 'argv', argv):
                if fault:
                    with self.assertRaises(RuntimeError):
                        boot.main()
                else:
                    boot.main()
            if execute:
                record = json.loads((output/'boot.json').read_text())
                self.assertFalse(record['physical_networking_verified'])
                self.assertEqual(record['state'], 'stopped_no_retry' if fault else 'native_start_ACK')
            else:
                self.assertFalse(output.exists())
            return calls

    def test_no_device_or_nonce_in_default_mode(self):
        self.assertEqual(self.scenario(execute=False), [])

    def test_burn_before_send_then_validate_before_start(self):
        self.assertEqual(self.scenario(), ['product', 'consume', 'send', 'transport', 'UEFI-product', 'stage', 'start', 'close'])

    def test_watchdog_is_confirmed_before_native_start(self):
        calls=self.scenario(watchdog=True)
        self.assertEqual(calls,['product','consume','send','transport','UEFI-product','stage',
                                'prestart-logs','upload','start','close'])
        calls=self.scenario(fault='watchdog',watchdog=True)
        self.assertNotIn('start',calls)
        self.assertEqual(calls.count('consume'),1)
        self.assertEqual(calls.count('send'),1)

    def test_each_failure_stops_without_replay(self):
        for fault, forbidden in [('product', 'consume'), ('send', 'transport'), ('stage', 'start'), ('start', 'reset')]:
            with self.subTest(fault=fault):
                calls = self.scenario(fault)
                self.assertNotIn(forbidden, calls)
                self.assertEqual(calls.count('consume'), 0 if fault == 'product' else 1)
                self.assertLessEqual(calls.count('send'), 1)
                self.assertLessEqual(calls.count('start'), 1)


if __name__ == '__main__':
    unittest.main()
