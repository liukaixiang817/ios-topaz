"""A UEFI diagnostics product must never pass the physical FASTBOOT gate."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from polaris_fastboot_identity import expected_polaris_fastboot


class FastbootIdentity(unittest.TestCase):
    def test_actual_cli_formats(self):
        for reply in ['product: polaris\r\nFinished. Total time: 0.001s\r\n',
                      '(bootloader) product: polaris\nOKAY [0.001s]\n']:
            self.assertTrue(expected_polaris_fastboot(0, reply))

    def test_native_UEFI_diagnostics_and_prefixes_are_not_physical_product(self):
        for product in ['polaris-uefi-diag', 'polaris-uefi', 'polaris2', 'dipper', 'polaris.extra']:
            self.assertFalse(expected_polaris_fastboot(0, 'product: '+product+'\n'))

    def test_conflicting_or_duplicate_replies_do_not_select_a_device(self):
        for reply in ['product: polaris\nproduct: dipper\n',
                      'product: polaris\nproduct: polaris\n',
                      'product: polaris\nproduct: polaris garbage\n']:
            self.assertFalse(expected_polaris_fastboot(0, reply))

    def test_nonzero_or_unknown_command_return_is_rejected(self):
        for status in [1, -9, None, False, '0']:
            self.assertFalse(expected_polaris_fastboot(status, 'product: polaris\n'))

    def test_product_in_unrelated_text_is_not_a_response(self):
        for reply in ['', 'waiting for product: polaris', 'getvar:product: polaris',
                      'OKAYpolaris-uefi-diag', 'product: polaris garbage']:
            self.assertFalse(expected_polaris_fastboot(0, reply))


if __name__ == '__main__':
    unittest.main()
