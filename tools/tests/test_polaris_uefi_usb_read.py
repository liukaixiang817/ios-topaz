"""Check the host consumer of actual EFI-map/PPM wire data."""
import importlib.util
from pathlib import Path
import struct
import unittest
spec=importlib.util.spec_from_file_location('reader',Path(__file__).parents[1]/'polaris-uefi-usb-read.py')
reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)


def wire(rows):
    data=b''.join(struct.pack('<IIQQQQ',kind,0,base,0,pages,attrs) for kind,base,pages,attrs in rows)
    return b'PEFIMAP1'+struct.pack('<QQQ',len(data),40,1)+data


class ConsumerTests(unittest.TestCase):
    def test_exact_product_before_any_OEM_command(self):
        self.assertTrue(reader.diagnostic_product('product: polaris-uefi-diag\nFinished. Total time: 0.01s\n'))
        for text in ['product: polaris\n','product: polaris-uefi-diag-other\n',
                     'product: polaris-uefi-diag\nproduct: polaris-uefi-diag\n']:
            self.assertFalse(reader.diagnostic_product(text))

    def test_actual_64bit_window_and_runtime_ownership(self):
        result=reader.map_summary(wire([(7,0x180000000,0xfc8a0,0)]))
        self.assertEqual(result['upper_free_pages'],0xfc8a0)
        self.assertEqual(result['upper_unmapped_pages'],0)
        result=reader.map_summary(wire([(2,0x180000000,1,1<<63)]))
        self.assertEqual(result['upper_retained_pages'],1)

    def test_map_rejects_bad_bounds_overlap_and_overflow(self):
        bads=[b'',wire([(7,0x180000001,1,0)]),wire([(7,0x180000000,0,0)]),
              wire([(7,0x180000000,2,0),(7,0x180001000,1,0)]),
              wire([(7,(1<<64)-4096,2,0)]),wire([(7,0x180000000,1,0)])[:-1]]
        for data in bads:
            with self.assertRaises(ValueError):reader.map_summary(data)

    def test_ppm_geometry_and_exact_rgb_payload(self):
        self.assertEqual(reader.ppm_info(b'P6\n2 1\n255\n'+bytes(6)),(2,1,11))
        for data in [b'P6\n4097 1\n255\n',b'P6\n2 1\n255\n'+bytes(5),b'P3\n2 1\n255\n']:
            with self.assertRaises(ValueError):reader.ppm_info(data)


if __name__=='__main__':unittest.main()
