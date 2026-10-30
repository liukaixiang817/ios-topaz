"""Current native/FW runtime option cannot produce a physical device image."""
from pathlib import Path
import subprocess
import importlib.util
import struct
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]


class NativeScope(unittest.TestCase):
    def test_native_faults_cannot_escape_the_runtime_software_fixture(self):
        with tempfile.TemporaryDirectory() as d:
            for fault in ('timeout','fault-ovp','fault-sc','fault-unknown','rt-ovp','rt-sc','rt-unknown','clock-regression'):
                for opts in ([],['--test-qemu'],['--test-qemu','--wled-native-runtime-test','--test-wled-write-timeout']):
                    p=subprocess.run(['python3',str(ROOT/'tools/build-polaris-uefi-xnu.py'),
                        '--kernel','/nonexistent/kernel','--payload','/nonexistent/payload',
                        '--zig','/nonexistent/zig','--output',d+'/refused','--test-wled-native-fault',fault,*opts],
                        capture_output=True,text=True)
                    self.assertEqual(p.returncode,2)
                    self.assertIn('native WLED fault requires only',p.stderr)
                    self.assertNotIn('FileNotFoundError',p.stderr)
                    self.assertFalse((Path(d)/'refused').exists())

    def test_lifecycle_scope_cannot_select_physical_or_mixed_faults(self):
        with tempfile.TemporaryDirectory() as d:
            for case in ('capacity','stale-ack','receipt-age','lease'):
                for opts in ([],['--test-qemu'],['--test-qemu','--wled-native-runtime-test','--test-wled-native-fault','timeout']):
                    p=subprocess.run(['python3',str(ROOT/'tools/build-polaris-uefi-xnu.py'),
                        '--kernel','/nonexistent/kernel','--payload','/nonexistent/payload',
                        '--zig','/nonexistent/zig','--output',d+'/refused','--test-wled-native-lifecycle',case,*opts],
                        capture_output=True,text=True)
                    self.assertEqual(p.returncode,2)
                    self.assertIn('native WLED lifecycle requires only',p.stderr)
                    self.assertNotIn('FileNotFoundError',p.stderr)
                    self.assertFalse((Path(d)/'refused').exists())

    def test_exact_new_symbols_are_found_but_undefined_duplicate_or_foreign_names_are_not(self):
        spec=importlib.util.spec_from_file_location('efi_builder',ROOT/'tools/build-polaris-uefi-xnu.py')
        builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
        def image(names):
            strings=bytearray(b'\0');entries=bytearray()
            for name,typ,section in names:
                entries+=struct.pack('<IBBHQ',len(strings),typ,section,0,0x100000)
                strings+=name.encode()+b'\0'
            raw=bytearray(32);raw[:4]=b'\xcf\xfa\xed\xfe';struct.pack_into('<II',raw,16,1,24)
            return bytes(raw)+struct.pack('<6I',2,24,56,len(names),56+len(entries),len(strings))+entries+strings
        base=[('_sweet_log_ring',15,1),('_sweet_log_total',15,1)]
        extra=[('_polaris_uefi_wled',15,2),('_PolarisWledNativeProbe',15,1)]
        self.assertEqual(set(builder.symbols(image(base+extra))),{r[0] for r in base+extra})
        for name in [r[0] for r in extra]:
            with self.assertRaises(ValueError):builder.symbols(image(base+[(name,1,0)]))
            with self.assertRaises(ValueError):builder.symbols(image(base+extra+[(name,15,2)]))
        self.assertNotIn('_PolarisWledNativeProbe',builder.symbols(image(base+[('_foreign_probe',15,1)])))

    def test_phone_mixed_and_incomplete_runtime_scopes_refuse_before_input_reads(self):
        complete=['--test-qemu','--kernel-core','7','--kernel-cpus','4',
                  '--test-ram-drain','success','--physical-buttons','--framebuffer-arrival-wake']
        cases=[[],['--test-qemu'],complete+['--wled-power-cycle-only'],
               complete+['--wled-inventory-only'],complete+['--wled-oem-physical-cycle'],
               complete+['--physical-owned-marker'],complete+['--test-qemu-owned']]
        with tempfile.TemporaryDirectory() as d:
            for at,case in enumerate(cases):
                output=Path(d)/str(at)
                p=subprocess.run(['python3',str(ROOT/'tools/build-polaris-uefi-xnu.py'),
                    '--kernel','/nonexistent/kernel','--payload','/nonexistent/payload',
                    '--zig','/nonexistent/zig','--output',str(output),'--wled-native-runtime-test',*case],
                    capture_output=True,text=True)
                self.assertEqual(p.returncode,2)
                self.assertIn('independent QEMU four-core',p.stderr)
                self.assertNotIn('FileNotFoundError',p.stderr)
                self.assertFalse(output.exists())


if __name__=='__main__':unittest.main()
