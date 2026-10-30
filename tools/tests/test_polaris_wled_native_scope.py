"""Current native/FW runtime option cannot produce a physical device image."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]


class NativeScope(unittest.TestCase):
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
