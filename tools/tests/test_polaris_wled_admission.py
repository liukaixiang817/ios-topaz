"""Inventory cannot start an OS or be promoted to a RAM iOS release proof."""
from pathlib import Path
import importlib.util,subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[2]
class WledAdmission(unittest.TestCase):
    def test_invalid_scope_refuses_before_any_payload_or_output_access(self):
        base=['python3',str(ROOT/'tools/build-polaris-uefi-xnu.py'),'--zig','/nonexistent/zig','--kernel','/nonexistent/kernel','--payload','/nonexistent/payload']
        valid=['--wled-inventory-only','--physical-buttons','--kernel-core','7','--kernel-cpus','4','--ram-shutdown-bridge']
        bad=[[],['--physical-buttons'],['--wled-inventory-only'],
             [x for x in valid if x!='--physical-buttons'],[x for x in valid if x!='--ram-shutdown-bridge'],
             valid+['--disk-guid','11111111-1111-1111-1111-111111111111'],valid+['--efi-application'],valid+['--physical-owned-marker'],
             valid+['--test-qemu-ufs'],valid+['--test-qemu-owned'],valid+['--test-wled-read-failure']]
        # Explicit refusal injection alone must also be rejected before reading files.
        bad[0]=['--test-wled-read-failure'];bad[1]=valid+['--kernel-cpus','2']
        bad+=[valid+['--test-qemu','--test-ram-drain','stale-cookie'],valid+['--chain-app-manifest','/nonexistent/chain']]
        with tempfile.TemporaryDirectory() as temp:
            for index,args in enumerate(bad):
                out=Path(temp)/str(index);p=subprocess.run(base+args+['--output',str(out)],capture_output=True,text=True)
                self.assertEqual(p.returncode,2,(args,p.stderr));self.assertIn('WLED',p.stderr);self.assertFalse(out.exists())
    def test_full_iOS_packager_rejects_inventory_even_when_tagged_passed(self):
        spec=importlib.util.spec_from_file_location('image',ROOT/'tools/polaris-uefi-xnu-image.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
        for d,q in [({'WLED_readonly_inventory_only':True},{}),({}, {'WLED_readonly_inventory_only':True,'passed':True,'release_handoff_admitted':True})]:
            with self.assertRaisesRegex(ValueError,'pre-XNU inventory'):m.admit(d,q,None,None,None)
if __name__=='__main__':unittest.main()
