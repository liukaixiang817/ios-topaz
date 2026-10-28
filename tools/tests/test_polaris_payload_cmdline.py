"""Never silently lose trailing safety or experiment flags from a RAM payload."""
from pathlib import Path
import sys,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools'))
import mkpayload
class PayloadCommandLine(unittest.TestCase):
 def test_invalid_line_is_rejected_before_any_input_is_read(self):
  for line in ('x'*608,'x'*610,'a\0polarisosm=1','频'*203):
   with self.subTest(bytes=len(line.encode())),self.assertRaisesRegex(ValueError,'command line'):
    mkpayload.build('/not-a-kernel','/not-a-tree',line)
 def test_exact_byte_boundary_and_no_truncation(self):
  for line in ('','cpus=4 polarisosm=1','x'*607,'频'*202):
   self.assertEqual(mkpayload.command_line_bytes(line),line.encode())
  for line in ('x'*608,'x\0y','频'*203):
   with self.assertRaises(ValueError):mkpayload.command_line_bytes(line)
class ReadonlyInventoryIntent(unittest.TestCase):
 def test_missing_truncated_duplicate_unexpected_or_unbound_flags_refused(self):
  import importlib.util
  spec=importlib.util.spec_from_file_location('builder',Path(__file__).resolve().parents[2]/'tools/build-polaris-uefi-xnu.py')
  m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
  good=[b'cpus=4',b'polarisosm=1']
  self.assertTrue(m.readonly_osm_intent(good,True,7,4,False,None,True,False,False))
  self.assertTrue(m.readonly_osm_intent(good,True,7,4,True,'success',False,False,False))
  for tokens in ([],[b'polarisos'],[b'polarisosm=0'],good+good):
   with self.subTest(tokens=tokens),self.assertRaises(ValueError):
    m.readonly_osm_intent(tokens,True,7,4,False,None,True,False,False)
  with self.assertRaises(ValueError):m.readonly_osm_intent(good,False,7,4,False,None,True,False,False)
  for core,count,qemu,drain,bridge,ufs,marker in [(1,4,False,None,True,False,False),
    (7,2,False,None,True,False,False),(7,4,True,None,True,False,False),
    (7,4,False,None,False,False,False),(7,4,False,None,True,True,False),
    (7,4,False,None,True,False,True)]:
   with self.assertRaises(ValueError):m.readonly_osm_intent(good,True,core,count,qemu,drain,bridge,ufs,marker)

if __name__=='__main__':unittest.main()
