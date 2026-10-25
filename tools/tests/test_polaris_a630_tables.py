"""A630 legacy wire tables against a native-DT/cmdDB/clock-source oracle."""
from pathlib import Path
import hashlib,struct,subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[2]
class A630TablesTests(unittest.TestCase):
 def test_native_packets_and_argument_boundaries(self):
  source=r'''
#include "polaris-a630-tables.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>
int main(void){
 uint32_t p[45],b[162];memset(p,0xa5,sizeof(p));memset(b,0xa5,sizeof(b));
 assert(!a630_hfi_tables(0,b+1,3,4)&&!a630_hfi_tables(p+1,0,3,4));
 assert(!a630_hfi_tables(p+1,b+1,4096,4)&&!a630_hfi_tables(p+1,b+1,3,4096));
 for(unsigned n=0;n<45;n++)assert(p[n]==0xa5a5a5a5);
 for(unsigned n=0;n<162;n++)assert(b[n]==0xa5a5a5a5);
 assert(a630_hfi_tables(p+1,b+1,3,4));
 assert(p[0]==0xa5a5a5a5&&p[44]==0xa5a5a5a5&&b[0]==0xa5a5a5a5&&b[161]==0xa5a5a5a5);
 assert(fwrite(p+1,4,43,stdout)==43&&fwrite(b+1,4,160,stdout)==160);return 0;
}
'''
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);(p/'test.c').write_text(source)
   subprocess.run(['/usr/bin/clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I',str(ROOT/'tools'),str(p/'test.c'),'-o',str(p/'test')],check=True)
   raw=subprocess.check_output([str(p/'test')])
  # Independently generated from pinned native bus graph/voltage algorithms,
  # including all13 DDR levels,2 CNOC levels and unused slots. Not a hash of
  # the implementation under test: the private source oracle is separate.
  self.assertEqual(hashlib.sha256(raw).hexdigest(),'f605b4fefb5ba1c38bfd258146cf6e2bd9c462081e71e6092e802a3a7b64f47b')
  perf=struct.unpack('<43I',raw[:172]);bw=struct.unpack('<160I',raw[172:])
  self.assertEqual(perf[:3],(0x00302b04,8,3))
  self.assertEqual(bw[:6],(0x0040a003,13,3,3,5,7))
  self.assertEqual(bw[6:9],(0x50034,0x5007c,0x5004c))
  self.assertEqual(bw[24:27],(0x50000,0x5003c,0x5000c))
if __name__=='__main__':unittest.main()
