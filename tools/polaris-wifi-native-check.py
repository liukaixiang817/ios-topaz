#!/usr/bin/env python3
"""Check native Wi-Fi RO admission boundaries, never a physical SMEM read."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
TEST=r'''
#include "polaris-wifi-native-policy.h"
#include <assert.h>
#include <stdio.h>
int main(void) {
 struct polaris_wifi_native_admission a={1,1,1,4,19200000,true,true,true,false,false};
 assert(polaris_wifi_native_admit(&a)==PWN_MPU_READ_UNKNOWN);
 a.independent_mpu_read=true;assert(polaris_wifi_native_admit(&a)==PWN_OK);
 for(unsigned i=0;i<9;i++) {
  struct polaris_wifi_native_admission b=a;
  if(i==0)b.version=0;if(i==1)b.enable=2;if(i==2)b.uefi=0;if(i==3)b.board=false;
  if(i==4)b.draining=true;if(i==5)b.el=8;if(i==6)b.frequency=1000000;
  if(i==7)b.overlay=false;if(i==8)b.root=false;
  assert(polaris_wifi_native_admit(&b)!=PWN_OK);
 }
 assert(polaris_wifi_native_admit(0)==PWN_BAD_DT);
 puts("PASS RO DT/boot/board/root/overlay/drain/EL/timer/MPU policy; default MPU unknown rejects; software only");
}
'''
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);args=p.parse_args();args.out.mkdir(parents=True,exist_ok=True)
 with tempfile.TemporaryDirectory(prefix='polaris-wifi-native-') as tmp:
  tmp=Path(tmp);(tmp/'test.c').write_text(TEST)
  cmd=['/usr/bin/clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(ROOT/'tools'),str(tmp/'test.c'),'-o',str(tmp/'test')]
  c=subprocess.run(cmd,capture_output=True,text=True);(args.out/'build.log').write_text(c.stdout+c.stderr)
  if c.returncode:raise SystemExit(c.returncode)
  r=subprocess.run([str(tmp/'test')],capture_output=True,text=True);(args.out/'run.log').write_text(r.stdout+r.stderr)
  src=(ROOT/'tools/polaris-wifi-native-ro.c').read_text()
  # Source safety assertions supplement the actual ARM64 object check. They
  # are not a substitute for native API compilation or live access proof.
  assert 'return false;\n}' in src[src.index('static bool pwn_independent_mpu_read_witness'):]
  assert 'ml_nofault_copy' in src and 'ml_io_map_with_prot' in src and 'VM_PROT_READ' in src
  assert not any(x in src for x in ['polaris_wifi_glink_start(', 'smem_get(', 'smem_alloc(', 'WRITE_ONCE(', 'ml_io_map('])
  v={'passed':r.returncode==0,'run_exit':r.returncode,'output':r.stdout.strip(),'physical_SMEM':False,
     'native_default_mpu_read_admission':False,'may_transmit':False,
     'sources':{name:hashlib.sha256((ROOT/'tools'/name).read_bytes()).hexdigest() for name in ['polaris-wifi-native-ro.c','polaris-wifi-native-policy.h']}}
  (args.out/'result.json').write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v));return r.returncode
if __name__=='__main__':raise SystemExit(main())
