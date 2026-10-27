"""Physical identity/base binding and live-firmware guard; not a phone write proof."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class MarkerAdmission(unittest.TestCase):
    def test_actual_shared_identity_base_and_guard_bounds(self):
        code = r'''
#include <assert.h>
#include <string.h>
#include "runtime-marker.h"
int main(void) {
 struct polaris_marker_identity i={.actual_cpu=0x81000700,.timer=19200000,
 .base=0x180000000,.bytes=0xfc8a0000,.reg={0x1d84000,0x2500},
 .mode=1,.core=0x700,.count=2,.file_root=1,.rootrw=1,.cow=1,.ram_mib=512,
 .marker=1,.guard=POLARIS_DURABLE_MARKER_GUARD};
 assert(polaris_marker_allowed(&i));assert(!polaris_marker_allowed(0));
 for(unsigned cpu=0;cpu<4096;cpu++) {
  i.actual_cpu=cpu;assert(polaris_marker_allowed(&i)==(cpu==0x600||cpu==0x700));
 }
 i.actual_cpu=0x81000700;
 size_t u64s[]={offsetof(struct polaris_marker_identity,timer),offsetof(struct polaris_marker_identity,base),
 offsetof(struct polaris_marker_identity,bytes),offsetof(struct polaris_marker_identity,reg),
 offsetof(struct polaris_marker_identity,reg)+8};
 for(unsigned f=0;f<sizeof(u64s)/sizeof(u64s[0]);f++)for(unsigned bit=0;bit<64;bit++){
  struct polaris_marker_identity changed=i;uint64_t v;memcpy(&v,(char*)&changed+u64s[f],8);
  v^=UINT64_C(1)<<bit;memcpy((char*)&changed+u64s[f],&v,8);assert(!polaris_marker_allowed(&changed));
 }
 for(size_t at=offsetof(struct polaris_marker_identity,mode);at<=offsetof(struct polaris_marker_identity,guard);at+=4)
  for(unsigned bit=0;bit<32;bit++){
   struct polaris_marker_identity changed=i;uint32_t v;memcpy(&v,(char*)&changed+at,4);
   v^=1u<<bit;memcpy((char*)&changed+at,&v,4);assert(!polaris_marker_allowed(&changed));
  }
 uint8_t expected[182*24]={0},provided[sizeof(expected)];
 for(size_t n=0;n<sizeof(expected);n++)expected[n]=(uint8_t)(n*31);
 memcpy(provided,expected,sizeof(provided));
#define BASE(p,n,b,e,en,eb,mb) polaris_marker_base_matches(p,n,b,e,en,eb,mb)
 assert(BASE(provided,sizeof(provided),4194304,expected,sizeof(expected),4194304,2048));
 for(size_t n=0;n<sizeof(provided);n++){
  provided[n]^=1;assert(!BASE(provided,sizeof(provided),4194304,expected,sizeof(expected),4194304,2048));provided[n]^=1;
 }
 assert(!BASE(provided,sizeof(provided)-1,4194304,expected,sizeof(expected),4194304,2048));
 assert(!BASE(provided,sizeof(provided),4194303,expected,sizeof(expected),4194304,2048));
 assert(!BASE(provided,sizeof(provided),4194304,expected,sizeof(expected),4194304,2049));
 assert(!BASE(provided,sizeof(provided),4194304,0,sizeof(expected),4194304,2048));
 for(unsigned physical=0;physical<2;physical++){
  char storage[642];memset(storage,0x55,sizeof(storage));char *line=storage+1;
  strcpy(line,"cpus=2 polarisownedmarker=1");
  assert(polaris_marker_append_guard(line,640,physical));
  assert(strstr(line,physical?"=0x50470001":"=0x50470002"));
  assert(!polaris_marker_template(line,640)&&!polaris_marker_append_guard(line,640,physical));
  assert(storage[0]==0x55&&storage[641]==0x55);
  for(size_t cap=0;cap<80;cap++){
   memset(storage,0x55,sizeof(storage));line=storage+1;
   if(cap)line[0]=0;
   bool result=polaris_marker_append_guard(line,cap,physical);
   assert(storage[0]==0x55&&storage[cap+1]==0x55);
   assert(result==(cap>strlen(" polarisdurableguard=0x50470001")));
  }
 }
 char forged[]="x polarisdurableguard=0x50470001";assert(!polaris_marker_template(forged,sizeof(forged)));
 char unterminated[4]={'x','x','x','x'};assert(!polaris_marker_template(unterminated,sizeof(unterminated)));
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            (folder/'test.c').write_text(code)
            subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
                            '-I'+str(ROOT/'shim/polaris'),str(folder/'test.c'),'-o',str(folder/'test')], check=True)
            subprocess.run([str(folder/'test')], check=True)


if __name__ == '__main__':
    unittest.main()
