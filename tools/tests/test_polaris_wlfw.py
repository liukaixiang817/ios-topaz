"""Original ICNSS capability protocol, not Wi-Fi initialization or connectivity."""
from pathlib import Path
import subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[2]


class WlfwCodec(unittest.TestCase):
    def test_wire_identity_transaction_and_malformed_messages(self):
        code=r'''
#include "polaris-wlfw.h"
#include <assert.h>
#include <string.h>
/* Independent explicit wire bytes: result/chip/board/soc/nested-string and
 * top-level string. Also compared privately to the pinned original encoder. */
static const uint8_t body[]={2,4,0,0,0,0,0,16,8,0,0x90,0x39,0,0,0x04,0,0,0,
 17,4,0,7,0,0,0,18,4,0,0x45,8,0,0,19,8,0,0x78,0x56,0x34,0x12,3,'a','b','c',
 20,4,0,'t','e','s','t'};
int main(void){uint8_t packet[7+203]={2,0x34,0x12,0x24,0,sizeof(body),0};
 memcpy(packet+7,body,sizeof(body));size_t bytes=7+sizeof(body);
 struct polaris_wlfw_cap cap,sentinel;memset(&sentinel,0xa5,sizeof(sentinel));
 assert(polaris_wlfw_cap_response(0x45,1,0,0x1234,packet,bytes,&cap));
 assert(cap.valid==31&&cap.chip_id==0x3990&&cap.chip_family==4&&cap.board_id==7&&cap.soc_id==0x845);
 assert(cap.firmware_version==0x12345678&&!strcmp(cap.timestamp,"abc")&&!strcmp(cap.build_id,"test"));
 assert(polaris_wlfw_cap_has_identity(&cap));
 uint8_t req[8]={0xa5};assert(polaris_wlfw_cap_request(0x1234,req,7));
 assert(!memcmp(req,(uint8_t[]){0,0x34,0x12,0x24,0,0,0},7));
 assert(!polaris_wlfw_cap_request(0,req,7)&&!polaris_wlfw_cap_request(1,req,6));
 for(size_t n=0;n<bytes;n++){cap=sentinel;assert(!polaris_wlfw_cap_response(0x45,1,0,0x1234,packet,n,&cap));assert(!memcmp(&cap,&sentinel,sizeof(cap)));}
 for(unsigned t=0;t<4;t++){
  cap=sentinel;assert(!polaris_wlfw_cap_response(t==0?0x46:0x45,t==1?2:1,t==2?1:0,t==3?0x1235:0x1234,packet,bytes,&cap));
  assert(!memcmp(&cap,&sentinel,sizeof(cap)));
 }
 uint8_t changed[sizeof(packet)];unsigned seed=71;
 for(unsigned n=0;n<10000;n++){
  memcpy(changed,packet,sizeof(packet));seed=seed*1664525u+1013904223u;
  unsigned at=seed%bytes;changed[at]^=(uint8_t)(1u<<((seed>>16)%8));cap=sentinel;
  bool ok=polaris_wlfw_cap_response(0x45,1,0,0x1234,changed,bytes,&cap);
  if(!ok)assert(!memcmp(&cap,&sentinel,sizeof(cap)));
  else {assert(cap.result<=1&&strlen(cap.timestamp)<=32&&strlen(cap.build_id)<=128);assert((cap.valid&~31u)==0);}
 }
 memcpy(changed,packet,sizeof(packet));changed[7+sizeof(body)]=2;changed[8+sizeof(body)]=4;
 changed[9+sizeof(body)]=0;memset(changed+10+sizeof(body),0,4);changed[5]+=7;
 assert(!polaris_wlfw_cap_response(0x45,1,0,0x1234,changed,bytes+7,&cap)); /* Duplicate result. */
 uint8_t error[]={2,1,0,0x24,0,7,0,2,4,0,1,0,42,0};
 assert(polaris_wlfw_cap_response(0x45,1,0,1,error,sizeof(error),&cap));
 assert(cap.result==1&&cap.error==42&&!polaris_wlfw_cap_has_identity(&cap));
 error[10]=0;assert(!polaris_wlfw_cap_response(0x45,1,0,1,error,sizeof(error),&cap));return 0;}
'''
        with tempfile.TemporaryDirectory() as directory:
            d=Path(directory);(d/'test.c').write_text(code)
            subprocess.run(['/usr/bin/clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(ROOT/'tools'),str(d/'test.c'),'-o',str(d/'test')],check=True)
            subprocess.run([str(d/'test')],check=True)


if __name__=='__main__':unittest.main()
