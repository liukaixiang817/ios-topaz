#!/usr/bin/env python3
"""Exercise the actual availability-query state machine with a software SMC peer.
Native ARM64 object/disassembly is separate; this test executes no SMC.
"""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
TEST=r'''
#include "polaris-wifi-scm-info.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
struct peer {unsigned mode,calls,gates;uint64_t ticks;};
static bool ready(void *v){struct peer*p=v;p->gates++;return p->mode!=8;}
static uint64_t counter(void *v){struct peer*p=v;p->ticks+=p->mode==7?500000:10;return p->ticks;}
static void invoke(void *v,uint64_t r[7]) {
 struct peer*p=v;
 if(!p->calls)assert(r[0]==0x42000601&&r[1]==1&&r[2]==0x02000501&&!r[3]&&!r[4]&&!r[5]&&!r[6]);
 else assert(r[0]==1&&r[1]==0x41&&r[2]==0x42&&r[3]==0x43&&r[4]==0x44&&r[5]==0x45&&r[6]==0x46);
 p->calls++;
 if(p->mode==0){r[0]=0;r[1]=1;return;}
 if(p->mode==1){r[0]=0;r[1]=0;return;}
 if(p->mode==2){r[0]=UINT64_MAX-3;r[1]=1;return;}
 if(p->mode==3){r[0]=0;r[1]=2;return;}
 if(p->mode==4||(p->mode==5&&p->calls==1)) {
  r[0]=1;for(unsigned i=1;i<7;i++)r[i]=0x40+i;return;
 }
 if(p->mode==6){r[0]=0;r[1]=1;p->ticks=0;return;}
 r[0]=0;r[1]=1;
}
int main(void) {
 for(unsigned mode=0;mode<=8;mode++) {
  struct peer p={mode,0,0,100};struct pwi_io io={&p,ready,counter,invoke};struct pwi_report r;
  polaris_wifi_scm_info_query(&io,&r);
  assert(r.calls==p.calls&&r.calls<=4);
  if(mode==0||mode==5)assert(r.error==PWI_OK&&r.complete&&r.available&&r.calls==(mode==5?2u:1u));
  if(mode==1)assert(r.error==PWI_OK&&r.complete&&!r.available);
  if(mode==2)assert(r.error==PWI_TRANSPORT&&!r.complete&&!r.available&&r.rounds[0].raw[0]==UINT64_MAX-3);
  if(mode==3)assert(r.error==PWI_RESULT&&!r.available);
  if(mode==4)assert(r.error==PWI_RESUME_LIMIT&&r.calls==4&&!r.complete);
  if(mode==6)assert(r.error==PWI_CLOCK&&!r.complete);
  if(mode==7)assert(r.error==PWI_DEADLINE&&!r.issued&&!r.calls);
  if(mode==8)assert(r.error==PWI_GATE&&!r.issued&&!r.calls);
 }
 puts("PASS SCM INFO exact IDs/value-only,0/1 replies,raw errors,all7 resume registers,4-call limit,clock/deadline/gate; no SMC executed");
}
'''
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);args=p.parse_args();args.out.mkdir(parents=True,exist_ok=True)
 with tempfile.TemporaryDirectory(prefix='polaris-wifi-info-') as tmp:
  tmp=Path(tmp);(tmp/'test.c').write_text(TEST)
  c=subprocess.run(['/usr/bin/clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(ROOT/'tools'),str(tmp/'test.c'),'-o',str(tmp/'test')],capture_output=True,text=True)
  (args.out/'host-build.log').write_text(c.stdout+c.stderr)
  if c.returncode:raise SystemExit(c.returncode)
  r=subprocess.run([str(tmp/'test')],capture_output=True,text=True);(args.out/'host-run.log').write_text(r.stdout+r.stderr)
  v={'passed':r.returncode==0,'run_exit':r.returncode,'output':r.stdout.strip(),'actual_SMC_executed':False,
     'sources':{f:hashlib.sha256((ROOT/'tools'/f).read_bytes()).hexdigest() for f in ['polaris-wifi-scm-info.c','polaris-wifi-scm-info.h']}}
  (args.out/'result.json').write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v));return r.returncode
if __name__=='__main__':raise SystemExit(main())
