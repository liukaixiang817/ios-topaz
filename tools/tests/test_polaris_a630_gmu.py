"""GMU hardware-stage model; no reset release or firmware execution."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class A630GMUTests(unittest.TestCase):
    def test_reset_ack_load_faults_and_retained_reset(self):
        source = r'''
#include "polaris-a630-images.h"
#include "polaris-a630-tcm.h"
#include "polaris-a630-gmu.h"
#include <assert.h>
#include <string.h>
struct model {
 uint32_t reset,fw,hfi,reads,writes,waits,reset_reads,ack,reset_writes,words[8192];
 uint32_t fail_read,fail_write,drop_at,lost_at;
 bool lease;
};
static bool lease(void *p) {struct model *m=p;return m->lease&&(!m->lost_at||m->writes<m->lost_at);}
static bool rd(void *p,uint32_t off,uint32_t *v) {
 struct model *m=p;m->reads++;if(off==m->fail_read)return false;
 if(off==0x14000){if(m->reset_writes&&++m->reset_reads==m->ack)m->reset=1;*v=m->reset;}
 else if(off==0x14070)*v=m->fw;else if(off==0x14600)*v=m->hfi;
 else if(off==0x14220)*v=0x12345678;
 else {assert(off>=0x3000&&off<0xb000&&!(off&3));*v=m->words[(off-0x3000)/4];}
 return true;
}
static bool wr(void *p,uint32_t off,uint32_t v) {
 struct model *m=p;m->writes++;
 if(off==0x14000){assert(v==1);m->reset_writes++;}
 else {assert(m->reset==1&&off>=0x3000&&off<0xb000&&!(off&3));
  if(off!=m->drop_at)m->words[(off-0x3000)/4]=v;}
 return off!=m->fail_write;
}
static bool sync_io(void *p){return lease(p);}
static void wait_io(void *p,uint32_t us){assert(us==1);((struct model*)p)->waits++;}
static void init(struct model *m){memset(m,0,sizeof(*m));m->lease=true;m->ack=1;}
int main(void) {
 uint8_t fw[32768]={0x80,0x3f,4,0,9,0,0,0};
 for(unsigned i=8;i<sizeof(fw);i++)fw[i]=(uint8_t)(i*3+1);
 struct a630_image image={fw,sizeof(fw)};
 struct a630_tcm_io io={lease,rd,wr,sync_io};
 struct a630_gmu_snapshot s;struct model m;init(&m);
 assert(a630_gmu_prepare(false,true,&image,&io,wait_io,&m,&s)==A630_GMU_DISABLED&&!m.reads&&!m.writes);
 assert(a630_gmu_prepare(true,false,&image,&io,wait_io,&m,&s)==A630_GMU_DISABLED&&!m.reads&&!m.writes);
 assert(a630_gmu_prepare(true,true,0,&io,wait_io,&m,&s)==A630_GMU_ARGUMENT&&!m.reads&&!m.writes);
 m.lease=false;assert(a630_gmu_prepare(true,true,&image,&io,wait_io,&m,&s)==A630_GMU_LEASE&&!m.reads);
 init(&m);m.fw=0xbabeface;assert(a630_gmu_prepare(true,true,&image,&io,wait_io,&m,&s)==A630_GMU_RUNNING&&!m.writes);
 init(&m);m.hfi=1;assert(a630_gmu_prepare(true,true,&image,&io,wait_io,&m,&s)==A630_GMU_RUNNING&&!m.writes);
 for(unsigned ack=1;ack<=1000;ack+=999) {
  init(&m);m.ack=ack;
  assert(a630_gmu_prepare(true,true,&image,&io,wait_io,&m,&s)==A630_GMU_LOADED);
  assert(s.stage==4&&s.retain_block_reset&&s.polls==ack&&s.reset_held==1);
  assert(m.reset==1&&m.reset_writes==1&&s.tcm.writes==8192&&m.writes==8193);
  for(unsigned i=0;i<8192;i++)assert(m.words[i]==a630_image_word(fw+4*i));
 }
 init(&m);m.ack=1001;
 assert(a630_gmu_prepare(true,true,&image,&io,wait_io,&m,&s)==A630_GMU_RESET_TIMEOUT);
 assert(s.retain_block_reset&&s.polls==1000&&m.writes==1&&!s.tcm.writes);
 init(&m);m.fail_write=0x14000;
 assert(a630_gmu_prepare(true,true,&image,&io,wait_io,&m,&s)==A630_GMU_IO&&s.retain_block_reset);
 const uint32_t offsets[]={0x14000,0x14070,0x14600,0x14220};
 for(unsigned n=0;n<4;n++) {
  init(&m);m.fail_read=offsets[n];
  assert(a630_gmu_prepare(true,true,&image,&io,wait_io,&m,&s)==A630_GMU_IO&&!m.writes&&!s.retain_block_reset);
 }
 init(&m);m.drop_at=0x7000;
 assert(a630_gmu_prepare(true,true,&image,&io,wait_io,&m,&s)==A630_GMU_TRANSFER_FAILED);
 assert(s.retain_block_reset&&s.tcm.result==A630_TCM_MISMATCH&&s.tcm.offset==0x7000&&m.reset==1);
 init(&m);m.lost_at=8;
 assert(a630_gmu_prepare(true,true,&image,&io,wait_io,&m,&s)==A630_GMU_TRANSFER_FAILED);
 assert(s.retain_block_reset&&s.tcm.result==A630_TCM_LEASE_LOST&&m.writes==8&&m.reset==1);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory)
            (p / 'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang', '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', '-I', str(ROOT / 'tools'),
                            str(p / 'test.c'), '-o', str(p / 'test')], check=True)
            subprocess.run([str(p / 'test')], check=True)


if __name__ == '__main__':
    unittest.main()
