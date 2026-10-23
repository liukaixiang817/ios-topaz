"""Run the actual diagnostic frame-chain bounds under ASan/UBSan."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class StackWalkTests(unittest.TestCase):
    def test_frame_chain_bounds_and_failed_reads(self):
        source = r'''
#include <assert.h>
#include <string.h>
#include "polaris-stack-walk.h"
struct memory { uint64_t data[16][2]; unsigned reads, fail; };
static bool read_frame(void *context, uint64_t fp, uint64_t out[2]) {
    struct memory *m = context; m->reads++;
    if (m->fail || fp < 0x1000 || fp >= 0x1100 || (fp & 15)) return false;
    memcpy(out, m->data[(fp - 0x1000) / 16], 16); return true;
}
int main(void) {
    struct memory m = {0}; uint64_t out[12] = {0}; struct polaris_bt_result r;
    m.data[0][0]=0x1010; m.data[0][1]=0xabc;
    m.data[1][0]=0x1020; m.data[1][1]=0xdef;
    m.data[2][0]=0; m.data[2][1]=0x123;
    r=polaris_walk_frames(0x1000,0x1000,out,4,read_frame,&m);
    assert(r.count==3 && r.stop==POLARIS_BT_END && m.reads==3);
    assert(out[0]==0xabc && out[1]==0xdef && out[2]==0x123);
    m.reads=0; r=polaris_walk_frames(0x1000,0x1000,out,2,read_frame,&m);
    assert(r.count==2 && r.stop==POLARIS_BT_LIMIT && m.reads==2);
    m.reads=0; m.fail=1; r=polaris_walk_frames(0x1000,0x1000,out,4,read_frame,&m);
    assert(r.count==0 && r.stop==POLARIS_BT_UNMAPPED && m.reads==1); m.fail=0;
    const uint64_t invalid[]={0xff0,0x1008,0x101000,UINT64_MAX-15};
    for(unsigned i=0;i<4;i++) {
        m.reads=0; r=polaris_walk_frames(0x1000,invalid[i],out,4,read_frame,&m);
        assert(r.count==0 && r.stop==POLARIS_BT_INVALID && m.reads==0);
    }
    m.data[0][0]=0x1000; m.reads=0;
    r=polaris_walk_frames(0x1000,0x1000,out,4,read_frame,&m);
    assert(r.count==1 && r.stop==POLARIS_BT_INVALID && m.reads==1);
    m.data[0][0]=0x1010; m.data[0][1]=0; m.reads=0;
    r=polaris_walk_frames(0x1000,0x1000,out,4,read_frame,&m);
    assert(r.count==0 && r.stop==POLARIS_BT_END && m.reads==1);
    m.reads=0; r=polaris_walk_frames(0x1000,0,out,4,read_frame,&m);
    assert(r.count==0 && r.stop==POLARIS_BT_END && m.reads==0);
    r=polaris_walk_frames(0x1000,0x1000,out,0,read_frame,&m);
    assert(r.count==0 && r.stop==POLARIS_BT_LIMIT && m.reads==0);
    m.reads=0; r=polaris_walk_frames(UINT64_MAX-31,UINT64_MAX-15,out,4,read_frame,&m);
    assert(r.count==0 && r.stop==POLARIS_BT_INVALID && m.reads==0);
    /* The focused diagnostic crosses the old six-frame boundary. Verify
     * its full twelve-frame capacity and the next frame never being read. */
    memset(&m,0,sizeof(m));
    for(unsigned i=0;i<16;i++) {
        m.data[i][0]=i==15?0:0x1010+16*i;
        m.data[i][1]=0x100000000ULL+i*4;
    }
    r=polaris_walk_frames(0x1000,0x1000,out,12,read_frame,&m);
    assert(r.count==12 && r.stop==POLARIS_BT_LIMIT && m.reads==12);
    for(unsigned i=0;i<12;i++) assert(out[i]==0x100000000ULL+i*4);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'walk.c'
            exe = Path(tmp) / 'walk'
            path.write_text(source)
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', '-I', str(ROOT / 'tools'),
                            str(path), '-o', str(exe)], check=True)
            subprocess.run([str(exe)], check=True)


if __name__ == '__main__':
    unittest.main()
