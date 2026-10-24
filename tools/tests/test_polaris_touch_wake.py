"""Board wake policy with electrical-state/timing and write-ownership checks."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class TouchWakeTests(unittest.TestCase):
    def test_shipped_header_matches(self):
        patch = (ROOT / 'xnu/profiles/polaris/0814-polaris-touch-reset-release.patch').read_text()
        lines = patch.split('+++ b/bsd/dev/polaris_touch_wake.h\n', 1)[1].splitlines()
        self.assertEqual('\n'.join(l[1:] for l in lines if l.startswith('+')) + '\n',
                         (ROOT / 'tools/polaris-touch-wake.h').read_text())

    def test_owned_enable_reset_release_and_failed_wake_restore(self):
        source = r'''
#include <assert.h>
#include <string.h>
#include "polaris-touch-wake.h"
struct board {
    uint32_t cfg[3],out[3];unsigned now,power_at,reset_ready,writes,sleeps,lines_reads;
    bool rails,enable_stuck,reset_stuck,lines_drop,after_reset_drop;
};
static unsigned idx(unsigned pin) {
    assert(pin==23 || pin==99 || pin==125);return pin==23?0:pin==99?1:2;
}
static bool enabled(struct board *b) {
    return pw_gpio_output(b->cfg[0]) && b->out[0]==2 && !b->enable_stuck;
}
static uint32_t rd(void *ctx,unsigned pin,unsigned off) {
    struct board *b=ctx;unsigned i=idx(pin);assert(off==0 || off==4);
    if(!off)return b->cfg[i];
    bool high=i==0?enabled(b):i==1?(b->out[1]==2 && !b->reset_stuck && b->now>=b->reset_ready):false;
    return b->out[i] | high;
}
static void wr(void *ctx,unsigned pin,unsigned off,uint32_t value) {
    struct board *b=ctx;unsigned i=idx(pin);assert(pin==23 || pin==99);
    assert(off==0 || off==4);b->writes++;
    if(pin==23)assert(!b->out[1]); /* Never change supply on a running controller. */
    bool before=enabled(b);
    if(!off)b->cfg[i]=value;
    else {
        assert(value==0 || value==2);
        if(pin==99 && value==2 && !b->out[1]) {
            assert(enabled(b) && b->rails && b->now>=10);
            b->reset_ready=b->now+200;
        }
        b->out[i]=value;
    }
    if(!before && enabled(b))b->power_at=b->now;
}
static void sleep_ms(void *ctx,unsigned ms) {
    struct board *b=ctx;assert(ms==5 || ms==200);b->now+=ms;b->sleeps++;
}
static unsigned lines(void *ctx) {
    struct board *b=ctx;b->lines_reads++;
    if(b->lines_drop && b->lines_reads>=3)return 1;
    if(b->after_reset_drop && b->out[1])return 0;
    return b->rails && enabled(b) && b->now>=b->power_at+4 ? 3:0;
}
static struct polaris_touch_wake init(struct board *b) {
    memset(b,0,sizeof(*b));b->cfg[0]=b->cfg[1]=0x201;b->rails=true;
    struct polaris_touch_wake g={.ctx=b,.read=rd,.write=wr,.sleep_ms=sleep_ms,.lines=lines};return g;
}
int main(void) {
    struct board b;struct polaris_touch_wake g=init(&b);
    assert(polaris_touch_wake(&g)==PW_OK && g.step==7 && g.changed==3 && !g.rolled_back);
    assert(b.now==210 && b.writes==4 && b.out[0]==2 && b.out[1]==2);
    assert(g.old_reset_cfg==0x201 && g.old_reset_io==0 && g.reset_cfg==0x203 && g.reset_io==3);
    g=init(&b);b.cfg[0]=0x20d;b.out[1]=2; /* Running reset: don't touch foreign supply mux. */
    assert(!polaris_touch_wake(&g) && g.step==8 && !b.writes && !b.now);
    g=init(&b);b.cfg[1]=0x209;
    assert(polaris_touch_wake(&g)==PW_OWNER && g.failed_pin==99 && !b.writes);
    g=init(&b);b.cfg[1]=1;
    assert(polaris_touch_wake(&g)==PW_OWNER && !b.writes);
    g=init(&b);b.cfg[2]=0x200;
    assert(polaris_touch_wake(&g)==PW_OWNER && g.failed_pin==125 && !b.writes);
    g=init(&b);b.cfg[0]=0x205;
    assert(polaris_touch_wake(&g)==PW_OWNER && g.failed_pin==23 && !b.writes);
    g=init(&b);b.enable_stuck=true;
    assert(polaris_touch_wake(&g)==PW_ENABLE && g.step==3 && g.rolled_back);
    assert(b.cfg[0]==0x201 && !b.out[0] && b.cfg[1]==0x201 && !b.out[1]);
    g=init(&b);b.rails=false;
    assert(polaris_touch_wake(&g)==PW_LINES && g.step==4 && g.rolled_back);
    assert(b.now==5 && b.cfg[0]==0x201 && !b.out[0] && !b.out[1]);
    g=init(&b);b.lines_drop=true;
    assert(polaris_touch_wake(&g)==PW_LINES && !b.out[0] && !b.out[1]);
    g=init(&b);b.reset_stuck=true;
    assert(polaris_touch_wake(&g)==PW_RESET && g.step==6 && g.rolled_back);
    assert(b.now==215 && b.writes==8 && b.cfg[0]==0x201 && b.cfg[1]==0x201);
    assert(!b.out[0] && !b.out[1]);
    g=init(&b);b.after_reset_drop=true;
    assert(polaris_touch_wake(&g)==PW_LINES && g.rolled_back && !b.out[0] && !b.out[1]);
    g=init(&b);b.out[0]=2; /* Inherited power stays on even if reset wake fails. */
    b.reset_stuck=true;
    assert(polaris_touch_wake(&g)==PW_RESET && g.changed==2 && b.out[0]==2 && !b.out[1]);
    g=init(&b);b.cfg[0]|=0xa0000000;b.cfg[1]|=0xb0000000;b.rails=false;
    assert(polaris_touch_wake(&g)==PW_LINES && b.cfg[0]==0xa0000201 && b.cfg[1]==0xb0000201);
    assert(polaris_touch_wake(0)==PW_ARGUMENT);
    g=init(&b);g.write=0;
    assert(polaris_touch_wake(&g)==PW_ARGUMENT && !b.writes);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / 'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang', '-std=c11', '-O1', '-g', '-Wall', '-Wextra',
                            '-Werror', '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                            '-I', str(ROOT / 'tools'), str(p / 'test.c'), '-o', str(p / 'test')], check=True)
            subprocess.run([str(p / 'test')], check=True)


if __name__ == '__main__':
    unittest.main()
