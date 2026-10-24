"""Exercise the shipped F01 initialization, including refused/stuck hardware."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class TouchModeTests(unittest.TestCase):
    def test_shipped_header_is_tested_header(self):
        patch = (ROOT / 'xnu/profiles/polaris/0816-polaris-f01-mode-diagnostics.patch').read_text()
        text = patch.split('+++ b/bsd/dev/polaris_touch_mode.h\n', 1)[1]
        content = '\n'.join(line[1:] for line in text.splitlines() if line.startswith('+')) + '\n'
        self.assertEqual(content, (ROOT / 'tools/polaris-touch-mode.h').read_text())

    def test_mode_admission_and_bounded_write_readback(self):
        source = r'''
#include <assert.h>
#include <string.h>
#include "polaris-touch-mode.h"
struct mock {
    unsigned calls,fail_at,writes,reads,delays,ready_after,never,status_late;
    uint8_t initial,status,written;
};
static int rd(void *ctx,uint16_t reg,uint8_t *out,size_t n) {
    struct mock *m=ctx;assert(n==1 && (reg==0x0c || reg==0x10));
    if (++m->calls==m->fail_at) return 5;
    if (reg==0x10) {
        *out=m->reads && m->status_late ? m->status_late : m->status;
        if (m->writes && !m->never && m->reads>=m->ready_after) *out&=~0x80u;
    } else if (!m->writes) *out=m->initial;
    else { ++m->reads;*out=!m->never && m->reads>=m->ready_after ? m->written : m->initial; }
    return 0;
}
static int wr(void *ctx,uint16_t reg,uint8_t val) {
    struct mock *m=ctx;assert(reg==0x0c);++m->writes;m->written=val;
    if (++m->calls==m->fail_at) return 6;
    return 0;
}
static void sleep_ms(void *ctx,unsigned ms) {
    struct mock *m=ctx;assert(ms==20);m->delays+=ms;assert(m->delays<=100);
}
static struct polaris_touch_mode make(struct mock *m) {
    struct polaris_touch_mode p={.ctx=m,.read=rd,.write=wr,.sleep_ms=sleep_ms,
        .control_reg=0x0c,.status_reg=0x10};return p;
}
int main(void) {
    struct mock m={.status=0x80,.ready_after=1};struct polaris_touch_mode p=make(&m);
    assert(!polaris_touch_mode(&p) && p.step==PM_READY && p.writes==1);
    assert(p.valid==15 && p.control_before==0 && p.want==0x80 && p.control_after==0x80);
    assert(p.status_before==0x80 && p.status_after==0 && p.checks==1 && p.waited_ms==0);
    /* Acknowledged write, delayed hardware acceptance: no repeated write. */
    memset(&m,0,sizeof(m));m.status=0x80;m.initial=0x75;m.ready_after=6;p=make(&m);
    assert(!polaris_touch_mode(&p) && p.want==0xf4 && p.control_after==0xf4);
    assert(m.writes==1 && p.writes==1 && p.checks==6 && p.waited_ms==100 && m.delays==100);
    /* Hardware ignores the write, matching a possible0018 explanation. */
    memset(&m,0,sizeof(m));m.never=1;p=make(&m);
    assert(polaris_touch_mode(&p)==PM_VERIFY && p.step==PM_STATUS_AFTER);
    assert(p.control_after==0 && p.want==0x80 && m.writes==1 && m.delays==100 && p.checks==6);
    /* Already configured: observe only, preserve flags. */
    memset(&m,0,sizeof(m));m.initial=0x84;p=make(&m);
    assert(!polaris_touch_mode(&p) && !m.writes && p.want==0x84 && p.control_after==0x84);
    for(unsigned s=0;s<256;s++) {
        if(!(s&0x40u) && (s&15u)<=1u) continue;
        memset(&m,0,sizeof(m));m.status=s;p=make(&m);
        assert(polaris_touch_mode(&p)==PM_STATUS && p.step==PM_STATUS_BEFORE && !m.writes && !m.delays);
    }
    /* Transport failures at initial status/control, write, readback/status. */
    const unsigned steps[]={PM_STATUS_BEFORE,PM_CONTROL_BEFORE,PM_WRITE,PM_CONTROL_AFTER,PM_STATUS_AFTER};
    for(unsigned i=1;i<=5;i++) {
        memset(&m,0,sizeof(m));m.fail_at=i;m.ready_after=1;p=make(&m);
        assert(polaris_touch_mode(&p)==PM_IO && p.step==steps[i-1] && p.io==(i==3?6u:5u));
        assert(m.writes==(i>=3) && !m.delays);
    }
    /* Never pass flash/error/CRC status after an accepted control write. */
    memset(&m,0,sizeof(m));m.status_late=0x40;m.ready_after=1;m.never=1;p=make(&m);
    assert(polaris_touch_mode(&p)==PM_STATUS && p.step==PM_STATUS_AFTER && m.writes==1);
    p=make(&m);p.control_reg=0xff;assert(polaris_touch_mode(&p)==PM_ARGUMENT);
    p=make(&m);p.status_reg=p.control_reg;assert(polaris_touch_mode(&p)==PM_ARGUMENT);
    assert(polaris_touch_mode(0)==PM_ARGUMENT);
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
