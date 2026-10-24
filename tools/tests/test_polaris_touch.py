"""Native sanitizers for the actual board input parser/transport/mapping."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class TouchTests(unittest.TestCase):
    def test_shipped_headers_match_tested_sources(self):
        patch = (ROOT / 'xnu/profiles/polaris/0811-polaris-synaptics-input.patch').read_text()
        for target, source in [
            ('bsd/dev/polaris_geni_i2c.h', 'polaris-geni-i2c.h'),
            ('bsd/dev/polaris_rmi.h', 'polaris-rmi.h'),
            ('iokit/Kernel/arm/polaris_touch_map.h', 'polaris-touch-map.h'),
        ]:
            lines = patch.split('+++ b/' + target + '\n', 1)[1].splitlines()
            content = []
            for line in lines:
                if line.startswith('--- '):
                    break
                if line.startswith('+'):
                    content.append(line[1:])
            self.assertEqual('\n'.join(content) + '\n', (ROOT / 'tools' / source).read_text())

    def run_c(self, source):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / 'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang', '-std=c11', '-O1', '-g',
                            '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                            '-I', str(ROOT / 'tools'), str(p / 'test.c'), '-o', str(p / 'test')], check=True)
            subprocess.run([str(p / 'test')], check=True)

    def test_inverse_fit_and_edge_gestures(self):
        self.run_c(r'''
#include <assert.h>
#include "polaris-touch-map.h"
#include "polaris-display-blit.h"
int main(void) {
    struct polaris_fb_view v; int32_t x,y,old=-1; bool edge;
    assert(polaris_fb_fit(1080,2160,1125,2436,&v));
    assert(v.x==41 && v.width==997 && v.height==2160);
    for(int i=0;i<1080;i++) {
        assert(polaris_touch_map(i,1000,&x,&y,&edge));
        assert(x>=old && x>=0 && x<65536); old=x;
    }
    assert(polaris_touch_map(41,0,&x,&y,&edge) && x==0 && y==0 && edge);
    assert(polaris_touch_map(1037,2159,&x,&y,&edge) && edge);
    assert(x==(int32_t)(1124LL*65536/1125) && y==(int32_t)(2435LL*65536/2436));
    assert(polaris_touch_map(540,2150,&x,&y,&edge) && edge); /* home swipe begins here */
    assert(polaris_touch_map(540,1000,&x,&y,&edge) && !edge);
    assert(!polaris_touch_map(0,2160,&x,&y,&edge));
    assert(!polaris_touch_map(-1,0,&x,&y,&edge));
    assert(!polaris_touch_map(1080,0,&x,&y,&edge));
    assert(!polaris_touch_map(0,0,0,&y,&edge));
    return 0;
}
''')

    def test_function_discovery_contacts_and_bad_reports(self):
        self.run_c(r'''
#include <assert.h>
#include <string.h>
#include "polaris-rmi.h"
struct mock { int fail, bad_size, bad_mask, bad_xy, status; unsigned reads,report_reads; uint16_t presence; };
static int read_reg(void *ctx,uint16_t a,uint8_t *b,size_t n) {
    struct mock *m=ctx;m->reads++;memset(b,0,n);
    if(m->fail)return 1;
    if(n==6 && (a&255)>=0xd1) {
        if(a==0xe9) { const uint8_t d[]={0x10,0x20,0x30,0x40,1,1};memcpy(b,d,6); }
        if(a==0x1e9) { const uint8_t d[]={0x50,0x60,0x70,0x90,1,0x12};memcpy(b,d,6); }
        return 0;
    }
    if(a==0x10 && n==1) { b[0]=1;return 0; }
    if(a==0x154 && n==1) { b[0]=m->bad_size?255:5;return 0; }
    /* Present controls8,23,28; offsets0,1,2. F12 logical register reads are
       variable-size blocks, not a flat memory bytearray. */
    if(a==0x155 && n==5) { b[2]=1;b[3]=0x80;b[4]=0x10;return 0; }
    if(a==0x170 && n==4) { b[0]=0x37;b[1]=4;b[2]=0x6f;b[3]=8;return 0; } /*1079,2159*/
    if(a==0x171 && n==2) { b[0]=1;b[1]=10;return 0; }
    if(a==0x172 && n==1) { b[0]=m->bad_mask?0x0f:0xff;return 0; }
    if(a==0x157 && n==1) { b[0]=3;return 0; }
    if(a==0x158 && n==3) { b[1]=3;b[2]=0x80;return 0; } /* Data0/1/15 */
    if(a==0x40 && (n==1 || n==2)) { b[0]=(uint8_t)m->status;return 0; }
    if(a==0x192 && n==2) { b[0]=m->presence;b[1]=m->presence>>8;return 0; }
    if(a==0x191 && n && n<=80 && n%8==0) {
        m->report_reads++;
        for(unsigned i=0;i<n/8;i++) {
            b[i*8]=i==1?6:1;b[i*8+1]=100+i;b[i*8+3]=200+i;
        }
        if(m->bad_xy) { b[1]=0xff;b[2]=0x7f; }
        return 0;
    }
    assert(!"unexpected register/length");return 1;
}
int main(void) {
    struct mock m={0};struct polaris_rmi_layout l={0};struct polaris_rmi_frame f;
    assert(polaris_rmi_discover(read_reg,&m,&l)==0);
    assert(l.f01_data==0x40 && l.report==0x191 && l.presence==0x192);
    assert(l.fingers==10 && l.stride==8 && l.max_x==1079 && l.max_y==2159);
    assert(m.reads<80);
    m.presence=3;assert(!polaris_rmi_sample(read_reg,&m,&l,&f));
    assert(f.mask==3 && f.x[0]==100 && f.y[1]==201);
    m.presence=0;unsigned before=m.report_reads;
    assert(!polaris_rmi_sample(read_reg,&m,&l,&f) && !f.mask && m.report_reads==before);
    m.presence=1;m.bad_xy=1;memset(&f,0xa5,sizeof(f));struct polaris_rmi_frame old=f;
    assert(polaris_rmi_sample(read_reg,&m,&l,&f)==POLARIS_RMI_FORMAT && !memcmp(&f,&old,sizeof(f)));
    m.bad_xy=0;m.status=0x40;assert(polaris_rmi_sample(read_reg,&m,&l,&f)==POLARIS_RMI_RESET);
    m.status=0;m.fail=1;assert(polaris_rmi_sample(read_reg,&m,&l,&f)==POLARIS_RMI_IO);
    m.fail=0;m.bad_size=1;struct polaris_rmi_layout keep=l;
    assert(polaris_rmi_discover(read_reg,&m,&l)==POLARIS_RMI_UNSUPPORTED && !memcmp(&l,&keep,sizeof(l)));
    m.bad_size=0;m.bad_mask=1;assert(polaris_rmi_discover(read_reg,&m,&l)==POLARIS_RMI_UNSUPPORTED);
    assert(!polaris_rmi_span(0xfe,2) && !polaris_rmi_span(0x100,81));
    for(unsigned n=0;n<256;n++) {
        l=keep;l.fingers=n;
        if(!n || n>10)assert(polaris_rmi_sample(read_reg,&m,&l,&f)==POLARIS_RMI_FORMAT);
    }
    return 0;
}
''')

    def test_fifo_bounds_partial_word_nack_timeout_and_foreign_busy(self):
        self.run_c(r'''
#include <assert.h>
#include <string.h>
#include "polaris-geni-i2c.h"
struct mock { unsigned mode,cmd,irq,count,reads,writes,aborts,delays,txword,rxwords;bool active; };
/*0 normal,1NACK+DONE,2timeout,3overflow,4inheritedbusy,5lateerror*/
static uint32_t rd(void *ctx,uint32_t r) {
    struct mock *m=ctx;m->reads++;
    if(r==PG_STATUS)return m->mode==4?1:m->mode==8?0x1000:0;
    if(r==PG_IRQ) {
        if(m->aborts)return m->mode==7?0:1u<<5;
        if(!m->active)return 0;
        if(m->mode==1)return PG_NACK|PG_DONE;
        if(m->mode==2 || m->mode==7)return 0;
        if((m->cmd>>27)==1 && !m->txword)return 1u<<30;
        if(m->mode==5 && m->rxwords)return PG_NACK|PG_DONE;
        return PG_DONE|(1u<<27);
    }
    if(r==PG_TX_COUNT)return 0;
    if(r==PG_RX_COUNT)return !m->active || m->mode==1?0:m->mode==3?65:m->count;
    if(r==PG_RX) { assert(m->count);m->count--;m->rxwords++;return 0x44332211; }
    return 0;
}
static void wr(void *ctx,uint32_t r,uint32_t v) {
    struct mock *m=ctx;m->writes++;
    if(r==PG_CMD) { m->active=true;m->cmd=v;if((v>>27)==1)m->txword=0;assert(((v>>9)&127)==0x20); }
    if(r==0x270)m->count=(v+3)/4;
    if(r==PG_TX)m->txword=v;
    if(r==PG_CTRL) { m->aborts++;m->count=0;m->active=false; }
    if(r==PG_CLEAR && v!=0xffffffffu && (v&PG_DONE))m->active=false;
}
static void pause_us(void *ctx,unsigned us) { struct mock *m=ctx;m->delays+=us; }
static struct polaris_geni make(struct mock *m) {
    struct polaris_geni g={.ctx=m,.read=rd,.write=wr,.delay_us=pause_us};return g;
}
int main(void) {
    struct mock m={0};struct polaris_geni g=make(&m);uint8_t out[7];memset(out,0xa5,sizeof(out));
    assert(pg_message(&g,0,0,out+1,5,false)==PG_OK);
    assert(out[0]==0xa5 && out[6]==0xa5 && out[1]==0x11 && out[4]==0x44 && out[5]==0x11);
    memset(&m,0,sizeof(m));g=make(&m);uint8_t tx[]={0xff,2};
    assert(pg_message(&g,tx,2,0,0,false)==PG_OK && m.txword==0x2ff);
    memset(&m,0,sizeof(m));m.mode=1;g=make(&m);
    assert(pg_message(&g,0,0,out,1,false)==PG_NO_DEVICE && !m.aborts);
    memset(&m,0,sizeof(m));m.mode=2;g=make(&m);
    assert(pg_message(&g,0,0,out,1,false)==PG_TIMEOUT && m.aborts==1 && m.delays<=30000);
    memset(&m,0,sizeof(m));m.mode=4;g=make(&m);
    assert(pg_message(&g,0,0,out,1,false)==PG_BUSY && m.writes==0 && !m.aborts && m.delays==5000);
    memset(&m,0,sizeof(m));g=make(&m);g.held=true;m.mode=4;
    assert(pg_message(&g,0,0,out,1,false)==PG_BUSY && m.aborts==1);
    memset(&m,0,sizeof(m));g=make(&m);memset(out,0xa5,sizeof(out));m.mode=5;
    assert(pg_message(&g,0,0,out+1,4,false)==PG_NO_DEVICE && out[0]==0xa5 && out[5]==0xa5);
    memset(&m,0,sizeof(m));g=make(&m);
    assert(pg_message(&g,0,0,out,81,false)==PG_BAD_ARGUMENT && !m.reads && !m.writes);
    assert(pg_message(&g,tx,3,0,0,false)==PG_BAD_ARGUMENT);
    memset(&m,0,sizeof(m));g=make(&m);m.mode=3;memset(out,0xa5,sizeof(out));
    assert(pg_message(&g,0,0,out+1,4,false)==PG_IO && m.aborts==1 && out[1]==0xa5);
    memset(&m,0,sizeof(m));g=make(&m);m.mode=7;
    assert(pg_message(&g,0,0,out,1,false)==PG_TIMEOUT && g.dead && m.delays<=30000);
    memset(&m,0,sizeof(m));g=make(&m);m.mode=8;
    assert(pg_message(&g,0,0,out,1,false)==PG_BUSY && !m.writes && !m.aborts);
    memset(&m,0,sizeof(m));g=make(&m);uint8_t pointer=0x10;
    assert(pg_message(&g,&pointer,1,0,0,true)==PG_OK && g.held);
    assert(pg_message(&g,0,0,out,1,false)==PG_OK && !g.held);

    return 0;
}
''')


if __name__ == '__main__':
    unittest.main()
