"""Exercise the shipped GPIO transport against an independent I2C wire slave."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class GpioI2CTests(unittest.TestCase):
    def test_shipped_header_matches(self):
        patch = (ROOT / 'xnu/profiles/polaris/0813-polaris-gpio-i2c-fallback.patch').read_text()
        lines = patch.split('+++ b/bsd/dev/polaris_gpio_i2c.h\n', 1)[1].splitlines()
        actual = '\n'.join(line[1:] for line in lines if line.startswith('+')) + '\n'
        self.assertEqual(actual, (ROOT / 'tools/polaris-gpio-i2c.h').read_text())

    def test_wire_protocol_and_failures(self):
        source = r'''
#include <assert.h>
#include <string.h>
#include "polaris-gpio-i2c.h"
struct wire {
    bool low[2], target, active, sending, address, next_read;
    bool last_sda,last_scl,master_nack;
    unsigned bit,byte,starts,stops,rises,writes,us,nrx,nack_at,reads;
    unsigned stretch,stretch_left;
    int fault;
    uint8_t received[256], data[80];
};
static unsigned physical(struct wire *w) {
    bool sda=!w->low[0] && !w->target;
    bool scl=!w->low[1] && !w->stretch_left;
    if(w->fault==1)sda=false; /* foreign bus busy */
    if(w->fault==2 && w->starts && w->rises>=2)scl=false;
    if(w->fault==3 && w->starts && w->rises>=1)sda=false;
    return (unsigned)sda | ((unsigned)scl<<1);
}
static void update(struct wire *w) {
    unsigned lines=physical(w);bool sda=lines&1,scl=lines&2;
    /* A slave changes SDA only on a falling SCL edge. It decodes actual
       master wire transitions; it has no knowledge of transport functions. */
    if(w->last_scl && scl && w->last_sda!=sda) {
        if(!sda) {
            w->starts++;w->active=true;w->address=true;w->sending=false;
            w->bit=0;w->byte=0;w->target=false;
        } else {w->stops++;w->active=false;w->target=false;}
    }
    if(!w->last_scl && scl && w->active) {
        w->rises++;
        if(w->bit<8) {
            if(!w->sending)w->byte=(w->byte<<1)|sda;
        } else if(w->sending)w->master_nack=sda;
        w->bit++;
    }
    if(w->last_scl && !scl && w->active) {
        if(w->bit==9) {
            if(!w->sending) {
                assert(w->nrx<sizeof(w->received));w->received[w->nrx++]=(uint8_t)w->byte;
                if(w->address) {
                    assert((w->byte>>1)==0x20);w->next_read=w->byte&1;w->address=false;
                } else w->next_read=false;
                w->sending=w->next_read;w->reads=0;
            } else {
                w->reads++;
                if(w->master_nack)w->sending=false;
            }
            w->bit=0;w->byte=0;
        }
        if(w->sending) {
            assert(w->reads<80);
            w->target=w->bit<8 ? !(w->data[w->reads]&(0x80u>>w->bit)) : false;
        } else w->target=w->bit==8 && w->nrx!=w->nack_at;
    }
    lines=physical(w);w->last_sda=lines&1;w->last_scl=lines&2;
}
static void low(void *ctx,unsigned pin,bool sink) {
    struct wire *w=ctx;assert(pin<2);w->writes++;
    bool was=w->low[pin];w->low[pin]=sink;
    if(pin==1 && was && !sink)w->stretch_left=w->stretch;
    if(pin==1 && sink)w->stretch_left=0;
    update(w);
}
static unsigned levels(void *ctx) {
    struct wire *w=ctx;
    if(w->stretch_left)w->stretch_left--;
    update(w);return physical(w);
}
static void pause_us(void *ctx,unsigned us) {struct wire *w=ctx;w->us+=us;}
static struct polaris_gpio_i2c init(struct wire *w) {
    memset(w,0,sizeof(*w));w->last_sda=w->last_scl=true;w->nack_at=999;
    for(unsigned i=0;i<80;i++)w->data[i]=(uint8_t)(0xa5u^i);
    struct polaris_gpio_i2c g={.ctx=w,.low=low,.levels=levels,.delay_us=pause_us};return g;
}
int main(void) {
    struct wire w;struct polaris_gpio_i2c g=init(&w);uint8_t tx[]={0xff,2},rx[82];
    assert(pb_transport(0x300,0,0,0,0)==PB_FIFO);
    assert(pb_transport(0x300,0,1,0,0)==PB_GPIO);
    assert(pb_transport(0x300,0,0,1,0)==PB_GPIO);
    assert(pb_transport(0x300,0,0,0,1)==PB_GPIO);
    assert(pb_transport(0x300,0,0,0,0x80000000)==PB_FIFO); /* RX_LAST,empty */
    assert(pb_transport(0x300,1,1,1,1)==PB_DENY);
    assert(pb_transport(0x300,0x1000,1,1,1)==PB_DENY);
    assert(pb_transport(0x200,0,1,1,1)==PB_DENY);
    assert(pb_message(&g,tx,2,0,0,false)==PB_OK);
    assert(w.starts==1 && w.stops==1 && w.nrx==3 && w.received[0]==0x40);
    assert(w.received[1]==0xff && w.received[2]==2 && !g.held && !g.dead);
    assert(!w.low[0] && !w.low[1]);
    g=init(&w);tx[0]=0x55;
    assert(pb_message(&g,tx,1,0,0,true)==PB_OK && g.held && !w.stops);
    memset(rx,0x77,sizeof(rx));
    assert(pb_message(&g,0,0,rx+1,80,false)==PB_OK);
    assert(w.starts==2 && w.stops==1 && !g.held && !g.dead);
    assert(w.received[0]==0x40 && w.received[1]==0x55 && w.received[2]==0x41);
    assert(!memcmp(rx+1,w.data,80) && rx[0]==0x77 && rx[81]==0x77);
    assert(w.master_nack && w.us<24000+1000);
    g=init(&w);w.stretch=3;
    assert(pb_message(&g,0,0,rx,7,false)==PB_OK && !memcmp(rx,w.data,7));
    assert(w.stops==1 && w.us<24000);
    g=init(&w);w.nack_at=0;
    assert(pb_message(&g,tx,1,0,0,false)==PB_NO_DEVICE);
    assert(w.stops==1 && !g.dead && !g.held && !w.low[0] && !w.low[1]);
    g=init(&w);w.nack_at=1;
    assert(pb_message(&g,tx,1,0,0,false)==PB_NO_DEVICE && w.stops==1);
    g=init(&w);w.fault=1;w.last_sda=false;
    assert(pb_message(&g,tx,1,0,0,false)==PB_BUSY);
    assert(!w.rises && !w.starts && !w.stops && g.dead);
    g=init(&w);w.fault=2;
    assert(pb_message(&g,tx,1,0,0,false)==PB_TIMEOUT && w.us<=24000);
    assert(g.dead && !g.held && !w.low[0] && !w.low[1]);
    g=init(&w);w.fault=3;
    assert(pb_message(&g,tx,1,0,0,false)==PB_ARBITRATION);
    assert(g.dead && !g.held && !w.low[0] && !w.low[1] && !w.stops);
    g=init(&w);
    assert(pb_message(&g,tx,3,0,0,false)==PB_BAD_ARGUMENT && !w.writes);
    assert(pb_message(&g,0,0,rx,81,false)==PB_BAD_ARGUMENT && !w.writes);
    assert(pb_message(&g,0,0,rx,1,true)==PB_BAD_ARGUMENT && !w.writes);
    assert(pb_message(&g,tx,1,rx,1,false)==PB_BAD_ARGUMENT && !w.writes);
    assert(pb_message(0,tx,1,0,0,false)==PB_BAD_ARGUMENT);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / 'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang', '-std=c11', '-O1', '-g',
                            '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                            '-fno-omit-frame-pointer', '-I', str(ROOT / 'tools'),
                            str(p / 'test.c'), '-o', str(p / 'test')], check=True)
            subprocess.run([str(p / 'test')], check=True)


if __name__ == '__main__':
    unittest.main()
