"""Read-only original A630 admission: gated regions must never be read."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from tools.tests.test_polaris_a630_firmware import fixture

ROOT = Path(__file__).resolve().parents[2]


class A630ProbeTests(unittest.TestCase):
    def test_actual_kernel_image_parser_under_sanitizers(self):
        images = fixture()
        names = ['a630_gmu.bin', 'a630_sqe.fw', 'a630_zap.mdt',
                 'a630_zap.b00', 'a630_zap.b01', 'a630_zap.b02']
        declarations = []
        for i, name in enumerate(names):
            data = images[name]
            if i == 0:
                declarations.append('uint8_t f0[32768]={0x80,0x3f,4,0,9};')
            else:
                declarations.append('uint8_t f%d[]={%s};' % (i, ','.join(str(v) for v in data)))
        source = r'''
#include "polaris-a630-images.h"
#include <assert.h>
#include <string.h>
int main(void) {
DECLARATIONS
    struct a630_image images[6]={{f0,sizeof(f0)},{f1,sizeof(f1)},{f2,sizeof(f2)},
        {f3,sizeof(f3)},{f4,sizeof(f4)},{f5,sizeof(f5)}};
    assert(a630_images_valid(images));
    assert(a630_image_word(f1+4)==0x12345678);
    for(unsigned i=0;i<6;i++) {
        uint32_t saved=images[i].bytes;
        for(uint32_t n=0;n<saved;n++) {
            images[i].bytes=n;
            /* SQE has no embedded word count. Whole-word shortening is
             * detected by the consumer's SHA256, not by this format parser. */
            if(i==1 && n>=8 && n%4==0)assert(a630_images_valid(images));
            else assert(!a630_images_valid(images));
        }
        images[i].bytes=saved;
        const uint8_t *p=images[i].data;images[i].data=NULL;
        assert(!a630_images_valid(images));images[i].data=p;
    }
    const unsigned offsets[]={0,4,16,20,28,40,44,52,56,68,84,100,108,116,132,136,140};
    for(unsigned i=0;i<sizeof(offsets)/sizeof(offsets[0]);i++) {
        unsigned o=offsets[i];f2[o]^=0x80;
        assert(!a630_images_valid(images));f2[o]^=0x80;
    }
    f0[4]=0;assert(!a630_images_valid(images));f0[4]=9;
    f1[0]=1;assert(!a630_images_valid(images));f1[0]=0;
    f2[179]^=1;assert(!a630_images_valid(images));f2[179]^=1;
    assert(a630_images_valid(images));return 0;
}
'''.replace('DECLARATIONS', '\n'.join(declarations))
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / 'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang', '-std=c11', '-O1', '-g', '-fsanitize=address,undefined',
                            '-I', str(ROOT / 'tools'), str(p / 'test.c'), '-o', str(p / 'test')], check=True)
            subprocess.run([str(p / 'test')], check=True)

    def test_actual_read_gate_and_fault_boundaries(self):
        source = r'''
#include "polaris-a630-probe.h"
#include <assert.h>
struct mock {unsigned calls,gpucc,gmu,fail;uint32_t cfg,mem,snoc,cx,hw,clocks[3];};
static bool rd(void *ctx,unsigned region,uint32_t off,uint32_t *v) {
    struct mock *m=ctx;if(++m->calls==m->fail)return false;
    if(region==0) {
        switch(off){case 0x71004:*v=m->cfg;break;case 0x7100c:*v=m->mem;break;
        case 0x71018:*v=m->snoc;break;default:assert(0);}return true;
    }
    assert(!(m->cfg & (1u<<31)));
    if(region==1) {
        m->gpucc++;
        switch(off){case 0x106c:*v=m->cx;break;case 0x1540:*v=m->hw;break;
        case 0x100c:*v=0;break;case 0x1004:*v=m->clocks[0];break;
        case 0x1098:*v=m->clocks[1];break;case 0x109c:*v=m->clocks[2];break;
        case 0x1120:case 0x1124:*v=0;break;default:assert(0);}return true;
    }
    assert(region==2 && m->hw>>31);
    assert(!((m->mem|m->snoc|m->clocks[0]|m->clocks[1]|m->clocks[2])>>31));
    assert(off==0x14070 || off==0x14220 || off==0x14224);m->gmu++;*v=off;return true;
}
int main(void) {
    struct a630_probe s;struct mock m={0};
    assert(a630_probe(0,true,rd,&m,&s)==A630_DISABLED && !m.calls);
    assert(a630_probe(1,false,rd,&m,&s)==A630_DISABLED && !m.calls);
    assert(a630_probe(2,true,rd,&m,&s)==A630_DISABLED && !m.calls);
    m.cfg=1u<<31;assert(a630_probe(1,true,rd,&m,&s)==A630_AHB_OFF && !m.gpucc && !m.gmu);
    m=(struct mock){0};assert(a630_probe(1,true,rd,&m,&s)==A630_CX_OFF && !m.gmu);
    for(unsigned gate=0;gate<5;gate++) {
        m=(struct mock){.cx=1u<<31,.hw=1u<<31};
        if(gate==0)m.mem=1u<<31;else if(gate==1)m.snoc=1u<<31;else m.clocks[gate-2]=1u<<31;
        assert(a630_probe(1,true,rd,&m,&s)==A630_CLOCK_OFF && !m.gmu);
    }
    for(unsigned fail=1;fail<=14;fail++) {
        m=(struct mock){.cx=1u<<31,.hw=1u<<31,.fail=fail};
        assert(a630_probe(1,true,rd,&m,&s)==A630_IO && m.calls==fail);
    }
    m=(struct mock){.cx=1u<<31,.hw=1u<<31};
    assert(a630_probe(1,true,rd,&m,&s)==A630_PREREQUISITES);
    assert(s.reads==14 && m.gmu==3 && s.counter_low==0x14220 && s.counter_high==0x14224);
    /* POWER_ON lives in the DT-selected status register. The request
     * register is not required to mirror it, and cannot override it. */
    m=(struct mock){.cx=0,.hw=1u<<31};
    assert(a630_probe(1,true,rd,&m,&s)==A630_PREREQUISITES && m.gmu==3);
    m=(struct mock){.cx=1u<<31,.hw=0};
    assert(a630_probe(1,true,rd,&m,&s)==A630_CX_OFF && !m.gmu);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / 'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang', '-std=c11', '-O1', '-g', '-fsanitize=address,undefined',
                            '-I', str(ROOT / 'tools'), str(p / 'test.c'), '-o', str(p / 'test')], check=True)
            subprocess.run([str(p / 'test')], check=True)


if __name__ == '__main__':
    unittest.main()
