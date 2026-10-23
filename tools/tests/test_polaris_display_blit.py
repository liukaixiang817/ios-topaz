"""Bounds and geometry of the actual CPU display copier shipped in 0807."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class DisplayTests(unittest.TestCase):
    def test_shipped_header(self):
        patch = (ROOT / 'xnu/profiles/polaris/0807-polaris-fitted-cpu-display.patch').read_text()
        part = patch.split('+++ b/iokit/Kernel/arm/polaris_display_blit.h\n')[1].split('--- a/')[0]
        shipped = '\n'.join(line[1:] for line in part.splitlines() if line.startswith('+')) + '\n'
        self.assertEqual(shipped, (ROOT / 'tools/polaris-display-blit.h').read_text())

    def test_real_blitter_under_sanitizers(self):
        source = r'''
#include "polaris-display-blit.h"
#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
static uint32_t pixel(const uint8_t *p) { uint32_t n; memcpy(&n,p,4);return n; }
int main(void) {
    struct polaris_fb_view v;
    assert(polaris_fb_fit(1080,2160,1125,2436,&v));
    assert(v.x==41 && v.y==0 && v.width==997 && v.height==2160);
    assert(!polaris_fb_fit(0,2160,1125,2436,&v));
    assert(!polaris_fb_fit(4097,2160,1125,2436,&v));
    assert(!polaris_fb_fit(1080,2160,1125,2436,NULL));
    const uint32_t ss=1125*4+16,ds=1080*4+32;
    const size_t sn=(size_t)ss*2436+8,dn=(size_t)ds*2160;
    uint8_t *src=malloc(sn),*dst=malloc(dn),*before=malloc(dn);
    uint32_t *columns=malloc(1080*4);
    assert(src && dst && before && columns);
    memset(src,0xa7,sn);memset(dst,0xc5,dn);
    for (unsigned y=0;y<2436;y++) for(unsigned x=0;x<1125;x++) {
        uint32_t n=(y<<16)|x;memcpy(src+8+(size_t)y*ss+x*4,&n,4);
    }
    struct polaris_fb_rect a={0,0,1125,2436},b=a;
    assert(polaris_fb_blit(dst,dn,1080,2160,ds,1125,2436,
        src,sn,1125,2436,ss,8,a,b,columns,1080)==(uint64_t)997*2160);
    assert(pixel(dst+41*4)==0);
    assert(pixel(dst+(41+996)*4)==1124);
    assert(pixel(dst+(size_t)2159*ds+41*4)==(2435u<<16));
    assert(pixel(dst+(size_t)2159*ds+(41+996)*4)==((2435u<<16)|1124));
    assert(polaris_fb_black_bars(dst,dn,1080,2160,ds,1125,2436));
    for (unsigned y=0;y<2160;y++) {
        assert(pixel(dst+(size_t)y*ds)==0);
        assert(pixel(dst+(size_t)y*ds+1079*4)==0);
        for (unsigned x=4320;x<ds;x++) assert(dst[(size_t)y*ds+x]==0xc5);
    }
    memcpy(before,dst,dn);
#define BLIT(SN,OFF,A,B,COLS) polaris_fb_blit(dst,dn,1080,2160,ds,1125,2436,src,SN,1125,2436,ss,OFF,A,B,columns,COLS)
    struct polaris_fb_rect bad[]={ {-1,0,1,1},{0,-1,1,1},{0,0,INT_MAX,1},{1124,0,2,1},{0,0,1,0} };
    for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++) assert(!BLIT(sn,8,bad[i],b,1080));
    struct polaris_fb_rect invalid={INT_MIN,0,10,10};
    assert(!BLIT(sn,8,a,invalid,1080));
    assert(!BLIT(sn,8,a,b,996));assert(!BLIT(sn, SIZE_MAX,a,b,1080));
    assert(!BLIT(sn-32,8,a,b,1080));
    assert(!memcmp(dst,before,dn));
    /* A single source pixel scales without dividing by zero. */
    struct polaris_fb_rect one={17,19,1,1};
    assert(BLIT(sn,8,one,b,1080)==(uint64_t)997*2160);
    assert(pixel(dst+41*4)==((19u<<16)|17));
    assert(pixel(dst+(size_t)2159*ds+1037*4)==((19u<<16)|17));
    /* Clipped destination and offset source stay within both buffers. */
    struct polaris_fb_rect clip={-100,-100,300,300};
    assert(BLIT(sn,8,one,clip,1080)>0);
    for(unsigned i=0;i<400;i++) {
        struct polaris_fb_rect fuzz={(int)(i%29)-14,(int)(i%31)-15,(int)(i%99)+1,(int)(i%97)+1};
        (void)polaris_fb_blit(dst,128*96*4,128,96,512,128,96,
            src,sn,1125,2436,ss,8,one,fuzz,columns,1080);
    }
    free(src);free(dst);free(before);free(columns);return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            p = Path(d); (p / 'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang', '-std=c11', '-O1', '-g',
                            '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                            '-I', str(ROOT / 'tools'), str(p / 'test.c'), '-o', str(p / 'test')], check=True)
            subprocess.run([str(p / 'test')], check=True)


if __name__ == '__main__':
    unittest.main()
