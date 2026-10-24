"""New row copier must preserve the previous pixels, clipping and bounds."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class StagedDisplayTests(unittest.TestCase):
    def test_pixels_padding_clipping_alias_and_invalid_bounds(self):
        source = r'''
#include "polaris-display-blit.h"
#include "polaris-display-staged.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
static unsigned state=427;
static unsigned rnd(void){state=state*1664525u+1013904223u;return state;}
int main(void){
    uint32_t c[1080],r[1080];
    size_t sn=1125u*4*2436+32,dn=1080u*4*2160+32;
    uint8_t *s=malloc(sn),*a=malloc(dn),*b=malloc(dn);
    assert(s&&a&&b);for(size_t i=0;i<sn;i++)s[i]=(uint8_t)rnd();
    struct polaris_fb_rect src={0,0,1125,2436},dst=src;
    memset(a,0xa7,dn);memset(b,0xa7,dn);
    uint64_t n=polaris_fb_blit(a,dn,1080,2160,4320,1125,2436,
        s,sn,1125,2436,4500,16,src,dst,c,1080);
    assert(n==997u*2160);
    assert(n==polaris_fb_blit_staged(b,dn,1080,2160,4320,1125,2436,
        s,sn,1125,2436,4500,16,src,dst,c,1080,r,1080));
    assert(!memcmp(a,b,dn));
    for(unsigned i=0;i<1500;i++){
        unsigned pw=2+rnd()%126,ph=2+rnd()%126,lw=2+rnd()%126,lh=2+rnd()%126;
        unsigned sw=1+rnd()%127,sh=1+rnd()%127,ss=sw*4+16,ds=pw*4+16;
        struct polaris_fb_rect x={(int)(rnd()%sw),(int)(rnd()%sh),1,1};
        x.width=1+rnd()%(sw-x.x);x.height=1+rnd()%(sh-x.y);
        struct polaris_fb_rect y={(int)(rnd()%250)-125,(int)(rnd()%250)-125,
            1+(int)(rnd()%250),1+(int)(rnd()%250)};
        memset(a,0x6c,ds*ph+16);memset(b,0x6c,ds*ph+16);
        n=polaris_fb_blit(a,ds*ph+16,pw,ph,ds,lw,lh,s,sn,sw,sh,ss,3,x,y,c,1080);
        assert(n==polaris_fb_blit_staged(b,ds*ph+16,pw,ph,ds,lw,lh,
            s,sn,sw,sh,ss,3,x,y,c,1080,r,1080));
        assert(!memcmp(a,b,ds*ph+16));
    }
    memset(a,0x33,dn);memcpy(b,a,dn);
#define NEW(N,OFF,X,Y,C,R) polaris_fb_blit_staged(b,dn,1080,2160,4320,1125,2436,s,N,1125,2436,4500,OFF,X,Y,c,C,r,R)
    struct polaris_fb_rect bad[]={ {-1,0,1,1},{0,0,INT_MAX,1},{0,0,1,0} };
    for(unsigned i=0;i<3;i++)assert(!NEW(sn,16,bad[i],dst,1080,1080));
    assert(!NEW(sn,16,src,dst,1080,996));assert(!NEW(sn,16,src,dst,996,1080));
    assert(!NEW(sn,SIZE_MAX,src,dst,1080,1080));
    assert(!NEW(sn-64,16,src,dst,1080,1080));assert(!memcmp(a,b,dn));
    /* Alias fallback retains the original write/read order. */
    for(unsigned i=0;i<65536;i++)a[i]=b[i]=(uint8_t)rnd();
    src=(struct polaris_fb_rect){0,0,128,128};dst=(struct polaris_fb_rect){-1,-2,127,126};
    n=polaris_fb_blit(a,65536,128,128,512,128,128,a,65536,128,128,512,0,src,dst,c,1080);
    assert(n==polaris_fb_blit_staged(b,65536,128,128,512,128,128,b,65536,
        128,128,512,0,src,dst,c,1080,r,1080));assert(!memcmp(a,b,65536));
    free(s);free(a);free(b);return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            (p / 'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang', '-std=c11', '-O1', '-g',
                            '-fsanitize=address,undefined', '-I', str(ROOT / 'tools'),
                            str(p / 'test.c'), '-o', str(p / 'test')], check=True)
            subprocess.run([str(p / 'test')], check=True)


if __name__ == '__main__':
    unittest.main()
