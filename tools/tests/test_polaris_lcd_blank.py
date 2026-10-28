"""Actual store-only native LCD helper: whole-byte and rejected-range oracles."""
from pathlib import Path
import re,subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[2]

class LcdBlank(unittest.TestCase):
    def test_actual_native_helper_keeps_padding_and_rejects_bounds(self):
        patch=(ROOT/'xnu/profiles/polaris/0892-polaris-store-only-LCD-blanking.patch').read_text()
        additions='\n'.join(line[1:] for line in patch.splitlines() if line.startswith('+') and not line.startswith('+++'))
        helper=re.search(r'static bool polaris_fb_black_frame\(.*?\n\}',additions,re.S).group()
        source='#include <stdint.h>\n#include <stdbool.h>\n#include <assert.h>\n#include <stdlib.h>\n#include <string.h>\n'+helper+r'''
int main(void){uint32_t actual[1024],expected[1024],seed=13;
 for(unsigned n=0;n<5000;n++){
  seed=seed*1664525u+1013904223u;unsigned w=1+seed%19,h=1+(seed>>8)%12,stride=(w+(seed>>16)%7)*4;
  memset(actual,0x5a,sizeof(actual));memcpy(expected,actual,sizeof(actual));
  unsigned char *want=(unsigned char *)expected+8;
  for(unsigned y=0;y<h;y++)for(unsigned x=0;x<w*4;x++)want[y*stride+x]=0;
  assert(polaris_fb_black_frame((uintptr_t)((unsigned char*)actual+8),stride*h,w,h,stride));
  assert(!memcmp(actual,expected,sizeof(actual)));
  memset(actual,0x5a,sizeof(actual));memset(expected,0x5a,sizeof(expected));
  assert(!polaris_fb_black_frame((uintptr_t)((unsigned char*)actual+8),stride*h-1,w,h,stride));
  assert(!memcmp(actual,expected,sizeof(actual)));
 }
 const uint32_t bad[][3]={{0,1,4},{1,0,4},{1081,1,4324},{1,2161,4},{2,1,4},{1,1,5},{0xffffffff,0xffffffff,0xffffffff}};
 memset(actual,0x5a,sizeof(actual));memset(expected,0x5a,sizeof(expected));
 for(unsigned n=0;n<sizeof(bad)/sizeof(*bad);n++)assert(!polaris_fb_black_frame((uintptr_t)actual,sizeof(actual),bad[n][0],bad[n][1],bad[n][2]));
 assert(!polaris_fb_black_frame((uintptr_t)actual+1,sizeof(actual)-1,1,1,4));
 assert(!polaris_fb_black_frame(0,4,1,1,4));assert(!polaris_fb_black_frame(UINTPTR_MAX-3,8,1,1,4));
 assert(!memcmp(actual,expected,sizeof(actual)));
 unsigned bytes=1080*2160*4;unsigned char *p=(unsigned char*)malloc(bytes+16);assert(p);memset(p,0x5a,bytes+16);
 assert(polaris_fb_black_frame((uintptr_t)(p+8),bytes,1080,2160,4320));
 for(unsigned n=0;n<bytes+16;n++)assert(p[n]==((n<8||n>=bytes+8)?0x5a:0));free(p);return 0;}
'''
        with tempfile.TemporaryDirectory() as temp:
            d=Path(temp);(d/'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(d/'test.c'),'-o',str(d/'test')],check=True)
            subprocess.run([str(d/'test')],check=True)

if __name__=='__main__':unittest.main()
