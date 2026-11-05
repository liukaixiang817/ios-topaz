#!/usr/bin/env python3
"""Exercise the actual patched framebuffer painter with guarded host RAM.

Argument: SweetFramebuffer.cpp after the complete Polaris patch sequence.
This checks drawing bounds and cached-status routing, not panel hardware.
"""
from pathlib import Path
import subprocess
import sys
import tempfile

from tests.test_polaris_gpu_lifetime import function

actual = function(Path(sys.argv[1]).read_text(), 'static void polaris_status_bar(')
source = r'''
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <vector>
struct AppleCLCD {
 uint8_t *fPixels;
 unsigned fWidth,fHeight,fRowBytes;
 unsigned fPolarisFPS10=0,fPolarisCopyMeanUS=0,fPolarisGapUS=0,fPolarisStatusPaintUS=0;
};
static uint8_t iso_font[256*16];
static unsigned wifi, wifi_calls, old_calls;
static uint32_t polaris_wifi_status_line(unsigned line,char *p,uint32_t n){
 wifi_calls++;assert(line<3);if(!wifi)return 0;
 return snprintf(p,n,"Wi-Fi row %u",line);
}
static uint32_t old(char*p,uint32_t n){old_calls++;return snprintf(p,n,"old status");}
static uint32_t polaris_usb_status(char*p,uint32_t n){return old(p,n);}
static uint32_t polaris_gpu_client_line(char*p,uint32_t n){return old(p,n);}
static uint32_t polaris_gpu_render_line(unsigned,char*p,uint32_t n){return old(p,n);}
static uint32_t polaris_gpu_fault_line(unsigned,char*p,uint32_t n){return old(p,n);}
static uint32_t polaris_gpu_crash_line(unsigned,char*p,uint32_t n){return old(p,n);}
''' + actual + r'''
int main(){
 memset(iso_font,255,sizeof(iso_font));unsigned cases=0;
 for(unsigned enabled: {0u,1u})for(unsigned w: {8u,16u,1080u})
 for(unsigned h: {31u,32u,64u,95u,96u,2160u}){
  unsigned stride=w*4+16;std::vector<uint8_t> pixels(stride*h+128,0xa5);
  AppleCLCD fb;fb.fPixels=pixels.data()+64;fb.fWidth=w;fb.fHeight=h;fb.fRowBytes=stride;
  wifi=enabled;wifi_calls=old_calls=0;polaris_status_bar(&fb);
  assert(wifi_calls==(enabled?3u:1u));assert(old_calls==(enabled?0u:10u));
  unsigned rows=enabled?3:11;if(rows>h/32)rows=h/32;rows*=32;
  for(unsigned i=0;i<64;i++)assert(pixels[i]==0xa5&&pixels[64+stride*h+i]==0xa5);
  for(unsigned y=0;y<h;y++)for(unsigned x=0;x<stride;x++){
   uint8_t b=fb.fPixels[y*stride+x];
   if(y>=rows||x>=w*4)assert(b==0xa5);else assert(b==0||b==255);
  }
  cases++;
 }
 printf("PASS: %u actual framebuffer routing/bounds cases\n",cases);
}
'''
with tempfile.TemporaryDirectory(prefix='polaris-wifi-display-') as directory:
    p = Path(directory)
    (p/'test.cpp').write_text(source)
    subprocess.run(['clang++', '-std=c++17', '-O1', '-g', '-Wall', '-Wextra',
                    '-Werror', '-fsanitize=address,undefined',
                    '-fno-sanitize-recover=all', str(p/'test.cpp'),
                    '-o', str(p/'test')], check=True)
    subprocess.run([str(p/'test')], check=True)
