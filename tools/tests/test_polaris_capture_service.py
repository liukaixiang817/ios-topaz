"""Actual PPM loop byte oracle and cooperative heartbeat, not physical timing."""
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[2]


class CaptureServiceTests(unittest.TestCase):
    def test_same_pixels_bounded_service_and_still_strict_expiry(self):
        source=r'''
#include "uefi-usb.h"
#include "polaris-uefi-buttons.h"
#include <assert.h>
#include <string.h>
#include <stdlib.h>
struct ctx {struct polaris_button_consumer keys;unsigned calls;uint64_t now;};
static void service(void *p){struct ctx*c=p;struct polaris_button_delivery d;
 c->calls++;c->now+=200000;
 assert(polaris_button_wire_apply(&c->keys,c->keys.sequence+1,1,c->now,0,true,c->now,&d));
 assert(!d.changed&&d.pressed==1);
 assert(polaris_button_wire_expire(&c->keys,c->now+199999,&d));}
int main(void){
 uint32_t pixels[19*145];for(unsigned n=0;n<19*145;n++)pixels[n]=n*37337u;
 struct polaris_gop_info i={0,17,145,0,{0},19};
 struct polaris_gop_mode m={1,0,&i,sizeof(i),(uintptr_t)pixels,sizeof(pixels)};
 uint8_t a[17*145*3+64],b[sizeof(a)];uint64_t an=0,bn=0;
 struct ctx c={0};c.now=1;struct polaris_button_delivery d;
 assert(polaris_button_wire_apply(&c.keys,1,0,1,0,true,1,&d));
 assert(polaris_button_wire_apply(&c.keys,2,1,2,0,true,2,&d));
 c.now=2;memset(a,0x5a,sizeof(a));memset(b,0x5a,sizeof(b));
 assert(polaris_usb_ppm(&m,a,sizeof(a),&an));
 assert(polaris_usb_ppm_service(&m,b,sizeof(b),&bn,service,&c));
 assert(an==bn&&!memcmp(a,b,sizeof(a)));assert(c.calls==(145+7)/8+1);
 assert(c.now>750000&&!c.keys.error&&c.keys.pressed==1);
 unsigned count=c.calls;
 assert(!polaris_usb_ppm_service(&m,b,16,&bn,service,&c)&&c.calls==count);
 i.format=2;assert(!polaris_usb_ppm_service(&m,b,sizeof(b),&bn,service,&c)&&c.calls==count);
 i.format=1;assert(polaris_usb_ppm(&m,a,sizeof(a),&an));
 assert(polaris_usb_ppm_service(&m,b,sizeof(b),&bn,0,0)&&an==bn&&!memcmp(a,b,bn));
 /* Lost firmware service still expires: no timeout/clock/guard was relaxed. */
 assert(!polaris_button_wire_expire(&c.keys,c.now+750000,&d));
 assert(d.changed==1&&!d.pressed&&c.keys.error==3);return 0;}
'''
        with tempfile.TemporaryDirectory() as directory:
            d=Path(directory);(d/'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror',
                '-fsanitize=address,undefined','-I'+str(ROOT/'shim/polaris'),'-I'+str(ROOT/'tools'),
                str(d/'test.c'),str(ROOT/'shim/polaris/uefi-usb-command.c'),'-o',str(d/'test')],check=True)
            subprocess.run([str(d/'test')],check=True)


if __name__=='__main__':unittest.main()
