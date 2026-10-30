"""Actual USB command parser: no reset after missing/failed witness delivery."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]


class WledUsb(unittest.TestCase):
    def test_optional_binary_receipt_order_failure_and_readonly_separation(self):
        source=r'''
#include "uefi-xnu.h"
#include <assert.h>
#include <string.h>
static uint8_t response[64],proof[56],journal[1349];static uint64_t length,proof_size=56,journal_size=68;
static unsigned permit=1,txok=1,proof_ok=1,journal_ok=1,resets,proof_calls,gate_calls;
static int tx(void*x,const uint8_t*p,uint64_t n){(void)x;assert(n<=64);memcpy(response,p,n);length=n;return txok;}
static int stage(void*x,unsigned s,const uint8_t**p,uint64_t*n){(void)x;(void)s;(void)p;(void)n;return 0;}
static int gate(void*x,unsigned mode){(void)x;assert(mode==1||mode==2);gate_calls++;return permit;}
static int receipt(void*x,unsigned mode,const uint8_t**p,uint64_t*n){
 (void)x;assert(gate_calls);proof_calls++;proof[26]=(uint8_t)mode;*p=proof;*n=proof_size;return proof_ok;}
static int capture(void*x,const uint8_t**p,uint64_t*n){(void)x;*p=journal;*n=journal_size;return journal_ok;}
static void reset(void*x,unsigned mode){(void)x;assert(permit&&txok&&mode==2&&!memcmp(response,"OKAY",4));resets++;}
static int command(struct polaris_usb_diag*d,struct polaris_usb_control*c,const char*s)
 {return polaris_usb_control_command(d,c,(const void*)s,strlen(s));}
int main(void){
 struct polaris_usb_diag d={0,tx,stage,0,0};
 struct polaris_usb_control c={.prepare_reset=gate,.reset=reset,.reset_receipt=receipt};
 memcpy(proof,"WLR2",4);
 permit=0;assert(command(&d,&c,"reboot-bootloader")&&!resets&&!proof_calls&&!memcmp(response,"FAIL",4));
 permit=1;proof_ok=0;assert(command(&d,&c,"reboot-bootloader")&&!resets&&!memcmp(response,"FAIL",4));
 proof_ok=1;proof_size=61;assert(command(&d,&c,"reboot-bootloader")&&!resets&&!memcmp(response,"FAIL",4));
 proof_size=0;assert(command(&d,&c,"reboot-bootloader")&&!resets&&!memcmp(response,"FAIL",4));
 proof_size=56;txok=0;assert(!command(&d,&c,"reboot-bootloader")&&!resets);
 txok=1;assert(command(&d,&c,"reboot-bootloader")&&resets==1&&length==60&&!memcmp(response+4,proof,56));
 c.reset_receipt=0;assert(command(&d,&c,"reboot-bootloader")&&resets==2&&length==4);
 d.staged=proof;d.staged_bytes=56;
 assert(command(&d,&c,"oem wled-journal")&&!d.staged&&!d.staged_bytes&&!memcmp(response,"FAIL",4));
 c.wled_journal=capture;assert(command(&d,&c,"oem wled-journal")&&d.staged==journal&&d.staged_bytes==68);
 journal_size=1349;assert(command(&d,&c,"oem wled-journal")&&!d.staged&&!d.staged_bytes&&!memcmp(response,"FAIL",4));
 journal_size=67;assert(command(&d,&c,"oem wled-journal")&&!d.staged&&!d.staged_bytes&&!memcmp(response,"FAIL",4));
 assert(polaris_usb_command(&d,(const void*)"oem wled-journal",16)&&!memcmp(response,"FAIL",4));
 assert(resets==2);return 0;}
'''
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory);(p/'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang','-std=c11','-O1','-Wall','-Wextra','-Werror',
                            '-fsanitize=address,undefined','-I'+str(ROOT/'shim/polaris'),str(p/'test.c'),
                            str(ROOT/'shim/polaris/uefi-usb-command.c'),str(ROOT/'shim/polaris/uefi-usb-control.c'),
                            '-o',str(p/'test')],check=True)
            subprocess.run([str(p/'test')],check=True)


if __name__=='__main__':unittest.main()
