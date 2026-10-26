"""RAM control commands must acknowledge only validated actions, never writes."""
import subprocess
import tempfile
from pathlib import Path
import unittest


class ControlCommands(unittest.TestCase):
    def test_real_parser_download_limits_reset_order_and_readonly_separation(self):
        root=Path(__file__).resolve().parents[2]
        source=r'''
#include "uefi-xnu.h"
#include <assert.h>
#include <string.h>
static char response[65];static int txok=1,permitted=1,reset_count,boot_count,staged;
static unsigned reset_mode;static unsigned char destination[32];static uint64_t copied;
static int tx(void *c,const uint8_t *p,uint64_t n){(void)c;assert(n<=64);memcpy(response,p,n);response[n]=0;return txok;}
static int stage(void *c,unsigned what,const uint8_t **p,uint64_t *n){(void)c;(void)what;(void)p;(void)n;staged++;return 0;}
static int begin(void *c,uint64_t n){(void)c;copied=0;return n==12&&permitted;}
static int receive(void *c,uint8_t *p,uint64_t n,uint64_t *got){(void)c;assert(n<=12);memset(p,'x',n);*got=n;return 1;}
static int write(void *c,uint64_t at,const uint8_t *p,uint64_t n){(void)c;assert(at==copied&&at+n<=sizeof(destination));memcpy(destination+at,p,n);copied+=n;return 1;}
static int finish(void *c){(void)c;return copied==12;}
static int prepare_boot(void *c){(void)c;return permitted;}
static void boot(void *c){(void)c;assert(!strcmp(response,"OKAY"));boot_count++;}
static int prepare_reset(void *c,unsigned mode){(void)c;assert(mode==1||mode==2);return permitted;}
static void reset(void *c,unsigned mode){(void)c;assert(!strcmp(response,"OKAY"));reset_count++;reset_mode=mode;}
static const char *state(void *c){(void)c;return "waiting-payload";}
static unsigned touches;
static int boot_data(void *c,const uint8_t **p,uint64_t *n){(void)c;static const uint8_t data[40]={0};*p=data;*n=40;return 1;}
static int touch(void *c,unsigned down,unsigned x,unsigned y){(void)c;assert(down<=1&&x<1080&&y<2160);touches++;return permitted;}
static int input(void *c,struct polaris_uefi_input_status *s){(void)c;*s=(struct polaris_uefi_input_status){1,2,2,0};return 1;}
int main(void){
 struct polaris_usb_diag d={0,tx,stage,0,0};
 struct polaris_usb_control c={.receive=receive,.begin=begin,.write=write,.finish=finish,.prepare_boot=prepare_boot,.boot=boot,.prepare_reset=prepare_reset,.reset=reset,.state=state,.touch=touch,.input_status=input};
 const char *bad[]={"flash:boot","erase:userdata","oem run","reboot recovery","reboot-bootloader extra","download:ffffffff","download:00000000","download:0000000g","oem touch:2:0:0","oem touch:1:1080:0","oem touch:1:0:2160","oem touch:1:-1:0","oem touch:1:0:0:1","oem touch:1:00000:0"};
 for(unsigned i=0;i<sizeof(bad)/sizeof(bad[0]);i++){
  assert(polaris_usb_control_command(&d,&c,(const void*)bad[i],strlen(bad[i])));assert(!strncmp(response,"FAIL",4));
 }assert(!reset_count&&!boot_count&&!copied&&!staged&&!touches);
 assert(polaris_usb_command(&d,(const void*)"oem boot-options",16));assert(!strncmp(response,"FAIL",4)&&!d.staged);
 c.boot_options=boot_data;assert(polaris_usb_control_command(&d,&c,(const void*)"oem boot-options",16));
 assert(!strcmp(response,"OKAY")&&d.staged&&d.staged_bytes==40);
 c.boot_options=0;assert(polaris_usb_control_command(&d,&c,(const void*)"oem boot-options",16));assert(!strncmp(response,"FAIL",4)&&!d.staged);
 assert(polaris_usb_control_command(&d,&c,(const void*)"getvar:input",12));assert(!strcmp(response,"OKAY1/00000002/00000002/00000000"));
 assert(polaris_usb_control_command(&d,&c,(const void*)"oem touch:1:1079:2159",21));assert(!strcmp(response,"OKAY")&&touches==1);
 assert(polaris_usb_control_command(&d,&c,(const void*)"download:0000000c",17));assert(!strcmp(response,"OKAY")&&copied==12);
 for(unsigned i=0;i<12;i++)assert(destination[i]=='x');
 assert(polaris_usb_command(&d,(const void*)"reboot",6));assert(!strncmp(response,"FAIL",4));assert(!reset_count);
 assert(polaris_usb_control_command(&d,&c,(const void*)"reboot",6));assert(reset_count==1&&reset_mode==1);
 assert(polaris_usb_control_command(&d,&c,(const void*)"reboot-bootloader",17));assert(reset_count==2&&reset_mode==2);
 permitted=0;assert(polaris_usb_control_command(&d,&c,(const void*)"reboot",6));assert(reset_count==2&&!strncmp(response,"FAIL",4));
 permitted=1;txok=0;assert(!polaris_usb_control_command(&d,&c,(const void*)"reboot",6));assert(reset_count==2);
 assert(!polaris_usb_control_command(&d,&c,(const void*)"oem boot",8));assert(!boot_count);
 txok=1;assert(polaris_usb_control_command(&d,&c,(const void*)"oem boot",8));assert(boot_count==1);
 assert(polaris_efi_crc32((const void*)"123456789",9)==0xcbf43926u);
 assert(polaris_efi_crc32((const void*)"",0)==0);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            c=Path(d)/'control.c';exe=Path(d)/'control';c.write_text(source)
            subprocess.run(['/usr/bin/clang','-std=c11','-O1','-Wall','-Wextra','-Werror',
                            '-fsanitize=address,undefined','-I'+str(root/'shim/polaris'),str(c),
                            str(root/'shim/polaris/uefi-usb-command.c'),str(root/'shim/polaris/uefi-usb-control.c'),
                            str(root/'shim/polaris/uefi-xnu-crc.c'),'-o',str(exe)],check=True)
            subprocess.run([str(exe)],check=True)


if __name__=='__main__':unittest.main()
