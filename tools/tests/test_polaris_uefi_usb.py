"""Compile the real read-only protocol/parser/capture with ASan and UBSan.

The fake host exercises USB API flow, not a physical Qualcomm controller.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[2]


class USBTests(unittest.TestCase):
    def test_real_parser_capture_and_firmware_protocol_flow(self):
        source=r'''
#include "uefi-usb.h"
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <setjmp.h>
static unsigned char output[200000];static size_t used;static int transmit_fails;
static int tx(void*c,const uint8_t*p,uint64_t n){(void)c;if(transmit_fails)return 0;assert(n<=65536&&used+n<sizeof(output));memcpy(output+used,p,n);used+=n;return 1;}
static unsigned char content[70000];static int bad_stage;
static int capture(void*c,unsigned what,const uint8_t**p,uint64_t*n){(void)c;assert(what>=1&&what<=3);*p=content;*n=bad_stage?0x1000001:sizeof(content);return 1;}
static void command(struct polaris_usb_diag*d,const char*s){used=0;assert(polaris_usb_command(d,(const uint8_t*)s,strlen(s)));}
static void parser(void){
 struct polaris_usb_diag d={0,tx,capture,0,0};
 const char *blocked[]={"flash:boot","erase:userdata","download:00000020","reboot","oem run","uploadx","getvar:productx"};
 for(unsigned i=0;i<sizeof(blocked)/sizeof(blocked[0]);i++){command(&d,blocked[i]);assert(!memcmp(output,"FAIL",4));}
 command(&d,"getvar:product");assert(used==21&&!memcmp(output,"OKAYpolaris-uefi-diag",21));
 command(&d,"upload");assert(!memcmp(output,"FAIL",4));
 used=0;assert(polaris_usb_command(&d,0,0));assert(!memcmp(output,"FAIL",4));
 unsigned char invalid[65];memset(invalid,'x',sizeof(invalid));used=0;assert(polaris_usb_command(&d,invalid,65));assert(!memcmp(output,"FAIL",4));
 invalid[1]=0;used=0;assert(polaris_usb_command(&d,invalid,3));assert(!memcmp(output,"FAIL",4));
 bad_stage=1;command(&d,"oem logs");assert(!memcmp(output,"FAIL",4));bad_stage=0;
 for(unsigned i=0;i<sizeof(content);i++)content[i]=(unsigned char)i;
 command(&d,"oem logs");assert(used==4&&!memcmp(output,"OKAY",4));
 command(&d,"upload");assert(used==12+sizeof(content)+4&&!memcmp(output,"DATA00011170",12));
 assert(!memcmp(output+12,content,sizeof(content))&&!memcmp(output+12+sizeof(content),"OKAY",4));
 transmit_fails=1;assert(!polaris_usb_command(&d,(const uint8_t*)"upload",6));transmit_fails=0;
}
static void ppm(void){
 uint32_t pixels[6]={0x00332211,0x00665544,0xdeadbeef,0x00998877,0x00ccbbaa,0xdeadbeef};
 struct polaris_gop_info i={0,2,2,0,{0},3};struct polaris_gop_mode m={1,0,&i,sizeof(i),(uintptr_t)pixels,sizeof(pixels)};
 uint8_t out[64];uint64_t n=0;assert(polaris_usb_ppm(&m,out,sizeof(out),&n));
 assert(n==23&&!memcmp(out,"P6\n2 2\n255\n",11));
 const uint8_t want[]={0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc};assert(!memcmp(out+11,want,12));
 i.format=1;assert(polaris_usb_ppm(&m,out,sizeof(out),&n));assert(out[11]==0x33&&out[12]==0x22&&out[13]==0x11);
 i.format=2;assert(!polaris_usb_ppm(&m,out,sizeof(out),&n));i.format=0;
 m.bytes=12;assert(!polaris_usb_ppm(&m,out,sizeof(out),&n));m.bytes=sizeof(pixels);
 assert(!polaris_usb_ppm(&m,out,1,&n));i.width=4097;assert(!polaris_usb_ppm(&m,out,sizeof(out),&n));
 i.width=2;i.stride=1;assert(!polaris_usb_ppm(&m,out,sizeof(out),&n));i.stride=3;
 m.base=UINT64_MAX-3;m.bytes=24;assert(!polaris_usb_ppm(&m,out,sizeof(out),&n));
}
static int cancelled;static jmp_buf finish;static int restored,initialized,started,allocations,connected,script,rx_pending,tx_pending,idle;
static void *pool_buffers[2];static unsigned pool_count;
static void *buffers[2];static uint64_t sent_bytes;static void *sent_buffer;static unsigned char transfers[1024];static size_t transfers_bytes;
static efi_status event_create(uint32_t flags,uint64_t tpl,void(*fn)(void*,void*),void*c,const efi_guid*g,void**out){(void)fn;(void)c;assert(flags==0x200&&tpl==8&&g->a==0x1c0cffce);*out=(void*)1;return 0;}
static efi_status signal_evt(void*e){assert(e==(void*)1);initialized=1;return 0;}
static efi_status close_event(void*e){assert(e==(void*)1);return 0;}
static void restore(uint64_t tpl){assert(tpl==4);restored=1;}
static efi_status pause_us(uint64_t us){assert(us<=1000);return 0;}
static efi_status start(struct polaris_usb_descriptors*d){assert(initialized&&restored);assert(d->string_count==4&&((const uint8_t*)d->device)[0]==18);assert(((const uint8_t*)*d->configs)[2]==32);assert(((const uint8_t*)*d->ss_configs)[2]==44);assert(((const uint8_t*)d->bos)[2]==22);for(unsigned j=0;j<4;j++)assert(((const uint8_t*)d->strings[j])[1]==3);started=1;return 0;}
static efi_status alloc(uint64_t n,void**out){assert(started&&n==65536&&allocations<2);*out=buffers[allocations++]=malloc(n);assert(*out);return 0;}
static efi_status release(void*p){free(p);return 0;}static efi_status stop(void){return 0;}static efi_status abort_ep(uint8_t ep){assert(ep==1||ep==0x81);return 0;}
static efi_status send(uint8_t ep,uint64_t n,void*p){assert(n<=65536);if(ep==1){assert(p==buffers[0]&&n==512);rx_pending=1;}else{assert(ep==0x81&&p==buffers[1]&&transfers_bytes+n<sizeof(transfers));memcpy(transfers+transfers_bytes,p,n);transfers_bytes+=n;tx_pending=1;sent_bytes=n;sent_buffer=p;}return 0;}
static efi_status events(uint32_t*kind,uint64_t*size,union polaris_usb_event*d){
 assert(*size==sizeof(*d));*kind=0;
 if(!connected){*kind=1;d->state=0;connected=1;return 0;}
 if(!idle++){return EFI_ERROR|6;} /* NOT_READY is an ordinary idle poll. */
 if(tx_pending){*kind=2;d->transfer.status=1;d->transfer.endpoint=0x81;d->transfer.bytes=sent_bytes;d->transfer.buffer=sent_buffer;tx_pending=0;return 0;}
 if(rx_pending&&!cancelled){cancelled=1;rx_pending=0;*kind=2;d->transfer.status=2;d->transfer.endpoint=1;d->transfer.bytes=0;d->transfer.buffer=buffers[0];return 0;}
 if(rx_pending){const char*commands[]={"getvar:product","oem logs","upload","oem screenshot","upload"};assert(script<5);const char*c=commands[script++];memcpy(buffers[0],c,strlen(c));*kind=2;d->transfer.status=1;d->transfer.endpoint=1;d->transfer.bytes=strlen(c);d->transfer.buffer=buffers[0];rx_pending=0;return 0;}
 if(script==5)longjmp(finish,1);return EFI_ERROR|6;
}
static struct polaris_usb_protocol usb={0x10000001,0,send,events,alloc,release,stop,abort_ep,0,start};
static efi_status blt(struct polaris_gop*g,void*p,uint32_t op,uint64_t sx,uint64_t sy,uint64_t dx,uint64_t dy,uint64_t w,uint64_t h,uint64_t delta){assert(g&&op==1&&!sx&&!sy&&!dx&&!dy&&w==2&&h==2&&delta==8);uint32_t data[]={0x00332211,0x00665544,0x00998877,0x00ccbbaa};memcpy(p,data,sizeof(data));return 0;}
static struct polaris_gop_info gi={0,2,2,3,{0},2};static struct polaris_gop_mode gm={1,0,&gi,sizeof(gi),0,0};static struct polaris_gop gop={0,0,blt,&gm};
static efi_status pool_alloc(uint32_t type,uint64_t n,void**p){assert(type==2&&n<=16*1024*1024&&pool_count<2);*p=pool_buffers[pool_count++]=malloc(n);assert(*p);return 0;}
static efi_status locate(const efi_guid*g,void*c,void**p){(void)c;if(g->a==0xd9d9ce48){*p=&usb;return 0;}if(g->a==0x9042a9de){*p=&gop;return 0;}*p=0;return EFI_ERROR|14;}
static void report(const char*s,uint64_t v){assert(s&&strlen(s)<64);(void)v;}
static void transport(void){
 struct efi_boot bs={0};bs.restore_tpl=restore;bs.create_event_ex=event_create;bs.signal_event=signal_evt;bs.close_event=close_event;bs.locate_protocol=locate;bs.stall=pause_us;bs.allocate_pool=pool_alloc;
 struct efi_system st={0};st.boot=&bs;const uint8_t log[]="report text";uint64_t log_bytes=11;
 usb.revision=0x10000;assert(polaris_efi_usb_serve(&st,log,&log_bytes,0,0,report)==(EFI_ERROR|3));assert(!started&&!allocations);
 usb.revision=0x10000001;
 if(!setjmp(finish)){polaris_efi_usb_serve(&st,log,&log_bytes,0,0,report);assert(0);}
 assert(started&&allocations==2&&script==5&&restored&&initialized&&cancelled);
 const char expected[]="OKAYpolaris-uefi-diagOKAYDATA0000000breport textOKAYOKAYDATA00000017";
 assert(!memcmp(transfers,expected,sizeof(expected)-1));
 const uint8_t ppm_expected[]={'P','6',10,'2',32,'2',10,'2','5','5',10,0x33,0x22,0x11,0x66,0x55,0x44,0x99,0x88,0x77,0xcc,0xbb,0xaa};
 assert(transfers_bytes==sizeof(expected)-1+sizeof(ppm_expected)+4);
 assert(!memcmp(transfers+sizeof(expected)-1,ppm_expected,sizeof(ppm_expected)));
 assert(!memcmp(transfers+transfers_bytes-4,"OKAY",4));
 free(buffers[0]);free(buffers[1]);for(unsigned j=0;j<pool_count;j++)free(pool_buffers[j]);
}
int main(void){parser();ppm();transport();return 0;}
'''
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror',
                            '-fsanitize=address,undefined','-I',str(ROOT/'shim/polaris'),
                            str(p/'test.c'),str(ROOT/'shim/polaris/uefi-usb.c'),
                            str(ROOT/'shim/polaris/uefi-usb-command.c'),
                            str(ROOT/'shim/polaris/uefi-usb-control.c'),'-o',str(p/'test')],check=True)
            subprocess.run([str(p/'test')],check=True,timeout=15)


if __name__=='__main__':unittest.main()
