"""Compile the firmware READ transport under ASan/UBSan; no PMIC emulation claim."""
from pathlib import Path
import unittest
from .test_polaris_gpu_bootstrap import run
ROOT=Path(__file__).resolve().parents[2]
H='#include "'+str(ROOT/'shim/polaris/uefi-buttons-spmi.h')+'"\n'+r'''
#include <assert.h>
#include <string.h>
struct fake {uint32_t maps[512],owners[512],version,status,cmd,off,writes,data_reads;
 uint64_t time;unsigned frozen,backward;uint8_t pmic[2][256];};
static uint32_t rd(void *ctx,unsigned bank,uint32_t off){struct fake *f=ctx;
 if(bank==PB_CORE){if(!off)return f->version;assert(off>=0x900&&off<0x1100&&!(off&3));return f->maps[(off-0x900)/4];}
 if(bank==PB_CONFIG){assert(off>=0x700&&off<0xf00&&!(off&3));return f->owners[(off-0x700)/4];}
 assert(bank==PB_OBSERVER&&off<0x10000);unsigned local=off-f->off;
 if(local==8)return f->status;
 assert(local==0x18||local==0x1c);f->data_reads++;uint32_t val=0;
 unsigned k=((f->maps[f->off/0x80]>>8)&0xfff)==8?0:1;
 unsigned reg=(f->cmd>>4)&255;
 for(unsigned n=0;n<4;n++){unsigned at=reg+n+(local==0x1c?4:0);if(at<256)val|=(uint32_t)f->pmic[k][at]<<(8*n);}
 return val;}
static void cmd(void *ctx,uint32_t off,uint32_t value){struct fake *f=ctx;
 assert(off<0x10000&&!(off%0x80));assert((value>>27)==1);assert(!(value&0x07fff008));
 f->cmd=value;f->off=off;f->writes++;}
static uint64_t now(void *ctx){struct fake *f=ctx;if(f->backward)return f->time--;return f->frozen?f->time:++f->time;}
static void init(struct fake *f,struct polaris_button_bus *b){memset(f,0,sizeof(*f));memset(b,0,sizeof(*b));
 f->version=0x50010000;f->maps[7]=0x800;f->owners[7]=3;f->maps[9]=0xc500;f->owners[9]=0;
 f->status=1;f->time=1;f->pmic[0][4]=1;f->pmic[0][5]=4;f->pmic[0][0x10]=3;
 f->pmic[1][4]=0x10;f->pmic[1][5]=0x10;f->pmic[1][0x42]=1;f->pmic[1][0x46]=0x80;f->pmic[1][0x10]=1;
 b->context=f;b->read=rd;b->read_command=cmd;b->now_us=now;}
'''


class ButtonSPMITests(unittest.TestCase):
    def test_only_read_commands_and_original_gpio6(self):
        run(H+r'''
int main(void){struct fake f;struct polaris_button_bus b;init(&f,&b);
 assert(pb_start(&b)&&b.active&&b.apid[0]==7&&b.apid[1]==9&&b.reads==4&&f.writes==4);
 uint8_t p=0,g=0;assert(pb_levels(&b,&p,&g)&&p==3&&g==1&&b.reads==6);
 uint8_t bytes[8]={0};for(unsigned n=0;n<8;n++)f.pmic[1][0xe0+n]=0x30+n;
 assert(pb_read(&b,1,0xe0,bytes,8));for(unsigned n=0;n<8;n++)assert(bytes[n]==0x30+n);
 unsigned writes=f.writes;
 assert(!pb_read(&b,1,255,bytes,2)&&b.fault==PB_E_ARGUMENT&&f.writes==writes);
 assert(!pb_levels(&b,&p,&g)&&f.writes==writes);return 0;}
''')

    def test_vendor_canonical_duplicates_and_changed_mapping_refusal(self):
        run(H+r'''
int main(void){struct fake f;struct polaris_button_bus b;init(&f,&b);
 f.maps[11]=0x800;f.owners[11]=2;assert(pb_map(&b)&&b.apid[0]==7);
 init(&f,&b);f.maps[11]=0x800;f.owners[11]=0;f.maps[12]=0x800;f.owners[12]=2;
 assert(pb_start(&b)&&b.apid[0]==11);unsigned writes=f.writes;uint8_t out;
 f.maps[13]=0x800;f.owners[13]=0;
 assert(!pb_read(&b,0,0x10,&out,1)&&b.fault==PB_E_MAPPING&&f.writes==writes);
 init(&f,&b);assert(pb_start(&b));f.owners[7]=4;writes=f.writes;
 assert(!pb_read(&b,0,0x10,&out,1)&&b.fault==PB_E_MAPPING&&f.writes==writes);
 init(&f,&b);f.maps[9]=0xc600;assert(!pb_start(&b)&&b.fault==PB_E_MAPPING&&!f.writes);
 return 0;}
''')

    def test_error_timeouts_and_unknown_status_never_read_data_or_retry(self):
        run(H+r'''
int main(void){struct fake f;struct polaris_button_bus b;uint8_t out;
 for(unsigned status=0;status<32;status++){if(status==1)continue;
  init(&f,&b);f.status=status;
  assert(!pb_read(&b,0,0x10,&out,1)&&b.fault==(status?PB_E_RESPONSE:PB_E_TIMEOUT));
  assert(f.writes==1&&!f.data_reads);assert(!pb_read(&b,0,0x10,&out,1)&&f.writes==1);
 }
 init(&f,&b);f.status=0;f.frozen=1;assert(!pb_read(&b,0,0x10,&out,1)&&b.fault==PB_E_TIMEOUT&&f.writes==1);
 init(&f,&b);f.backward=1;f.time=100;assert(!pb_read(&b,0,0x10,&out,1)&&b.fault==PB_E_TIME&&f.writes==1);
 init(&f,&b);f.frozen=1;f.time=0;assert(!pb_read(&b,0,0x10,&out,1)&&b.fault==PB_E_TIME&&!f.writes);
 for(unsigned v=0;v<8;v++){if(v==5)continue;init(&f,&b);f.version=v<<28;
  assert(!pb_start(&b)&&b.fault==PB_E_VERSION&&!f.writes);}
 init(&f,&b);assert(pb_start(&b));unsigned writes=f.writes;f.version++;
 assert(!pb_read(&b,0,0x10,&out,1)&&b.fault==PB_E_VERSION&&f.writes==writes);return 0;}
''')

    def test_pin_identity_input_enable_pull_and_classic_direction(self):
        run(H+r'''
int main(void){struct fake f;struct polaris_button_bus b;
 for(unsigned subtype=0;subtype<256;subtype++)for(unsigned dir=0;dir<8;dir++) {
  init(&f,&b);f.pmic[1][5]=subtype;
  bool classic=subtype==1||subtype==5||subtype==9||subtype==13;
  bool lv=subtype==0x10||subtype==0x11;
  f.pmic[1][0x40]=classic?dir<<4:dir;
  assert(pb_start(&b)==((classic&&dir==0)||(lv&&(dir&3)==0)));
 }
 for(unsigned v=0;v<256;v++){
  init(&f,&b);f.pmic[1][0x42]=v;assert(pb_start(&b)==((v&7)<4));
  init(&f,&b);f.pmic[1][0x46]=v;assert(pb_start(&b)==!!(v&0x80));
  init(&f,&b);f.pmic[1][0x44]=v;assert(pb_start(&b)==!(v&15));
  init(&f,&b);f.pmic[1][0x43]=v;assert(pb_start(&b)==!(v&0x80));
 }
 init(&f,&b);f.pmic[0][5]=9;assert(!pb_start(&b)&&b.fault==PB_E_IDENTITY);
 init(&f,&b);f.pmic[0][4]=8;assert(!pb_start(&b)&&b.fault==PB_E_IDENTITY);
 init(&f,&b);f.pmic[1][4]=8;assert(!pb_start(&b)&&b.fault==PB_E_INPUT);
 return 0;}
''')


if __name__=='__main__':unittest.main()
