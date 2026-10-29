"""Same bounded firmware observer parser; no physical WLED emulation claim."""
from pathlib import Path
import unittest
from .test_polaris_gpu_bootstrap import run
ROOT=Path(__file__).resolve().parents[2]
H='#include "'+str(ROOT/'shim/polaris/uefi-wled-readonly.h')+'"\n'+r'''
#include <assert.h>
#include <string.h>
struct fake {uint32_t maps[512],owners[512],version,status,cmd,offset,commands,data_reads;
 uint64_t time;unsigned frozen,backward,fail_command,mutate_after,mutate_map;uint8_t pmic[2][256];};
static uint32_t rd(void *ctx,unsigned bank,uint32_t off){struct fake*f=ctx;
 if(bank==PW_CORE){if(!off)return f->version;assert(off>=0x900&&off<0x1100&&!(off&3));return f->maps[(off-0x900)/4];}
 if(bank==PW_CONFIG){assert(off>=0x700&&off<0xf00&&!(off&3));return f->owners[(off-0x700)/4];}
 assert(bank==PW_OBSERVER);unsigned local=off-f->offset;
 if(local==8)return f->commands==f->fail_command?2:f->status;
 assert(local==0x18||local==0x1c);f->data_reads++;uint32_t value=0;
 unsigned k=((f->maps[f->offset/0x80]>>8)&0xfff)==0x3d8?0:1,reg=(f->cmd>>4)&255;
 for(unsigned n=0;n<4;n++){unsigned at=reg+n+(local==0x1c?4:0);if(at<256)value|=(uint32_t)f->pmic[k][at]<<(8*n);}
 return value;}
static void cmd(void*ctx,uint32_t off,uint32_t value){struct fake*f=ctx;
 assert(off<0x10000&&!(off%0x80));assert((value>>27)==1);assert(!(value&0x07fff008));
 f->cmd=value;f->offset=off;f->commands++;
 if(f->mutate_after&&f->commands==f->mutate_after)f->pmic[0][0x46]^=0x80;
 if(f->mutate_map&&f->commands==f->mutate_map){f->maps[11]=0x3d800;f->owners[11]=0;}}
static uint64_t now(void*ctx){struct fake*f=ctx;if(f->backward)return f->time--;return f->frozen?f->time:++f->time;}
static void init(struct fake*f,struct polaris_wled_read_bus*b){memset(f,0,sizeof(*f));memset(b,0,sizeof(*b));
 f->version=0x50000000;f->maps[7]=0x3d800;f->owners[7]=0;f->maps[9]=0x3d900;f->owners[9]=3;f->status=1;f->time=1;
 for(unsigned k=0;k<2;k++)for(unsigned n=0;n<256;n++)f->pmic[k][n]=(uint8_t)(n*7+k*31);
 b->context=f;b->read=rd;b->read_command=cmd;b->now_us=now;}
'''
class WledReadOnly(unittest.TestCase):
    def test_exact_inventory_and_no_power_commands(self):
        run(H+r'''
int main(void){struct fake f;struct polaris_wled_read_bus b;struct polaris_wled_snapshot s;init(&f,&b);
 uint8_t original[2][256];memcpy(original,f.pmic,sizeof(original));assert(polaris_wled_inventory(&b,&s));
 assert(b.reads==32&&f.commands==32&&b.apid[0]==7&&b.apid[1]==9&&b.owner[1]==3);
 assert(!memcmp(s.revision,f.pmic[0],8)&&!memcmp(s.revision[1],f.pmic[1],8));
 assert(!memcmp(s.ctrl,f.pmic[0]+0x44,3)&&s.faults[0]==f.pmic[0][8]&&s.faults[1]==f.pmic[0][0x10]);
 assert(!memcmp(s.sink,f.pmic[1]+0x46,6));for(unsigned n=0;n<4;n++)assert(!memcmp(s.string[n],f.pmic[1]+0x50+n*0x10,9));
 assert(s.psm[0]==f.pmic[0][0x5a]&&s.psm[1]==f.pmic[0][0x5b]&&s.irq_enable==f.pmic[0][0x15]);assert(!memcmp(original,f.pmic,sizeof(original)));return 0;}
''')
    def test_every_read_failure_and_changed_snapshot_keep_output_unpublished(self):
        run(H+r'''
int main(void){struct fake f;struct polaris_wled_read_bus b;struct polaris_wled_snapshot s,sentinel;memset(&sentinel,0xa5,sizeof(sentinel));
 for(unsigned n=1;n<=32;n++){init(&f,&b);s=sentinel;f.fail_command=n;assert(!polaris_wled_inventory(&b,&s)&&b.fault==PW_E_RESPONSE&&f.commands==n);
  assert(!memcmp(&s,&sentinel,sizeof(s)));assert(!polaris_wled_inventory(&b,&s)&&f.commands==n);}
 init(&f,&b);s=sentinel;f.mutate_after=17;assert(!polaris_wled_inventory(&b,&s)&&b.fault==PW_E_CHANGED);assert(!memcmp(&s,&sentinel,sizeof(s)));
 assert(b.changed_byte_plus_one==19&&b.changed_first==((0x46*7)&255)&&b.changed_after==(((0x46*7)&255)^0x80));
 init(&f,&b);s=sentinel;f.mutate_map=3;assert(!polaris_wled_inventory(&b,&s)&&b.fault==PW_E_MAPPING&&f.commands==3);assert(!memcmp(&s,&sentinel,sizeof(s)));return 0;}
''')
    def test_bounds_versions_owner_changes_and_clock_failures_stop_before_more_commands(self):
        run(H+r'''
int main(void){struct fake f;struct polaris_wled_read_bus b;uint8_t out[8];
 for(unsigned status=0;status<64;status++){if(status==1)continue;init(&f,&b);f.status=status;
  assert(!pw_read(&b,0,0x44,out,3)&&b.fault==(status?PW_E_RESPONSE:PW_E_TIMEOUT)&&f.commands==1&&!f.data_reads);
  assert(!pw_read(&b,0,0x44,out,3)&&f.commands==1);}
 init(&f,&b);f.status=0;f.frozen=1;assert(!pw_read(&b,0,4,out,1)&&b.fault==PW_E_TIMEOUT);
 init(&f,&b);f.backward=1;f.time=100;assert(!pw_read(&b,0,4,out,1)&&b.fault==PW_E_TIME);
 init(&f,&b);f.frozen=1;f.time=0;assert(!pw_read(&b,0,4,out,1)&&!f.commands);
 for(unsigned bank=2;bank<8;bank++){init(&f,&b);assert(!pw_read(&b,bank,4,out,1)&&!f.commands);}
 for(unsigned count=0;count<12;count++){if(count>=1&&count<=8)continue;init(&f,&b);assert(!pw_read(&b,0,0,out,count)&&!f.commands);}
 init(&f,&b);assert(!pw_read(&b,0,255,out,2)&&!f.commands);
 for(unsigned v=0;v<8;v++){if(v==5)continue;init(&f,&b);f.version=v<<28;assert(!pw_read(&b,0,0,out,1)&&b.fault==PW_E_VERSION&&!f.commands);}
 init(&f,&b);assert(pw_read(&b,0,0,out,1));unsigned commands=f.commands;b.version++;assert(!pw_read(&b,0,0,out,1)&&f.commands==commands);
 init(&f,&b);assert(pw_read(&b,0,0,out,1));f.owners[7]=2;commands=f.commands;assert(!pw_read(&b,0,0,out,1)&&b.fault==PW_E_MAPPING&&f.commands==commands);
 init(&f,&b);f.maps[9]=0xc500;assert(!pw_read(&b,0,0,out,1)&&b.fault==PW_E_MAPPING&&!f.commands);
 init(&f,&b);f.maps[11]=0x3d800;f.owners[11]=3;assert(pw_map(&b)&&b.apid[0]==7);
 init(&f,&b);f.maps[11]=0x3d800;f.owners[11]=0;f.maps[12]=0x3d800;f.owners[12]=2;assert(pw_map(&b)&&b.apid[0]==11);return 0;}
''')
if __name__=='__main__':unittest.main()
