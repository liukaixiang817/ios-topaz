"""Exercise the actual watchdog read policy, including refusal before MMIO."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class WatchdogReadOnlyTests(unittest.TestCase):
    def test_fixed_reads_map_translation_and_liveness(self):
        source = r'''
#include "uefi-apps-watchdog-readonly.h"
#include <assert.h>
struct fixture {unsigned reads,ats,arch_calls,fail_at;int bad;};
static int arch(void *opaque,struct pawr_arch *a){
 struct fixture *f=opaque;f->arch_calls++;
 *a=(struct pawr_arch){4,0x81000000,0,1,0x80803518,0x13ffe89000,0,0,19200000,10+f->arch_calls};
 if(f->bad==1)a->el=8;
 if(f->bad==2)a->mpidr++;
 if(f->bad==3)a->daif=0x80;
 if(f->bad==4)a->sctlr=0;
 if(f->bad==5)a->tcr|=0x4000;
 if(f->bad==6)a->tcr|=0x80;
 if(f->bad==7)a->frequency=1000000;
 if(f->bad==8 && f->arch_calls>1)a->ttbr0+=4096;
 if(f->bad==9 && f->arch_calls>1)a->ticks+=19200000;
 return f->bad!=10;
}
static int at(void *opaque,uint64_t address,struct pawr_translation *t){
 struct fixture *f=opaque;assert(address==PAWR_BASE+8 || address==PAWR_BASE+12 ||
  address==PAWR_BASE+16 || address==PAWR_BASE+20);f->ats++;
 *t=(struct pawr_translation){42,PAWR_BASE|0x200,42};
 if(f->bad==11)t->par|=1;
 if(f->bad==12)t->par^=0x1000;
 if(f->bad==13)t->par&=~UINT64_C(0x200);
 if(f->bad==14)t->par|=UINT64_C(0xff00000000000000);
 if(f->bad==15)t->restored++;
 return f->bad!=16;
}
static int read32(void *opaque,uint64_t address,uint32_t *value){
 struct fixture *f=opaque;static const unsigned offset[]={8,12,16,20};
 assert(address==PAWR_BASE+offset[f->reads%4]);f->reads++;
 if(f->fail_at==f->reads)return 0;
 *value=(uint32_t)address;
 if(address==PAWR_BASE+12)*value=f->reads; /* live status may advance */
 if(f->bad==17 && f->reads==5)(*value)++;
 return 1;
}
int main(void){
 struct efi_memory map[2]={{11,0,PAWR_BASE,0,1,1},{7,0,0x80000000,0,1,0}};
 struct fixture f={0};struct pawr_result r;
 struct pawr_ops ops={&f,arch,at,read32};
#define RUN() pawr_run(map,sizeof(map),sizeof(map),40,1,&ops,&r)
 assert(RUN() && r.error==0 && r.issued==8 && r.returned==8 && r.stable==1);
 assert(f.reads==8 && f.ats==8 && r.value[0][1]!=r.value[1][1]);
 for(int bad=1;bad<=16;bad++){
  f=(struct fixture){.bad=bad};assert(!RUN());assert(f.reads==0 && r.issued==0);
 }
 f=(struct fixture){.bad=17};assert(!RUN() && r.error==7 && f.reads==8);
 for(unsigned i=1;i<=8;i++){
  f=(struct fixture){.fail_at=i};assert(!RUN() && r.error==6);
  assert(r.issued==i && r.returned==i-1 && f.reads==i);
 }
 for(unsigned kind=0;kind<16;kind++)if(kind!=11){
  f=(struct fixture){0};map[0].type=kind;assert(!RUN() && f.reads==0 && f.ats==0);
 }
 map[0].type=11;
 for(unsigned attrs=0;attrs<16;attrs++){
  f=(struct fixture){0};map[0].attributes=attrs;
  assert(RUN()==(!!(attrs&1) && !(attrs&8)));
  if(!(attrs&1)||(attrs&8))assert(f.reads==0 && f.ats==0);
 }
 map[0].attributes=1;f=(struct fixture){0};map[1].physical=PAWR_BASE;
 assert(!RUN() && r.error==1 && f.reads==0 && f.ats==0);
 map[1].physical=0x80000000;map[0].physical+=4096;
 assert(RUN() && r.map_present==0 && f.reads==8);
 map[0].physical-=4096;
 f=(struct fixture){0};
 assert(!pawr_run(map,sizeof(map),sizeof(map),40,2,&ops,&r) && f.reads==0);
 assert(!pawr_run(map,sizeof(map),sizeof(map)-1,40,1,&ops,&r) && f.reads==0);
 assert(!pawr_run(map,sizeof(map),sizeof(map),39,1,&ops,&r) && f.reads==0);
 assert(!pawr_run(map,sizeof(map),sizeof(map),40,1,0,&r) && r.error==3);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder)
            (p / 'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-O1', '-g', '-fsanitize=address,undefined', '-I',
                            str(ROOT / 'shim/polaris'), str(p / 'test.c'), '-o', str(p / 'test')],
                           check=True)
            subprocess.run([str(p / 'test')], check=True)

    def test_builder_requires_hold_only_usb_scope(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / 'must-not-exist'
            run = subprocess.run(['python3', str(ROOT / 'tools/build-polaris-uefi-probe.py'),
                                  '--zig', '/not/executed', '--output', str(target),
                                  '--apps-watchdog-readonly'], capture_output=True, text=True)
            self.assertNotEqual(run.returncode, 0)
            self.assertIn('requires --hold --ready-to-boot --usb-diag', run.stderr)
            self.assertFalse(target.exists())


if __name__ == '__main__':
    unittest.main()
