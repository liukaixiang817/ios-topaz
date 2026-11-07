"""Execute the native watchdog policy with bounded failing hardware leaves."""
from pathlib import Path
import subprocess
import tempfile
import unittest

from tools.tests.test_polaris_mss_word_trace import execute, function

ROOT = Path(__file__).resolve().parents[2]


class NativeWatchdogTests(unittest.TestCase):
    def test_actual_arch_callback_requires_live_bound_native_cpu0(self):
        source = (ROOT/'shim/polaris/uefi-xnu.c').read_text()
        callback = function(source, 'static int wifi_native_watchdog_arch(void*context,')
        execute('#include "'+str(ROOT/'shim/polaris/uefi-apps-watchdog-native-readonly.h')+'"\n'+r'''
#include <assert.h>
struct pwfc_arch {uint64_t el,mpidr,ttbr0,ttbr1,tcr,sctlr,mair,daif,sre,group1,frequency,ticks;};
struct pgcd_arch {struct pwfc_arch cpu;uint64_t cpacr;};
struct pmsc_owner {unsigned phase,held,complete,unknown,error;uint64_t last;struct pgcd_arch entry;};
static struct {struct pmsc_owner owner;}wifi_native_parent;
static struct pgcd_arch current;
static unsigned wifi_native_boot_phase=5,wln_cpu_on_issued,calls;
static int pgcd_actual_arch(void*c,struct pgcd_arch*a){assert(!c);*a=current;calls++;return 1;}
static int pmsc_time(const struct pmsc_owner*o,uint64_t ticks){assert(o==&wifi_native_parent.owner);return ticks<=1000;}
''' + callback + r'''
static void init(void){
 wifi_native_boot_phase=5;wln_cpu_on_issued=calls=0;
 current=(struct pgcd_arch){.cpu={.el=4,.mpidr=0x81000000,.ttbr0=0x13ffe89000,
 .tcr=0x80803518,.sctlr=5,.daif=0xc0,.frequency=19200000,.ticks=100}};
 wifi_native_parent.owner=(struct pmsc_owner){.phase=2,.held=1,.last=90,.entry=current};
}
int main(void){
 struct pawn_arch out;init();assert(wifi_native_watchdog_arch(&wifi_native_parent.owner,&out));
 init();assert(!wifi_native_watchdog_arch(0,&out)&&!calls);
 for(unsigned field=0;field<7;field++){
 init();switch(field){case 0:wifi_native_boot_phase=4;break;case 1:wln_cpu_on_issued=1;break;
 case 2:wifi_native_parent.owner.phase=1;break;case 3:wifi_native_parent.owner.held=0;break;
 case 4:wifi_native_parent.owner.complete=1;break;case 5:wifi_native_parent.owner.unknown=1;break;
 case 6:wifi_native_parent.owner.error=1;break;}
 assert(!wifi_native_watchdog_arch(&wifi_native_parent.owner,&out)&&!calls);
 }
 for(unsigned field=0;field<13;field++){
 if(field==11)continue; /* A later monotonic tick is admitted. */
 init();((uint64_t*)&current)[field]^=1;
 assert(!wifi_native_watchdog_arch(&wifi_native_parent.owner,&out));
 }
 init();current.cpu.ticks=89;assert(!wifi_native_watchdog_arch(&wifi_native_parent.owner,&out));
 init();current.cpu.ticks=1001;assert(!wifi_native_watchdog_arch(&wifi_native_parent.owner,&out));
 return 0;
}
''')

    def test_actual_policy_refuses_context_translation_and_read_failures(self):
        execute('#include "'+str(ROOT/'shim/polaris/uefi-apps-watchdog-native-readonly.h')+'"\n'+r'''
#include <assert.h>
#include <string.h>
static struct pawn_arch base;
static unsigned archs,ats,reads,fail_arch,fail_at,fail_read,drift_at,unstable;
static int arch(void*c,struct pawn_arch*a){assert(c==&base);archs++;*a=base;
 a->cpu.ticks+=archs;if(archs==drift_at)a->cpu.daif=0;
 return archs!=fail_arch;}
static int at(void*c,uint64_t address,struct pawr_translation*t){assert(c==&base);
 assert(address==PAWR_BASE+8+4*(ats%4));ats++;
 *t=(struct pawr_translation){17,PAWR_BASE|0x200,17};
 if(ats==fail_at)t->par|=1;return 1;}
static int rd(void*c,uint64_t address,uint32_t*v){assert(c==&base);
 assert(address==PAWR_BASE+8+4*(reads%4));reads++;*v=(unsigned)address;
 if(unstable&&reads==5)*v^=1;return reads!=fail_read;}
static struct efi_memory map;
static struct pawn_ops ops;
static struct pawn_result result;
static void init(void){
 base=(struct pawn_arch){.cpu={4,0x81000000,0xc0,5,0x80803518,0x13ffe89000,0,0,19200000,100}};
 archs=ats=reads=fail_arch=fail_at=fail_read=drift_at=unstable=0;
 map=(struct efi_memory){.type=7,.physical=0x180000000,.pages=1,.attributes=8};
 ops=(struct pawn_ops){&base,arch,at,rd};memset(&result,0,sizeof(result));
}
static int run(void){return pawn_run(&map,sizeof(map),sizeof(map),sizeof(map),1,&base,&ops,&result);}
int main(void){
 init();assert(run()&&reads==8&&ats==8&&archs==18&&result.stable&&result.returned==8);
 for(unsigned n=1;n<=18;n++){init();fail_arch=n;assert(!run());assert(reads<8||n==18);}
 for(unsigned n=1;n<=18;n++){init();drift_at=n;assert(!run());assert(reads<8||n==18);}
 for(unsigned n=1;n<=8;n++){init();fail_at=n;assert(!run()&&reads==n-1&&result.error==5);}
 for(unsigned n=1;n<=8;n++){init();fail_read=n;assert(!run()&&reads==n&&result.issued==n&&result.returned==n-1);}
 init();unstable=1;assert(!run()&&result.error==7);
 init();map.physical=PAWR_BASE;assert(!run()&&!reads&&!ats&&!archs&&result.error==2);
 init();map.physical=PAWR_BASE;map.type=11;map.attributes=1;assert(run());
 init();base.cpu.daif=0;assert(!run()&&!archs&&!ats&&!reads);
 init();base.group1=1;assert(!run()&&!archs&&!ats&&!reads);
 init();base.cpu.mpidr|=0x100;assert(!run()&&!archs&&!ats&&!reads);
 init();base.cpu.el=8;assert(!run()&&!archs&&!ats&&!reads);
 init();assert(!pawr_arch_valid(&base.cpu));
 init();struct pawn_arch other=base;other.cpu.ticks+=384001;assert(!pawn_same(&base,&other));
 init();other=base;other.cpu.ttbr0^=4096;assert(!pawn_same(&base,&other));
 return 0;
}
''')

    def test_actual_sampler_bounds_frequency_and_stops_on_failure(self):
        source = (ROOT/'shim/polaris/uefi-xnu.c').read_text()
        sample = function(source, 'static int wifi_native_watchdog_sample(void)')
        execute('#include "'+str(ROOT/'shim/polaris/uefi-apps-watchdog-native-readonly.h')+'"\n'+r'''
#include <assert.h>
#include <string.h>
struct pweh_result {struct {unsigned char data[48];struct {uint64_t bytes,stride;unsigned version;}map;}map;};
struct pmsc_owner {uint64_t retained;};
static struct {struct pmsc_owner owner;struct pawn_state watchdog;}wifi_native_parent;
static struct pweh_result retained;
static uint64_t ticks;static unsigned calls,arch_ok=1,run_ok=1;
static int wifi_native_watchdog_arch(void*c,struct pawn_arch*a){assert(c==&wifi_native_parent.owner);a->cpu.ticks=ticks;return arch_ok;}
static int wifi_native_watchdog_translate(void*c,uint64_t p,struct pawr_translation*t){(void)c;(void)p;(void)t;assert(0);return 0;}
static int wifi_native_watchdog_read(void*c,uint64_t p,uint32_t*v){(void)c;(void)p;(void)v;assert(0);return 0;}
static int simulated_run(const void*m,uint64_t b,uint64_t cap,uint64_t stride,uint32_t version,
 const struct pawn_arch*bound,const struct pawn_ops*ops,struct pawn_result*r){
 assert(m==retained.map.data&&b==48&&cap==48&&stride==48&&version==1&&bound->cpu.ticks==ticks);
 assert(ops->context==&wifi_native_parent.owner&&ops->arch==wifi_native_watchdog_arch&&
 ops->translate==wifi_native_watchdog_translate&&ops->read32==wifi_native_watchdog_read);
 calls++;r->value[0][0]=calls;r->value[0][2]=2;r->value[0][3]=3;r->error=run_ok?0:6;return run_ok;}
#define pawn_run simulated_run
''' + sample + r'''
int main(void){
 retained.map.map.bytes=retained.map.map.stride=48;retained.map.map.version=1;
 wifi_native_parent.owner.retained=(uintptr_t)&retained;ticks=100;
 assert(wifi_native_watchdog_sample()&&calls==1&&wifi_native_parent.watchdog.snapshots==1);
 assert(wifi_native_parent.watchdog.first==100&&wifi_native_parent.watchdog.initial[0]==1);
 ticks+=4799999;assert(wifi_native_watchdog_sample()&&calls==1);
 ticks++;assert(wifi_native_watchdog_sample()&&calls==2&&wifi_native_parent.watchdog.snapshots==2);
 assert(wifi_native_parent.watchdog.initial[0]==1);
 arch_ok=0;assert(!wifi_native_watchdog_sample()&&calls==2);arch_ok=1;
 ticks+=4800000;run_ok=0;assert(!wifi_native_watchdog_sample()&&calls==3);
 run_ok=1;ticks+=4800000;assert(!wifi_native_watchdog_sample()&&calls==3);
 wifi_native_parent.watchdog.result.error=0;wifi_native_parent.watchdog.snapshots=720;
 assert(!wifi_native_watchdog_sample()&&calls==3);
 return 0;
}
''')

    def test_builder_requires_marker_before_creating_output(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            result = subprocess.run(['python3', str(ROOT/'tools/build-polaris-uefi-xnu.py'),
                '--zig', str(path/'missing'), '--kernel', str(path/'kernel'), '--payload', str(path/'payload'),
                '--output', str(path/'output'), '--wifi-native-watchdog-readonly'], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('requires --wifi-native-bootloader-marker', result.stderr)
            self.assertFalse((path/'output').exists())


if __name__ == '__main__':
    unittest.main()
