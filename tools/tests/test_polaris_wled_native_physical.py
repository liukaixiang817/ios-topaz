"""Independent physical-runtime admission and no-CPU/no-WRITE recovery.

Host checks execute only pure guards/serialization; they do not access PMIC,
firmware cache instructions, a display, USB or an actual reset.
"""
from pathlib import Path
import importlib.util
import subprocess
import tempfile
import unittest
from .test_polaris_gpu_lifetime import function
from .test_polaris_gpu_bootstrap import run
from .test_polaris_wled_status import OEM_H

ROOT=Path(__file__).resolve().parents[2]


class PhysicalRuntime(unittest.TestCase):
    def test_physical_scope_rejects_incomplete_mixed_or_fault_intent_before_input(self):
        complete=['--kernel-core','7','--kernel-cpus','4','--ram-shutdown-bridge',
                  '--physical-buttons','--framebuffer-arrival-wake','--cpu-osm-stock-performance',
                  '--gpu-stock-request','3','--tsens-readonly','--gpu-thermal-lease',
                  '--gpu-thermal-extended','--tsens-pair-witness']
        cases=[[],complete+['--test-qemu'],complete+['--wled-native-runtime-test'],
               complete+['--wled-power-cycle-only'],complete+['--wled-inventory-only'],
               complete+['--physical-owned-marker'],complete+['--efi-application'],
               complete+['--test-wled-prepare-refusal'],complete+['--test-omit-durable-guard']]
        with tempfile.TemporaryDirectory() as d:
            for case in cases:
                p=subprocess.run(['python3',str(ROOT/'tools/build-polaris-uefi-xnu.py'),
                    '--kernel','/nonexistent/kernel','--payload','/nonexistent/payload',
                    '--zig','/nonexistent/zig','--output',d+'/refused','--wled-native-runtime',*case],
                    capture_output=True,text=True)
                self.assertEqual(p.returncode,2)
                self.assertNotIn('FileNotFoundError',p.stderr)
                self.assertFalse((Path(d)/'refused').exists())

    def test_exact_payload_intent_has_no_vm_alias_or_write_escape(self):
        spec=importlib.util.spec_from_file_location('builder',ROOT/'tools/build-polaris-uefi-xnu.py')
        b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
        tokens=b'ufsrw=0 rootrw=1 polarisramcow=1 polarisrammb=512 polarisquiesce=1 ca_vbl=1 polariswled=1'.split()
        b.wled_native_intent(tokens,True,False)
        for extra in (b'polariswled=1',b'polariswledvm=1',b'polarisperf=1',b'polarisownedmarker=0',b'ufsrw=1'):
            with self.assertRaises(ValueError):b.wled_native_intent(tokens+[extra],True,False)
        for at in range(len(tokens)):
            with self.assertRaises(ValueError):b.wled_native_intent(tokens[:at]+tokens[at+1:],True,False)
        for physical,test in ((False,False),(False,True),(True,True)):
            with self.assertRaises(ValueError):b.wled_native_intent(tokens,physical,test)

    def test_zero_write_recovery_cannot_follow_cpu_on_or_uncertain_command(self):
        source=(ROOT/'shim/polaris/uefi-wled-native.h').read_text()
        names=('static int wln_zero_ready(', 'static int wln_zero_receipt_make(', 'static int wln_final_fresh(')
        body='\n'.join(function(source,n) for n in names)
        run(OEM_H+'#include "'+str(ROOT/'shim/polaris/uefi-wled-runtime.h')+'"\n'+
            '#include "'+str(ROOT/'shim/polaris/uefi-wled-journal.h')+'"\n'+
            '#include "'+str(ROOT/'tools/polaris-wled-mailbox.h')+'"\n'+r'''
static unsigned wln_cpu_on_issued,wln_zero_receipt_issued,wln_receipt_issued,wln_closing_mode;
static uint64_t wln_cookie,wln_zero_receipt_us,time_us=100;
static uint8_t wln_zero_receipt[40];
static struct {uint64_t stage;} polaris_efi_ap_state;
static struct polaris_wled_power wln_power;
static struct polaris_wled_runtime wln_runtime;
static struct polaris_wled_firmware wln_firmware;
static struct polaris_wled_runtime_record wln_archive[2];
static uint64_t buttons_us(void *x){(void)x;return time_us;}
static void bytes_zero(void *p,uint64_t n){memset(p,0,n);}
static void bytes_copy(void *p,const void *s,uint64_t n){memcpy(p,s,n);}
''' + body + r'''
int main(void){
 const uint8_t *wire=0;uint64_t size=0;
 assert(wln_zero_ready(2)&&!wln_zero_ready(1)&&!wln_final_fresh(2));
 for(unsigned bad=0;bad<5;bad++){
  wln_cpu_on_issued=bad==0;polaris_efi_ap_state.stage=bad==1;
  wln_power.issued=bad==2;wln_power.completed=bad==3;wln_power.uncertain=bad==4;
  assert(!wln_zero_ready(2)&&!wln_zero_receipt_make(2,&wire,&size)&&!wln_final_fresh(2));
 }
 wln_cpu_on_issued=0;polaris_efi_ap_state.stage=0;
 wln_power.issued=wln_power.completed=wln_power.uncertain=0;
 wln_power.error=PWP_E_SCOPE; /* Preserve a real prepare failure, do not clear it. */
 assert(wln_zero_receipt_make(2,&wire,&size)&&size==40&&!memcmp(wire,"WLZ4",4));
 assert(wln_power.error==PWP_E_SCOPE&&wire[24]==PWP_E_SCOPE);
 for(unsigned i=32;i<36;i++)assert(!wire[i]);
 assert(wln_final_fresh(2)&&!wln_zero_receipt_make(2,&wire,&size));
 time_us=wln_zero_receipt_us-1;assert(!wln_final_fresh(2));
 time_us=wln_zero_receipt_us+PWS_MAX_CHECK_US+1;assert(!wln_final_fresh(2));
 time_us=wln_zero_receipt_us+1;wln_cpu_on_issued=1;assert(!wln_final_fresh(2));
 return 0;
}
''')

    def test_physical_write_and_completion_operations_match_completed_optical_cycle(self):
        old=(ROOT/'shim/polaris/uefi-wled-cycle.h').read_text()
        new=(ROOT/'shim/polaris/uefi-wled-native.h').read_text().split('#else\n/* Exact original v5 channel',1)[1]
        # Compare the actual volatile MMIO/DSB statements, not a hand-copied register table.
        for source in (old,new):
            stores=[line.strip() for line in source.splitlines() if
                    'volatile uint32_t *)(uintptr_t)(UINT64_C(0xc600000)' in line or
                    '__asm__ volatile("dsb sy"' in line]
            if source is old:expected=stores[:6]
            else:self.assertEqual(stores[:6],expected)


if __name__=='__main__':unittest.main()
