"""Actual layout policy and explicit terminal-only native fault build scope."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class NativeFaultTests(unittest.TestCase):
    def test_actual_enabled_entry_arms_once_and_stays_terminal(self):
        from tools.tests.test_polaris_wifi_firmware_only import ACTUAL
        source = r'''
#include <assert.h>
#include <setjmp.h>
#define EFI_XNU_WIFI_FIRMWARE_DIAGNOSTIC_ONLY 1
#define EFI_XNU_WIFI_AUTH_METADATA_CHECKPOINT 10
#define EFI_XNU_WIFI_NATIVE_FAULT_HOLD 1
static jmp_buf stop;
static unsigned starts,steps,arms,holds,prefix,wifi_native_boot_phase,wifi_native_firmware_ready_seen;
static int arm_result,terminal;
static void wifi_native_startup(void){starts++;}
static int wifi_native_startup_step(void){return ++steps<=prefix?1:terminal;}
static int wifi_native_fault_arm(void){arms++;return arm_result;}
__attribute__((noreturn)) static void power_unknown_hold(void){holds++;longjmp(stop,1);}
'''+ACTUAL+r'''
int main(void){
 unsigned cases=0;
 for(prefix=0;prefix<=64;prefix++)for(arm_result=0;arm_result<=1;arm_result++)for(unsigned k=0;k<2;k++){
  terminal=k?2:-1;starts=steps=arms=holds=wifi_native_boot_phase=wifi_native_firmware_ready_seen=0;
  if(!setjmp(stop))wifi_native_boot();
  assert(starts==1 && arms==1 && holds==1 && wifi_native_boot_phase==5);
  assert(steps==(arm_result?prefix+1+k:0));
  assert(wifi_native_firmware_ready_seen==(unsigned)(arm_result && k));
  cases++;
 }
 assert(cases==260);return 0;
}
'''
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder)
            (p/'entry.c').write_text(source)
            subprocess.run(['/usr/bin/clang', '-std=c11', '-O1', '-g', '-Wall', '-Wextra',
                            '-Werror', '-fsanitize=address,undefined', str(p/'entry.c'),
                            '-o', str(p/'entry')], check=True)
            subprocess.run([str(p/'entry')], check=True)

    def test_owned_nonoverlapping_vector_stack_record_layout(self):
        source = r'''
#include "uefi-wifi-native-fault.h"
#include <assert.h>
int main(void){
 struct pfnf_layout l={0x100000,0x100000,0x102000,0x102800,0x102900,0x104000,
  0x110000,16384,0x120000,sizeof(struct pfnf_record),0x130000,131072};
 assert(pfnf_layout_valid(&l));
 struct pfnf_layout b=l;b.vectors++;assert(!pfnf_layout_valid(&b));
 b=l;b.vectors_end+=128;assert(!pfnf_layout_valid(&b));
 b=l;b.code_end=l.vectors_end;assert(!pfnf_layout_valid(&b));
 b=l;b.code_end=l.vectors+8192;assert(!pfnf_layout_valid(&b));
 b=l;b.handler++;assert(!pfnf_layout_valid(&b));
 b=l;b.handler=l.image+l.image_bytes;assert(!pfnf_layout_valid(&b));
 b=l;b.handler=l.stack;assert(!pfnf_layout_valid(&b));
 b=l;b.stack++;assert(!pfnf_layout_valid(&b));
 b=l;b.stack_bytes=4096;assert(!pfnf_layout_valid(&b));
 b=l;b.stack=l.vectors;assert(!pfnf_layout_valid(&b));
 b=l;b.record=l.stack;assert(!pfnf_layout_valid(&b));
 b=l;b.record_bytes++;assert(!pfnf_layout_valid(&b));
 b=l;b.gop=l.record;assert(!pfnf_layout_valid(&b));
 b=l;b.gop_bytes=0;assert(!pfnf_layout_valid(&b));
 b=l;b.gop_bytes=262145;assert(!pfnf_layout_valid(&b));
 b=l;b.image=UINT64_MAX-4095;assert(!pfnf_layout_valid(&b));
 b=l;b.image_bytes=0;assert(!pfnf_layout_valid(&b));
 b=l;b.stack=UINT64_MAX-4095;assert(!pfnf_layout_valid(&b));
 assert(!pfnf_layout_valid(0));
 assert(!pfnf_inside(0x1000,0x1000,UINT64_MAX-3,8));
 assert(!pfnf_disjoint(UINT64_MAX-3,8,0,4));
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder)
            (p/'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang', '-std=c11', '-O1', '-g', '-Wall', '-Wextra',
                            '-Werror', '-fsanitize=address,undefined', '-I', str(ROOT/'shim/polaris'),
                            str(p/'test.c'), '-o', str(p/'test')], check=True)
            subprocess.run([str(p/'test')], check=True)

    def test_fault_vectors_cannot_compile_without_opt_in(self):
        with tempfile.TemporaryDirectory() as folder:
            obj = Path(folder)/'must-not-exist.obj'
            run = subprocess.run(['/usr/bin/clang', '--target=aarch64-unknown-windows', '-c',
                                  str(ROOT/'shim/polaris/uefi-wifi-native-fault.S'), '-o', str(obj)],
                                 capture_output=True, text=True)
            self.assertNotEqual(run.returncode, 0)
            self.assertIn('separate explicit diagnostic build', run.stderr)
            self.assertFalse(obj.exists())

    def test_builder_refuses_fault_flag_without_firmware_only_native_ready(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder)/'must-not-exist'
            run = subprocess.run(['python3', str(ROOT/'tools/build-polaris-uefi-xnu.py'),
                                  '--zig', '/not/executed', '--kernel', '/not/executed',
                                  '--payload', '/not/executed', '--output', str(out),
                                  '--wifi-native-fault-hold'], capture_output=True, text=True)
            self.assertNotEqual(run.returncode, 0)
            self.assertIn('native fault hold requires firmware-only native-ready', run.stderr)
            self.assertFalse(out.exists())


if __name__ == '__main__':
    unittest.main()
