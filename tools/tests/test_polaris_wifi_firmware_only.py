"""Kernel-entry closure in the actual firmware diagnostic, and root admission isolation."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'tools'))


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT/'tools'/(name+'.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


native = module('polaris-wifi-native-boot')
firmware = module('polaris-wifi-firmware-boot')
SOURCE = (ROOT/'shim/polaris/uefi-xnu.c').read_text()
start = SOURCE.index('#ifndef EFI_XNU_WIFI_FIRMWARE_DIAGNOSTIC_ONLY')
GUARD = SOURCE[start:SOURCE.index('\n#if EFI_XNU_WIFI_NATIVE_RUNTIME_AVAILABLE\n', start)]
start = SOURCE.index('__attribute__((noreturn)) static void wifi_native_boot(void)')
brace = SOURCE.index('{', start)
depth, end = 1, brace+1
while depth:
    depth += (SOURCE[end] == '{') - (SOURCE[end] == '}')
    end += 1
ACTUAL = SOURCE[start:end]


class FirmwareOnlyTests(unittest.TestCase):
    def test_actual_entry_never_reaches_kernel_even_if_checkpoint_is_missed(self):
        # No kernel/UI/worker declarations exist in this fixture: retaining
        # even a single reference to that branch fails the real C compilation.
        peer = r'''
#include <assert.h>
#include <limits.h>
#include <setjmp.h>
#include <stdio.h>
static jmp_buf stop;
static unsigned wifi_native_boot_phase, starts, steps, holds, prefix;
static int terminal;
static void wifi_native_startup(void){starts++;}
static int wifi_native_startup_step(void){return ++steps<=prefix?1:terminal;}
__attribute__((noreturn)) static void power_unknown_hold(void){holds++;longjmp(stop,1);}
'''
        main = r'''
int main(void){
 unsigned cases=0;const int values[]={2,-1,-7,INT_MIN};
 for(prefix=0;prefix<=64;prefix++)for(unsigned n=0;n<4;n++){
  terminal=values[n];starts=steps=holds=wifi_native_boot_phase=0;
  if(!setjmp(stop))wifi_native_boot();
  assert(starts==1&&steps==prefix+1&&holds==1&&wifi_native_boot_phase==5);
  cases++;
 }
 printf("PASS %u actual firmware-only terminal cases\n",cases);
 return cases==260?0:1;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            for checkpoint in (1, 2, 3, 4):
                source = folder/f'checkpoint-{checkpoint}.c'
                source.write_text('#define EFI_XNU_WIFI_NATIVE_RUNTIME_AVAILABLE 1\n'
                                  '#define EFI_XNU_WIFI_FIRMWARE_DIAGNOSTIC_ONLY 1\n'
                                  f'#define EFI_XNU_WIFI_AUTH_METADATA_CHECKPOINT {checkpoint}\n'
                                  + GUARD+'\n'+peer+ACTUAL+'\n'+main)
                binary = source.with_suffix('')
                subprocess.run(['clang', '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                                '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                                str(source), '-o', str(binary)], check=True, capture_output=True)
                result = subprocess.run([str(binary)], check=True, capture_output=True, text=True)
                self.assertIn('PASS 260 actual firmware-only terminal cases', result.stdout)

    def test_actual_compile_guard_rejects_unbounded_or_disk_profiles(self):
        for checkpoint, runtime, disk in ((0, 1, False), (5, 1, False), (4, 0, False), (4, 1, True)):
            with self.subTest(checkpoint=checkpoint, runtime=runtime, disk=disk):
                text = ('#define EFI_XNU_WIFI_FIRMWARE_DIAGNOSTIC_ONLY 1\n'
                        f'#define EFI_XNU_WIFI_NATIVE_RUNTIME_AVAILABLE {runtime}\n'
                        f'#define EFI_XNU_WIFI_AUTH_METADATA_CHECKPOINT {checkpoint}\n'
                        + ('#define EFI_XNU_DISK_GUID 1\n' if disk else '') + GUARD)
                result = subprocess.run(['clang', '-x', 'c', '-fsyntax-only', '-'],
                                        input=text, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Firmware-only diagnostic requires', result.stderr)

    def test_normal_runtime_still_refuses_incomplete_or_dirty_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            case = root/'research/case'
            for name in ('image-0001', 'driver-0001'):
                (case/name).mkdir(parents=True)
                (case/name/'manifest.json').write_text('{}')
            review = dict(scope='one_native_WiFi_RO_RAMCOW_trial', temporary_trial_review_complete=True,
                          physical_networking_verified=False, may_write_userdata=False,
                          boot_helper_sha256='hash', gates={str(n):dict(trial_review_passed=True) for n in range(1, 6)},
                          files={}, case='research/case')
            path = root/'review.json'
            path.write_text(json.dumps(review))
            for count, passed, dirty, writable in ((40, False, True, False), (40, True, True, False),
                                                   (39, True, False, False), (40, True, False, True)):
                data = dict(passed=passed, checks={str(n):True for n in range(count)}, may_write_userdata=writable)
                if dirty:
                    data['checks']['0'] = data['checks']['1'] = False
                (case/'fresh-20F66-readonly-root-review.json').write_text(json.dumps(data))
                with self.subTest(count=count, passed=passed, dirty=dirty, writable=writable), \
                     patch.object(native, 'ROOT', root), patch.object(native, 'sha', return_value='hash'), \
                     self.assertRaisesRegex(ValueError, 'current readonly root review incomplete'):
                    native.validate(path)

    def test_reviews_cannot_be_used_with_the_other_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'review.json'
            for validator, scope, message in (
                    (native.validate, 'one_native_WiFi_firmware_diagnostic_RAM_trial', 'wrong trial review scope'),
                    (firmware.validate, 'one_native_WiFi_RO_RAMCOW_trial', 'wrong firmware-only review scope')):
                path.write_text(json.dumps(dict(scope=scope)))
                with self.subTest(scope=scope), self.assertRaisesRegex(ValueError, message):
                    validator(path)


if __name__ == '__main__':
    unittest.main()
