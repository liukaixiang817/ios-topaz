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
#if EFI_XNU_WIFI_AUTH_METADATA_CHECKPOINT == 8
static const unsigned char polaris_wifi_image_nonces[32]={1};
static const unsigned char polaris_wifi_image_nonce_sha256[32]={2};
#endif
static void wifi_native_startup(void){starts++;}
static int wifi_native_startup_step(void){return ++steps<=prefix?1:terminal;}
__attribute__((noreturn)) static void power_unknown_hold(void){holds++;longjmp(stop,1);}
'''
        main = r'''
int main(void){
#if EFI_XNU_WIFI_AUTH_METADATA_CHECKPOINT == 8
 if(!setjmp(stop))wifi_native_boot();
 assert(!starts&&!steps&&holds==1&&wifi_native_boot_phase==5);
 puts("PASS 1 idle firmware-only terminal case");return 0;
#else
 unsigned cases=0;const int values[]={2,-1,-7,INT_MIN};
 for(prefix=0;prefix<=64;prefix++)for(unsigned n=0;n<4;n++){
  terminal=values[n];starts=steps=holds=wifi_native_boot_phase=0;
  if(!setjmp(stop))wifi_native_boot();
  assert(starts==1&&steps==prefix+1&&holds==1&&wifi_native_boot_phase==5);
  cases++;
 }
 printf("PASS %u actual firmware-only terminal cases\n",cases);
 return cases==260?0:1;
#endif
}
'''
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            profiles = ([(n, None, None, None) for n in range(1, 6)] +
                        [(6, n, None, None) for n in range(1, 7)] +
                        [(7, None, n, None) for n in range(1, 29)] + [(8, None, None, None)] +
                        [(9, None, None, n) for n in (1, 221, 256, 30719)])
            for checkpoint, events, segments, page in profiles:
                source = folder/f'checkpoint-{checkpoint}-{events}-{segments}-{page}.c'
                source.write_text('#define EFI_XNU_WIFI_NATIVE_RUNTIME_AVAILABLE 1\n'
                                  '#define EFI_XNU_WIFI_FIRMWARE_DIAGNOSTIC_ONLY 1\n'
                                  f'#define EFI_XNU_WIFI_AUTH_METADATA_CHECKPOINT {checkpoint}\n'
                                  + (f'#define EFI_XNU_WIFI_FIRST_RMB_EVENTS {events}\n' if events is not None else '')
                                  + (f'#define EFI_XNU_WIFI_COPY_SEGMENTS {segments}\n' if segments is not None else '')
                                  + (f'#define EFI_XNU_WIFI_COPY_PAGE_BEFORE {page}\n' if page is not None else '')
                                  + GUARD+'\n'+peer+ACTUAL+'\n'+main)
                binary = source.with_suffix('')
                subprocess.run(['clang', '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                                '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                                str(source), '-o', str(binary)], check=True, capture_output=True)
                result = subprocess.run([str(binary)], check=True, capture_output=True, text=True)
                self.assertIn('PASS 1 idle firmware-only terminal case' if checkpoint==8 else 'PASS 260 actual firmware-only terminal cases', result.stdout)

    def test_actual_compile_guard_rejects_unbounded_or_disk_profiles(self):
        profiles = ((0, 1, False, None, None), (9, 1, False, None, None),
                    (4, 0, False, None, None), (4, 1, True, None, None),
                    (6, 1, False, None, None), (6, 1, False, 0, None),
                    (6, 1, False, 7, None), (5, 1, False, 1, None),
                    (7, 1, False, None, None), (7, 1, False, None, 0),
                    (7, 1, False, None, 29), (7, 1, False, None, -1),
                    (7, 0, False, None, 14), (7, 1, True, None, 14),
                    (6, 1, False, 1, 14), (5, 1, False, None, 14),
                    (8, 0, False, None, None), (8, 1, True, None, None))
        profiles = tuple((*p, None) for p in profiles) + (
            (10, 1, False, None, None, None),
            (9, 1, False, None, None, 0), (9, 1, False, None, None, -1),
            (9, 1, False, None, None, 30720), (9, 0, False, None, None, 256),
            (9, 1, True, None, None, 256), (9, 1, False, 1, None, 256),
            (9, 1, False, None, 9, 256), (7, 1, False, None, 9, 256))
        for checkpoint, runtime, disk, events, segments, page in profiles:
            with self.subTest(checkpoint=checkpoint, runtime=runtime, disk=disk, events=events, segments=segments, page=page):
                text = ('#define EFI_XNU_WIFI_FIRMWARE_DIAGNOSTIC_ONLY 1\n'
                        f'#define EFI_XNU_WIFI_NATIVE_RUNTIME_AVAILABLE {runtime}\n'
                        f'#define EFI_XNU_WIFI_AUTH_METADATA_CHECKPOINT {checkpoint}\n'
                        + (f'#define EFI_XNU_WIFI_FIRST_RMB_EVENTS {events}\n' if events is not None else '')
                        + (f'#define EFI_XNU_WIFI_COPY_SEGMENTS {segments}\n' if segments is not None else '')
                        + (f'#define EFI_XNU_WIFI_COPY_PAGE_BEFORE {page}\n' if page is not None else '')
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

    def test_actual_page_callback_is_terminal_for_valid_and_invalid_contexts(self):
        start = SOURCE.index('__attribute__((noinline,noreturn)) static void pmlc_page_checkpoint(struct pmlc_copy*c)')
        brace = SOURCE.index('{', start)
        depth, end = 1, brace+1
        while depth:
            depth += (SOURCE[end] == '{') - (SOURCE[end] == '}')
            end += 1
        actual = SOURCE[start:end]
        peer = r'''
#include <assert.h>
#include <setjmp.h>
#include <string.h>
#define EFI_XNU_WIFI_COPY_PAGE_BEFORE 256
#define PMIM_SEGMENTS 28
#define PWNS_AUTH 9
#define PMSN_COPY 5
struct pmlc_copy {unsigned ready,unknown,error,complete,pages,segments;};
struct pmsn_state {unsigned phase,ready,pending,error,unknown,assignments;};
struct pwns_parent {unsigned phase,error,unknown;struct pmsn_state auth;
 struct pmlc_copy copy;struct {unsigned held,error,unknown;} owner;};
static struct pwns_parent wifi_native_parent;
static unsigned wifi_native_boot_phase,wln_cpu_on_issued,wifi_native_copy_page_seen,holds;
static jmp_buf stop;
__attribute__((noreturn)) static void power_unknown_hold(void){holds++;longjmp(stop,1);}
'''
        faults = ('c=(void*)1', 'wifi_native_boot_phase=4', 'wln_cpu_on_issued=1',
                  's->phase=8', 's->error=1', 's->unknown=1', 's->auth.phase=6',
                  's->auth.ready=0', 's->auth.pending=1', 's->auth.error=1',
                  's->auth.unknown=1', 's->auth.assignments=2', 's->copy.ready=0',
                  's->copy.unknown=0', 's->copy.error=1', 's->copy.complete=1',
                  's->copy.pages=255', 's->copy.segments=28', 's->owner.held=0',
                  's->owner.error=1', 's->owner.unknown=1')
        switches = ''.join(f'case {n}: {code};break;\n' for n, code in enumerate(faults, 1))
        main = r'''
int main(void){
 for(unsigned fault=0;fault<=FAULTS;fault++){
  struct pwns_parent*s=&wifi_native_parent;memset(s,0,sizeof(*s));
  s->phase=PWNS_AUTH;s->auth.phase=PMSN_COPY;s->auth.ready=1;s->auth.assignments=3;
  s->copy.ready=s->copy.unknown=1;s->copy.pages=256;s->copy.segments=8;s->owner.held=1;
  wifi_native_boot_phase=5;wln_cpu_on_issued=wifi_native_copy_page_seen=holds=0;
  struct pmlc_copy*c=&s->copy;switch(fault){SWITCHES}
  if(!setjmp(stop))pmlc_page_checkpoint(c);
  assert(holds==1&&wifi_native_copy_page_seen==(fault?2u:1u));
 }
 return 0;
}
'''.replace('FAULTS', str(len(faults))).replace('SWITCHES', switches)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)/'page-callback.c'
            source.write_text(peer+actual+main)
            binary = source.with_suffix('')
            subprocess.run(['clang', '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                            str(source), '-o', str(binary)], check=True, capture_output=True)
            subprocess.run([str(binary)], check=True, capture_output=True)

    def test_reviews_cannot_be_used_with_the_other_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'review.json'
            for validator, scope, message in (
                    (native.validate, 'one_native_WiFi_firmware_diagnostic_RAM_trial', 'wrong trial review scope'),
                    (firmware.validate, 'one_native_WiFi_RO_RAMCOW_trial', 'wrong firmware-only review scope')):
                path.write_text(json.dumps(dict(scope=scope)))
                with self.subTest(scope=scope), self.assertRaisesRegex(ValueError, message):
                    validator(path)

    def test_page_translation_probe_holds_without_target_access(self):
        def actual_function(source, signature):
            start = source.index(signature)
            brace = source.index('{', start)
            depth, end = 1, brace+1
            while depth:
                depth += (source[end] == '{') - (source[end] == '}')
                end += 1
            return source[start:end]

        callback = actual_function(SOURCE, '__attribute__((noinline,noreturn)) static void pmlc_page_checkpoint(struct pmlc_copy*c)')
        header = (ROOT/'shim/polaris/uefi-wifi-remote-memory.h').read_text()
        valid = actual_function(header, 'static inline int pwmc_translation_valid(')
        peer = r'''
#include <assert.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>
#define EFI_XNU_WIFI_COPY_PAGE_PROBE 1
#define EFI_XNU_WIFI_COPY_PAGE_BEFORE 223
#define PMIM_SEGMENTS 28
#define PWNS_AUTH 19
#define PMSN_COPY 5
struct pwmc_translation {
 uint64_t page,saved,read_par,write_par,restored;
 uint32_t read_issued,read_returned,write_issued,write_returned;
};
struct pmlc_copy {unsigned ready,unknown,error,complete,pages,segments;uint64_t base;};
struct pmsn_state {unsigned phase,ready,pending,error,unknown,assignments;struct {uint64_t base;} modem;};
struct pwns_parent {unsigned phase,error,unknown;struct pmsn_state auth;
 struct pmlc_copy copy;struct {unsigned held,error,unknown;} owner;};
static struct pwns_parent wifi_native_parent;
static struct pwmc_translation wifi_native_copy_page_AT;
static unsigned wifi_native_boot_phase,wln_cpu_on_issued,wifi_native_copy_page_seen;
static unsigned wifi_native_copy_page_probe_result,holds,calls,failure;
static jmp_buf stop;
__attribute__((noreturn)) static void power_unknown_hold(void){holds++;longjmp(stop,1);}
static int pwmc_actual_translate(struct pwmc_translation*t){
 calls++;assert(t==&wifi_native_copy_page_AT&&t->page==UINT64_C(0xf81df000));
 t->saved=t->restored=0x1234;t->read_issued=t->read_returned=t->write_issued=t->write_returned=1;
 t->read_par=t->write_par=UINT64_C(0xff00000000000b80)|t->page;
 if(failure==7)t->read_par=0x10f;
 if(failure==8)t->write_par=0x10f;
 if(failure==9)t->restored++;
 if(failure==10)t->read_returned=0;
 if(failure==11)t->write_returned=0;
 return failure!=6;
}
'''
        main = r'''
int main(void){
 for(failure=0;failure<12;failure++){
  struct pwns_parent*s=&wifi_native_parent;memset(s,0,sizeof(*s));
  memset(&wifi_native_copy_page_AT,0,sizeof(wifi_native_copy_page_AT));
  s->phase=PWNS_AUTH;s->auth.phase=PMSN_COPY;s->auth.ready=1;s->auth.assignments=3;
  s->copy.ready=s->copy.unknown=1;s->copy.pages=223;s->copy.segments=8;s->owner.held=1;
  s->copy.base=s->auth.modem.base=UINT64_C(0xf8100000);
  wifi_native_boot_phase=5;wln_cpu_on_issued=wifi_native_copy_page_seen=0;
  wifi_native_copy_page_probe_result=holds=calls=0;
  struct pmlc_copy*c=&s->copy;
  if(failure==1)c=(void*)1;
  if(failure==2)s->copy.base+=0x100000;
  if(failure==3)s->copy.base=s->auth.modem.base=0x70000000;
  if(failure==4)s->copy.base=s->auth.modem.base=0xf8101000;
  if(failure==5)s->copy.base=s->auth.modem.base=UINT64_C(0x100000000);
  if(!setjmp(stop))pmlc_page_checkpoint(c);
  assert(holds==1);
  if(failure>=1&&failure<=5){assert(wifi_native_copy_page_seen==2&&!calls&&!wifi_native_copy_page_probe_result);}
  else{assert(wifi_native_copy_page_seen==1&&calls==1&&wifi_native_copy_page_probe_result==(failure?2u:1u));}
  assert(!s->copy.complete&&s->copy.pages==223&&s->copy.segments==8);
 }
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)/'page-at.c'
            source.write_text(peer+valid+callback+main)
            binary = source.with_suffix('')
            subprocess.run(['clang', '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                            '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                            str(source), '-o', str(binary)], check=True, capture_output=True)
            subprocess.run([str(binary)], check=True, capture_output=True)

    def test_probe_compile_guard_rejects_other_profiles(self):
        for mode, enabled in ((8, 1), (9, -1), (9, 2)):
            text = ('#define EFI_XNU_WIFI_FIRMWARE_DIAGNOSTIC_ONLY 1\n'
                    '#define EFI_XNU_WIFI_NATIVE_RUNTIME_AVAILABLE 1\n'
                    f'#define EFI_XNU_WIFI_AUTH_METADATA_CHECKPOINT {mode}\n'
                    f'#define EFI_XNU_WIFI_COPY_PAGE_PROBE {enabled}\n'
                    + ('#define EFI_XNU_WIFI_COPY_PAGE_BEFORE 223\n' if mode==9 else '') + GUARD)
            result = subprocess.run(['clang', '-x', 'c', '-fsyntax-only', '-'],
                                    input=text, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('page translation probe', result.stderr)

    def test_after_write_callback_requires_returned_words_and_unissued_cache(self):
        def function(source, signature):
            start=source.index(signature);end=source.index('{',start)+1;depth=1
            while depth:
                depth+=(source[end]=='{')-(source[end]=='}');end+=1
            return source[start:end]
        callback=function(SOURCE,'__attribute__((noinline,noreturn)) static void pmlc_page_checkpoint(struct pmlc_copy*c)')
        header=(ROOT/'shim/polaris/uefi-wifi-remote-memory.h').read_text()
        valid=function(header,'static inline int pwmc_translation_valid(')
        peer=r'''
#include <assert.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>
#define EFI_XNU_WIFI_COPY_PAGE_AFTER_WRITE 1
#define EFI_XNU_WIFI_COPY_PAGE_BEFORE 223
#define PMIM_SEGMENTS 28
#define PWNS_AUTH 19
#define PMSN_COPY 5
struct pwmc_translation {uint64_t page,saved,read_par,write_par,restored;uint32_t read_issued,read_returned,write_issued,write_returned;};
struct pmsi_page {struct pwmc_translation target;struct {unsigned attempted,complete;} cache;unsigned bytes,words_issued,words_returned,complete;};
struct pmlc_copy {unsigned ready,unknown,error,complete,pages,segments;uint64_t base;struct pmsi_page page[224];};
struct pmsn_state {unsigned phase,ready,pending,error,unknown,assignments;struct {uint64_t base;} modem;};
struct pwns_parent {unsigned phase,error,unknown;struct pmsn_state auth;struct pmlc_copy copy;struct {unsigned held,error,unknown;} owner;};
static struct pwns_parent wifi_native_parent;
static unsigned wifi_native_boot_phase,wln_cpu_on_issued,wifi_native_copy_page_seen,holds;
static jmp_buf stop;
__attribute__((noreturn)) static void power_unknown_hold(void){holds++;longjmp(stop,1);}
static int pwmc_zero(const void*p,unsigned n){const uint8_t*b=p;for(unsigned j=0;j<n;j++)if(b[j])return 0;return 1;}
'''
        main=r'''
int main(void){for(unsigned fault=0;fault<17;fault++){
 struct pwns_parent*s=&wifi_native_parent;memset(s,0,sizeof(*s));
 s->phase=PWNS_AUTH;s->auth.phase=PMSN_COPY;s->auth.ready=1;s->auth.assignments=3;s->owner.held=1;
 struct pmlc_copy*c=&s->copy;c->ready=c->unknown=1;c->pages=223;c->segments=8;c->base=s->auth.modem.base=0xf8100000;
 struct pmsi_page*p=&c->page[223];p->target.page=0xf81df000;
 p->target.read_par=p->target.write_par=UINT64_C(0xff000000f81dfb80);
 p->target.read_issued=p->target.read_returned=p->target.write_issued=p->target.write_returned=1;
 p->words_issued=p->words_returned=512;
 wifi_native_boot_phase=5;wln_cpu_on_issued=wifi_native_copy_page_seen=holds=0;
 switch(fault){
 case 1:c=(void*)1;break;case 2:wifi_native_boot_phase=4;break;
 case 3:s->copy.base+=0x100000;break;case 4:s->copy.base=s->auth.modem.base=0x70000000;break;
 case 5:s->copy.base=s->auth.modem.base=0xf8101000;break;case 6:p->target.page+=4096;break;
 case 7:p->target.read_par=0x10f;break;case 8:p->words_issued--;break;case 9:p->words_returned--;break;
 case 10:p->complete=1;break;case 11:p->cache.attempted=1;break;case 12:p->cache.complete=1;break;
 case 13:p->bytes=4097;break;case 14:p->target.restored=1;break;
 case 15:p->target.write_par=0x10f;break;case 16:s->owner.error=1;break;
 }
 struct pwns_parent saved=*s;if(!setjmp(stop))pmlc_page_checkpoint(c);
 assert(holds==1&&wifi_native_copy_page_seen==(fault?2u:1u));assert(!memcmp(&saved,s,sizeof(saved)));
}return 0;}
'''
        with tempfile.TemporaryDirectory() as directory:
            source=Path(directory)/'page-write.c';source.write_text(peer+valid+callback+main)
            binary=source.with_suffix('')
            subprocess.run(['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror',
                            '-fsanitize=address,undefined','-fno-sanitize-recover=all',str(source),'-o',str(binary)],check=True,capture_output=True)
            subprocess.run([str(binary)],check=True,capture_output=True)


if __name__ == '__main__':
    unittest.main()
