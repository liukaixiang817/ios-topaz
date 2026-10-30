#!/usr/bin/env python3
"""Execute the actual WLED state machine as an isolated AArch64 EFI program.

The PMIC is explicitly a software fixture. Softstart uses the guest's real
architectural clock and cooperative EFI stalls. No phone image is produced.
"""
import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--zig', type=Path, required=True)
    ap.add_argument('--oem-status', action='store_true',
                    help='Exercise the separate volatile-status policy; no phone image/admission')
    ap.add_argument('--runtime-core', action='store_true',
                    help='Isolated runtime policy core with SOFTWARE PMIC; requires --oem-status, no native integration')
    ap.add_argument('--qemu', type=Path, default=Path('/opt/homebrew/bin/qemu-system-aarch64'))
    a = ap.parse_args()
    if a.runtime_core and not a.oem_status:
        ap.error('--runtime-core requires explicit --oem-status')
    root = Path(__file__).resolve().parents[1]
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(root))
    fixture = importlib.import_module('tools.tests.test_polaris_wled_power')
    if a.oem_status:
        fixture = importlib.import_module('tools.tests.test_polaris_wled_status')
    if a.runtime_core:
        fixture = importlib.import_module('tools.tests.test_polaris_wled_runtime')
    prefix = r'''
#include "uefi.h"
static unsigned checks;
static void serial(const char *s) {
 volatile uint32_t *uart=(void*)(uintptr_t)0x9000000;
 while(*s){while(uart[6]&(1u<<5))__asm__ volatile("yield");uart[0]=(uint8_t)*s++;}
}
static void checked(int ok) {
 if(!ok){serial("WLED_POWER_MODEL_FAILED\n");for(;;)__asm__ volatile("wfe");}
 checks++;
}
static void number(const char *name,uint64_t value) {
 char bytes[18];bytes[0]='0';bytes[1]='x';
 for(unsigned n=0;n<16;n++)bytes[2+n]="0123456789abcdef"[(value>>(60-4*n))&15];
 serial(name);for(unsigned n=0;n<18;n++){char out[2]={bytes[n],0};serial(out);}serial("\n");
}
#define assert(c) checked(!!(c))
static void *memset(void *p,int c,size_t count) {
 for(size_t n=0;n<count;n++)((unsigned char*)p)[n]=(unsigned char)c;return p;
}
static void *memcpy(void *p,const void *s,size_t count) {
 for(size_t n=0;n<count;n++)((unsigned char*)p)[n]=((const unsigned char*)s)[n];return p;
}
static int memcmp(const void *a,const void *b,size_t count) {
 for(size_t n=0;n<count;n++)if(((const unsigned char*)a)[n]!=((const unsigned char*)b)[n])return 1;
 return 0;
}
'''
    # Same independently asserted register semantics as ASan/UBSan tests.
    body = (fixture.H if a.runtime_core else fixture.OEM_H if a.oem_status else fixture.H).replace(
        '#include <assert.h>', '').replace('#include <string.h>', '').replace('#include <stdlib.h>', '')
    suffix = r'''
static uint64_t actual_clock(void *ctx) {
 struct fake *f=ctx;uint64_t ticks,freq;
 __asm__ volatile("mrs %0,cntvct_el0":"=r"(ticks));
 __asm__ volatile("mrs %0,cntfrq_el0":"=r"(freq));
 assert(freq&&freq<=1000000000);
 return f->time=ticks/freq*1000000+(ticks%freq)*1000000/freq;
}
static void actual_drive(struct efi_system *st,struct polaris_wled_power *p,uint64_t seq) {
 uint64_t began=actual_clock(p->bus->context);unsigned service=0;
 while(p->acknowledged!=seq) {
  assert(actual_clock(p->bus->context)-began<200000);
  assert(pwp_poll(p));service++;assert(!st->boot->stall(100));
 }
 assert(service>1);
}
efi_status EfiMain(efi_handle image,struct efi_system *st) {
 (void)image;assert(st&&st->boot&&st->boot->stall);
 serial("WLED_POWER_MODEL_SOFTWARE_PMIC_ONLY\n");
 uint64_t el;__asm__ volatile("mrs %0,CurrentEL":"=r"(el));assert(el==4);
 number("WLED_POWER_CURRENT_EL=",el);
 struct fake f;struct polaris_wled_read_bus b;struct polaris_wled_power p;
 start(&f,&b,&p);b.now_us=actual_clock;p.previous_us=0;
 assert(pwp_request(&p,1,false));actual_drive(st,&p,1);
 assert(!p.actual_on&&!pwp_restored(&p));
 assert(pwp_request(&p,2,true));actual_drive(st,&p,2);
 assert(pwp_restored(&p)&&!memcmp(f.original,f.pmic,sizeof(f.pmic)));
 assert(f.writes==4&&p.completed==4&&f.ovp_time-f.enable_time>=10000);
 number("WLED_POWER_SOFTSTART_US=",f.ovp_time-f.enable_time);
 serial("WLED_POWER_ACTUAL_CLOCK_OFF_ON_PASS\n");
 start(&f,&b,&p);assert(pwp_request(&p,1,false)&&pwp_request(&p,2,true));
 until_ack(&f,&p,2);assert(!f.writes&&pwp_restored(&p));
 serial("WLED_POWER_COALESCED_PASS\n");
 start(&f,&b,&p);assert(pwp_request(&p,1,false)&&pwp_poll(&p));
 f.foreign_owner=1;assert(!pwp_poll(&p)&&!f.writes&&!pwp_restored(&p));
 serial("WLED_POWER_FOREIGN_OWNER_PASS\n");
 start(&f,&b,&p);assert(pwp_request(&p,1,false)&&pwp_poll(&p));
 f.pmic[0][0x5a]^=1;assert(!pwp_poll(&p)&&!f.writes&&!pwp_restored(&p));
 serial("WLED_POWER_CHANGED_CONFIG_PASS\n");
 start(&f,&b,&p);f.fail_write=1;f.status=0;
 assert(pwp_request(&p,1,false)&&pwp_poll(&p));assert(!pwp_poll(&p));
 assert(p.uncertain&&p.completed==0&&f.writes==1&&p.error==PWP_E_WRITE_TIMEOUT);
 for(unsigned n=0;n<100;n++)assert(!pwp_poll(&p));
 assert(f.writes==1&&!pwp_restored(&p));serial("WLED_POWER_UNCERTAIN_NO_RETRY_PASS\n");
 start(&f,&b,&p);assert(pwp_request(&p,1,false));until_ack(&f,&p,1);
 assert(pwp_request(&p,2,true));while(p.phase!=PWP_SOFTSTART)assert(pwp_poll(&p));
 p.phase=PWP_ON_IRQ;assert(!pwp_poll(&p)&&p.error==PWP_E_CLOCK&&f.writes==3);
 serial("WLED_POWER_EARLY_IRQ_RESTORE_REFUSED\n");
 assert(checks>1000);serial("WLED_POWER_MODEL_DONE\n");
 for(;;)__asm__ volatile("wfe");
}
'''
    if a.oem_status and not a.runtime_core:
        oem_checks = r'''
 setup(&f,&b,&p);b.now_us=actual_clock;
 struct polaris_wled_snapshot expected;
 assert(polaris_wled_inventory(&b,&expected));
 f.pulse=1;b.read_command=dynamic_command;
 assert(pwp_init_oem_status(&p,&b,&expected,false));
 assert(pwp_request(&p,1,false));actual_drive(st,&p,1);
 assert(!p.actual_on&&!pwp_restored(&p));
 assert(pwp_request(&p,2,true));actual_drive(st,&p,2);
 assert(pwp_restored(&p)&&f.writes==4&&!p.uncertain);
 assert(f.ovp_time-f.enable_time>=10000);
 number("WLED_POWER_OEM_SOFTSTART_US=",f.ovp_time-f.enable_time);
 assert(p.witness.fault_or==1&&p.witness.rt_or==1&&p.witness.count>=24);
 unsigned high=0,low=0;
 for(unsigned n=0;n<p.witness.count;n++) {
  assert(p.witness.record[n].valid==3);
  high+=p.witness.record[n].fault==1;low+=p.witness.record[n].fault==0;
 }
 assert(high&&low);serial("WLED_POWER_OEM_VOLATILE_CYCLE_PASS\n");
 for(unsigned bank=0;bank<2;bank++)for(unsigned bit=1;bit<8;bit++) {
  oem_start(&f,&b,&p,0);unsigned count=p.witness.count;
  f.pmic[0][bank?0x10:8]=(uint8_t)(1u<<bit);
  assert(!pwp_verify(&p)&&p.error==PWS_E_STATUS&&!f.writes&&!pwp_restored(&p));
  assert((bank?p.witness.rt_or:p.witness.fault_or)&(1u<<bit));
  assert((bank?p.witness.record[count].rt:p.witness.record[count].fault)==(1u<<bit));
 }
 serial("WLED_POWER_OEM_ALL_SEVERE_UNKNOWN_PASS\n");
 for(unsigned bad=0;bad<3;bad++) {
  oem_start(&f,&b,&p,1);assert(pwp_request(&p,1,false)&&pwp_poll(&p));
  if(bad==0)f.foreign_owner=1;
  if(bad==1)f.pmic[1][0x54]^=1;
  if(bad==2){f.fail_write=1;f.status=0;}
  assert(!pwp_poll(&p)&&!pwp_restored(&p)&&p.error);
  unsigned writes=f.writes;for(unsigned n=0;n<20;n++)assert(!pwp_poll(&p));
  assert(f.writes==writes&&writes==(bad==2?1u:0u));
 }
 serial("WLED_POWER_OEM_OWNER_CONFIG_UNCERTAIN_PASS\n");
 setup(&f,&b,&p);assert(polaris_wled_inventory(&b,&expected));
 f.pulse=1;b.read_command=dynamic_command;
 assert(!pwp_init(&p,&b,&expected,false)&&!f.writes&&b.fault==PW_E_CHANGED);
 assert(!pwp_init_oem_status(&p,&b,&expected,false)&&!f.writes);
 serial("WLED_POWER_OEM_NO_SWITCH_AFTER_REFUSAL_PASS\n");
'''
        suffix = suffix.replace(' assert(checks>1000);', oem_checks+' assert(checks>1000);')
    if a.runtime_core:
        suffix = (root/'tools/tests/polaris_wled_runtime_efi.c').read_text()
    source = out/'model.c'
    source.write_text(prefix+body+suffix)
    obj = out/'model.obj'
    app = out/'WledPowerModel.efi'
    commands = [[ '/usr/bin/clang', '--target=aarch64-unknown-windows', '-ffreestanding',
                 '-fno-builtin', '-fno-stack-protector', '-fshort-wchar', '-mgeneral-regs-only',
                 '-O2', '-Wall', '-Wextra', '-Werror', '-I'+str(root/'shim/polaris'),
                 '-c', str(source), '-o', str(obj)],
                [str(a.zig.resolve()), 'build-exe', str(obj), '-target', 'aarch64-uefi',
                 '--subsystem', 'efi_application', '-O', 'ReleaseSmall', '-femit-bin='+str(app)]]
    env = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(out/'zig-global'), ZIG_LOCAL_CACHE_DIR=str(out/'zig-local'))
    for n, cmd in enumerate(commands):
        p = subprocess.run(cmd, capture_output=True, env=env, timeout=120)
        (out/f'build-{n}.log').write_bytes(p.stdout+p.stderr)
        if p.returncode:
            raise RuntimeError('isolated EFI model build failed; see build log')
    esp = out/'esp/EFI/BOOT'
    esp.mkdir(parents=True)
    shutil.copyfile(app, esp/'BOOTAA64.EFI')
    shutil.copyfile('/opt/homebrew/share/qemu/edk2-arm-vars.fd', out/'vars.fd')
    cmd = [str(a.qemu), '-M', 'virt,gic-version=3,virtualization=off', '-cpu', 'cortex-a55',
           '-smp', '1', '-m', '1G', '-display', 'none', '-monitor', 'none', '-nic', 'none',
           '-serial', 'file:'+str(out/'serial.log'), '-no-reboot',
           '-drive', 'if=pflash,format=raw,readonly=on,file=/opt/homebrew/share/qemu/edk2-aarch64-code.fd',
           '-drive', 'if=pflash,format=raw,file='+str(out/'vars.fd'),
           '-drive', 'if=none,id=esp,format=raw,readonly=on,file=fat:ro:'+str(out/'esp'),
           '-device', 'virtio-blk-pci,drive=esp']
    began = time.monotonic()
    with (out/'qemu.log').open('wb') as log:
        p = subprocess.Popen(cmd, stdout=log, stderr=log)
        text = ''
        try:
            while time.monotonic()-began < 40:
                text = (out/'serial.log').read_text(errors='replace') if (out/'serial.log').exists() else ''
                if 'WLED_POWER_MODEL_DONE' in text or 'WLED_POWER_MODEL_FAILED' in text or p.poll() is not None:
                    break
                time.sleep(.1)
        finally:
            if p.poll() is None:
                p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill(); p.wait()
    expected = ['MODEL_SOFTWARE_PMIC_ONLY', 'ACTUAL_CLOCK_OFF_ON_PASS', 'COALESCED_PASS',
                'FOREIGN_OWNER_PASS', 'CHANGED_CONFIG_PASS', 'UNCERTAIN_NO_RETRY_PASS',
                'EARLY_IRQ_RESTORE_REFUSED', 'MODEL_DONE']
    if a.oem_status and not a.runtime_core:
        expected += ['OEM_VOLATILE_CYCLE_PASS', 'OEM_ALL_SEVERE_UNKNOWN_PASS',
                     'OEM_OWNER_CONFIG_UNCERTAIN_PASS', 'OEM_NO_SWITCH_AFTER_REFUSAL_PASS']
    if a.runtime_core:
        expected = ['MODEL_SOFTWARE_PMIC_ONLY', 'RUNTIME_REAL_CLOCK_16_CYCLES_PASS',
                    'RUNTIME_FINAL_NEW_READS_PASS', 'RUNTIME_CAPACITY_RESERVE_PASS',
                    'RUNTIME_ALL_SEVERE_PARTIAL_PASS', 'RUNTIME_UNCERTAIN_PASS',
                    'RUNTIME_MAILBOX_NO_RETRY_PASS', 'MODEL_DONE']
    checks = {name: text.count('WLED_POWER_'+name+'\n') == 1 for name in expected}
    values = {k: int(v,16) for k,v in re.findall(r'(WLED_POWER_\w+)=0x([0-9a-f]{16})',text)}
    checks['actual_EL1'] = values.get('WLED_POWER_CURRENT_EL') == 4
    softstart_field = 'WLED_POWER_RUNTIME_MIN_SOFTSTART_US' if a.runtime_core else 'WLED_POWER_SOFTSTART_US'
    checks['actual_architectural_softstart'] = values.get(softstart_field,0) >= 10000
    if a.oem_status and not a.runtime_core:
        checks['OEM_actual_architectural_softstart'] = values.get('WLED_POWER_OEM_SOFTSTART_US',0) >= 10000
    checks['no_assertion_failure'] = 'WLED_POWER_MODEL_FAILED' not in text
    paths = [Path(__file__).resolve(), root/'shim/polaris/uefi-wled-power.h',
             root/'shim/polaris/uefi-wled-readonly.h', root/'shim/polaris/uefi.h',
             root/'shim/polaris/uefi-wled-status.h',
             root/'tools/tests/test_polaris_wled_power.py']
    if a.oem_status:
        paths.append(root/'tools/tests/test_polaris_wled_status.py')
    if a.runtime_core:
        paths += [root/'shim/polaris/uefi-wled-runtime.h', root/'tools/polaris-wled-mailbox.h',
                  root/'tools/tests/test_polaris_wled_runtime.py', root/'tools/tests/polaris_wled_runtime_efi.c']
    result = dict(passed=all(checks.values()), checks=checks, seconds=time.monotonic()-began,
                  inputs={str(p.relative_to(root)): sha(p) for p in paths}, source_sha256=sha(source),
                  binary_sha256=sha(app), serial_sha256=sha(out/'serial.log'), raw_fields=values, command=cmd,
                  actual_phone_or_PMIC_emulated=False, phone_compatible=False,
                  release_handoff_admitted=False, XNU_started=False,
                  OEM_status_policy_explicit=a.oem_status,
                  runtime_core_only=a.runtime_core, native_runtime_integrated=False,
                  real_guest_clock_softstart=True, synthetic_fault_clocks=True)
    (out/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))
    raise SystemExit(not result['passed'])


if __name__ == '__main__':
    main()
