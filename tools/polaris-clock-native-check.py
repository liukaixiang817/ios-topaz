#!/usr/bin/env python3
"""Run the actual native poll/seal/RAM-calendar body with software clock/cache
adapters. Native AArch64 object compilation separately checks real instructions.
No USB, kernel, physical counter, RTC or storage is touched by this check.
"""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent


def replace_function(text, name, replacement):
    # Deliberately limited to four local counter/cache adapter definitions.
    start = text.index("static ", text.index(name) - 30)
    opening = text.index("{", text.index(name))
    depth = 1
    end = opening + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[:start] + replacement + text[end:]


def main():
    native = (ROOT / "polaris-clock-native.h").read_text()
    native = replace_function(native, "pc_counter(void)", "static uint64_t pc_counter(void){return fake_ticks;}")
    native = replace_function(native, "pc_frequency(void)", "static uint64_t pc_frequency(void){return fake_frequency;}")
    native = replace_function(native, "pc_cache_line(void)", "static uint64_t pc_cache_line(void){return 64;}")
    native = replace_function(native, "pc_cache(uintptr_t", "static void pc_cache(uintptr_t p,bool clean){(void)p;(void)clean;cache_calls++;}")
    harness = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
typedef uint32_t clock_sec_t,clock_usec_t;
static uint64_t fake_ticks=19200000,fake_frequency=19200000,calendar_us,calendar_ticks;
static unsigned clock_sets,cache_calls,checks;
static bool root_allowed;
static bool polaris_ram_overlay_allowed(void){return root_allowed;}
static void clock_set_calendar_microtime(clock_sec_t,clock_usec_t);
static void clock_get_calendar_microtime(clock_sec_t *,clock_usec_t *);
#include "native.h"
#include "polaris-clock-uefi.h"
static void clock_set_calendar_microtime(clock_sec_t s,clock_usec_t us)
{clock_sets++;calendar_us=(uint64_t)s*1000000+us;calendar_ticks=fake_ticks;polaris_clock_ram_set(s,us);}
static void clock_get_calendar_microtime(clock_sec_t *s,clock_usec_t *us)
{uint64_t elapsed=0;assert(pc_elapsed_us(calendar_ticks,fake_ticks,&elapsed));
 uint64_t v=calendar_us+elapsed;*s=(clock_sec_t)(v/1000000);*us=(clock_usec_t)(v%1000000);}
static uint64_t fake_counter(void *x){(void)x;return fake_ticks;}
static uint64_t fake_hz(void *x){(void)x;return fake_frequency;}
static void fake_cache(void *x,uintptr_t p,size_t n){(void)x;(void)p;(void)n;cache_calls++;}
#define CHECK(x) do {assert(x);checks++;}while(0)
int main(void)
{
 struct pc_fw f={0};struct pc_fw_io io={fake_counter,fake_hz,fake_cache,fake_cache,NULL};
 CHECK(pc_fw_prepare(&f,&polaris_uefi_clock,19,&io,true));
 polaris_clock_poll();CHECK(!polaris_uefi_clock.kernel.magic && !clock_sets);
 root_allowed=true;fake_ticks+=PC_FREQUENCY/10;polaris_clock_poll();
 CHECK(polaris_uefi_clock.kernel.status==PC_READY && pc_bound);
 clock_sec_t sec=0;clock_usec_t us=0;CHECK(!polaris_clock_ram_get(&sec,&us));
 uint8_t wire[60];CHECK(pc_fw_probe(&f,1,wire));
 uint64_t epoch=UINT64_C(1793404800000000),anchor=f.rx+(f.tx-f.rx)/2;
 CHECK(pc_fw_set(&f,1,epoch,anchor,12000));
 polaris_clock_poll();CHECK(!clock_sets); /* 100ms resident-thread budget */
 fake_ticks+=PC_FREQUENCY/10;uint64_t unchanged_counter=fake_ticks;polaris_clock_poll();
 CHECK(clock_sets==1 && fake_ticks==unchanged_counter);
 CHECK(polaris_uefi_clock.kernel.status==PC_APPLIED && polaris_uefi_clock.kernel.sequence==1);
 CHECK(polaris_clock_ram_get(&sec,&us) && (uint64_t)sec*1000000+us==epoch+100000);
 fake_ticks+=PC_FREQUENCY;CHECK(polaris_clock_ram_get(&sec,&us) && (uint64_t)sec*1000000+us==epoch+1100000);
 CHECK(pc_fw_probe(&f,2,wire));anchor=f.rx+(f.tx-f.rx)/2;
 CHECK(pc_fw_set(&f,2,epoch+2000000,anchor,12000));
 polaris_uefi_clock.firmware.source=2; /* corrupt producer denied natively */
 polaris_clock_poll();CHECK(clock_sets==1 && polaris_uefi_clock.kernel.status==PC_REJECTED);
 CHECK(polaris_uefi_clock.kernel.error==PC_BAD_SOURCE && polaris_uefi_clock.kernel.sequence==2);
 CHECK(pc_fw_probe(&f,3,wire));anchor=f.rx+(f.tx-f.rx)/2;
 CHECK(pc_fw_set(&f,3,epoch+3000000,anchor,12000));
 fake_ticks+=PC_FREQUENCY/10;polaris_clock_poll();CHECK(clock_sets==2);
 CHECK(pc_fw_status_wire(&f,wire) && polaris_uefi_clock.kernel.applied_count==2);
 CHECK(pc_fw_probe(&f,4,wire));anchor=f.rx+(f.tx-f.rx)/2;
 CHECK(pc_fw_set(&f,4,epoch+4000000,anchor,12000));
 fake_ticks+=PC_MAX_AGE_TICKS+1;polaris_clock_poll();
 CHECK(clock_sets==2 && polaris_uefi_clock.kernel.error==PC_BAD_COUNTER);
 polaris_clock_seal();CHECK(polaris_uefi_clock.kernel.status==PC_SEALED);
 CHECK(!pc_fw_probe(&f,5,wire));
 fake_ticks+=PC_FREQUENCY;polaris_clock_poll();CHECK(clock_sets==2);
 CHECK(cache_calls>10 && !polaris_uefi_clock.kernel.reserved[4]);
 printf("PASS %u actual native-body software checks; counter/cache/kernel-clock adapters only\n",checks);
 return 0;
}
'''
    with tempfile.TemporaryDirectory(prefix="polaris-clock-native-check-") as directory:
        temp = Path(directory)
        (temp / "native.h").write_text(native)
        (temp / "polaris_clock_wire.h").write_bytes((ROOT / "polaris-clock-sync.h").read_bytes())
        (temp / "check.c").write_text(harness)
        subprocess.run(["clang", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                        "-fsanitize=address,undefined", "-I", str(ROOT), str(temp / "check.c"),
                        "-o", str(temp / "check")], check=True)
        subprocess.run([str(temp / "check")], check=True)


if __name__ == "__main__":
    main()
