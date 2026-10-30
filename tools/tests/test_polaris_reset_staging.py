"""Execute the actual reset-arm admission guard; no PMIC/mapping/clock emulation."""
from pathlib import Path
import unittest
from .test_polaris_gpu_bootstrap import run
from .test_polaris_gpu_lifetime import function
ROOT=Path(__file__).resolve().parents[2]


class ResetStaging(unittest.TestCase):
    def test_sticky_native_failures_refuse_before_any_firmware_marker_call(self):
        body=function((ROOT/'shim/polaris/uefi-xnu.c').read_text(),'static int runtime_arm_reset(unsigned mode)')
        run(r'''
#include <stdint.h>
#include <assert.h>
#define POLARIS_EFI_TEST_QEMU 1
static unsigned runtime_reset_armed,runtime_reset_mode,runtime_reset_error,wln_actual_reset_entered;
static unsigned wln_cpu_on_issued=1,wln_closing_mode=2,calls;
static struct {unsigned error,uncertain,actual_on;} wln_power;
static struct {unsigned error,pending;} wln_runtime;
static struct {unsigned error;} wln_firmware;
static struct {void *reset_system;} runtime_table={(void *)(uintptr_t)1};
static struct {void *boot;__typeof__(&runtime_table) runtime;} table={0,&runtime_table},*system_table=&table;
static int cache_reset_protocol(void){calls++;return 1;}
static uint64_t buttons_us(void *x){(void)x;static uint64_t time=100;return ++time;}
static int runtime_unarm_reset(void){runtime_reset_armed=0;return 1;}
static void report(const char*s,uint64_t v){(void)s;(void)v;}
''' + body + r'''
int main(void){
 for(unsigned bad=1;bad<=10;bad++){
  runtime_reset_armed=runtime_reset_error=wln_actual_reset_entered=calls=0;
  wln_power.error=wln_power.uncertain=wln_runtime.error=wln_runtime.pending=wln_firmware.error=0;
  wln_power.actual_on=1;wln_closing_mode=2;
  if(bad==1)wln_power.error=65;
  if(bad==2)wln_runtime.error=96;
  if(bad==3)wln_firmware.error=128;
  if(bad==4)wln_power.uncertain=1;
  if(bad==5)wln_runtime.pending=1;
  if(bad==6)wln_power.actual_on=0;
  if(bad==7)wln_closing_mode=1;
  if(bad==8)runtime_reset_error=1;
  if(bad==9)wln_actual_reset_entered=1;
  assert(!runtime_arm_reset(bad==10?1:2)&&!calls&&!runtime_reset_armed);
 }
 runtime_reset_error=wln_actual_reset_entered=0;wln_closing_mode=2;wln_power.actual_on=1;
 assert(runtime_arm_reset(2)&&calls==1&&runtime_reset_armed&&runtime_reset_mode==2);
 assert(runtime_arm_reset(2)&&calls==1); /* No duplicate marker API. */
 runtime_reset_armed=calls=0;wln_cpu_on_issued=0;wln_power.error=32;wln_power.actual_on=0;
 assert(runtime_arm_reset(2)&&calls==1); /* Independent no-CPU/no-WLED-WRITE refusal path. */
 return 0;}
''')


if __name__=='__main__':unittest.main()
