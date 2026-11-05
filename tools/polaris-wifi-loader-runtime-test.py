#!/usr/bin/env python3
"""Execute the actual loader's native boot body with software producer leaves.

This checks call ordering, state transitions and terminal failure propagation;
it does not qualify the complete producers, timing, privileged calls or DMA.
"""
import json
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
out = Path(sys.argv[1]).resolve()
out.mkdir(parents=True, exist_ok=True)
source = (root / "shim/polaris/uefi-xnu.c").read_text()
start = source.index("__attribute__((noreturn)) static void wifi_native_boot(void)")
opening = source.index("{", start)
depth = 1
end = opening + 1
while depth:
    depth += (source[end] == "{") - (source[end] == "}")
    end += 1
body = source[start:end]
prefix = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <setjmp.h>
#define EFI_XNU_BUTTONS_AVAILABLE 1
#define EFI_XNU_WLED_NATIVE_RUNTIME 1
#define EFI_XNU_DURABLE_GUARD 1
#define EFI_XNU_PHYSICAL_MARKER 1
#define EFI_XNU_GCD_MMIO_QUERY_AVAILABLE 1
#define EFI_XNU_PAYLOAD_BYTES 1024
#define EFI_XNU_LOG_SIZE 4096
#define EFI_XNU_MSS_PAYLOAD_FIRMWARE_AVAILABLE 1
#define EFI_XNU_MSS_FIRMWARE_OFFSET 128
#define PMSF_BLOB_BYTES 256
#define PMSF_ASSETS 28
#define POLARIS_WIFI_IMAGE_NONCE_BYTES 2128
#define EFI_XNU_WIFI_MAILBOX_VA UINT64_C(0xfffffe0007c04000)
#define EFI_XNU_WIFI_SHUTDOWN_VA UINT64_C(0xfffffe0006002000)
#define EFI_XNU_WIFI_COUNTRY 36
typedef _Bool bool;
#define false 0
#define true 1
static unsigned checks,calls,fail_at,failed,completed,unexpected,turns,polls,steps;
static unsigned terminal_mode,terminal_steps,wifi_native_terminal;
static unsigned events[64],states[64];static jmp_buf terminal;
#define CHECK(x) do{checks++;if(!(x)){fprintf(stderr,"line%d: %s\n",__LINE__,#x);exit(1);}}while(0)
static unsigned load_state,wifi_native_prepared,wifi_native_boot_phase,log_overflow;
static unsigned early_wifi_memory,retained_wifi_memory,mss_memory,mss_stage,mss_mba_share;
static uint8_t early_wifi_digest[32],mss_memory_digest[32],pmsf_assets[28],pmsf_segments[28];
static uint8_t storage[1024],*payload=storage,*log_snapshot,log_buffer[64],ap_stack[4096];
static uint8_t polaris_wifi_image_nonces[2128],polaris_wifi_image_nonce_sha256[32];
static uint64_t received=1024,payload_count=1024;
static unsigned mss_retained_attempted,mss_retained_ok,pgcd_resident_context;
static unsigned wifi_native_nv,wifi_native_ce_memory,wifi_native_htt_memory,polaris_efi_ap_state;
static struct {unsigned terminal_requested;}wifi_native_worker;
static int64_t cpu_status;
static struct {unsigned active;}ram_lease;
static struct {struct {struct {int64_t result;}runtime;}owner;}wifi_native_parent;
struct args {char cmdline[608];};static struct args arguments;
static struct {uint64_t args_pa;}plan;
struct pweh_input {
 const void*early;const uint8_t*digest;uint8_t**payload_slot,**log_slot;unsigned*state;
 uint64_t*received,*count;uint64_t logical_bytes,log_bytes;
};
static int record(unsigned id)
{CHECK(calls<64);states[calls]=load_state;events[calls++]=id;if(calls==fail_at){failed=1;return 0;}return 1;}
static void buttons_prepare(void){unexpected++;}
static void wln_begin(void){unexpected++;}
static void polaris_efi_ap_entry(void){unexpected++;}
__attribute__((noreturn)) static void power_unknown_hold(void){longjmp(terminal,1);}
static int polaris_marker_append_guard(char*p,size_t n,bool physical)
{CHECK(p==arguments.cmdline&&n==608&&physical);return record(1);}
static void clean(uint64_t p,uint64_t n){CHECK(p==plan.args_pa&&n==sizeof(arguments));CHECK(record(2));}
static int new_original_unknown(void){return log_overflow;}
static int pacgq_prestart_checkpoint(void*p){CHECK(p==&pgcd_resident_context);return record(3);}
static int pweh_run(void*p,const struct pweh_input*i)
{CHECK(p==&retained_wifi_memory&&i->state==&load_state&&*i->state==2&&i->payload_slot==&payload&&i->early==&early_wifi_memory&&i->logical_bytes==1024);return record(4);}
static void pweh_digest(const void*p,unsigned n,uint8_t*h)
{CHECK(p==polaris_wifi_image_nonces&&n==2128);memset(h,0,32);CHECK(record(5));}
static int pgcd_equal(const void*a,const void*b,unsigned n)
{CHECK(a&&b==polaris_wifi_image_nonce_sha256&&n==32);return record(6);}
static int pmmn_retained(const void*m,const void*d,const void*h)
{CHECK(m==&mss_memory&&d==mss_memory_digest&&h==&retained_wifi_memory);return record(7);}
static int pmsi_stage(void*s,const void*m,const void*d,const void*h,const void*f,unsigned z,const void*a,unsigned n)
{CHECK(s==&mss_stage&&m==&mss_memory&&d==mss_memory_digest&&h==&retained_wifi_memory&&f==payload+128&&z==256&&a==pmsf_assets&&n==28);return record(8);}
static int pmsb_share(void*b,const void*s){CHECK(b==&mss_mba_share&&s==&mss_stage);return record(9);}
static int pwns_begin(void*p,const void*h,const void*m,const void*d,const void*b,void*n,void*c,void*t,const void*g,const void*r,const void*hash)
{CHECK(p==&wifi_native_parent&&h==&retained_wifi_memory&&m==&mss_memory&&d==mss_memory_digest&&b==&mss_mba_share&&n==&wifi_native_nv&&c==&wifi_native_ce_memory&&t==&wifi_native_htt_memory&&g==pmsf_segments&&r==polaris_wifi_image_nonces&&hash==polaris_wifi_image_nonce_sha256);return record(10);}
static int pwns_step(void*p){CHECK(p==&wifi_native_parent&&load_state==2);if(!record(11))return -1;return ++turns==3?2:1;}
static int pwkr_begin(void*p,const void*k,void*a,uint64_t e,uint64_t b,uint64_t z,const void*q,uint64_t va);
static unsigned wifi_native_kernel_copy;
static int pwkr_begin(void*p,const void*k,void*a,uint64_t e,uint64_t b,uint64_t z,const void*q,uint64_t va)
{CHECK(p==&wifi_native_parent&&k==&wifi_native_kernel_copy&&a==&polaris_efi_ap_state&&e==(uintptr_t)polaris_efi_ap_entry&&b==(uintptr_t)ap_stack&&z==sizeof(ap_stack)&&q==&plan&&va==EFI_XNU_WIFI_MAILBOX_VA&&turns==3&&load_state==2);if(!record(12))return -1;load_state=4;return 1;}
static int pwkr_poll(void*p){CHECK(p==&wifi_native_parent&&load_state==4);if(!record(13))return 0;return ++polls==2?2:1;}
static int pwwn_begin(void*w,void*p,unsigned country)
{CHECK(w==&wifi_native_worker&&p==&wifi_native_parent&&country==36&&polls==2);return record(14);}
static int pwwn_step(void*w)
{CHECK(w==&wifi_native_worker&&load_state==4);if(!record(15))return -1;if(++steps==3){
 if(terminal_mode){wifi_native_worker.terminal_requested=terminal_mode!=2;return terminal_mode==3?3:2;}
 completed=1;longjmp(terminal,2);}return 1;}
static int pwno_begin(void*s,void*w,uint64_t va)
{CHECK(s==&wifi_native_terminal&&w==&wifi_native_worker&&w&&wifi_native_worker.terminal_requested&&va==EFI_XNU_WIFI_SHUTDOWN_VA&&wifi_native_boot_phase==9);return record(16);}
static int pwno_step(void*s)
{CHECK(s==&wifi_native_terminal&&wifi_native_boot_phase==10);if(!record(17))return -1;
 if(terminal_mode==4)return 0;if(++terminal_steps==2){completed=1;longjmp(terminal,3);}return 1;}
'''
suffix = r'''
static void reset(void)
{calls=failed=completed=unexpected=turns=polls=steps=terminal_mode=terminal_steps=0;wifi_native_worker.terminal_requested=0;load_state=2;wifi_native_prepared=1;wifi_native_boot_phase=log_overflow=0;ram_lease.active=1;plan.args_pa=(uintptr_t)&arguments;memset(events,0,sizeof(events));memset(log_buffer,0,sizeof(log_buffer));}
int main(void)
{
 reset();fail_at=0;int r=setjmp(terminal);if(!r)wifi_native_boot();
 CHECK(r==2&&completed&&!failed&&!unexpected&&!ram_lease.active&&wifi_native_boot_phase==8&&load_state==4);
 const unsigned expected[]={1,2,3,4,5,6,7,8,9,10,11,11,11,12,13,13,14,15,15,15};
 CHECK(calls==20&&!memcmp(events,expected,sizeof(expected)));
 for(unsigned n=0;n<20;n++)CHECK(states[n]==(n<14?2u:4u));
 for(unsigned fail=1;fail<=20;fail++){
   if(fail==2||fail==5)continue; /* Non-failing native RAM helpers. */
   reset();fail_at=fail;r=setjmp(terminal);if(!r)wifi_native_boot();
   CHECK(r==1&&failed&&!completed&&!unexpected&&calls==fail&&!ram_lease.active);
 }
 for(unsigned invalid=0;invalid<4;invalid++){
   reset();fail_at=0;if(invalid==0)load_state=3;if(invalid==1)wifi_native_prepared=0;if(invalid==2)wifi_native_boot_phase=1;if(invalid==3)log_overflow=1;
   r=setjmp(terminal);if(!r)wifi_native_boot();CHECK(r==1&&!completed&&!unexpected&&calls==(invalid==3?2u:0u));
 }
 reset();terminal_mode=1;fail_at=0;r=setjmp(terminal);if(!r)wifi_native_boot();
 CHECK(r==3&&completed&&!failed&&!unexpected&&wifi_native_boot_phase==10&&calls==23);
 CHECK(!memcmp(events,expected,sizeof(expected))&&events[20]==16&&events[21]==17&&events[22]==17);
 for(unsigned fail=21;fail<=23;fail++){
   reset();terminal_mode=1;fail_at=fail;r=setjmp(terminal);if(!r)wifi_native_boot();
   CHECK(r==1&&failed&&!completed&&!unexpected&&calls==fail);
 }
 for(unsigned mode=2;mode<=4;mode++){
   reset();terminal_mode=mode;fail_at=0;r=setjmp(terminal);if(!r)wifi_native_boot();
   CHECK(r==1&&!completed&&!unexpected&&calls==(mode==4?22u:20u));
 }
 printf("PASS %u extracted native loader call-order checks; SOFTWARE leaves, no full parent/CPU/DMA\n",checks);return 0;
}
'''
(out / "actual-body.c").write_text(prefix + body + suffix)
cmd = ["clang", "-std=c11", "-O1", "-g", "-fsanitize=address,undefined",
       "-fno-sanitize-recover=all", "-Wall", "-Wextra", "-Werror",
       str(out / "actual-body.c"), "-o", str(out / "actual-body-test")]
(out / "callsite-command.json").write_text(json.dumps(cmd, indent=2) + "\n")
subprocess.run(cmd, check=True)
result = subprocess.run([str(out / "actual-body-test")], text=True, capture_output=True)
(out / "callsite-test.log").write_text(result.stdout + result.stderr)
print(result.stdout + result.stderr, end="")
sys.exit(result.returncode)
