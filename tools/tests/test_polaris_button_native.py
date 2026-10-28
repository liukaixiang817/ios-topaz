"""Compile actual native poll/delivery functions, not user-space HID success."""
from pathlib import Path
import importlib.util
import unittest
from .test_polaris_gpu_bootstrap import run
from .test_polaris_gpu_lifetime import function
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('builder',ROOT/'tools/build-polaris-uefi-xnu.py')
builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)


class NativeButtonTests(unittest.TestCase):
    def test_actual_loader_never_CPU_ON_after_button_precheck_refusal(self):
        text=(ROOT/'shim/polaris/uefi-xnu.c').read_text()
        actual=function(text,'static void boot_kernel(')
        # Only architectural register accesses are stubbed in this host test;
        # actual precheck/refusal/lease/load-state/PSCI ordering stays intact.
        actual=actual.replace('__asm__ volatile("mrs %0,cntvct_el0":"=r"(now));','now=100000;')
        actual=actual.replace('__asm__ volatile("msr daifset,#15; dsb sy; isb":::"memory");','masked=1;')
        actual=actual.replace('__asm__ volatile("msr ICC_IGRPEN1_EL1,%0; isb"::"r"(UINT64_C(0)):"memory");','group_disabled=1;')
        actual=actual.replace('__asm__ volatile("mrs %0,ICC_IGRPEN1_EL1":"=r"(group1));','group1=0;')
        self.assertNotIn('__asm__',actual)
        run('#include "'+str(ROOT/'shim/polaris/uefi-ram-lease.h')+'"\n'+r'''
#include <assert.h>
#define EFI_XNU_BUTTONS_AVAILABLE 1
#define EFI_XNU_CPU 1792u
static unsigned load_state,masked,group_disabled,checks,permitted,calls;
static int64_t cpu_status;static struct polaris_efi_ram_lease ram_lease;
static unsigned polaris_efi_ap_state;
static void polaris_efi_ap_entry(void){}
static void report(const char *s,uint64_t v){(void)s;(void)v;}
static int buttons_prepare(void){assert(masked&&group_disabled&&!calls);checks++;return permitted;}
static int64_t psci(uint64_t fn,uint64_t cpu,uint64_t entry,uint64_t arg){
 assert(checks&&permitted&&fn==UINT64_C(0xc4000003)&&cpu==1792);
 assert(entry==(uintptr_t)polaris_efi_ap_entry&&arg==(uintptr_t)&polaris_efi_ap_state);calls++;return 0;}
'''+actual+r'''
int main(void){load_state=2;boot_kernel(0);assert(!checks&&!calls&&load_state==2);
 load_state=3;boot_kernel(0);assert(checks==1&&!calls&&load_state==3&&ram_lease.active);
 permitted=1;boot_kernel(0);assert(checks==2&&calls==1&&load_state==4&&!cpu_status);
 boot_kernel(0);assert(checks==2&&calls==1);return 0;}
''')

    def test_actual_native_deliver_edges_refusal_timeout_and_shutdown(self):
        patch=(ROOT/'xnu/profiles/polaris/0890-polaris-three-physical-key-consumer.patch').read_text()
        added='\n'.join(l[1:] for l in patch.splitlines() if l.startswith('+') and not l.startswith('+++'))
        native=function(added,'static void pk_deliver(')+'\n'+function(added,'static void pk_poll(')
        run('#include "'+str(ROOT/'tools/polaris-uefi-buttons.h')+'"\n'+r'''
#include <assert.h>
#include <string.h>
#define printf(...) ((void)0)
static struct polaris_uefi_button_slot polaris_uefi_buttons;
static struct polaris_button_consumer pk_consumer;
static bool pk_enabled;static int hid_ready;static uint64_t ns;static unsigned edges,current;
static int polaris_hid_buttons_ready(void){return hid_ready;}
static uint64_t mach_absolute_time(void){return ns;}
static void absolutetime_to_nanoseconds(uint64_t a,uint64_t*b){*b=a;}
static void pi_cache(uint64_t a,bool clean){
 assert(a==(uintptr_t)&polaris_uefi_buttons+(clean?128:0));}
static void sweet_hid_key(int key,int down){assert(key>=0&&key<3);unsigned mask=1u<<key;
 assert(!!(current&mask)!=!!down);current^=mask;edges++;}
'''+native+r'''
int main(void){pk_poll(false);assert(!polaris_uefi_buttons.ready);
 pk_enabled=true;pk_poll(false);assert(!polaris_uefi_buttons.ready);
 hid_ready=1;ns=100000;pk_poll(false);assert(polaris_uefi_buttons.ready==POLARIS_BUTTONS_READY);
 struct polaris_uefi_button_slot*s=&polaris_uefi_buttons;
 s->request=1;s->sampled_us=10;ns+=100000;pk_poll(false);assert(!edges&&s->acknowledged==1);
 s->request=2;s->sampled_us=20;s->pressed=7;ns+=100000;pk_poll(false);
 assert(edges==3&&current==7&&s->events==1&&s->acknowledged==2);
 s->request=3;s->sampled_us=30;s->pressed=5;ns+=100000;pk_poll(false);assert(edges==4&&current==5);
 ns+=750000000;pk_poll(false);assert(current==0&&edges==6&&s->error==3);
 s->request=4;s->sampled_us=40;s->pressed=7;ns+=100000;pk_poll(false);assert(current==0&&edges==6);
 memset(s,0,sizeof(*s));memset(&pk_consumer,0,sizeof(pk_consumer));
 ns+=100000;pk_poll(false);s->request=1;s->sampled_us=1;ns+=100000;pk_poll(false);
 s->request=2;s->sampled_us=2;s->pressed=1;ns+=100000;pk_poll(false);assert(current==1);
 pk_poll(true);assert(current==0&&s->error==4);
 memset(s,0,sizeof(*s));memset(&pk_consumer,0,sizeof(pk_consumer));
 ns+=100000;pk_poll(false);s->request=1;s->sampled_us=1;s->producer_padding[95]=1;
 ns+=100000;pk_poll(false);assert(s->error==1&&!current);
 return 0;}
''')

    def test_unique_explicit_intent_and_native_shutdown_required(self):
        base=[b'polarisinput=1',b'polarisramcow=1',b'ufsrw=0',b'polarisquiesce=1']
        valid=base+[b'polarisbuttons=1']
        self.assertTrue(builder.physical_buttons_intent(valid,True,7,4,False,None,True,False,False))
        self.assertTrue(builder.physical_buttons_intent(valid,True,7,2,True,'success',False,False,False))
        for bad in [base,valid+[b'polarisbuttons=1'],base+[b'polarisbuttons=0'],
                    valid+[b'ufsrw=1'],valid+[b'polarisinput=0']]:
            with self.subTest(bad=bad),self.assertRaises(ValueError):
                builder.physical_buttons_intent(bad,True,7,4,False,None,True,False,False)
        for args in [(1,1,False,None,True,False,False),(7,4,False,None,False,False,False),
                     (7,4,False,None,True,True,False),(7,4,False,None,True,False,True)]:
            with self.subTest(args=args),self.assertRaises(ValueError):
                builder.physical_buttons_intent(valid,True,*args)
        with self.assertRaises(ValueError):builder.physical_buttons_intent(valid,False,7,4,False,None,True,False,False)

    def test_native_patch_header_and_no_new_worker(self):
        p=(ROOT/'xnu/profiles/polaris/0890-polaris-three-physical-key-consumer.patch').read_text()
        expected=(ROOT/'tools/polaris-uefi-buttons.h').read_text()
        section=p.split('+++ b/bsd/dev/polaris_uefi_buttons.h\n',1)[1]
        actual=''.join(l[1:]+'\n' for l in section.splitlines() if l.startswith('+'))
        self.assertEqual(actual,expected)
        added='\n'.join(l for l in p.splitlines() if l.startswith('+'))
        self.assertNotIn('kernel_thread_start',added)
        self.assertIn('pk_poll(true);ps_execute();',added)


if __name__=='__main__':unittest.main()
