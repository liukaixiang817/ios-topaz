"""Execute the actual terminal-only RMTFS rows on saved control fields."""
import unittest
import subprocess
import tempfile
from pathlib import Path

from tools.tests.test_polaris_mss_word_trace import ROOT, execute, function


class RmtfsDiagnosticTests(unittest.TestCase):
    def test_auth_envelope_compiler_and_builder_scope(self):
        text = (ROOT/'shim/polaris/uefi-mss-rmtfs-native.h').read_text()
        start = text.index('#ifndef EFI_XNU_WIFI_RMTFS_AUTH_ENVELOPE')
        guard = text[start:text.index('#ifndef EFI_XNU_MSS_RMTFS_NATIVE_AVAILABLE', start)]
        for value, fault, accepted in [(0, 0, True), (1, 1, True), (1, 0, False),
                                       (2, 1, False), (-1, 1, False)]:
            result = subprocess.run(['/usr/bin/clang', '-E', '-x', 'c', '-'],
                input=f'#define EFI_XNU_WIFI_RMTFS_AUTH_ENVELOPE {value}\n#define EFI_XNU_WIFI_NATIVE_FAULT_HOLD {fault}\n'+guard,
                capture_output=True, text=True)
            self.assertEqual(result.returncode == 0, accepted)
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder)
            result = subprocess.run(['python3', str(ROOT/'tools/build-polaris-uefi-xnu.py'),
                '--zig', str(p/'missing'), '--kernel', str(p/'kernel'), '--payload', str(p/'payload'),
                '--output', str(p/'output'), '--wifi-rmtfs-auth-envelope'], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('requires --wifi-native-fault-hold', result.stderr)
            self.assertFalse((p/'output').exists())

    def test_actual_compiler_and_builder_refuse_wrong_scope(self):
        text = (ROOT/'shim/polaris/uefi-xnu.c').read_text()
        start = text.index('#ifndef EFI_XNU_WIFI_NATIVE_RMTFS_DIAGNOSTICS')
        guard = text[start:text.index('#ifndef POLARIS_WIFI_SCALAR_SHA256_FAST', start)]
        for value, fault, accepted in [(0, 0, True), (1, 1, True), (1, 0, False),
                                       (2, 1, False), (-1, 1, False)]:
            result = subprocess.run(['/usr/bin/clang', '-E', '-x', 'c', '-'],
                input=f'#define EFI_XNU_WIFI_NATIVE_RMTFS_DIAGNOSTICS {value}\n#define EFI_XNU_WIFI_NATIVE_FAULT_HOLD {fault}\n'+guard,
                capture_output=True, text=True)
            self.assertEqual(result.returncode == 0, accepted)
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder)
            result = subprocess.run(['python3', str(ROOT/'tools/build-polaris-uefi-xnu.py'),
                '--zig', str(p/'missing'), '--kernel', str(p/'kernel'), '--payload', str(p/'payload'),
                '--output', str(p/'output'), '--wifi-native-rmtfs-diagnostics'], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('requires --wifi-native-fault-hold', result.stderr)
            self.assertFalse((p/'output').exists())

    def test_actual_rows_bound_events_preserve_state_and_show_saved_ages(self):
        actual = function((ROOT/'shim/polaris/uefi-xnu.c').read_text(),
                          'static void wifi_native_rmtfs_diagnostic_lines(')
        # Deliberately provide no descriptor page, remote target or hardware
        # API in the field-only model; adding any such access fails compilation.
        execute(r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>
#define PWNS_RMTFS 21
#define PWMT_EVENTS 6
struct registers {uint64_t x[7];};
struct cache {unsigned error,attempted,barrier_issued,barrier_returned,complete;};
struct pwmt_event {struct {unsigned operation;}command;uint64_t before,after;
 unsigned issued,returned;int32_t return_raw;};
struct pwmt_transaction {uint64_t opening,last;unsigned started,unknown,error,pending,step,events,rounds,complete;
 struct pwmt_event event[PWMT_EVENTS];};
struct pmsn_assignment {struct pwmt_transaction transaction;struct registers response[PWMT_EVENTS];
 struct cache cache[PWMT_EVENTS];unsigned error,attempted,unknown,complete;};
struct pmtf_state {struct pmsn_assignment assignment;unsigned error,pages,complete,pending,attempted,ready,unknown;};
struct pwns_parent {unsigned phase;struct pmtf_state rmtfs;struct {unsigned complete,error;}auth;
 struct {unsigned error,held;}owner;};
struct pwtg_result {unsigned unused;};
static unsigned calls;static uint32_t rows[16][2];static const char*labels[16];
static void pwtg_line(struct pwtg_result*r,unsigned n,const char*label,uint32_t a,uint32_t b){
 (void)r;assert(n<16);rows[n][0]=a;rows[n][1]=b;labels[n]=label;calls++;
}
''' + actual + r'''
static uint64_t value(unsigned row){return (uint64_t)rows[row][0]<<32|rows[row][1];}
int main(void){
 struct pwtg_result r={0};struct pwns_parent s={0},before;
 unsigned events[]={0,1,2,6,7,UINT32_MAX};
 for(unsigned phase=0;phase<=46;phase++)for(unsigned error=0;error<=5;error++)
 for(unsigned n=0;n<6;n++)for(unsigned returned=0;returned<=1;returned++){
  memset(&s,0,sizeof(s));s.phase=phase;s.rmtfs.error=error;s.rmtfs.pages=512;
  s.rmtfs.assignment.transaction.events=events[n];s.rmtfs.assignment.transaction.opening=100;
  s.rmtfs.assignment.transaction.last=150;s.rmtfs.assignment.transaction.error=3;
  for(unsigned k=0;k<6;k++){
   s.rmtfs.assignment.transaction.event[k]=(struct pwmt_event){.command={k+1},.before=110+k,
    .after=200+k,.issued=1,.returned=returned,.return_raw=1};
   s.rmtfs.assignment.response[k].x[0]=UINT64_C(0x1234567800000000)+k;
   s.rmtfs.assignment.response[k].x[1]=UINT64_C(0xabcdef1200000000)+k;
  }
  before=s;calls=0;wifi_native_rmtfs_diagnostic_lines(&r,&s);assert(!memcmp(&s,&before,sizeof(s)));
  if(phase!=21||!error){assert(!calls);continue;}
  assert(calls==16&&!strcmp(labels[0],"RMTFS HOLD")&&rows[0][0]==error&&rows[1][0]==512&&rows[4][0]==3);
  unsigned valid=events[n]>0&&events[n]<=6,k=valid?events[n]-1:0;
  assert(value(7)==(valid&&returned?100+k:50));assert(value(8)==(valid&&returned?90:UINT64_MAX));
  assert(rows[9][0]==(valid?k+1:0)&&rows[10][1]==(valid?returned:0));
  assert(value(11)==(valid?UINT64_C(0x1234567800000000)+k:0));
  assert(value(12)==(valid?UINT64_C(0xabcdef1200000000)+k:0));
 }
 memset(&s,0,sizeof(s));s.phase=21;s.rmtfs.error=4;s.rmtfs.assignment.transaction.events=1;
 s.rmtfs.assignment.transaction.opening=100;s.rmtfs.assignment.transaction.last=90;
 s.rmtfs.assignment.transaction.event[0]=(struct pwmt_event){.before=100,.after=99,.returned=1};
 calls=0;wifi_native_rmtfs_diagnostic_lines(&r,&s);assert(calls==16&&value(7)==UINT64_MAX&&value(8)==UINT64_MAX);
 return 0;
}
''')


if __name__ == '__main__':
    unittest.main()
