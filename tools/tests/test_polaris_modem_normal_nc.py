"""Actual scoped NC translation, whole-map delta and native identity guards."""
from pathlib import Path
import subprocess
import tempfile
import unittest

from tools.tests.test_polaris_mss_word_trace import execute, function
from tools.tests.test_polaris_fast_scalar_sha256 import core

ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT/'shim/polaris/uefi-mss-modem-mapping.h'


class ModemNormalNCTests(unittest.TestCase):
    def test_exact_translation_every_page_domains_and_bit_refusals(self):
        decl = function((ROOT/'shim/polaris/uefi-wifi-remote-memory.h').read_text(),
                        'struct pwmc_translation {')+';\n'
        policy = function(HEADER.read_text(), 'static inline int pmnc_translation(')
        execute('#include <stdint.h>\n#include <assert.h>\n'+decl+policy+r'''
int main(void){
 for(unsigned inner=0;inner<2;inner++)for(unsigned page=0;page<30720;page++){
  uint64_t at=UINT64_C(0xf8000000)+4096*page;
  uint64_t par=inner?UINT64_C(0x4400000000000b80):UINT64_C(0x4400000000000b00);
  struct pwmc_translation t={.page=at,.saved=123,.restored=123,.read_par=par|at,.write_par=par|at,
   .read_issued=1,.read_returned=1,.write_issued=1,.write_returned=1};
  assert(pmnc_translation(&t,at,par));
  for(unsigned bit=0;bit<64;bit++){
   t.read_par^=UINT64_C(1)<<bit;assert(!pmnc_translation(&t,at,par));t.read_par^=UINT64_C(1)<<bit;
  }
  t.write_par^=4096;assert(!pmnc_translation(&t,at,par));t.write_par^=4096;
  t.restored++;assert(!pmnc_translation(&t,at,par));t.restored--;
  t.read_returned=0;assert(!pmnc_translation(&t,at,par));t.read_returned=1;
  assert(!pmnc_translation(&t,at+1,par)&&!pmnc_translation(&t,0,par)&&!pmnc_translation(0,at,par));
 }
 struct pwmc_translation t={.page=0xf8000000,.read_issued=1,.read_returned=1,.write_issued=1,.write_returned=1};
 for(unsigned attr=0;attr<256;attr++)for(unsigned sh=0;sh<4;sh++){
  uint64_t par=((uint64_t)attr<<56)|0xa00|((uint64_t)sh<<7);t.read_par=t.write_par=par|t.page;
  assert(pmnc_translation(&t,t.page,par)==(attr==0x44&&sh>=2));
 }
 return 0;
}
''')

    def test_complete_map_splits_only_exact_bank_attribute_changes(self):
        header = HEADER.read_text()
        funcs = function(header, 'static inline int pmnc_map_direction(')+function(header, 'static inline int pmnc_maps(')
        execute('#include "'+str(ROOT/'shim/polaris/uefi-memory.h')+'"\n'+r'''
#include <assert.h>
#include <string.h>
#define PGCD_MAP_CAP 8192
#define PMNC_BYTES UINT64_C(0x7800000)
struct pwea_map {struct {uint64_t bytes,stride,key,status;unsigned valid,version;}map;uint8_t data[8192];};
''' + funcs + r'''
static void emit(struct pwea_map*m,unsigned index,unsigned type,uint64_t base,uint64_t bytes,unsigned attr){
 struct efi_memory d={.type=type,.physical=base,.pages=bytes/4096,.attributes=attr};
 memcpy(m->data+index*m->map.stride,&d,40);if(m->map.stride==48)memset(m->data+index*48+40,0x5a,8);
}
int main(void){
 for(unsigned stride=40;stride<=48;stride+=8){
  struct pwea_map a={.map={.bytes=2*stride,.stride=stride,.key=1,.valid=1,.version=1}},b=a;
  uint64_t base=0xf8000000;b.map.bytes=4*stride;b.map.key=2;
  emit(&a,0,2,base-4096,PMNC_BYTES+8192,8);emit(&a,1,3,0x180000000,4096,8);
  emit(&b,0,2,base-4096,4096,8);emit(&b,1,2,base,PMNC_BYTES,2);
  emit(&b,2,2,base+PMNC_BYTES,4096,8);emit(&b,3,3,0x180000000,4096,8);
  assert(pmnc_maps(&a,&b,base));
  for(unsigned fault=0;fault<12;fault++){
   struct pwea_map bad=b;struct efi_memory*d=(void*)(bad.data+stride);
   if(fault==0)d->attributes=8;if(fault==1)d->type=7;if(fault==2)d->virtual_address=base;
   if(fault==3)d->physical+=4096;if(fault==4)d->pages--;
   if(fault==5)((struct efi_memory*)bad.data)->attributes=2;
   if(fault==6)((struct efi_memory*)(bad.data+3*stride))->attributes=2;
   if(fault==7)bad.map.key=0;if(fault==8)bad.map.stride=56;if(fault==9)bad.map.status=1;
   if(fault==10)bad.map.bytes-=stride;if(fault==11)d->attributes=UINT64_C(0x8000000000000002);
   assert(!pmnc_maps(&a,&bad,base));
  }
  if(stride==48){b.data[40]^=1;assert(!pmnc_maps(&a,&b,base));}
  assert(!pmnc_maps(&a,&a,base)&&!pmnc_maps(&a,&b,base+4096));
 }
 return 0;
}
''')

    def test_actual_native_record_identity_digest_and_range_refusals(self):
        text = (ROOT/'shim/polaris/uefi-xnu.c').read_text()
        bound = function(text, 'static int pmlc_normal_nc_bound(')
        target = function(text, 'static int pmlc_normal_nc_target(')
        translation = function(HEADER.read_text(), 'static inline int pmnc_translation(')
        decl = function((ROOT/'shim/polaris/uefi-wifi-remote-memory.h').read_text(), 'struct pwmc_translation {')+';\n'
        execute('#include <stdint.h>\n#include <stddef.h>\n#include <assert.h>\n#include <string.h>\n#define POLARIS_WIFI_SCALAR_SHA256_FAST 1\n'+core()+r'''
#define PMNC_BYTES UINT64_C(0x7800000)
#define PMNC_CALLS 5
struct pmlc_copy {uint64_t base;};
static struct {struct pmlc_copy copy;}wifi_native_parent;
static struct {unsigned unused;}early_wifi_memory;
static struct {struct {struct {uint64_t requested;}claim[1];}memory;}mss_memory;
static struct pmnc_result {uint64_t self,early,memory,base,bytes,par;unsigned attempted,unknown,error,pending,complete,calls,translated[2];uint8_t digest[32];}mss_modem_mapping;
static void pweh_digest(const void*p,size_t n,uint8_t out[32]){struct pwfi_sha256 h;pwfi_init(&h);for(size_t k=0;k<n;k++)pwfi_byte(&h,((const uint8_t*)p)[k]);pwfi_final(&h,out);}
static int pgcd_equal(const void*a,const void*b,size_t n){return !memcmp(a,b,n);}
''' + decl + translation + bound + target + r'''
static void setup(void){struct pmnc_result*n=&mss_modem_mapping;memset(n,0,sizeof(*n));
 n->self=(uintptr_t)n;n->early=(uintptr_t)&early_wifi_memory;n->memory=(uintptr_t)&mss_memory;
 n->base=wifi_native_parent.copy.base=mss_memory.memory.claim[0].requested=0xf8000000;
 n->bytes=PMNC_BYTES;n->par=UINT64_C(0x4400000000000b80);n->attempted=n->complete=1;n->calls=5;n->translated[0]=n->translated[1]=30720;
 pweh_digest(n,offsetof(struct pmnc_result,digest),n->digest);
}
int main(void){
 struct pmlc_copy*c=&wifi_native_parent.copy;setup();assert(pmlc_normal_nc_bound(c));
 assert(!pmlc_normal_nc_bound((void*)1));
 for(unsigned fault=0;fault<15;fault++){
  setup();struct pmnc_result*n=&mss_modem_mapping;
  if(fault==0)n->self=1;if(fault==1)n->early=1;if(fault==2)n->memory=1;if(fault==3)n->attempted=0;
  if(fault==4)n->unknown=1;if(fault==5)n->error=1;if(fault==6)n->pending=1;if(fault==7)n->complete=0;
  if(fault==8)n->calls--;if(fault==9)n->translated[0]--;if(fault==10)n->translated[1]--;
  if(fault==11)n->bytes--;if(fault==12)c->base+=4096;if(fault==13)n->base+=4096;if(fault==14)n->digest[0]^=1;
  assert(!pmlc_normal_nc_bound(c));
 }
 setup();struct pwmc_translation t={.page=c->base,.read_issued=1,.read_returned=1,.write_issued=1,.write_returned=1};
 t.read_par=t.write_par=UINT64_C(0x4400000000000b80)|t.page;
 assert(pmlc_normal_nc_target(c,&t,t.page)&&!pmlc_normal_nc_target((void*)1,(void*)1,0));
 assert(!pmlc_normal_nc_target(c,&t,c->base-4096)&&!pmlc_normal_nc_target(c,&t,c->base+PMNC_BYTES));
 mss_modem_mapping.unknown=1;assert(!pmlc_normal_nc_target(c,&t,t.page));return 0;
}
''')

    def test_actual_compiler_and_builder_scope(self):
        text = HEADER.read_text()
        guard = text[text.index('#ifndef EFI_XNU_MSS_MODEM_NORMAL_NC'):text.index('#if EFI_XNU_MSS_MODEM_NORMAL_NC\n#include')]
        for value, fault, diag, mode, mem, accepted in [(0,0,0,0,0,True),(1,1,1,10,1,True),(1,0,1,10,1,False),(1,1,0,10,1,False),(1,1,1,9,1,False),(1,1,1,10,0,False),(2,1,1,10,1,False)]:
            result = subprocess.run(['/usr/bin/clang','-E','-x','c','-'],capture_output=True,text=True,
                input=f'#define EFI_XNU_MSS_MODEM_NORMAL_NC {value}\n#define EFI_XNU_WIFI_NATIVE_FAULT_HOLD {fault}\n#define EFI_XNU_WIFI_FIRMWARE_DIAGNOSTIC_ONLY {diag}\n#define EFI_XNU_WIFI_AUTH_METADATA_CHECKPOINT {mode}\n#define EFI_XNU_MSS_MEMORY_AVAILABLE {mem}\n'+guard)
            self.assertEqual(result.returncode==0,accepted)
        with tempfile.TemporaryDirectory() as folder:
            p=Path(folder)
            result=subprocess.run(['python3',str(ROOT/'tools/build-polaris-uefi-xnu.py'),'--zig',str(p/'missing'),'--kernel',str(p/'kernel'),'--payload',str(p/'payload'),'--output',str(p/'out'),'--mss-modem-normal-nc'],capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('requires --wifi-native-fault-hold',result.stderr)
            self.assertFalse((p/'out').exists())


if __name__ == '__main__':
    unittest.main()
