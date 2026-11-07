"""Check candidate binding and bounded reads in the actual remnant observer."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class NativeFaultWitnessTests(unittest.TestCase):
    def test_descriptor_rejects_wrong_candidate_or_changed_nonce(self):
        spec = importlib.util.spec_from_file_location('witness', ROOT / 'tools/polaris-native-fault-witness.py')
        module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder);case = root / 'research/prior';driver = case / 'driver-0001'
            driver.mkdir(parents=True);(case / 'phone-native-0001').mkdir()
            out = root / 'output';out.mkdir()
            pe = bytearray(1024);pe[:2] = b'MZ';struct.pack_into('<I', pe, 60, 128)
            pe[128:132] = b'PE\0\0';struct.pack_into('<HH', pe, 132, 0xaa64, 1)
            struct.pack_into('<H', pe, 148, 240);struct.pack_into('<I', pe, 208, 0x20000)
            struct.pack_into('<IIII', pe, 400, 64, 0x3000, 64, 512)
            nonce = bytes(range(64));pe[512:576] = nonce
            image = driver / 'prior.efi';image.write_bytes(pe)
            image_hash = module.sha(image);base = 0x100000000
            manifest = dict(artifact='prior.efi', wifi_native_fault_hold=True,
                            wifi_firmware_diagnostic_only=True, kernel_handoff=False,
                            sha256=image_hash, inputs={'shim/polaris/uefi-xnu.c': 'native-source'})
            boot = dict(native_command_ACK=True, image_sha256='old-image')
            outcome = dict(image_and_nonce_spent=True)
            def write_json(p, d):
                p.write_text(json.dumps(d))
            write_json(driver / 'manifest.json', manifest)
            write_json(case / 'phone-native-0001/boot.json', boot)
            write_json(case / 'physical-outcome-0001.json', outcome)
            d = dict(scope='one_spent_native_fault_record_readonly', maximum_record_read_bytes=272,
                     record_bytes=272, arbitrary_memory_read_API=False, old_RAM_write_API=False,
                     prior_case='research/prior', driver_sha256=image_hash, prior_image_sha256='old-image',
                     native_source_sha256='native-source', image_base=base, image_bytes=0x20000,
                     record_address=base+0x5010, nonce_address=base+0x3000, nonce_bytes=64,
                     nonce_sha256=hashlib.sha256(nonce).hexdigest(),
                     expected_layout=[base, 0x20000, base+0x1000, base+0x1800, base+0x1880,
                                      base+0x2000, base+0xa000, 16384, base+0x5010, 272, base+0x6000, 256])
            def bind():
                d['inputs'] = {str(p.relative_to(root)): module.sha(p) for p in (
                    image, driver / 'manifest.json', case / 'phone-native-0001/boot.json',
                    case / 'physical-outcome-0001.json')}
                if (root / 'research/scalar-layout.json').exists():
                    d['inputs']['research/scalar-layout.json'] = module.sha(root / 'research/scalar-layout.json')
                write_json(root / 'research/descriptor.json', d)
            descriptor = root / 'research/descriptor.json';bind()
            result = module.prepare(root, descriptor, out)
            self.assertTrue(result['enabled']);self.assertFalse(result['old_RAM_writes'])
            self.assertTrue((out / 'native-fault-witness-config.h').is_file())
            abi = dict(target='aarch64-unknown-windows', actual_base_references=2,
                       native_source_sha256='native-source', native_driver_sha256=image_hash,
                       parent_address=base+0x12000, parent_bytes=4096,
                       scalars=[dict(name='ATTEMPTED', field='attempted', offset=0, bytes=4, maximum=1),
                                dict(name='PHASE', field='phase', offset=4, bytes=4, maximum=46)])
            write_json(root / 'research/scalar-layout.json', abi)
            d['scalar_witness'] = dict(parent_address=base+0x12000, parent_bytes=4096, layout='research/scalar-layout.json')
            bind();result = module.prepare(root, descriptor, out)
            self.assertEqual(result['scalar_count'], 2);self.assertEqual(result['scalar_bytes'], 8)
            abi['scalars'][1]['offset'] = 0;write_json(root / 'research/scalar-layout.json', abi);bind()
            with self.assertRaisesRegex(ValueError, 'invalid fixed scalar'):
                module.prepare(root, descriptor, out)
            abi['scalars'][1]['offset'] = 4096;write_json(root / 'research/scalar-layout.json', abi);bind()
            with self.assertRaisesRegex(ValueError, 'invalid fixed scalar'):
                module.prepare(root, descriptor, out)
            d.pop('scalar_witness');bind()
            outcome['image_and_nonce_spent'] = False;write_json(case / 'physical-outcome-0001.json', outcome);bind()
            with self.assertRaisesRegex(ValueError, 'spent firmware-only'):
                module.prepare(root, descriptor, out)
            outcome['image_and_nonce_spent'] = True;write_json(case / 'physical-outcome-0001.json', outcome);bind()
            pe[512] ^= 1;image.write_bytes(pe)
            with self.assertRaisesRegex(ValueError, 'input changed'):
                module.prepare(root, descriptor, out)
            # Even a newly rebound PE must contain the claimed actual nonce.
            manifest['sha256'] = d['driver_sha256'] = module.sha(image)
            write_json(driver / 'manifest.json', manifest);bind()
            with self.assertRaisesRegex(ValueError, 'actual linked image bytes'):
                module.prepare(root, descriptor, out)
            d['nonce_bytes'] = 4097;bind()
            with self.assertRaisesRegex(ValueError, 'bounded nonce'):
                module.prepare(root, descriptor, out)

    def test_explicit_reset_defers_writes_and_restores_on_return(self):
        source = r'''
#include "uefi-probe-reset.h"
#include "uefi-usb.h"
#include <assert.h>
#include <string.h>
struct fixture {unsigned bad,archs,reads,writes,sets,gets,resets;uint32_t reason;uint8_t pon;} f;
static unsigned marker_ack_expected;
static int arch(void*ctx,struct pawr_arch*a){
 (void)ctx;f.archs++;
 *a=(struct pawr_arch){4,0x81000000,0,1,0x80803518,0x13ffe89000,0,0,19200000,10+f.archs};
 if(f.bad==1)a->el=8;
 if(f.bad==2)a->daif=0x80;
 if(f.bad==3)a->ttbr0=0;
 if(f.bad==10&&f.sets)a->ttbr0^=4096;
 if(f.bad==11&&f.writes)a->ticks+=19200000;
 return 1;
}
static int at(void*ctx,unsigned write,struct pawr_translation*t){
 (void)ctx;assert(write<2);
 *t=(struct pawr_translation){42,(PPR_REASON&~UINT64_C(4095))|0xb00,42};
 if(f.bad==4)t->par|=1;
 if(f.bad==5)t->par|=UINT64_C(0xff00000000000000); /* WB is refused. */
 if(f.bad==6)t->restored++;
 return 1;
}
static int read_reason(void*ctx,uint32_t*v){(void)ctx;f.reads++;*v=f.reason;return f.bad!=7;}
static int write_reason(void*ctx,uint32_t v){(void)ctx;f.writes++;f.reason=v;return f.bad!=8||f.writes!=1;}
static void reset_system(void*ctx){(void)ctx;assert(f.reason==0x77665500 && f.pon==5);f.resets++;}
static efi_status get(uint32_t chip,uint32_t reg,uint8_t*v){
 assert(!chip&&reg==3);f.gets++;*v=f.pon;return f.bad==9?EFI_ERROR|7:0;
}
static efi_status set(uint32_t chip,uint32_t reg,uint8_t value,uint8_t mask){
 assert(!chip&&reg==3&&mask==0xfe);f.sets++;f.pon=(f.pon&~mask)|(value&mask);return 0;
}
static struct polaris_efi_pon pon={0x10001,get,set};
static struct ppr_result result;
static struct ppr_ops ops={0,arch,at,read_reason,write_reason,reset_system,&pon};
static void init(void){memset(&f,0,sizeof(f));memset(&result,0,sizeof(result));f.reason=0x12345678;f.pon=0xa1;marker_ack_expected=0;}
static int prepare(void*ctx,unsigned mode){(void)ctx;return ppr_prepare(&result,&ops,mode);}
static void execute(void*ctx,unsigned mode){(void)ctx;ppr_execute(&result,&ops,mode);}
static int arm_marker(void*ctx){(void)ctx;int ok=ppr_arm_marker(&result,&ops);if(ok)marker_ack_expected=1;return ok;}
static int tx_ok=1;static unsigned replies;static uint8_t response[128];
static int tx(void*ctx,const uint8_t*p,uint64_t n){
 (void)ctx;assert(n<sizeof(response));memcpy(response,p,n);replies++;
 if(marker_ack_expected&&!memcmp(p,"OKAY",4))assert(result.prepared&&f.reason==0x77665500&&f.pon==5&&!f.resets);
 return tx_ok;
}
static int stage(void*ctx,unsigned which,const uint8_t**p,uint64_t*n){
 (void)ctx;(void)which;(void)p;(void)n;return 0;
}
int main(void){
 init();assert(!prepare(0,1)&&!f.reads&&!f.writes&&!f.sets&&!f.resets);
 assert(prepare(0,2)&&result.prepared&&!f.reads&&!f.writes&&!f.sets&&!f.resets);
 execute(0,2);assert(result.attempted && result.error==5 && f.resets==1);
 assert(f.reason==0x12345678 && f.pon==0xa1 && result.reason_restored && result.pon_restored);
 unsigned writes=f.writes,sets=f.sets;assert(!prepare(0,2));execute(0,2);
 assert(f.writes==writes&&f.sets==sets&&f.resets==1); /* No second attempt. */
 for(unsigned bad=1;bad<=6;bad++){
  init();f.bad=bad;assert(!prepare(0,2));assert(!f.reads&&!f.writes&&!f.sets&&!f.resets);
 }
 for(unsigned bad=7;bad<=9;bad++){
  init();f.bad=bad;assert(prepare(0,2));execute(0,2);assert(!f.resets&&result.error);
  assert(f.reason==0x12345678&&f.pon==0xa1);
 }
 struct polaris_usb_diag d={.transmit=tx,.stage=stage};
 struct polaris_usb_control c={.prepare_reset=prepare,.reset=execute};
 const char*rejected[]={"download:00001000","oem boot","erase:userdata","flash:boot","reboot"};
 for(unsigned n=0;n<5;n++){
  init();assert(polaris_usb_control_command(&d,&c,(const uint8_t*)rejected[n],strlen(rejected[n])));
  assert(!memcmp(response,"FAIL",4)&&!f.writes&&!f.sets&&!f.resets);
 }
 init();tx_ok=0;assert(!polaris_usb_control_command(&d,&c,(const void*)"reboot-bootloader",17));
 assert(!f.writes&&!f.sets&&!f.resets); /* Failed ACK cannot write markers. */
 init();tx_ok=1;assert(polaris_usb_control_command(&d,&c,(const void*)"reboot-bootloader",17));
 assert(!memcmp(response,"OKAY",4)&&f.resets==1&&result.reason_restored&&result.pon_restored);
 assert(replies==7);
 /* The new command ACK follows verified writes; it never invokes reset. */
 const char*marker="oem native-bootloader-marker";
 init();assert(polaris_usb_control_command(&d,&c,(const void*)marker,strlen(marker)));
 assert(!memcmp(response,"FAIL",4)&&!f.writes&&!f.sets&&!f.resets);
 assert(!polaris_usb_bind_native_marker(0,arm_marker));
 assert(!polaris_usb_bind_native_marker(&c,0));
 assert(polaris_usb_bind_native_marker(&c,arm_marker));
 assert(polaris_usb_bind_native_marker(&c,arm_marker));
 struct polaris_usb_control other=c;
 assert(!polaris_usb_bind_native_marker(&other,arm_marker));
 init();assert(polaris_usb_control_command(&d,&other,(const void*)marker,strlen(marker)));
 assert(!memcmp(response,"FAIL",4)&&!f.writes&&!f.sets&&!f.resets);
 init();assert(polaris_usb_control_command(&d,&c,(const void*)marker,strlen(marker)));
 assert(!memcmp(response,"OKAY",4)&&result.prepared&&result.attempted&&!f.resets);
 writes=f.writes;sets=f.sets;
 assert(polaris_usb_control_command(&d,&c,(const void*)marker,strlen(marker)));
 assert(!memcmp(response,"FAIL",4)&&writes==f.writes&&sets==f.sets&&!f.resets);
 for(unsigned bad=1;bad<=11;bad++){
  init();f.bad=bad;assert(polaris_usb_control_command(&d,&c,(const void*)marker,strlen(marker)));
  assert(!memcmp(response,"FAIL",4)&&!f.resets);
  if(bad<=6)assert(!f.writes&&!f.sets);
  if(bad==7||bad==8||bad==9||bad==10)assert(f.reason==0x12345678&&f.pon==0xa1);
  if(bad==11)assert(result.error==3&&!result.prepared&&f.pon==0xa1&&!result.reason_restored);
 }
 init();tx_ok=0;assert(!polaris_usb_control_command(&d,&c,(const void*)marker,strlen(marker)));
 assert(result.prepared&&f.reason==0x77665500&&f.pon==5&&!f.resets);
 writes=f.writes;sets=f.sets;tx_ok=1;
 assert(polaris_usb_control_command(&d,&c,(const void*)marker,strlen(marker)));
 assert(!memcmp(response,"FAIL",4)&&writes==f.writes&&sets==f.sets&&!f.resets);
 /* Arm-only needs no ResetSystem callback at all. */
 init();struct ppr_ops no_reset=ops;no_reset.reset_system=0;
 assert(ppr_arm_marker(&result,&no_reset)&&result.prepared&&!f.resets);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder);(p / 'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-O1', '-g', '-fsanitize=address,undefined', '-I', str(ROOT / 'shim/polaris'),
                            str(p / 'test.c'), str(ROOT / 'shim/polaris/uefi-usb-control.c'),
                            str(ROOT / 'shim/polaris/uefi-usb-command.c'),
                            '-o', str(p / 'test')], check=True)
            subprocess.run([str(p / 'test')], check=True)

    def test_nonce_record_and_current_mapping(self):
        nonce = bytes((n * 73 + 11) % 256 for n in range(2128))
        digest = ','.join(str(n) for n in hashlib.sha256(nonce).digest())
        source = r'''
#include "uefi-native-fault-witness.h"
#include <assert.h>
#include <string.h>
struct fixture {
 struct pnfw_config config;struct pfnf_record record;
 unsigned reads,record_reads,scalar_reads,ats,archs,fail_at;int bad,zero;
 uint64_t scalar[4];
};
static int arch(void *opaque,struct pawr_arch *a){
 struct fixture *f=opaque;f->archs++;
 *a=(struct pawr_arch){4,0x81000000,0,1,0x80803518,0x13ffe89000,0,0,19200000,10+f->archs};
 if(f->bad==1)a->el=8;
 if(f->bad==2)a->daif=0x80;
 if(f->bad==3 && f->archs>1)a->ttbr0+=4096;
 if(f->bad==4 && f->archs>1)a->ticks+=19200000;
 return f->bad!=5;
}
static int at(void *opaque,uint64_t address,struct pawr_translation *t){
 struct fixture *f=opaque;assert(pnfw_range(&f->config,address));f->ats++;
 *t=(struct pawr_translation){42,UINT64_C(0xff00000000000b80)|(address&~UINT64_C(4095)),42};
 if(f->bad==6)t->par|=1;
 if(f->bad==7)t->par^=0x1000;
 if(f->bad==8)t->par^=0x200;
 if(f->bad==9)t->restored++;
 return f->bad!=10;
}
static int read8(void *opaque,uint64_t address,uint8_t *v){
 struct fixture *f=opaque;assert(pnfw_range(&f->config,address));f->reads++;
 if(f->fail_at==f->reads)return 0;
 if(address>=f->config.nonce && address-f->config.nonce<f->config.nonce_bytes){
  unsigned n=(unsigned)(address-f->config.nonce);*v=(uint8_t)(n*73+11);
  if(f->bad==11 || (f->bad==12 && f->record_reads) || (f->bad==14 && f->scalar_reads))(*v)^=1;
 }else{
  for(unsigned k=0;k<f->config.scalar_count;k++){
   struct pnfw_scalar*s=&f->config.scalar[k];
   if(address>=s->address&&address-s->address<s->bytes){
    *v=(uint8_t)(f->scalar[k]>>(8*(address-s->address)));f->scalar_reads++;
    if(f->bad==15 && f->scalar_reads>20)(*v)^=1;
    return 1;
   }
  }
  assert(f->reads>f->config.nonce_bytes);f->record_reads++;
  unsigned n=(unsigned)(address-f->config.layout.record);
  *v=f->zero?0:((const uint8_t *)&f->record)[n];
  if(f->bad==13 && f->record_reads>sizeof(f->record))(*v)^=1;
 }
 return 1;
}
static void init(struct fixture*f){
 memset(f,0,sizeof(*f));uint64_t base=UINT64_C(0x100000000);
 f->config=(struct pnfw_config){
  .layout={base,0x20000,base+0x1000,base+0x1800,base+0x1880,base+0x2000,
   base+0xa000,16384,base+0x5010,sizeof(struct pfnf_record),base+0x6000,256},
  .nonce=base+0x3cf0,.nonce_bytes=2128,.nonce_sha256={DIGEST}};
 f->record.layout=f->config.layout;f->record.attempted=1;f->record.armed=1;
 f->record.entered=1;f->record.vector=4;f->record.ticks=123;
 f->record.esr=0x96000010;f->record.elr=base+0x100;f->record.copy_pages=240;
}
static void progress(struct fixture*f){
 init(f);f->config.scalar_parent=f->config.layout.image+0x12000;f->config.scalar_parent_bytes=4096;
 f->config.scalar_count=4;
 f->config.scalar[0]=(struct pnfw_scalar){f->config.scalar_parent,1,4,0};
 f->config.scalar[1]=(struct pnfw_scalar){f->config.scalar_parent+4,46,4,0};
 f->config.scalar[2]=(struct pnfw_scalar){f->config.scalar_parent+8,30720,4,0};
 f->config.scalar[3]=(struct pnfw_scalar){f->config.scalar_parent+16,UINT64_MAX,8,0};
 f->scalar[0]=1;f->scalar[1]=19;f->scalar[2]=240;f->scalar[3]=1234;
}
int main(void){
 _Static_assert(sizeof(struct pfnf_record)==272,"fixed old record ABI");
 struct fixture f;init(&f);struct pnfw_result r;
 struct pnfw_ops ops={&f,arch,at,read8};
 struct efi_memory map[2]={{7,0,UINT64_C(0x100000000),0,16,8},
                         {3,0,UINT64_C(0x100010000),0,16,15}};
#define RUN() pnfw_run(&f.config,map,sizeof(map),sizeof(map),40,1,&ops,&r)
 assert(RUN() && r.valid && r.stable && !r.zero && r.record.copy_pages==240);
 assert(r.record.esr==0x96000010 && r.issued==4800 && r.returned==4800);
 assert(f.reads==4800 && f.record_reads==544 && f.ats==6 && r.nonce_match[0] && r.nonce_match[1]);
 for(int bad=1;bad<=10;bad++){
  init(&f);f.bad=bad;assert(!RUN() && !r.valid && !f.reads);
 }
 init(&f);f.bad=11;assert(!RUN() && r.error==6 && f.reads==2128 && !f.record_reads);
 init(&f);f.bad=12;assert(!RUN() && r.error==6 && f.record_reads==272 && !r.valid);
 init(&f);f.bad=13;assert(!RUN() && r.error==7 && !r.valid);
 init(&f);f.zero=1;assert(RUN() && r.zero && !r.valid && r.stable);
 init(&f);f.record.layout.handler+=4;assert(!RUN() && r.error==8 && !r.valid);
 init(&f);f.record.attempted=0;assert(!RUN() && r.error==9 && !r.valid);
 init(&f);f.record.error=3;f.record.armed=0;f.record.entered=0;
 assert(RUN() && r.valid && !r.record.armed && r.record.error==3);
 for(unsigned failure=1;failure<=4800;failure++){
  init(&f);f.fail_at=failure;assert(!RUN() && r.error==5 && !r.valid);
  assert(r.issued==failure && r.returned==failure-1 && f.reads==failure);
 }
 for(unsigned kind=0;kind<16;kind++){
  init(&f);map[0].type=kind;int allowed=kind==7||(kind>=1&&kind<=4);
  assert(RUN()==allowed);if(!allowed)assert(!f.reads && !f.ats);
 }
 map[0].type=7;
 for(unsigned attrs=0;attrs<16;attrs++){
  init(&f);map[0].attributes=attrs;assert(RUN()==!!(attrs&8));
  if(!(attrs&8))assert(!f.reads && !f.ats);
 }
 init(&f);map[0].attributes=UINT64_C(0x8000000000000008);assert(!RUN() && !f.reads);
 map[0].attributes=8;
 init(&f);map[1].physical=map[0].physical;assert(!RUN() && !f.reads);
 map[1].physical=UINT64_C(0x100010000);
 init(&f);f.config.nonce_bytes=4097;assert(!RUN() && !f.reads);
 init(&f);f.config.nonce=f.config.layout.record;assert(!RUN() && !f.reads);
 init(&f);assert(!pnfw_run(&f.config,map,sizeof(map),sizeof(map),40,2,&ops,&r) && !f.reads);
 init(&f);assert(!pnfw_run(&f.config,map,sizeof(map),sizeof(map)-1,40,1,&ops,&r) && !f.reads);
 init(&f);assert(!pnfw_run(&f.config,map,sizeof(map),sizeof(map),40,1,0,&r) && !f.reads);
 progress(&f);assert(RUN() && r.scalar_valid && r.scalar_stable && r.issued==9096);
 assert(r.nonce_match[2] && r.nonce_match[3] && f.scalar_reads==40 && r.scalar_value[0][2]==240);
 progress(&f);f.bad=14;assert(!RUN() && r.error==6 && !r.scalar_valid && f.scalar_reads==20);
 progress(&f);f.bad=15;assert(!RUN() && r.error==11 && !r.scalar_valid);
 progress(&f);f.scalar[2]=30721;assert(!RUN() && r.error==12 && !r.scalar_valid);
 progress(&f);f.scalar[0]=0;assert(!RUN() && r.error==12 && !r.scalar_valid);
 progress(&f);f.record.layout.handler+=4;assert(!RUN() && r.error==8 && !f.scalar_reads);
 progress(&f);f.config.scalar[1].address=f.config.scalar[0].address;
 assert(!RUN() && r.error==10 && !f.reads);
 progress(&f);f.config.scalar_count=65;assert(!RUN() && !f.reads);
 unsigned failures[]={4801,6928,6929,6948,6949,9076,9077,9096};
 for(unsigned n=0;n<sizeof(failures)/sizeof(failures[0]);n++){
  progress(&f);f.fail_at=failures[n];assert(!RUN() && r.error==5 && !r.scalar_valid);
  assert(r.issued==f.fail_at && r.returned==f.fail_at-1);
 }
 return 0;
}
'''.replace('DIGEST', digest)
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder);(p / 'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-O1', '-g', '-fsanitize=address,undefined', '-I',
                            str(ROOT / 'shim/polaris'), '-I', str(ROOT / 'tools'),
                            str(p / 'test.c'), '-o', str(p / 'test')], check=True)
            subprocess.run([str(p / 'test')], check=True)

    def test_builder_refuses_non_inventory_scope(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / 'must-not-exist'
            run = subprocess.run(['python3', str(ROOT / 'tools/build-polaris-uefi-probe.py'),
                                  '--zig', '/not/executed', '--output', str(target),
                                  '--native-fault-witness', '/not/opened'], capture_output=True, text=True)
            self.assertNotEqual(run.returncode, 0)
            self.assertIn('requires --hold --ready-to-boot --usb-diag', run.stderr)
            self.assertFalse(target.exists())
            run = subprocess.run(['python3', str(ROOT / 'tools/build-polaris-uefi-probe.py'),
                                  '--zig', '/not/executed', '--output', str(target),
                                  '--bootloader-reset'], capture_output=True, text=True)
            self.assertNotEqual(run.returncode, 0)
            self.assertIn('requires --hold --ready-to-boot --usb-diag', run.stderr)
            self.assertFalse(target.exists())


if __name__ == '__main__':
    unittest.main()
