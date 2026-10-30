"""Atomic terminal raw evidence/USB ordering; SOFTWARE fixtures, no device access."""
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
import zlib
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools import polaris_wled_runtime_journal as wire
from tools.polaris_wled_runtime_control import WledRuntimeProtocol
from .test_polaris_wled_runtime_journal import pages,reCRC
from .test_polaris_wled_runtime import H
from .test_polaris_gpu_bootstrap import run
from .test_polaris_gpu_lifetime import function

ROOT=Path(__file__).resolve().parents[2]


def captured(records,flags=11,snapshot=1):
    result=[]
    for b in pages(records):
        b=bytearray(b);b[74]=flags;struct.pack_into('<I',b,16,snapshot);result.append(reCRC(b))
    return result,wire.journal(result)


def footer(prefix,tail,native_cookie=456):
    records=prefix['records']+tail
    raw=b''.join(wire.RECORD.pack(*(r[k] for k in ('began_us','ended_us','fault','rt','valid','expected','sequence'))) for r in records)
    b=bytearray(100+28*len(tail));b[:8]=b'WLEXIT05'
    struct.pack_into('<QIIIHHI',b,8,prefix['cookie'],prefix['snapshot']+1,len(records),prefix['total'],len(tail),28,zlib.crc32(raw))
    struct.pack_into('<IIIIIQQ',b,36,0,0,0,prefix['issued'],prefix['completed'],prefix['request'],prefix['ack'])
    b[72:77]=bytes([128,2,27,prefix['fault_or'],prefix['rt_or']]);struct.pack_into('<QII',b,80,native_cookie,1,2)
    b[96:-4]=raw[-28*len(tail):] if tail else b''
    return reCRC(b)


def final(sealed):
    last=sealed['records'][-1]['ended_us'];tail=[]
    for n in range(2):tail.append(dict(began_us=last+10+n*20,ended_us=last+20+n*20,fault=0,rt=0,valid=3,expected=130,sequence=sealed['request']))
    raw=b''.join(wire.RECORD.pack(*(r[k] for k in ('began_us','ended_us','fault','rt','valid','expected','sequence'))) for r in sealed['records']+tail)
    b=bytearray(60);b[:4]=b'WLR5';struct.pack_into('<QII',b,4,sealed['cookie'],sealed['total']+2,zlib.crc32(raw))
    for n,r in enumerate(tail):struct.pack_into('<QQBBBB',b,20+n*20,*(r[k] for k in ('began_us','ended_us','fault','rt','valid','expected')))
    return bytes(b)


def fixture():
    j=wire.journal(pages());records=j['records'];_,prefix=captured([tuple(r[k] for k in ('began_us','ended_us','fault','rt','valid','expected','sequence')) for r in records[:-4]])
    f=footer(prefix,records[-4:]);sealed=wire.exit_footer(f,prefix,native_cookie=456,native_sequence=1)
    return prefix,f,sealed,final(sealed)


class RuntimeExit(unittest.TestCase):
    def test_actual_footer_and_fresh_pair_extend_complete_history_and_native_token(self):
        prefix,f,sealed,r=fixture();j=wire.exit_receipt(r,sealed)
        self.assertEqual((prefix['total'],sealed['total'],j['total']),(74,78,80))
        self.assertEqual(j['issued'],12);self.assertFalse(j['physical_admission'])
        recovery=footer(j,[]);next_sealed=wire.exit_footer(recovery,j,native_cookie=456,native_sequence=1,recover=True)
        self.assertEqual(wire.exit_receipt(final(next_sealed),next_sealed)['total'],82)
        with self.assertRaises(ValueError):wire.exit_footer(recovery,j,native_cookie=456,native_sequence=1)
        with self.assertRaises(ValueError):wire.exit_receipt(r,next_sealed)

    def test_every_truncation_bit_foreign_token_or_recomputed_raw_fault_refuses(self):
        prefix,f,sealed,r=fixture()
        for raw,decode in [(f,lambda b:wire.exit_footer(b,prefix,native_cookie=456,native_sequence=1)),(r,lambda b:wire.exit_receipt(b,sealed))]:
            for n in range(len(raw)):
                with self.assertRaises(ValueError):decode(raw[:n])
            for at in range(len(raw)):
                for bit in range(8):
                    b=bytearray(raw);b[at]^=1<<bit
                    with self.assertRaises(ValueError):decode(bytes(b))
        for nc,ns in ((457,1),(456,2),(0,1)):
            with self.assertRaises(ValueError):wire.exit_footer(f,prefix,native_cookie=nc,native_sequence=ns)
        for at in (8,16,20,24,28,32,48,56,64,74,75,80,88,92,112,114,115):
            b=bytearray(f);b[at]^=2
            with self.assertRaises(ValueError):wire.exit_footer(reCRC(b),prefix,native_cookie=456,native_sequence=1)

    def test_host_saves_literal_evidence_and_never_replays_unknown_ack_or_raw_reset(self):
        prefix,f,sealed,r=fixture()
        class Transport:
            def __init__(self,replies):self.replies=replies;self.commands=[]
            def write(self,b):self.commands.append(b)
            def read(self,n):return self.replies.pop(0)
        t=Transport([b'DATA000000d4',f,b'OKAY'+r]);p=WledRuntimeProtocol(t);p.verified=True;p.shutdown_token=(456,1,2)
        self.assertEqual(p.atomic_exit(prefix)['total'],80)
        self.assertEqual((p.actual_footer,p.actual_reply),(f,b'OKAY'+r))
        with self.assertRaises(ValueError):p.atomic_exit(prefix)
        with self.assertRaises(ValueError):p.reboot(True)
        t=Transport([b'DATA000000d4',f,b'FAILdelivery']);p=WledRuntimeProtocol(t);p.verified=True;p.shutdown_token=(456,1,2)
        with self.assertRaises(RuntimeError):p.atomic_exit(prefix)
        self.assertEqual(p.actual_footer,f);self.assertEqual(len(t.commands),1)
        with self.assertRaises(ValueError):p.atomic_exit(prefix,recover=True)
        self.assertEqual(len(t.commands),1)

    def test_real_command_parser_delivers_footer_before_new_pair_and_resets_only_after_receipt(self):
        source=r'''
#include "uefi-xnu.h"
#include <assert.h>
#include <string.h>
static unsigned txcount,failat,finishes,resets,aborts,cause;static uint64_t clock_us=1,fresh;
static uint8_t footer[212],receipt[60];
static int tx(void*x,const uint8_t*p,uint64_t n){(void)x;txcount++;
 if(txcount==1)assert(n==12&&!memcmp(p,"DATA000000d4",12));
 if(txcount==2){assert(n==212&&p==footer);clock_us+=250001;}
 if(txcount==3)assert(n==64&&!memcmp(p,"OKAYWLR5",8));
 return txcount!=failat;}
static int stage(void*x,unsigned n,const uint8_t**p,uint64_t*b){(void)x;(void)n;(void)p;(void)b;return 0;}
static int begin(void*x,int recover,uint64_t cookie,uint32_t count,uint32_t crc,const uint8_t**p,uint64_t*n){
 (void)x;assert(!recover&&cookie==0x123&&count==74&&crc==0x456);*p=footer;*n=212;return 1;}
static int finish(void*x,const uint8_t**p,uint64_t*n){(void)x;assert(txcount==2&&clock_us>200000);finishes++;fresh=clock_us;memcpy(receipt,"WLR5",4);*p=receipt;*n=60;return 1;}
static void reset(void*x,unsigned mode){(void)x;assert(mode==2&&txcount==3&&clock_us-fresh<=200000);resets++;}
static void abort_exit(void*x,unsigned why){(void)x;aborts++;cause=why;}
int main(void){
 const char *cmd="oem wled-exit:0000000000000123:0000004a:00000456";
 struct polaris_usb_diag d={0,tx,stage,0,0};struct polaris_usb_control c={.reset=reset,.wled_exit_begin=begin,.wled_exit_finish=finish,.wled_exit_abort=abort_exit};
 for(failat=0;failat<=3;failat++){
  txcount=finishes=resets=aborts=cause=0;
  int ok=polaris_usb_control_command(&d,&c,(const void*)cmd,strlen(cmd));
  assert(ok==!failat&&resets==!failat&&aborts==1&&cause==(failat?1u:2u));
  assert(finishes==(failat==1||failat==2?0u:1u));
 }return 0;}
'''
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'test.c').write_text(source)
            subprocess.run(['/usr/bin/clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(ROOT/'shim/polaris'),str(p/'test.c'),str(ROOT/'shim/polaris/uefi-usb-control.c'),str(ROOT/'shim/polaris/uefi-usb-command.c'),'-o',str(p/'test')],check=True)
            subprocess.run([str(p/'test')],check=True)

    def test_actual_FW_functions_allow_only_one_newly_inventoried_readonly_recovery(self):
        text=(ROOT/'shim/polaris/uefi-wled-native.h').read_text()
        names=('static void wln_encode_record(', 'static void wln_sync_history(', 'static int wln_capture_page(',
               'static int wln_reset_ready(', 'static int wln_exit_begin(', 'static int wln_exit_finish(', 'static void wln_exit_abort(')
        functions='\n'.join(function(text,n) for n in names)
        run(H+'#include "'+str(ROOT/'shim/polaris/uefi-wled-journal.h')+'"\n'+r'''
#define wln_power p
#define wln_runtime r
#define wln_firmware fw
#define wln_archive archive
#define WLN_CAPACITY 8192u
static uint32_t wln_crc=~0u,wln_crc_count,wln_snapshot_sequence,wln_snapshot_count;
static uint8_t wln_snapshot_header[80],wln_page[980],wln_exit_footer[212],wln_exit_receipt[60];
static uint64_t wln_cookie=123,wln_native_cookie;
static uint32_t wln_native_sequence,wln_exit_sealed_count;
static unsigned wln_started=1,wln_cpu_on_issued=1,wln_closing_mode=2,wln_receipt_issued;
static unsigned wln_exit_attempt,wln_exit_active,wln_exit_aborted,wln_exit_finished,wln_actual_reset_entered,wln_reset_retryable;
struct polaris_shutdown_status {uint64_t cookie;uint32_t sequence,mode;};
static struct polaris_shutdown_status native={456,1,2};
static void bytes_copy(void*d,const void*s,uint64_t n){memcpy(d,s,n);}
static void bytes_zero(void*d,uint64_t n){memset(d,0,n);}
static void report(const char*s,uint64_t n){(void)s;(void)n;}
static uint64_t buttons_us(void*x){(void)x;return f.time;}
static int wln_zero_ready(unsigned mode){(void)mode;return 0;}
static int shutdown_reset_ready(void*x,unsigned mode){(void)x;return mode==2;}
static int shutdown_status(void*x,const uint8_t**d,uint64_t*n){(void)x;*d=(void*)&native;*n=128;return 1;}
static int prepare_reset(void*,unsigned);
''' + functions + r'''
static int prepare_reset(void*x,unsigned mode){(void)x;return wln_reset_ready(native.cookie,native.sequence,mode);}
int main(void){
 begin(8192,1);for(unsigned c=0;c<3;c++){target(false);target(true);}assert(r.count==74&&f.writes==12);
 assert(pwr_close(&r));wln_sync_history();unsigned prefix=r.count;uint32_t crc=~wln_crc;
 const uint8_t *data=0;uint64_t bytes=0;
 assert(wln_exit_begin(0,0,wln_cookie,prefix,crc,&data,&bytes)&&bytes==212&&r.count==78);
 unsigned read_before=f.read_count;
 f.time+=250001;assert(wln_exit_finish(0,&data,&bytes)&&bytes==60&&r.count==80&&!memcmp(data,"WLR5",4)&&f.writes==12);
 unsigned reads=f.read_count-read_before;assert(reads>0&&reads<=64);
 wln_exit_abort(0,1);assert(wln_exit_aborted&&!wln_exit_active);
 assert(!wln_exit_begin(0,1,wln_cookie,prefix,crc,&data,&bytes));
 assert(wln_exit_begin(0,1,wln_cookie,r.count,~wln_crc,&data,&bytes)&&bytes==100);
 f.time+=250001;assert(wln_exit_finish(0,&data,&bytes)&&r.count==82&&f.writes==12);
 wln_exit_abort(0,1);assert(!wln_exit_begin(0,1,wln_cookie,r.count,~wln_crc,&data,&bytes));
 assert(p.issued==p.completed&&p.issued==12&&!p.uncertain);
 for(unsigned bad=1;bad<=reads+5;bad++) {
  wln_crc=~0u;wln_crc_count=wln_snapshot_sequence=wln_snapshot_count=0;
  wln_native_cookie=wln_native_sequence=wln_receipt_issued=0;
  wln_exit_attempt=wln_exit_active=wln_exit_aborted=wln_exit_finished=wln_actual_reset_entered=wln_reset_retryable=0;
  begin(8192,1);for(unsigned c=0;c<3;c++){target(false);target(true);}
  assert(pwr_close(&r));wln_sync_history();
  assert(wln_exit_begin(0,0,wln_cookie,r.count,~wln_crc,&data,&bytes));
  if(bad<=reads)f.fail_read=f.read_count+bad;
  if(bad==reads+1){f.pulse=0;f.pmic[0][8]=2;}
  if(bad==reads+2){f.pulse=0;f.pmic[0][0x10]=4;}
  if(bad==reads+3)f.foreign_owner=1;
  if(bad==reads+4)f.bad_map=1;
  if(bad==reads+5)f.backward=1;
  assert(!wln_exit_finish(0,&data,&bytes)&&f.writes==12&&p.error);
  wln_exit_abort(0,1);
  assert(!wln_exit_begin(0,1,wln_cookie,r.count,~wln_crc,&data,&bytes));
  assert(r.copied==p.witness.count); /* Every partial failure retained. */
 }
 return 0;}
''')


if __name__=='__main__':unittest.main()
