"""Native C wire oracle and host rejection tests; SOFTWARE PMIC, no phone."""
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib
from .test_polaris_wled_status import OEM_H

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from polaris_wled_journal import parse_packet,parse_reset_receipt,parse_zero_write_receipt,WledOemProtocol

SOURCE=OEM_H+'\n#include "'+str(ROOT/'shim/polaris/uefi-wled-journal.h')+'"\n'+r'''
#include <stdio.h>
static void save(const char*dir,const char*name,const uint8_t*p,unsigned bytes) {
 char path[4096];assert(snprintf(path,sizeof(path),"%s/%s",dir,name)>0);
 FILE *f=fopen(path,"wb");assert(f&&fwrite(p,1,bytes,f)==bytes&&!fclose(f));
}
int main(int argc,char **argv) {
 assert(argc==2);
 struct fake f;struct polaris_wled_read_bus b;struct polaris_wled_power p;
 struct polaris_wled_journal j={.cookie=0x123456789abcdef0ull};
 uint8_t packet[PWJ_LIMIT],receipt[PWJ_RECEIPT];unsigned bytes=0;
 oem_start(&f,&b,&p,1);oem_cycle(&f,&p);
 assert(pwj_packet(&j,&p,packet,sizeof(packet),&bytes));save(argv[1],"journal.bin",packet,bytes);
 assert(!pwj_receipt(&j,&p,2,f.time,receipt)); /* Old completed-cycle print is insufficient. */
 assert(pwp_restored(&p)&&pwj_receipt(&j,&p,2,f.time,receipt));
 save(argv[1],"receipt.bin",receipt,sizeof(receipt));
 assert(!pwj_receipt(&j,&p,2,f.time+200001,receipt));
 assert(pwp_restored(&p)&&!pwj_receipt(&j,&p,2,f.time,receipt)); /* Four pending records: never drop two. */
 assert(pwj_packet(&j,&p,packet,sizeof(packet),&bytes));save(argv[1],"journal2.bin",packet,bytes);
 assert(pwp_restored(&p)&&pwj_receipt(&j,&p,2,f.time,receipt));
 save(argv[1],"receipt2.bin",receipt,sizeof(receipt));
 f.pulse=0;f.pmic[0][8]=2;
 assert(!pwp_restored(&p)&&p.error==PWS_E_STATUS);
 assert(!pwj_receipt(&j,&p,2,f.time,receipt));
 assert(pwj_packet(&j,&p,packet,sizeof(packet),&bytes));save(argv[1],"failed.bin",packet,bytes);
 unsigned writes=f.writes;for(unsigned n=0;n<10;n++)assert(!pwp_poll(&p));assert(f.writes==writes);
 memset(&p,0,sizeof(p));j=(struct polaris_wled_journal){.cookie=0xabcdef};
 assert(pwj_packet(&j,&p,packet,sizeof(packet),&bytes));save(argv[1],"unstarted.bin",packet,bytes);
 pwp_fail(&p,PWP_E_CONFIG);
 assert(p.status_policy==PWP_STRICT_SNAPSHOT&&pwj_packet(&j,&p,packet,sizeof(packet),&bytes));
 save(argv[1],"early-failed.bin",packet,bytes);
 assert(!pwp_init_oem_status(&p,&b,0,false)); /* Publishing is never a policy switch. */
 p.issued=1;assert(!pwj_packet(&j,&p,packet,sizeof(packet),&bytes));
 return 0;
}
'''


def repaired(raw):
    b=bytearray(raw);struct.pack_into('<I',b,len(b)-4,zlib.crc32(b[:-4]));return bytes(b)


class WledJournal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();p=Path(cls.tmp.name)
        (p/'fixture.c').write_text(SOURCE)
        subprocess.run(['/usr/bin/clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror',
                        '-fsanitize=address,undefined',str(p/'fixture.c'),'-o',str(p/'fixture')],check=True)
        subprocess.run([str(p/'fixture'),str(p)],check=True)
        cls.packet=(p/'journal.bin').read_bytes();cls.receipt=(p/'receipt.bin').read_bytes()
        cls.packet2=(p/'journal2.bin').read_bytes();cls.receipt2=(p/'receipt2.bin').read_bytes()
        cls.failed=(p/'failed.bin').read_bytes()
        cls.unstarted=(p/'unstarted.bin').read_bytes();cls.early_failed=(p/'early-failed.bin').read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_actual_C_packet_and_final_receipt_extend_every_record(self):
        p=parse_packet(self.packet);r=parse_reset_receipt(self.receipt,self.packet)
        self.assertTrue(p['cycle_restored_readbacks']);self.assertEqual(p['count'],26)
        self.assertEqual((p['fault_or'],p['rt_or']),(1,1))
        self.assertTrue(r['final_restore_receipt_valid']);self.assertEqual(r['final_count'],28)
        self.assertFalse(r['physical_darkness_proven']);self.assertFalse(r['actual_FASTBOOT_proven'])
        self.assertEqual(len(r['final_records']),2)
        p2=parse_packet(self.packet2);self.assertEqual(p2['records'][:26],p['records'])
        r2=parse_reset_receipt(self.receipt2,self.packet2);self.assertEqual((p2['count'],r2['final_count']),(30,32))
        with self.assertRaises(ValueError):parse_reset_receipt(self.receipt2,self.packet)

    def test_failures_preserve_faults_without_claiming_restored_or_allowing_reset(self):
        p=parse_packet(self.failed);self.assertEqual((p['error'],p['fault_or']),(65,3))
        self.assertFalse(p['cycle_restored_readbacks'])
        self.assertEqual(p['records'][-1]['fault'],2);self.assertEqual(p['records'][-1]['valid'],1)
        with self.assertRaises(ValueError):parse_reset_receipt(self.receipt,self.failed)

    def test_every_truncation_and_single_bit_corruption_is_rejected(self):
        for n in range(len(self.packet)):
            with self.assertRaises(ValueError):parse_packet(self.packet[:n])
        for n in range(len(self.packet)):
            for bit in range(8):
                b=bytearray(self.packet);b[n]^=1<<bit
                with self.assertRaises(ValueError):parse_packet(bytes(b))
        for n in range(len(self.receipt)):
            for bit in range(8):
                b=bytearray(self.receipt);b[n]^=1<<bit
                with self.assertRaises(ValueError):parse_reset_receipt(bytes(b),self.packet)

    def test_rechecksummed_semantic_forgery_does_not_become_a_reset_witness(self):
        for at,value in [(8,0),(28,65),(30,1),(36,1),(38,9),(39,7),(40,3),(41,3),(42,0),(43,0),(44,1),(52,1),(60,0),(62,1)]:
            b=bytearray(self.packet);b[at]=value;b=repaired(b)
            try:
                parsed=parse_packet(b)
            except ValueError:
                continue
            # A different nonzero cookie can describe a different valid
            # session; it must still refuse THIS session's final receipt.
            if at!=8:self.assertFalse(parsed['cycle_restored_readbacks'])
            with self.assertRaises(ValueError):parse_reset_receipt(self.receipt,b)
        for value in (2,4,128):
            b=bytearray(self.packet);b[64+16]=value
            struct.pack_into('<I',b,32,zlib.crc32(b[64:-4]));b[60]|=value;b=repaired(b)
            with self.assertRaises(ValueError):parse_packet(b)

    def test_dedicated_client_and_final_binary_response(self):
        class Transport:
            def __init__(self,replies):self.replies=list(replies);self.commands=[]
            def write(self,b):self.commands.append(b)
            def read(self,n):
                reply=self.replies.pop(0);assert len(reply)<=n;return reply
        t=Transport([b'OKAYpolaris-uefi-diag',b'OKAYprepared',b'OKAY',
                     f'DATA{len(self.packet):08x}'.encode(),self.packet,b'OKAY',
                     b'OKAYprepared',b'OKAY'+self.receipt])
        c=WledOemProtocol(t);c.product();raw,_=c.capture_journal();self.assertEqual(raw,self.packet)
        self.assertTrue(c.reboot_restored()['final_restore_receipt_valid'])
        self.assertEqual(t.commands[-1],b'reboot-bootloader');self.assertFalse(t.replies)
        for command in (b'oem touch:1:1:1',b'oem shutdown:2',b'reboot-bootloader'):
            with self.assertRaises(ValueError):c._control(command)
        with self.assertRaises(ValueError):c.reboot(True)
        with self.assertRaises(ValueError):c.reboot_restored()

    def test_zero_write_recovery_and_no_retry_after_uncertain_response(self):
        class Transport:
            def __init__(self,replies):self.replies=list(replies);self.commands=[]
            def write(self,b):self.commands.append(b)
            def read(self,n):return self.replies.pop(0)
        zero=b'WLR0'+bytes(8)+b'\x02\x00\x00\x00'
        t=Transport([b'OKAYpolaris-uefi-diag',b'OKAYwaiting-payload',b'OKAY'+zero])
        c=WledOemProtocol(t);c.product()
        self.assertTrue(c.recover_unstarted_fastboot()['no_PMIC_command_issued_receipt'])
        with self.assertRaises(ValueError):c.recover_unstarted_fastboot()
        t=Transport([b'OKAYprepared']);c=WledOemProtocol(t);c.verified=True;c.journal=self.failed
        with self.assertRaises(ValueError):c.recover_unstarted_fastboot()
        self.assertEqual(t.commands,[b'getvar:kernel-state'])
        t=Transport([b'OKAYprepared',b'OKAY']);c=WledOemProtocol(t);c.verified=True;c.journal=self.packet
        with self.assertRaises(ValueError):c.reboot_restored()
        before=len(t.commands)
        with self.assertRaises(ValueError):c.reboot_restored()
        self.assertEqual(len(t.commands),before)

    def test_unstarted_and_pre_policy_failure_packets_only_admit_zero_write_recovery(self):
        for packet,error in [(self.unstarted,0),(self.early_failed,33)]:
            parsed=parse_packet(packet)
            self.assertEqual((parsed['issued'],parsed['completed'],parsed['count']),(0,0,0))
            self.assertFalse(parsed['cycle_restored_readbacks'])
            receipt=b'WLR0'+struct.pack('<Q',parsed['cookie'])+bytes([2,error,0,0])
            self.assertTrue(parse_zero_write_receipt(receipt,packet)['no_PMIC_command_issued_receipt'])
            with self.assertRaises(ValueError):parse_reset_receipt(self.receipt,packet)


if __name__=='__main__':unittest.main()
