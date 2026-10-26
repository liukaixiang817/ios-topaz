from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
import uuid
from tools.polaris_uefi_boot_options import parse_snapshot,load_option


def fixture():
    guid=uuid.UUID('11223344-5566-7788-9900-aabbccddeeff')
    hd=struct.pack('<BBHIQQ16sBB',4,1,42,23,1234,65536,guid.bytes_le,2,2)
    path='\\EFI\\Microsoft\\Boot\\bootmgfw.efi'.encode('utf-16-le')+b'\0\0'
    nodes=hd+struct.pack('<BBH',4,4,len(path)+4)+path+b'\x7f\xff\x04\0'
    option=struct.pack('<IH',1,len(nodes))+'Windows'.encode('utf-16-le')+b'\0\0'+nodes+b'original optional data'
    values=[(0x10000,7,0,struct.pack('<H',0x1234)),(0x10001,6,0,struct.pack('<H',0x1234)),
            (0x10002,0,0x800000000000000e,b''),(0x1234,7,0,option)]
    raw=bytearray(b'PEFIBV01'+struct.pack('<IIQQ',1,len(values),0,1))
    for ident,attrs,status,data in values:
        raw+=struct.pack('<IIQQQ',ident,attrs,status,len(data),len(data))+data+b'\0'*((-len(data))%8)
    struct.pack_into('<Q',raw,16,len(raw));return bytes(raw),option


class BootOptions(unittest.TestCase):
    def test_backup_preserves_attributes_description_GPT_and_optional_data(self):
        raw,option=fixture();r=parse_snapshot(raw)
        self.assertTrue(r['complete']);self.assertFalse(r['UEFI_variable_writes'])
        self.assertEqual(r['records'][0]['order'],[0x1234])
        item=r['records'][-1];self.assertEqual(item['attributes'],7)
        self.assertEqual(raw[item['data_offset']:item['data_offset']+item['bytes']],option)
        o=item['load_option'];self.assertEqual(o['description'],'Windows')
        self.assertEqual(o['nodes'][0]['GPT_partition_GUID'],'11223344-5566-7788-9900-aabbccddeeff')
        self.assertEqual(o['nodes'][1]['file_path'],'\\EFI\\Microsoft\\Boot\\bootmgfw.efi')
        self.assertEqual(o['optional_data_bytes'],len(b'original optional data'))

    def test_truncation_overflow_duplicates_and_incomplete_backups(self):
        raw,option=fixture()
        for bad in (raw[:-1],raw+b'x',b'x'*32):
            with self.assertRaises(ValueError):parse_snapshot(bad)
        for offset,fmt,value in ((12,'I',68),(32,'I',0x10002),(48,'Q',5000)):
            bad=bytearray(raw);struct.pack_into('<'+fmt,bad,offset,value)
            with self.assertRaises(ValueError):parse_snapshot(bad)
        bad=bytearray(raw);struct.pack_into('<Q',bad,24,0)
        self.assertFalse(parse_snapshot(bad)['complete'])
        bad=bytearray(option);struct.pack_into('<H',bad,4,65535)
        with self.assertRaises(ValueError):load_option(bad)

    def test_real_EFI_capture_is_readonly_bounded_and_retains_failures(self):
        root=Path(__file__).resolve().parents[2]
        source=r'''
#include "uefi-boot-options.h"
#include <assert.h>
static unsigned mode,calls;
static efi_status get(const uint16_t *name,const efi_guid *guid,uint32_t *attrs,uint64_t *size,void *out){
 assert(guid->a==0x8be4df61);calls++;uint8_t *p=out;*attrs=7;
 if(name[4]=='O'){
  if(mode==3){for(unsigned i=0;i<64;i++){p[2*i]=(uint8_t)i;p[2*i+1]=0;}*size=128;return 0;}
  p[0]=1;p[1]=0;p[2]=1;p[3]=0;*size=mode==1?3:4;return 0;
 }
 if(name[4]=='N')return EFI_ERROR|14;
 if(name[4]=='C'){p[0]=1;p[1]=0;*size=2;return 0;}
 if(mode==2){*size=5000;return EFI_TOO_SMALL;}
 if(mode==3){if(*size<4096){*size=4096;return EFI_TOO_SMALL;}for(unsigned i=0;i<4096;i++)p[i]=(uint8_t)i;*size=4096;return 0;}
 assert(*size>=8);for(unsigned i=0;i<8;i++)p[i]=(uint8_t)i;*size=8;return 0;
}
int main(void){
 static struct polaris_efi_boot_options b;struct efi_runtime rt={0};rt.get_variable=get;
 assert(polaris_efi_boot_options_capture(&rt,&b));assert(b.used==184&&calls==4&&b.data[24]==1);
 mode=1;calls=0;assert(!polaris_efi_boot_options_capture(&rt,&b));assert(calls==3&&!b.data[24]);
 mode=2;calls=0;assert(!polaris_efi_boot_options_capture(&rt,&b));assert(calls==4&&!b.data[24]);
 mode=3;calls=0;assert(!polaris_efi_boot_options_capture(&rt,&b));assert(b.used<=65536&&!b.data[24]);
 assert(!polaris_efi_boot_options_capture(0,&b));return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            c=Path(d)/'capture.c';exe=Path(d)/'capture';c.write_text(source)
            subprocess.run(['/usr/bin/clang','-std=c11','-Wall','-Wextra','-Werror',
                            '-fsanitize=address,undefined','-I'+str(root/'shim/polaris'),str(c),'-o',str(exe)],check=True)
            subprocess.run([str(exe)],check=True)


if __name__=='__main__':unittest.main()
