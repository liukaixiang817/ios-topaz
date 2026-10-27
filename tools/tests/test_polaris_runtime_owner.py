"""Actual fragmented ext4 metadata plus native ASan/UBSan refusal tests.

Creates only new ordinary files in a temporary directory. No phone, mounts,
host block devices, repair, writable kernel admission or UFS I/O is involved.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import polaris_runtime_owner as owner


class RuntimeOwnership(unittest.TestCase):
    legacy_checksums = False
    tail_blocks = 0
    @classmethod
    def setUpClass(cls):
        prefix = Path(os.environ.get('POLARIS_E2FSPROGS_BIN', '/opt/homebrew/opt/e2fsprogs/sbin'))
        cls.mk = prefix / 'mke2fs'
        cls.debug = prefix / 'debugfs'
        if not cls.mk.is_file() or not cls.debug.is_file() or not shutil.which('clang'):
            raise unittest.SkipTest('real e2fsprogs mke2fs/debugfs and Clang required')
        cls.temp = tempfile.TemporaryDirectory(prefix='polaris-owner-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.folder = Path(cls.temp.name)
        source = cls.folder / 'source'
        source.mkdir()
        for name, size, value in [('runtime.img', 32 << 20, 0xa5), ('immutable.img', 1 << 20, 0x5a)]:
            with (source / name).open('xb') as out:
                for _ in range(size >> 20):
                    out.write(bytes([value]) * (1 << 20))
            (source / name).chmod(0o600)
        cls.image = cls.folder / 'filesystem.img'
        with cls.image.open('xb') as out:
            out.truncate(128 << 20)
        features = ('extent,uninit_bg,^64bit,^metadata_csum,^orphan_file' if cls.legacy_checksums else
                    'extent,64bit,metadata_csum,^orphan_file')
        subprocess.run([str(cls.mk), '-q', '-F', '-t', 'ext4', '-b', '4096', '-I', '256',
                        '-g', '1024', '-G', '1', '-N', '1024', '-O',
                        features, '-d', str(source), str(cls.image), str(32768-cls.tail_blocks)],
                       check=True, capture_output=True)
        commands = cls.folder / 'debugfs.commands'
        lines = [
            'set_inode_field /runtime.img uid 0', 'set_inode_field /runtime.img gid 0',
            'set_inode_field /runtime.img flags 0x80090']
        # Changing i_generation manually also changes extent-checksum seeds.
        # Keep allocator generation in the CRC32C fixture; exercise a nonzero
        # generation in the legacy layout used by the real phone instead.
        if cls.legacy_checksums:
            lines.append('set_inode_field /runtime.img generation 305419896')
        commands.write_text('\n'.join(lines + ['stat /runtime.img']) + '\n')
        result = subprocess.run([str(cls.debug), '-w', '-f', str(commands), str(cls.image)],
                                check=True, capture_output=True)
        cls.inode = int(re.search(rb'Inode:\s*(\d+)', result.stdout)[1])
        subprocess.run([str(prefix / 'e2fsck'), '-fn', str(cls.image)],
                       check=True, capture_output=True)
        result = subprocess.run([str(cls.debug), '-R', 'blocks /immutable.img', str(cls.image)],
                                check=True, capture_output=True)
        blocks = [int(n) for n in result.stdout.split()]
        if len(blocks) != 256 or blocks != list(range(blocks[0], blocks[0]+256)):
            raise AssertionError('unexpected preserved-base fixture geometry')
        cls.base = blocks[0]
        with cls.image.open('rb') as f:
            cls.packet, cls.proof = owner.snapshot(
                lambda block: (f.seek(block*4096), f.read(4096))[1], 2048, 32768, cls.inode)
        if cls.proof['extent_nodes'] < 1 or cls.proof['extents'] <= 4:
            raise AssertionError('fixture did not exercise real indexed/fragmented extents')
        cls.before = hashlib.sha256(cls.image.read_bytes()).digest()

    def test_native_metadata_and_CDB_fault_injection(self):
        code = r'''
#define _XOPEN_SOURCE 700
#include "runtime-owner.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
struct disk {int fd;uint64_t fail,flip,desc;unsigned offset;uint8_t mask;unsigned calls;
 unsigned group,desc_size,desc_offset;uint8_t uuid[16];uint32_t seed;bool metadata,repair;};
static unsigned cases;
#define CHECK(x) do{cases++;assert(x);}while(0)
static bool read_(void *context,uint64_t lba,uint8_t *out){
 struct disk *d=context;d->calls++;
 if(lba<2048||lba-2048>=32768||lba-2048==d->fail)return false;
 if(pread(d->fd,out,4096,(off_t)(lba-2048)*4096)!=4096)return false;
 if(lba-2048==d->flip){
  out[d->offset]^=d->mask;
  if(d->repair&&lba==2048&&d->metadata){
   uint32_t crc=po_crc32c(UINT32_MAX,out+1024,1020);
   for(unsigned i=0;i<4;i++)out[1024+1020+i]=(uint8_t)(crc>>(i*8));
  }else if(d->repair&&lba-2048==d->desc){
   uint8_t *desc=out+d->desc_offset;
   uint16_t crc=po_group_checksum(desc,d->desc_size,d->group,d->uuid,d->metadata,d->seed);
   desc[30]=(uint8_t)crc;desc[31]=(uint8_t)(crc>>8);
  }
 }return true;
}
static void clear(struct disk *d){d->fail=d->flip=UINT64_MAX;d->offset=0;d->mask=0;d->calls=0;d->repair=false;}
static void cdb_at(uint8_t *p,uint64_t lba,unsigned blocks){
 memset(p,0,10);p[0]=0x2a;for(unsigned i=0;i<4;i++)p[2+i]=(uint8_t)(lba>>(24-8*i));
 p[7]=(uint8_t)(blocks>>8);p[8]=(uint8_t)blocks;
}
int main(int argc,char **argv){
 CHECK(argc==5);FILE *f=fopen(argv[2],"rb");CHECK(f);CHECK(!fseek(f,0,SEEK_END));
 size_t n=(size_t)ftell(f);CHECK(n>=384&&n<1<<20);rewind(f);
 uint8_t *p=malloc(n),*copy=malloc(n);CHECK(p&&copy&&fread(p,1,n,f)==n);fclose(f);memcpy(copy,p,n);
 struct disk d={.fd=open(argv[1],O_RDONLY)};CHECK(d.fd>=0);clear(&d);
 uint8_t initial[4096];CHECK(pread(d.fd,initial,4096,0)==4096);
 d.desc=po64(p+56);d.desc_size=po32(p+116);d.desc_offset=po32(p+64);
 d.group=(po32(p+40)-1)/po32(p+108);memcpy(d.uuid,p+88,16);
 d.metadata=(po32(p+124)&0x400)!=0;
 d.seed=(po32(p+120)&0x2000)?po32(initial+1024+624):po_crc32c(UINT32_MAX,d.uuid,16);
 struct polaris_owner_work *w=calloc(1,sizeof(*w));CHECK(w);
 struct polaris_owner_extent base={0,2048+strtoull(argv[3],0,0),strtoull(argv[4],0,0)};
 uint8_t cdb[10];cdb_at(cdb,2048,1);
 CHECK(!polaris_owned_data_cdb(w,cdb,10,4096,true,0));
 CHECK(polaris_owner_verify(p,n,2048,32768,read_,&d,w));
 CHECK(w->filesystem_blocks==po32(initial+1024+4));
 CHECK(w->metadata_verified&&!w->admitted);
 CHECK(!polaris_owned_data_cdb(w,cdb,10,4096,true,0));
 CHECK(polaris_owner_exclude_base(w,&base,1,256)&&w->admitted);
 /* Even a corrupted admitted map cannot grant the unowned filesystem tail. */
 struct polaris_owner_extent saved=w->map[0];w->map[0].physical=2048+w->filesystem_blocks;
 cdb_at(cdb,w->map[0].physical,1);CHECK(!polaris_owned_data_cdb(w,cdb,10,4096,true,0));w->map[0]=saved;
 for(unsigned i=0;i<w->map_count;i++){
  cdb_at(cdb,w->map[i].physical,1);CHECK(polaris_owned_data_cdb(w,cdb,10,4096,true,0));
  cdb_at(cdb,w->map[i].physical+w->map[i].blocks-1,1);CHECK(polaris_owned_data_cdb(w,cdb,10,4096,true,0));
  cdb_at(cdb,w->map[i].physical+w->map[i].blocks-1,2);CHECK(!polaris_owned_data_cdb(w,cdb,10,8192,true,0));
 }
 cdb_at(cdb,base.physical,1);CHECK(!polaris_owned_data_cdb(w,cdb,10,4096,true,0));
 cdb_at(cdb,w->map[0].physical,1);
 for(unsigned op=0;op<256;op++){
  cdb[0]=(uint8_t)op;CHECK(polaris_owned_data_cdb(w,cdb,10,4096,true,0)==(op==0x2a));
  CHECK(polaris_owned_data_cdb(w,cdb,10,4096,false,0)==(op==0x28));
 }
 cdb[0]=0x2a;
 CHECK(!polaris_owned_data_cdb(w,cdb,9,4096,true,0));CHECK(!polaris_owned_data_cdb(w,cdb,10,4096,true,1));
 CHECK(!polaris_owned_data_cdb(w,cdb,10,4095,true,0));CHECK(!polaris_owned_data_cdb(w,cdb,10,4097,true,0));
 for(unsigned field=0;field<3;field++)for(unsigned bit=0;bit<8;bit++){
  unsigned at=field==0?1:field==1?6:9;cdb[at]=(uint8_t)(1u<<bit);
  CHECK(!polaris_owned_data_cdb(w,cdb,10,4096,true,0));cdb[at]=0;
 }
 cdb_at(cdb,w->map[0].physical,257);CHECK(!polaris_owned_data_cdb(w,cdb,10,257*4096,true,0));
 cdb_at(cdb,w->map[0].physical,0);CHECK(!polaris_owned_data_cdb(w,cdb,10,0,true,0));
 uint8_t sync[10]={0x35};CHECK(polaris_owned_sync_cdb(w,sync,10,0,false,0));
 for(unsigned i=1;i<10;i++){sync[i]=1;CHECK(!polaris_owned_sync_cdb(w,sync,10,0,false,0));sync[i]=0;}
 CHECK(!polaris_owned_sync_cdb(w,sync,10,0,true,0));CHECK(!polaris_owned_sync_cdb(w,sync,10,1,false,0));
 CHECK(!polaris_owned_sync_cdb(w,sync,10,0,false,1));
 struct polaris_owner_extent bad=base;bad.physical=w->map[0].physical;bad.blocks=1;
 CHECK(!polaris_owner_exclude_base(w,&bad,1,256)&&!w->admitted);
 CHECK(!polaris_owner_exclude_base(w,0,0,256));bad=base;bad.logical=1;CHECK(!polaris_owner_exclude_base(w,&bad,1,256));
 bad=base;bad.physical=2047;CHECK(!polaris_owner_exclude_base(w,&bad,1,256));
 CHECK(!polaris_owner_exclude_base(w,&base,1,257));
 CHECK(polaris_owner_exclude_base(w,&base,1,256));
 uint64_t inode=po64(p+48),desc=po64(p+56),node=po64(po_node(p,0));
 unsigned io=po32(p+68),gd=po32(p+64);
 struct fault {uint64_t lba;unsigned offset;uint8_t mask;} faults[]={
  {0,1024+56,1},{0,1024+24,1},{0,1024+4,1},{0,1024+58,2},{0,1024+96,4},
  {0,1024+100+1,2},{0,1024+104,1},{0,1024+88,1},{0,1024+232,1},
  {desc,gd+8,1},{inode,io+100,1},{inode,io+32,0x10},{inode,io+32,0x80},
  {inode,io+26,2},{inode,io+4,1},{inode,io+40,1},{inode,io+120,1},{node,0,1},{node,4095,1}
 };
 for(unsigned i=0;i<sizeof(faults)/sizeof(faults[0]);i++){
  clear(&d);d.flip=faults[i].lba;d.offset=faults[i].offset;d.mask=faults[i].mask;
  CHECK(!polaris_owner_verify(p,n,2048,32768,read_,&d,w)&&!w->admitted);
  CHECK(!polaris_owned_sync_cdb(w,sync,10,0,false,0));
 }
 uint64_t addresses[]={0,desc,inode,node};
 for(unsigned i=0;i<4;i++){clear(&d);d.fail=addresses[i];CHECK(!polaris_owner_verify(p,n,2048,32768,read_,&d,w));}
 /* Changes unrelated to the owned inode must not create false refusals. */
 clear(&d);d.flip=0;d.offset=1024+44;d.mask=1;d.repair=true;CHECK(polaris_owner_verify(p,n,2048,32768,read_,&d,w));
 clear(&d);d.flip=desc;d.offset=gd+12;d.mask=1;d.repair=true;CHECK(polaris_owner_verify(p,n,2048,32768,read_,&d,w));
 clear(&d);d.flip=inode;d.offset=io?io-1:256;d.mask=1;CHECK(polaris_owner_verify(p,n,2048,32768,read_,&d,w));
 clear(&d);CHECK(!polaris_owner_verify(p,n,2049,32768,read_,&d,w));
 CHECK(!polaris_owner_verify(p,n,2048,32767,read_,&d,w));
 CHECK(!polaris_owner_verify(p,383,2048,32768,read_,&d,w));
 CHECK(!polaris_owner_verify(p,n-1,2048,32768,read_,&d,w));
 unsigned bad_fields[]={0,8,12,16,24,32,40,44,48,56,64,68,72,76,80,88,104,108,112,116,120,124,128};
 for(unsigned i=0;i<sizeof(bad_fields)/sizeof(bad_fields[0]);i++){
  memcpy(copy,p,n);copy[bad_fields[i]]^=1;
  CHECK(!polaris_owner_verify(copy,n,2048,32768,read_,&d,w)&&!w->admitted);
 }
 /* Cannot add unreachable metadata or alias a second expected node. */
 memcpy(copy,p,n);copy[384]=0;copy[385]=0;CHECK(!polaris_owner_verify(copy,n,2048,32768,read_,&d,w));
 /* Deterministic packet mutations/truncations exercise native bounds under
  * sanitizers. A changed snapshot cannot match the untouched real filesystem. */
 uint32_t random=0x61c0ffee;
 for(unsigned i=0;i<5000;i++){
  random=random*1664525u+1013904223u;size_t at=random%n;
  memcpy(copy,p,n);copy[at]^=(uint8_t)(1u<<((random>>24)&7));
  CHECK(!polaris_owner_verify(copy,n,2048,32768,read_,&d,w));
  CHECK(!polaris_owner_verify(copy,random%n,2048,32768,read_,&d,w));
 }
 printf("OWNER_FIXTURE_PASS %u checks, real indexed ext4, no writes\n",cases);
 free(w);free(p);free(copy);close(d.fd);return 0;
}
'''
        source = self.folder / 'check.c'
        exe = self.folder / 'check'
        packet = self.folder / 'owner.bin'
        source.write_text(code)
        packet.write_bytes(self.packet)
        subprocess.run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-I'+str(ROOT / 'shim/polaris'),
                        str(source), '-o', str(exe)], check=True, capture_output=True)
        result = subprocess.run([str(exe), str(self.image), str(packet), str(self.base), '256'],
                                check=True, capture_output=True)
        self.assertIn(b'OWNER_FIXTURE_PASS', result.stdout)
        self.assertEqual(hashlib.sha256(self.image.read_bytes()).digest(), self.before)

    def test_exporter_identity_and_independent_map_refusals(self):
        with self.image.open('rb') as f:
            def read(block):
                return os.pread(f.fileno(), 4096, block*4096)
            count = self.proof['extent_nodes']
            rows = [struct.unpack_from('<QQQ', self.packet, 384+count*4104+24*i)
                    for i in range(self.proof['extents'])]
            mapping = dict(file_bytes=32 << 20, inode=self.inode,
                           readonly_snapshot=True, raw_write_allowed=False,
                           extents=[dict(logical=l*4096, physical=p*4096, length=n*4096)
                                    for l,p,n in rows])
            packet, proof = owner.snapshot(read, 2048, 32768, self.inode, mapping)
            self.assertEqual(packet, self.packet)
            self.assertTrue(proof['independently_matched_FIEMAP'])
            broken = json.loads(json.dumps(mapping))
            broken['extents'][0]['physical'] += 4096
            with self.assertRaisesRegex(ValueError, 'independent FIEMAP'):
                owner.snapshot(read, 2048, 32768, self.inode, broken)
            ilba = struct.unpack_from('<Q', self.packet, 48)[0]
            ioff = struct.unpack_from('<I', self.packet, 68)[0]
            for lba, offset, mask in [(0,1128,1),(0,1120,4),
                                      (ilba,ioff+32,0x10),(ilba,ioff+32,0x80),
                                      (ilba,ioff+26,2)]:
                def bad(block):
                    data = bytearray(read(block))
                    if block == lba:
                        data[offset] ^= mask
                    return bytes(data)
                with self.subTest(lba=lba, offset=offset, mask=mask):
                    with self.assertRaises(ValueError):
                        owner.snapshot(bad, 2048, 32768, self.inode)


class LegacyRuntimeOwnership(RuntimeOwnership):
    """32byte descriptors/GDT CRC16, matching the phone's checksum scheme."""
    legacy_checksums = True


class TailLegacyRuntimeOwnership(LegacyRuntimeOwnership):
    """Actual mkfs filesystem with the phone's four unowned tail blocks."""
    tail_blocks = 4


class TailMetadataRuntimeOwnership(RuntimeOwnership):
    tail_blocks = 4


if __name__ == '__main__':
    unittest.main()
