"""Create a task-owned GPT/FAT emulator image. Never accept a device path."""
from pathlib import Path
import hashlib
import struct
import subprocess
import uuid
import zlib


def create(path, app, payload, guid, start, blocks, payload_path, mtools):
    path=Path(path)
    if path.exists() or path.suffix!='.raw':raise ValueError('new regular .raw fixture required')
    if start!=2048 or blocks!=258048:raise ValueError('fixed emulator geometry required')
    if payload_path!='\\EFI\\Polaris\\V0061\\PAYLOAD.BIN':raise ValueError('unexpected fixture payload path')
    total=262144
    entries=bytearray(16384)
    struct.pack_into('<16s16sQQQ',entries,0,uuid.UUID('c12a7328-f81f-11d2-ba4b-00a0c93ec93b').bytes_le,
                     uuid.UUID(str(guid)).bytes_le,start,start+blocks-1,0)
    name='Polaris offline fixture'.encode('utf-16le');entries[56:56+len(name)]=name
    disk=uuid.uuid4().bytes_le
    def header(current,backup,array):
        b=bytearray(512)
        struct.pack_into('<8sIIIIQQQQ16sQIII',b,0,b'EFI PART',0x10000,92,0,0,
                         current,backup,34,total-34,disk,array,128,128,zlib.crc32(entries))
        struct.pack_into('<I',b,16,zlib.crc32(b[:92]));return b
    with path.open('xb') as f:
        f.truncate(total*512)
        mbr=bytearray(512);struct.pack_into('<B3sB3sII',mbr,446,0,b'\0\2\0',0xee,b'\xff'*3,1,total-1)
        mbr[510:512]=b'\x55\xaa';f.write(mbr);f.write(header(1,total-1,2));f.write(entries)
        f.seek((total-33)*512);f.write(entries);f.write(header(total-1,1,total-33))
    # Every target is the newly exclusively-created ordinary fixture file.
    target=str(path.resolve())+'@@'+str(start*512)
    def call(tool,*args):subprocess.run([str(Path(mtools)/tool),*args],check=True,capture_output=True)
    call('mformat','-i',target,'-T',str(blocks),'-H',str(start),'-F','-v','POLARIS', '::')
    for folder in ['::/EFI','::/EFI/BOOT','::/EFI/Polaris','::/EFI/Polaris/V0061']:
        call('mmd','-i',target,folder)
    call('mcopy','-i',target,str(Path(app).resolve()),'::/EFI/BOOT/BOOTAA64.EFI')
    call('mcopy','-i',target,str(Path(payload).resolve()),'::/EFI/Polaris/V0061/PAYLOAD.BIN')
    # Readback through the FAT consumer, not just trusting mcopy exit status.
    for source,name in [(app,'::/EFI/BOOT/BOOTAA64.EFI'),(payload,'::/EFI/Polaris/V0061/PAYLOAD.BIN')]:
        got=subprocess.run([str(Path(mtools)/'mtype'),'-i',target,name],check=True,capture_output=True).stdout
        if hashlib.sha256(got).digest()!=hashlib.sha256(Path(source).read_bytes()).digest():raise ValueError('FAT readback mismatch')
    return dict(regular_file_only=True,sector_bytes=512,start_lba=start,blocks=blocks,
                partition_guid=str(guid),fat_readback_matches=True,
                sha256=hashlib.sha256(path.read_bytes()).hexdigest())
