#!/usr/bin/env python3
"""Integrate our new-root stream receiver with an interrupted file on an isolated real ext4 disk."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]
E2 = Path('/opt/homebrew/opt/e2fsprogs/sbin')
def sha(p):
    with p.open('rb') as f: return hashlib.file_digest(f,'sha256').hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('kernel','init','receiver','production-receiver','output'):
        p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args(); out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    for path in (a.kernel,a.init,a.receiver,a.production_receiver):
        if path.is_symlink() or not path.is_file():raise ValueError('ordinary read-only inputs required')
    files=out/'root-files';files.mkdir()
    for name in ('proc','sys','dev','mnt'):(files/name).mkdir()
    for name,path in [('init',a.init),('receiver',ROOT/'research/polaris/uefi-ios-0124/polaris-root-receive-vm'),('physical-append',a.production_receiver),('append',a.receiver)]:
        d=files/name;d.write_bytes(path.read_bytes());d.chmod(0o700)
    data=bytearray(8<<20);data[1024:1028]=b'HX\0\5';struct.pack_into('>II',data,1064,4096,len(data)//4096)
    (files/'input-good').write_bytes(data);(files/'input-short').write_bytes(data[:(4<<20)+17]);(files/'input-tail').write_bytes(data[4<<20:]);(files/'prefix.sha').write_text(hashlib.sha256(data[:4<<20]).hexdigest())
    data[-1]^=1;(files/'input-bad-hash').write_bytes(data);data[1024]^=1;(files/'input-bad-header').write_bytes(data)
    root=out/'our-readonly-root.raw'
    with root.open('xb') as f:f.truncate(64<<20)
    subprocess.run([str(E2/'mke2fs'),'-q','-F','-t','ext4','-b','4096','-E','root_owner=0:0','-d',str(files),str(root)],check=True,capture_output=True)
    commands=out/'console.commands';commands.write_text('cd /dev\nmknod console c 5 1\n')
    subprocess.run([str(E2/'debugfs'),'-w','-f',str(commands),str(root)],check=True,capture_output=True)
    before_root=sha(root);initial=out/'initial';initial.mkdir();(initial/'baseline.img').write_bytes(b'\x5a'*(1<<20))
    drives=[];baselines=[]
    debug=lambda disk,cmd:subprocess.check_output([str(E2/'debugfs'),'-R',cmd,str(disk)],stderr=subprocess.DEVNULL)
    for i in range(1):
        disk=out/f'new-synthetic-{i}.raw'
        with disk.open('xb') as f:f.truncate(128<<20)
        subprocess.run([str(E2/'mke2fs'),'-q','-F','-t','ext4','-b','4096','-I','256','-g','1024','-G','1','-N','1024','-O','extent,encrypt,uninit_bg,^64bit,^metadata_csum,^orphan_file','-E','root_owner=0:0','-d',str(initial),str(disk)],check=True,capture_output=True)
        blocks=[int(n) for n in debug(disk,'blocks /baseline.img').split()];assert len(blocks)==256
        baselines.append((blocks,debug(disk,'stat /baseline.img')));drives.append(disk)
    cmd=['/opt/homebrew/bin/qemu-system-aarch64','-M','virt,gic-version=3','-cpu','max','-smp','2','-m','512M','-display','none','-monitor','none','-nic','none','-no-reboot','-serial','file:'+str(out/'serial.log'),'-kernel',str(a.kernel),'-append','console=ttyAMA0 root=/dev/vda ro init=/init panic=-1','-drive','if=none,id=root,format=raw,readonly=on,file='+str(root),'-device','virtio-blk-pci,drive=root']
    for i,disk in enumerate(drives):cmd+=['-drive',f'if=none,id=test{i},format=raw,file='+str(disk),'-device',f'virtio-blk-pci,drive=test{i}']
    with (out/'qemu.log').open('wb') as log:
        subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT,timeout=100,check=True)
    log=(out/'serial.log').read_text(errors='replace');checks={s:s+'=1' in log for s in ('ROOT_APPEND_VM_RESULT','ROOT_APPEND_PRODUCTION_VM_REFUSAL_UNCHANGED','ROOT_APPEND_WRONG_GENERATION_ZERO_WRITE','ROOT_APPEND_WRONG_PREFIX_ZERO_WRITE','ROOT_APPEND_SAME_INODE_EXACT_COMPLETION','ROOT_APPEND_COMPLETE_IMMUTABLE_REUSE_REFUSED','ROOT_APPEND_ACTUAL_UNMOUNT_RO_PIN')}
    checks['readonly_root_unchanged']=sha(root)==before_root
    for i,disk in enumerate(drives):
        blocks,st=baselines[i]
        with disk.open('rb') as f:blob=b''.join((f.seek(b*4096),f.read(4096))[1] for b in blocks)
        checks[f'baseline_{i}_raw_data_unchanged']=blob==b'\x5a'*(1<<20)
        checks[f'baseline_{i}_inode_unchanged']=debug(disk,'stat /baseline.img')==st
        test=subprocess.run([str(E2/'e2fsck'),'-fn',str(disk)],capture_output=True)
        (out/f'e2fsck-{i}.log').write_bytes(test.stdout+test.stderr);checks[f'readonly_e2fsck_{i}_clean']=test.returncode==0
    exported=out/'new-root-readback.bin'
    subprocess.run([str(E2/'debugfs'),'-R','dump /polaris-ios-20F66-0124-0001/root.img '+str(exported),str(drives[0])],check=True,capture_output=True)
    checks['post_unmount_whole_stream_digest']=sha(exported)==sha(files/'input-good')
    result=dict(passed=all(checks.values()),checks=checks,source_sha256=sha(ROOT/'tools/polaris-root-append.c'),init_source_sha256=sha(ROOT/'tools/tests/polaris_root_append_vm_init.c'),receiver_sha256=sha(a.receiver),production_receiver_sha256=sha(a.production_receiver),kernel_sha256=sha(a.kernel),isolated_Linux_only=True,phone_touched=False,physical_UFS_durability_proven=False)
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2));assert result['passed']
if __name__=='__main__':main()
