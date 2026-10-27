#!/usr/bin/env python3
"""Run our exclusive-file helper in an isolated real Linux/ext4 VM.

No phone, shared directory, caller-supplied writable disk or network is used.
An installed generic ARM64 Linux kernel is a read-only input, not SDM845 proof.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f,'sha256').hexdigest()


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('qemu','kernel','init','creator','production-creator','exporter','output'):
        ap.add_argument('--'+name,type=Path,required=True)
    ap.add_argument('--symlink',action='store_true')
    ap.add_argument('--e2fsprogs',type=Path,default=Path('/opt/homebrew/opt/e2fsprogs/sbin'))
    a=ap.parse_args();root=Path(__file__).resolve().parents[1];out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    for path in (a.kernel,a.init,a.creator,a.production_creator,a.exporter):
        if not path.is_file() or path.is_symlink():raise ValueError('ordinary read-only kernel/binary inputs required')
    root_files=out/'our-Linux-root';root_files.mkdir(mode=0o700)
    for folder in ('dev','proc','sys','mnt'):(root_files/folder).mkdir(mode=0o755)
    for name,path in [('init',a.init),('creator',a.creator),('physical-creator',a.production_creator),('exporter',a.exporter)]:
        dest=root_files/name;dest.write_bytes(path.read_bytes());dest.chmod(0o700)
    root_disk=out/'our-readonly-Linux-root.raw'
    with root_disk.open('xb') as f:f.truncate(32<<20)
    subprocess.run([str(a.e2fsprogs/'mke2fs'),'-q','-F','-t','ext4','-b','4096',
                    '-E','root_owner=0:0','-d',str(root_files),str(root_disk)],check=True,capture_output=True)
    subprocess.run([str(a.e2fsprogs/'debugfs'),'-w','-R','cd /dev',str(root_disk)],check=True,capture_output=True)
    commands=out/'root-dev-console.commands';commands.write_text('cd /dev\nmknod console c 5 1\n')
    subprocess.run([str(a.e2fsprogs/'debugfs'),'-w','-f',str(commands),str(root_disk)],check=True,capture_output=True)
    root_before=sha(root_disk)
    source=out/'initial-files';source.mkdir(mode=0o700)
    baseline=source/'baseline.img';baseline.write_bytes(bytes([0x5a])*(1<<20));baseline.chmod(0o600)
    disk=out/'new-synthetic-ext4.raw'
    with disk.open('xb') as f:f.truncate(128<<20)
    mk=[str(a.e2fsprogs/'mke2fs'),'-q','-F','-t','ext4','-b','4096','-I','256',
        '-g','1024','-G','1','-N','1024','-O','extent,encrypt,uninit_bg,^64bit,^metadata_csum,^orphan_file',
        '-E','root_owner=0:0','-d',str(source),str(disk)]
    subprocess.run(mk,check=True,capture_output=True)
    debug=lambda command:subprocess.check_output([str(a.e2fsprogs/'debugfs'),'-R',command,str(disk)],stderr=subprocess.DEVNULL)
    blocks=[int(n) for n in debug('blocks /baseline.img').split()]
    assert len(blocks)==256 and len(set(blocks))==256
    baseline_stat=debug('stat /baseline.img')
    with disk.open('rb') as f:
        before=b''.join((f.seek(n*4096),f.read(4096))[1] for n in blocks)
    assert before==baseline.read_bytes()
    disk_before=sha(disk)
    cmd=[str(a.qemu),'-M','virt,gic-version=3','-cpu','max','-smp','2','-m','512M',
         '-display','none','-monitor','none','-nic','none','-no-reboot',
         '-serial','file:'+str(out/'serial.log'),'-kernel',str(a.kernel),
         '-append','console=ttyAMA0 earlycon=pl011,mmio32,0x9000000 root=/dev/vda ro init=/init panic=-1'+(' owned_symlink=1' if a.symlink else ''),
         '-drive','if=none,id=our-Linux-root,format=raw,readonly=on,file='+str(root_disk),
         '-device','virtio-blk-pci,drive=our-Linux-root',
         '-drive','if=none,id=only-synthetic,format=raw,file='+str(disk),
         '-device','virtio-blk-pci,drive=only-synthetic']
    error=None
    with (out/'qemu.log').open('wb') as log:
        p=subprocess.Popen(cmd,stdout=log,stderr=subprocess.STDOUT)
        try:p.wait(timeout=120)
        except subprocess.TimeoutExpired:p.kill();p.wait();error='synthetic Linux VM deadline'
    text=(out/'serial.log').read_text(errors='replace') if (out/'serial.log').exists() else ''
    checks={'real_Linux_filesystem_completed':'OWNED_LINUX_VM_RESULT=1' in text and 'OWNED_LINUX_FILESYSTEM_TEST_COMPLETE=1' in text,
            'actual_unmount':'OWNED_REAL_EXT4_UNMOUNTED=1' in text,
            'production_build_refuses_synthetic_geometry_before_creation':'OWNED_PHYSICAL_BUILD_REFUSED_SYNTHETIC_DISK=1' in text,
            'expected_existing_refusal':('OWNED_SYMLINK_NAMESPACE_REFUSED=1' if a.symlink else 'OWNED_EXISTING_NAMESPACE_REFUSED=1') in text}
    with disk.open('rb') as f:
        after=b''.join((f.seek(n*4096),f.read(4096))[1] for n in blocks)
    checks['all_original_baseline_bytes_identical']=after==before
    checks['Linux_root_unchanged']=sha(root_disk)==root_before
    checks['original_baseline_inode_identical']=debug('stat /baseline.img')==baseline_stat
    e=subprocess.run([str(a.e2fsprogs/'e2fsck'),'-fn',str(disk)],capture_output=True)
    (out/'e2fsck-readonly.log').write_bytes(e.stdout+e.stderr)
    with disk.open('rb') as f:f.seek(1024);sb=f.read(1024)
    checks['actual_readonly_e2fsck_clean']=e.returncode==0 and bool(int.from_bytes(sb[58:60],'little')&1) and not int.from_bytes(sb[96:100],'little')&4
    records=[]
    for line in text.splitlines():
        if line.startswith('{'):
            try:records.append(json.loads(line))
            except json.JSONDecodeError:pass
    if not a.symlink:
        creation=next((j for j in records if 'created_file_exclusive' in j),{})
        fiemap=next((j for j in records if j.get('readonly_snapshot')), {})
        checks['actual_exclusive_full_zero_pin_sync']=bool(creation and creation.get('test_build') is True and
            creation.get('file_bytes')==8<<20 and creation.get('flags')==0x80090 and
            all(creation.get(k) is True for k in ('created_namespace_exclusive','created_file_exclusive',
                 'fully_written','initial_zero_readback','file_fsync','directory_fsync','syncfs')))
        checks['independent_readonly_FIEMAP']=bool(fiemap and fiemap.get('raw_write_allowed') is False and
            fiemap.get('file_bytes')==8<<20 and fiemap.get('inode')==creation.get('inode'))
        if creation and fiemap:
            sys.path.insert(0,str(root/'tools'));import polaris_runtime_owner as owner
            with disk.open('rb') as f:
                packet,proof=owner.snapshot(lambda block:(f.seek(block*4096),f.read(4096))[1],2048,32768,creation['inode'],fiemap)
            (out/'runtime-owner.packet').write_bytes(packet);(out/'owner-export-proof.json').write_text(json.dumps(proof,indent=2)+'\n')
            checks['raw_inode_CRC_extents_match_real_FIEMAP']=proof['independently_matched_FIEMAP']
    result=dict(passed=all(checks.values()) and error is None,checks=checks,error=error,
        Linux_model_only=True,physical_phone_touched=False,physical_UFS_persistence_proven=False,
        kernel_sha256=sha(a.kernel),init_sha256=sha(a.init),creator_sha256=sha(a.creator),production_creator_sha256=sha(a.production_creator),exporter_sha256=sha(a.exporter),
        creator_source_sha256=sha(root/'tools/polaris-owned-file-create.c'),init_source_sha256=sha(root/'tools/tests/polaris_owned_file_vm_init.c'),
        disk_before_sha256=disk_before,disk_after_sha256=sha(disk),command=cmd,records=records)
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:result[k] for k in ('passed','checks','error')},indent=2))
    return 0 if result['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
