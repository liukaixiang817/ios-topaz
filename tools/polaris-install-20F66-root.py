"""Install one NEW immutable20F66 file; no existing file or raw block writes.
Default only freezes host inputs. --install-once is the explicit physical action.
"""
from pathlib import Path
import argparse,datetime,hashlib,json,re,struct,subprocess,sys,time
r=Path(__file__).resolve().parents[1];w=r/'research/polaris/uefi-ios-0124';sys.path.insert(0,str(r/'tools'))
import polaris_adb_exec as framing
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
now=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat()
ap=argparse.ArgumentParser();ap.add_argument('--install-once',action='store_true');ap.add_argument('--attempt',choices=('0001','0002'),default='0001');args=ap.parse_args()
image=w/'root-transfer-recovery-0001/polaris-backup-recovery.img';manifest=json.loads((image.parent/'manifest.json').read_text())
assert sha(image)==manifest['sha256']=='f9ad6529c1632fa2116377ec5f12c78f6d5cf7f5a1baa0b0f1bec4b5a518bd99'
root=w/'ios16.5-20F66-full-root-0001.img';rootmeta=json.loads(root.with_suffix('.json').read_text())
assert rootmeta['complete'] and rootmeta['build']=='20F66' and rootmeta['version']=='16.5' and root.stat().st_size==16<<30
assert rootmeta['sha256']=='91515474f2f886e1508e2ef62f0d8dce6fe4188c0dd382e566ba819264d37c0f'
# Streamed hashing keeps the16GiB host input outside process memory.
with root.open('rb') as stream:assert hashlib.file_digest(stream,'sha256').hexdigest()==rootmeta['sha256']
vm=json.loads((w/'Linux-root-receive-0002/result.json').read_text());assert vm['passed']
receiver=w/'polaris-root-receive';assert vm['production_receiver_sha256']==sha(receiver)
for path,key in [('tools/polaris-root-receive.c','source_sha256'),('tools/tests/polaris_root_receive_vm_init.c','init_source_sha256')]:
 assert sha(r/path)==vm[key]
 assert hashlib.sha256(subprocess.check_output(['git','show','HEAD:'+path])).hexdigest()==vm[key],'commit source before physical use'
assert hashlib.sha256(subprocess.check_output(['git','show','HEAD:tools/polaris-install-20F66-root.py'])).hexdigest()==sha(Path(__file__)),'commit controller before physical use'
if not args.install_once:print('Exact new16.5 root/receiver/recovery frozen; no device command sent');sys.exit(0)
if args.attempt=='0002':
 prior=json.loads((w/'phone-new-root-install-0001/result.json').read_text())
 assert prior['phone_partition_writes'] is False and prior['mounted_at_end'] is False and prior['actual_expected_FASTBOOT_after'] is True
o=w/('phone-new-root-install-'+args.attempt);o.mkdir(exist_ok=False)
serial=re.search(r'androidboot.serialno=(\S+)',(r/'backup/polaris-20261023-193109/cmdline.txt').read_text()).group(1)
adb=[str(r/'research/host-tools/platform-tools/adb'),'-s',serial];fb=[str(r/'research/host-tools/platform-tools/fastboot'),'-s',serial]
record=dict(state='prepared',phone_partition_writes=False,journal_replayed=False,metadata_repaired=False,may_boot_iOS=False,may_write_userdata=False,image_sha256=sha(image),script_sha256=sha(Path(__file__)),new_root_sha256=rootmeta['sha256'],new_file_only=True,raw_device_writes=False,old_root_overwritten=False);mounted=False;own=False;sent=False;start=None
save=lambda:(o/'result.json').write_text(json.dumps(dict(record,updated_utc=now()),indent=2)+'\n')
def call(cmd,timeout=15):
 p=subprocess.run(cmd,capture_output=True,timeout=timeout)
 if p.returncode:raise RuntimeError('bounded device command failed: '+(p.stderr+p.stdout)[-250:].decode(errors='replace').replace(serial,'<redacted>'))
 return p.stdout
def budget(timeout):
 if start is None:return timeout
 left=1100-(time.monotonic()-start)
 if left<2:raise RuntimeError('new-root migration host budget reached; cleanup required')
 return min(timeout,left)
def sh(command,timeout=20):
 wrapped,nonce=framing.wrap(command);data,rc=framing.decode(call(adb+['exec-out',wrapped],budget(timeout)),nonce)
 if rc:raise RuntimeError('remote framed exit '+str(rc)+' for '+command.split()[0])
 return data
def raw(path,block,count=1):
 assert isinstance(block,int) and block>=0 and 1<=count<=65536
 data=sh(f'dd if={path} bs=4096 skip={block} count={count} 2>/dev/null',60)
 assert len(data)==count*4096,'short raw read';return data
def fastboot():
 p=subprocess.run(fb+['getvar','product'],capture_output=True,timeout=8)
 return p.returncode==0 and bool(re.search(rb'product:\s*polaris\b',p.stdout+p.stderr))
def wait_result(path,seconds):
 until=time.monotonic()+seconds
 while time.monotonic()<until:
  value=sh('if [ -f '+path+' ]; then cat '+path+'; else echo pending; fi').strip()
  if value!=b'pending':return value
  time.sleep(1)
 raise RuntimeError('remote completion still unknown for '+path+'; no retransmission')
def clean_header(header):
 sb=header[1024:2048]
 assert struct.unpack_from('<H',sb,56)[0]==0xef53 and struct.unpack_from('<I',sb,24)[0]==2
 assert struct.unpack_from('<H',sb,58)[0]==1 and not struct.unpack_from('<I',sb,96)[0]&4
 assert struct.unpack_from('<I',sb,232)[0]==0 and struct.unpack_from('<I',sb,404)[0]==0
 return hashlib.sha256(header).hexdigest()
def mount_ro():
 global mounted
 sh('mount -t ext4 -o ro,noload,nodev,nosuid,noexec /dev/block/sda22 '+mount);mounted=True
 lines=[x.split() for x in sh('cat /proc/mounts').splitlines() if x.startswith(b'/dev/block/')]
 assert len(lines)==1 and lines[0][1].decode()==mount and b'ro' in lines[0][3].split(b',') and any(x in lines[0][3].split(b',') for x in (b'noload',b'norecovery'))
def unmount():
 global mounted
 sh('umount '+mount,90);mounted=False
 assert not any(x.startswith(b'/dev/block/') for x in sh('cat /proc/mounts').splitlines())
def whole(path,expected):
 began=time.monotonic();got=sh('/dev/polaris-sha256 '+path+' 2>/dev/root-hash-progress',130).strip().decode();assert got==expected
 return dict(sha256=got,seconds=time.monotonic()-began)
def critical_and_gpt(label):
 old=r/'research/polaris/uefi-integration-0057/original-current';layout=json.loads((r/'backup/polaris-20261023-193109/layout.json').read_text())
 for disk in ['sda','sdb','sdc','sdd','sde','sdf']:
  size=int(sh('blockdev --getsize64 /dev/block/'+disk));assert size==layout[disk]['disk_bytes']
  for edge,block in [('head',0),('tail',(size-1048576)//4096)]:
   blob=raw('/dev/block/'+disk,block,256);assert blob==(old/f'{disk}.{edge}.bin').read_bytes();(o/f'{label}-{disk}.{edge}.bin').write_bytes(blob)
 for item in json.loads((old/'manifest.json').read_text())['files']:
  name=item['name']
  if name in ('boot','recovery','abl_a','abl_b','mindowsesp'):
   expected='7338692a4e42db7f53fac8fe2ff3bb3bf55bd5dec4bdc6d5c4243d8d49794ef3' if name=='mindowsesp' else item['sha256']
   assert sh('sha256sum /dev/block/bootdevice/by-name/'+name,50).split()[0].decode()==expected
 record[label+'_sixGPT_critical_ESP_match']=True;save()
def marker_review(label):
 got=json.loads(sh('/dev/polaris-file-extents --identity '+marker));expected=json.loads((r/'research/polaris/uefi-ios-0123/phone-readonly-audit-0001/marker-identity.json').read_text())
 (o/(label+'-marker-identity.json')).write_text(json.dumps(got,indent=2)+'\n')
 assert {k:v for k,v in got.items() if k!='identity'}=={k:v for k,v in expected.items() if k!='identity'}
 ignored=('device_minor','free_blocks','available_blocks')
 assert {k:v for k,v in got['identity'].items() if k not in ignored}=={k:v for k,v in expected['identity'].items() if k not in ignored}
 assert raw(marker,0,2048)==bytes((i*37+0x76)&255 for i in range(4096))+bytes((8<<20)-4096)
 record[label+'_marker_unchanged']=True;save()
mount='/mnt/polaris-root-migrate-0124';base=mount+'/polaris-ios/root-20H392-v1.img';marker=mount+'/polaris-owned-v0077-0001/marker.bin';new=mount+'/polaris-ios-20F66-0124-0001/root.img'
receiver_live=False;rw=False;blocks=[]
try:
 assert fastboot();record['actual_FASTBOOT_before_utc']=now();record.update(state='RAM_boot_attempt_recorded',boot_attempt_utc=now());save();sent=True;start=time.monotonic()
 (o/'boot.log').write_bytes(call(fb+['boot',str(image)],120).replace(serial.encode(),b'<phone>'))
 while time.monotonic()-start<65:
  p=subprocess.run(adb+['get-state'],capture_output=True,timeout=3)
  if p.returncode==0 and p.stdout.strip() in (b'device',b'recovery'):break
  time.sleep(1)
 else:raise RuntimeError('new recovery unavailable; no second boot')
 assert sh('getprop ro.product.device').strip()==b'polaris' and sh('id').startswith(b'uid=0(root)')
 assert sha(r/'tools/build-polaris-backup-recovery.py')=='213ccf8ec143c530dd9bb4ded7888a2f4c0c1178c7f78759ce4a229950e7acb1'
 assert not any(x.startswith(b'/dev/block/') for x in sh('cat /proc/mounts').splitlines());own=True
 assert int(sh('cat /sys/class/power_supply/battery/temp'))<450
 blocks=sh('ls /sys/class/block').decode().split();blocks=[x for x in blocks if re.fullmatch(r'sd[a-f][0-9]*',x)]
 assert 'sda22' in blocks and all(d in blocks for d in ('sda','sdb','sdc','sdd','sde','sdf'))
 for disk in blocks:sh('blockdev --setro /dev/block/'+disk)
 assert all(sh('blockdev --getro /dev/block/'+disk).strip()==b'1' for disk in blocks)
 assert sh('readlink -f /dev/block/bootdevice/by-name/userdata').strip()==b'/dev/block/sda22' and int(sh('blockdev --getsize64 /dev/block/sda22'))==115167178752
 header=raw('/dev/block/sda22',0);record['outer_header_before_sha256']=clean_header(header);(o/'outer-before.bin').write_bytes(header)
 assert record['outer_header_before_sha256']=='c042a66f19da2ca5c32d84418dcec0419dc723db07dbfe834de08d34e76c7cdb'
 critical_and_gpt('before')
 for source,name in [(r/'research/polaris/uefi-ios-0077/owned-file-vm-exporter','polaris-file-extents'),(r/'research/polaris/fs-inspect-0001/polaris-sha256','polaris-sha256'),(receiver,'polaris-root-receive')]:
  call(adb+['push',str(source),'/dev/'+name]);sh('chmod 700 /dev/'+name);assert sh('sha256sum /dev/'+name).split()[0].decode()==sha(source)
 # Exercise the actual stdin transport in RAM before any writable mount.
 probe=bytes((i*37+0x24)&255 for i in range(65536))
 command='dd of=/dev/polaris-root-stream-probe bs=1 count=65536 2>/dev/polaris-root-stream-probe.log; probe_rc=$?; echo $probe_rc >/dev/polaris-root-stream-probe.rc'
 transport=subprocess.run(adb+['exec-in',command],input=probe,capture_output=True,timeout=20)
 (o/'RAM-stream-probe.log').write_bytes((transport.stdout+transport.stderr).replace(serial.encode(),b'<phone>'))
 completion=wait_result('/dev/polaris-root-stream-probe.rc',8)
 actual_probe=sh('cat /dev/polaris-root-stream-probe');(o/'RAM-stream-probe.bin').write_bytes(actual_probe)
 (o/'RAM-stream-remote.log').write_bytes(sh('cat /dev/polaris-root-stream-probe.log'))
 record['RAM_stream_probe']=dict(transport_exit=transport.returncode,remote_exit=completion.decode(),actual_bytes=len(actual_probe),actual_sha256=hashlib.sha256(actual_probe).hexdigest(),expected_sha256=hashlib.sha256(probe).hexdigest());save()
 assert transport.returncode==0 and completion==b'0' and actual_probe==probe,'actual complete RAM transport content mismatch'
 record['actual_RAM_stream_transport_verified']=True;save()
 sh('mkdir -m 700 '+mount);mount_ro()
 oldmap=json.loads(sh('/dev/polaris-file-extents '+base));assert oldmap==json.loads((r/'research/polaris/uefi-ios-0123/phone-readonly-audit-0001/root-fiemap.json').read_text())
 marker_review('before');record['old_root_before']=whole(base,'689a8cd1df0fc0093706272241a9ac77d5eddd7a62df5d340913ec6abcd7ce2b')
 # A fresh namespace must be absent even as a symlink; writer repeats this atomically.
 sh('test ! -e '+mount+'/polaris-ios-20F66-0124-0001 && test ! -L '+mount+'/polaris-ios-20F66-0124-0001')
 unmount();assert raw('/dev/block/sda22',0)==header
 for disk in ('sda','sda22'):sh('blockdev --setrw /dev/block/'+disk)
 assert all(sh('blockdev --getro /dev/block/'+disk).strip()==b'1' for disk in blocks if disk not in ('sda','sda22'))
 sh('mount -t ext4 -o rw,noatime,nodev,nosuid,noexec,noinit_itable,nodiscard /dev/block/sda22 '+mount);mounted=True;rw=True
 rows=[x.split() for x in sh('cat /proc/mounts').splitlines() if x.startswith(b'/dev/block/')];assert len(rows)==1 and rows[0][1].decode()==mount and b'rw' in rows[0][3].split(b',')
 record.update(state='new_file_receiver_attempt_recorded',phone_partition_writes=True,new_file_attempt_utc=now());save()
 command='/dev/polaris-root-receive '+mount+' >/dev/root-receive-result.json 2>/dev/root-receive.log; root_rc=$?; echo $root_rc >/dev/root-receive.rc; exit $root_rc'
 receiver_live=True
 with root.open('rb') as source,(o/'stream-transport.log').open('wb') as log:
  proc=subprocess.Popen(adb+['exec-in',command],stdin=source,stdout=log,stderr=log)
  try:rc=proc.wait(timeout=660)
  except subprocess.TimeoutExpired:proc.kill();proc.wait();raise RuntimeError('stream transport deadline; no retransmission')
 # A failed/unknown transport is never retried. Inspect actual completion first.
 actual=wait_result('/dev/root-receive.rc',150);receiver_live=False
 (o/'receiver.log').write_bytes(sh('cat /dev/root-receive.log'))
 result=json.loads(sh('cat /dev/root-receive-result.json'));(o/'receiver-result.json').write_text(json.dumps(result,indent=2)+'\n')
 assert rc==0 and actual==b'0' and result['complete'] is True and result['test_build'] is False and result['sha256']==rootmeta['sha256'] and result['bytes']==16<<30
 unmount();rw=False
 for disk in ('sda22','sda'):sh('blockdev --setro /dev/block/'+disk)
 assert all(sh('blockdev --getro /dev/block/'+disk).strip()==b'1' for disk in blocks)
 after=raw('/dev/block/sda22',0);record['outer_header_after_sha256']=clean_header(after);(o/'outer-after.bin').write_bytes(after)
 mount_ro();mapping=json.loads(sh('/dev/polaris-file-extents --identity '+new));(o/'new-root-fiemap.json').write_text(json.dumps(mapping,indent=2)+'\n')
 assert mapping['file_bytes']==16<<30 and mapping['identity']['flags']==0x80090
 record['new_root_after_unmount_RO']=whole(new,rootmeta['sha256']);record['old_root_after_unmount_RO']=whole(base,'689a8cd1df0fc0093706272241a9ac77d5eddd7a62df5d340913ec6abcd7ce2b')
 assert json.loads(sh('/dev/polaris-file-extents '+base))==oldmap;marker_review('after');assert json.loads(sh('/dev/polaris-file-extents --identity '+new))==mapping
 unmount();assert raw('/dev/block/sda22',0)==after;critical_and_gpt('after')
 record.update(state='new_root_verified_RO_unmounted',new_root_readonly_verified=True,old_root_marker_preserved=True,may_boot_iOS=False,may_write_userdata=False);save()
except Exception as e:
 record.update(state='stopped_for_review',error=(type(e).__name__+': '+str(e)).replace(serial,'<phone>'),mounted_at_error=mounted,receiver_completion_unknown=receiver_live);save();print(record['error'],flush=True)
finally:
 if own and receiver_live:
  # The helper has its own600s lifetime. Do not reboot/unmount a possible writer.
  try:
   if sh('test -f /dev/root-receive.rc && cat /dev/root-receive.rc').strip():receiver_live=False
  except Exception:pass
 if own and not receiver_live:
  if mounted:
   try:unmount();rw=False
   except Exception as e:record['unmount_error']=str(e).replace(serial,'<phone>')
  if not mounted:
   for disk in ('sda22','sda'):
    try:sh('blockdev --setro /dev/block/'+disk)
    except Exception:pass
   record['bootloader_request_once_utc']=now();save()
   try:subprocess.run(adb+['reboot','bootloader'],capture_output=True,timeout=10)
   except subprocess.TimeoutExpired:record['bootloader_ACK_unknown']=True
   until=time.monotonic()+35
   while time.monotonic()<until:
    try:
     if fastboot():record['actual_expected_FASTBOOT_after']=True;record['actual_FASTBOOT_utc']=now();break
    except subprocess.TimeoutExpired:pass
    time.sleep(1)
 record.update(mounted_at_end=mounted,receiver_completion_unknown=receiver_live);save()
 print(json.dumps({k:record.get(k) for k in ('state','error','new_root_readonly_verified','actual_expected_FASTBOOT_after','actual_FASTBOOT_utc','receiver_completion_unknown')},indent=2),flush=True)
 assert record.get('actual_expected_FASTBOOT_after') and record.get('new_root_readonly_verified'),'Migration incomplete; inspect saved state without retry'
