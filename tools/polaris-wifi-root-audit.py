"""Native Wi-Fi candidate bounded strict-RO two-root plus own NV audit; default offline; NEVER repair/replay/RW/install."""
from pathlib import Path
import argparse,datetime,hashlib,json,re,struct,subprocess,sys,time
r=Path(__file__).resolve().parents[1];w=r/'research/polaris/uefi-ios-0120';sys.path.insert(0,str(r/'tools'))
import polaris_adb_exec as framing
from polaris_fastboot_identity import expected_polaris_fastboot
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
now=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat()
ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--boot-once',action='store_true')
for name in ('candidate-directory','serial-file','fastboot','adb','output'):ap.add_argument('--'+name,type=Path,required=True)
args=ap.parse_args()
assert args.output.resolve().is_relative_to(r/'research') and not args.output.exists(),'exclusive private audit output required'
image=w/'watchdog-0001/polaris-backup-recovery.img';manifest=json.loads((image.parent/'manifest.json').read_text());proof=json.loads((w/'readonly-watchdog-image-proof.json').read_text())
assert proof['passed'] and proof['image_sha256']==sha(image)==manifest['sha256']=='ecb73be4bd591f836ab1a9132e998a28fd4ef356624ba3dab1550b5a105f12ba' and manifest['watchdog_seconds']==300
assert manifest['builder_sha256']==sha(r/'tools/build-polaris-backup-recovery.py')
assert 'Ran 7 tests' in (w/'local-watchdog-0002.log').read_text() and '\nOK\n' in (w/'local-watchdog-0002.log').read_text()
assert hashlib.sha256(subprocess.check_output(['git','show','HEAD:tools/build-polaris-backup-recovery.py'])).hexdigest()==manifest['builder_sha256'],'source must be committed'
RAMTOOLS=[(r/'research/polaris/uefi-ios-0077/owned-file-vm-exporter','polaris-file-extents','abdcb124d738b8146fbe785c03915476cc4b652081f138eb422513b065865999'),(r/'research/polaris/fs-inspect-0001/polaris-sha256','polaris-sha256','93fa02d44e7ad1081d18a6f42780d35c9437cf40ae1a6c24a19485c2efe607c0')]
assert all(sha(source)==expected for source,_,expected in RAMTOOLS),'RAM-only audit tools changed'
# This recovery audit executes neither the new radio driver nor a storage
# installer. Bind it to the concrete new offline image instead of re-labelling
# an old WLED candidate. Native Wi-Fi boot admission is a later separate review.
case=args.candidate_directory.resolve();assert case.is_relative_to(r/'research')
candidate=json.loads((case/'image-0001/manifest.json').read_text())
driver=json.loads((case/'driver-0001/manifest.json').read_text())
assert candidate['scope']=='native_WiFi_retained_CPU0_RO_RAMCOW'
assert candidate['boot_admission'] is False and candidate['device_command_executed'] is False
assert candidate['may_write_userdata'] is False and candidate['immutable_root_RAMCOW_only'] is True
assert candidate['original_inner_files']==candidate['unchanged_inner_files']==81
assert candidate['original_codec_round_trip'] is True
assert candidate['packager_sha256']==sha(r/'tools/polaris-wifi-native-image.py')
assert candidate['driver_manifest_sha256']==sha(case/'driver-0001/manifest.json')
assert Path(candidate['artifact']).name==candidate['artifact']
assert candidate['sha256']==sha(case/'image-0001'/candidate['artifact'])
assert driver['sha256']==candidate['driver_sha256']==sha(case/'driver-0001'/driver['artifact'])
assert driver['payload_sha256']==candidate['payload_sha256']==sha(case/'payload-0001/payload.bin')
assert driver['wifi_native_runtime_enabled'] is True and driver['wifi_native_display_input_integrated'] is True
assert driver['storage_write_api'] is False and driver['NVRAM_write_api'] is False
assert candidate['source_inputs']==driver['inputs']
for name,digest in driver['inputs'].items():
 p=(r/name).resolve();assert p.is_relative_to(r) and sha(p)==digest,name
# The later complete backup is independently bound to the same six original
# GPT byte copies; do not fabricate a hydrated copy of the older layout file.
layout=json.loads((r/'backup/polaris-20261023-205328/layout.json').read_text())
assert set(layout)=={'sda','sdb','sdc','sdd','sde','sdf'}
assert args.fastboot.is_file() and args.adb.is_file() and args.serial_file.is_file()
serial=args.serial_file.read_text().strip()
assert re.fullmatch(r'[A-Za-z0-9._-]{1,128}',serial)

if not args.boot_once:print('Offline admission passed; no device command sent');sys.exit(0)
o=args.output.resolve();o.mkdir(parents=True,exist_ok=False)
adb=[str(args.adb.resolve()),'-s',serial];fb=[str(args.fastboot.resolve()),'-s',serial]
record=dict(candidate_image_sha256=candidate['sha256'],candidate_driver_sha256=driver['sha256'],layout_source='backup/polaris-20261023-205328/layout.json',state='prepared',phone_partition_writes=False,journal_replayed=False,metadata_repaired=False,may_boot_iOS=False,may_write_userdata=False,image_sha256=sha(image),script_sha256=sha(Path(__file__)),builder_sha256=manifest['builder_sha256'],audit_only=True,new_install=False,host_work_budget_seconds=250,watchdog_seconds=300);mounted=False;own=False;sent=False;start=None;cleanup_phase=False
save=lambda:(o/'result.json').write_text(json.dumps(dict(record,updated_utc=now()),indent=2)+'\n')
def call(cmd,timeout=15):
 began=time.monotonic();kind=('adb_exec' if 'exec-out' in cmd else ('fastboot_boot' if 'boot' in cmd else Path(cmd[0]).name));status='UNKNOWN'
 try:
  p=subprocess.run(cmd,capture_output=True,timeout=timeout);status=p.returncode
  if p.returncode:raise RuntimeError('bounded device command failed: '+(p.stderr+p.stdout)[-250:].decode(errors='replace').replace(serial,'<redacted>'))
  return p.stdout
 finally:
  record.setdefault('bounded_call_times',[]).append(dict(kind=kind,began_since_boot=None if start is None else began-start,seconds=time.monotonic()-began,timeout_seconds=timeout,status=status));save()
def budget(timeout):
 if start is None:return timeout
 left=(285 if cleanup_phase else 250)-(time.monotonic()-start)
 if left<2:raise RuntimeError('read-only audit host budget reached; cleanup/watchdog required')
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
 return expected_polaris_fastboot(p.returncode,(p.stdout+p.stderr).decode(errors='replace'))
def inode_capture(header,ino,prefix):
 sb=header[1024:2048];u16=lambda b,at:struct.unpack_from('<H',b,at)[0];u32=lambda b,at:struct.unpack_from('<I',b,at)[0]
 assert u16(sb,56)==0xef53 and 1024<<u32(sb,24)==4096
 per=u32(sb,40);isz=u16(sb,88);ds=u16(sb,254) if u32(sb,96)&0x80 else 32
 fsblocks=u32(sb,4)+(u32(sb,336)<<32 if u32(sb,96)&0x80 else 0)
 assert 0<fsblocks<=115167178752//4096 and ino>=1 and per>0 and isz in (128,256,512) and ds in (32,64)
 group=(ino-1)//per;gd_at=group*ds;gd_block=1+gd_at//4096;gd_offset=gd_at%4096;assert gd_block<fsblocks and gd_offset+ds<=4096
 gd=raw('/dev/block/sda22',gd_block);(o/(prefix+'-group-descriptor-page.bin')).write_bytes(gd)
 descriptor=gd[gd_offset:gd_offset+ds]
 table=u32(descriptor,8)+(u32(descriptor,40)<<32 if ds>=64 else 0)
 at=((ino-1)%per)*isz;assert 0<table<fsblocks and table+at//4096<fsblocks and at%4096+isz<=4096
 page=raw('/dev/block/sda22',table+at//4096);(o/(prefix+'-inode-page.bin')).write_bytes(page)
 inode=page[at%4096:at%4096+isz];(o/(prefix+'-inode.bin')).write_bytes(inode)
 info=dict(inode=ino,filesystem_raw_blocks=fsblocks,group=group,descriptor_block=gd_block,descriptor_offset=gd_offset,descriptor_bytes=ds,inode_table=table,inode_page=table+at//4096,inode_offset=at%4096,inode_bytes=isz,raw_generation=u32(inode,100),raw_flags=u32(inode,32),raw_mode=u16(inode,0),raw_uid=u16(inode,2)+(u16(inode,120)<<16),raw_gid=u16(inode,24)+(u16(inode,122)<<16),raw_size=u32(inode,4)+(u32(inode,108)<<32),raw_links=u16(inode,26),raw_allocated_512byte_blocks=u32(inode,28)+(u16(inode,116)<<32))
 (o/(prefix+'-raw-location.json')).write_text(json.dumps(info,indent=2)+'\n');return inode,info

def journal_capture(header):
 # Metadata+first superblock ONLY. A512MiB inode is an explicit diagnostic
 # cap refusal, never a corruption assertion and never reason for another boot.
 sb=header[1024:2048];ino=struct.unpack_from('<I',sb,224)[0]
 inode,location=inode_capture(header,ino,'journal');u16=lambda b,at:struct.unpack_from('<H',b,at)[0];u32=lambda b,at:struct.unpack_from('<I',b,at)[0]
 size=u32(inode,4)+(u32(inode,108)<<32);fsblocks=location['filesystem_raw_blocks']
 assert u16(inode,0)&0xf000==0x8000 and u32(inode,32)&0x80000 and 4096<=size<=fsblocks*4096 and size%4096==0
 nodes=[];seen=set()
 def extents(b,maxdepth):
  magic,entries,maximum,depth=struct.unpack_from('<4H',b);assert magic==0xf30a and depth<=maxdepth and 0<entries<=maximum and 12+entries*12<=len(b)
  spans=[]
  for n in range(entries):
   at=12+12*n
   if depth:
    logical,low,high,_=struct.unpack_from('<IIHH',b,at);block=low+(high<<32)
    assert 0<block<fsblocks and block not in seen and len(seen)<16;seen.add(block)
    child=raw('/dev/block/sda22',block);nodes.append(dict(block=block,sha256=hashlib.sha256(child).hexdigest()));(o/f'journal-index-{block}.bin').write_bytes(child);spans+=extents(child,depth-1)
   else:
    logical,length,high,low=struct.unpack_from('<IHHI',b,at)
    # ext4 ee_len==0x8000 means initialized32768 blocks; only greater is unwritten.
    assert 0<length<=0x8000;spans.append((logical,low+(high<<32),length))
  return spans
 spans=extents(inode[40:100],1);position=0
 for logical,physical,count in spans:
  assert logical==position and physical>0 and physical+count<=fsblocks and position+count<=size//4096;position+=count
 assert position*4096==size and len(spans)<=64
 assert all(a[1]+a[2]<=b[1] or b[1]+b[2]<=a[1] for i,a in enumerate(spans) for b in spans[i+1:]),'journal physical alias'
 assert all(not physical<=block<physical+count for _,physical,count in spans for block in seen),'journal data/index alias'
 superblock=raw('/dev/block/sda22',spans[0][1]);(o/'journal-superblock.bin').write_bytes(superblock)
 words=list(struct.unpack_from('>9I',superblock));assert words[0]==0xc03b3998 and words[1] in (3,4) and words[3]==4096 and words[4]*4096==size
 cap=256<<20;info=dict(inode=ino,size=size,extents=spans,index_nodes=nodes,raw_location=location,superblock_big_endian_words=words,superblock_sha256=hashlib.sha256(superblock).hexdigest(),metadata_capture_complete=True,whole_capture_complete=False,whole_capture_cap_bytes=cap,whole_capture_skipped=size>cap,whole_capture_skipped_reason='journal inode exceeds256MiB diagnostic cap; metadata+superblock only' if size>cap else 'metadata-only policy; no whole-journal capture requested',cap_refusal_is_corruption=False,replayed=False,read_only_diagnostic=True,whole_journal_integrity_proven=False)
 (o/'journal-capture.json').write_text(json.dumps(info,indent=2)+'\n');return info

try:
 assert fastboot();(o/'fresh-actual-fastboot.json').write_text(json.dumps(dict(utc=now(),expected_polaris=True,read_only=True))+'\n')
 record.update(state='RAM_boot_attempt_recorded',boot_attempt_utc=now());save();sent=True;start=time.monotonic()
 (o/'boot.log').write_bytes(call(fb+['boot',str(image)],120).replace(serial.encode(),b'<phone>'));record['state']='RAM_boot_sent';save()
 while time.monotonic()-start<65:
  p=subprocess.run(adb+['get-state'],capture_output=True,timeout=3)
  if p.returncode==0 and p.stdout.strip() in (b'device',b'recovery'):break
  time.sleep(1)
 else:raise RuntimeError('bounded audit ADB unavailable; wait for watchdog, no second boot')
 assert sh('getprop ro.product.device').strip()==b'polaris' and sh('id').startswith(b'uid=0(root)')
 assert sh('getprop init.svc.polaris-audit-watchdog').strip()==b'running'
 assert sh('sha256sum /sbin/polaris-audit-watchdog.sh').split()[0].decode()==proof['watchdog_sha256']
 assert sh('sha256sum /init.rc').split()[0].decode()==proof['init_sha256'];own=True
 initial_mounts=sh('cat /proc/mounts');(o/'mounts-initial.txt').write_bytes(initial_mounts);assert not any(x.startswith(b'/dev/block/') for x in initial_mounts.splitlines())
 assert any(len(x.split())>2 and x.split()[1]==b'/dev' and x.split()[2] in (b'tmpfs',b'devtmpfs') for x in initial_mounts.splitlines())
 assert int(sh('cat /sys/class/power_supply/battery/temp'))<450
 for disk in ['sda','sdb','sdc','sdd','sde','sdf','sda22']:
  sh('blockdev --setro /dev/block/'+disk);assert sh('blockdev --getro /dev/block/'+disk).strip()==b'1'
 assert sh('readlink -f /dev/block/bootdevice/by-name/userdata').strip()==b'/dev/block/sda22' and int(sh('blockdev --getsize64 /dev/block/sda22'))==115167178752
 header=raw('/dev/block/sda22',0);(o/'outer-header-before.bin').write_bytes(header);record['outer_header_sha256']=hashlib.sha256(header).hexdigest()
 old=r/'research/polaris/uefi-integration-0057/original-current';layout=json.loads((r/'backup/polaris-20261023-205328/layout.json').read_text())
 for disk in ['sda','sdb','sdc','sdd','sde','sdf']:
  size=int(sh('blockdev --getsize64 /dev/block/'+disk));assert size==layout[disk]['disk_bytes']
  for label,block in [('head',0),('tail',(size-1048576)//4096)]:
   data=raw('/dev/block/'+disk,block,256);assert data==(old/f'{disk}.{label}.bin').read_bytes();(o/f'{disk}.{label}.bin').write_bytes(data)
 critical=[]
 for item in json.loads((old/'manifest.json').read_text())['files']:
  name=item['name']
  if name not in ('boot','recovery','abl_a','abl_b','mindowsesp'):continue
  path='/dev/block/bootdevice/by-name/'+name;sh('blockdev --setro '+path);assert sh('blockdev --getro '+path).strip()==b'1'
  expected='7338692a4e42db7f53fac8fe2ff3bb3bf55bd5dec4bdc6d5c4243d8d49794ef3' if name=='mindowsesp' else item['sha256']
  began=time.monotonic();digest=sh('sha256sum '+path,50).split()[0].decode();assert digest==expected;critical.append(dict(name=name,sha256=digest));record.setdefault('critical_read_times',[]).append(dict(name=name,seconds=time.monotonic()-began));save();print('Actual strictRO critical hash matched: '+name,flush=True)
 espbaseline=r/'research/polaris/uefi-ios-0062/menu-additive-physical-0001/ESP-after.img'
 assert sha(espbaseline)=='7338692a4e42db7f53fac8fe2ff3bb3bf55bd5dec4bdc6d5c4243d8d49794ef3'
 plan=json.loads((r/'research/polaris/uefi-ios-0062/menu-additive-plan-0001/plan.json').read_text())
 side=json.loads((r/'research/polaris/uefi-ios-0062/menu-additive-physical-0001/result.json').read_text())
 inventory=plan['original_files']+side['new_files_written'];assert len(inventory)==102
 assert side['ESP_after_sha256']==next(x['sha256'] for x in critical if x['name']=='mindowsesp')
 (o/'ESP-102file-rawhash-correspondence.json').write_text(json.dumps(dict(passed=True,actual_raw_partition_SHA256=side['ESP_after_sha256'],known_raw_image_SHA256=sha(espbaseline),all102files_correspond_by_whole_raw_byte_hash=True,inventory=inventory,ESP_mounted=False,ESP_written=False),indent=2)+'\n')
 record['ESP_102files_rawhash_correspondence']=True
 record.update(state='critical_and_GPT_RO_passed',critical=critical);save();print('Actual RO: six GPT + critical/ESP unchanged; auditing root and marker',flush=True)
 # Read only own exact modemst1/modemst2/fsg partitions after actual original
 # GPT byte equality. No firmware service/RMTFS publication or storage write.
 nv=[]
 for name,disk,number,first,last,size in [('modemst1','sdf',6,2048,4095,8<<20),('modemst2','sdf',7,4096,6143,8<<20),('fsg','sde',36,8192,10239,8<<20)]:
  part=[p for p in layout[disk]['partitions'] if p['name']==name]
  assert part==[dict(number=number,name=name,first_lba=first,last_lba=last,bytes=size)]
  path='/dev/block/'+disk+str(number)
  assert sh('readlink -f /dev/block/bootdevice/by-name/'+name).strip().decode()==path
  assert int(sh('blockdev --getsize64 '+path))==size
  sh('blockdev --setro '+path);assert sh('blockdev --getro '+path).strip()==b'1'
  before=sh('sha256sum '+path,20).split()[0].decode()
  data=raw(path,0,size//4096);assert hashlib.sha256(data).hexdigest()==before
  target=o/(name+'.bin')
  with target.open('xb') as f:
   import os
   os.fchmod(f.fileno(),0o600);f.write(data)
  nv.append(dict(name=name,disk=disk,partition=number,first_lba=first,last_lba=last,bytes=size,sha256_before=before,local_sha256=hashlib.sha256(data).hexdigest(),path=target.name))
 # FSC is already completely captured in the fresh original sdf head.
 fsc=(o/'sdf.head.bin').read_bytes()[6*4096:70*4096];assert len(fsc)==262144
 assert hashlib.sha256(fsc).hexdigest()=='8a39d2abd3999ab73c34db2476849cddf303ce389b35826850f9a700589b4a90'
 with (o/'fsc.bin').open('xb') as f:
  import os
  os.fchmod(f.fileno(),0o600);f.write(fsc)
 record['fresh_NV_inputs']=nv;record['fresh_FSC_SHA256']=hashlib.sha256(fsc).hexdigest();save()

 for source,name,expected in RAMTOOLS:
  call(adb+['push',str(source),'/dev/'+name],budget(15));sh('chmod 700 /dev/'+name);assert sh('sha256sum /dev/'+name).split()[0].decode()==expected
 record['RAM_tools']={name:expected for _,name,expected in RAMTOOLS}
 mount='/mnt/polaris-wifi-audit-0189-0001';base=mount+'/polaris-ios/root-20H392-v1.img';newroot=mount+'/polaris-ios-20F66-0124-0001/root.img';marker=mount+'/polaris-owned-v0077-0001/marker.bin'
 sh('mkdir -m 700 '+mount);record['mount_attempt_once_utc']=now();mounted=None;save()
 sh('mount -t ext4 -o ro,noload,nodev,nosuid,noexec /dev/block/sda22 '+mount);mounted=True
 mounts=sh('cat /proc/mounts');(o/'mounts-readonly.txt').write_bytes(mounts);active=[x.split() for x in mounts.splitlines() if x.startswith(b'/dev/block/')]
 assert len(active)==1 and active[0][0]==b'/dev/block/sda22' and active[0][2]==b'ext4' and active[0][1].decode()==mount and {b'ro',b'nodev',b'nosuid',b'noexec'}<=set(active[0][3].split(b',')) and any(x in active[0][3].split(b',') for x in (b'noload',b'norecovery'))
 runtime=sh('cat /sys/class/block/sda22/dev').strip().decode()
 record['runtime_userdata_device']=runtime;save()
 assert len(runtime)<32 and re.fullmatch(r'[0-9]+:[0-9]+',runtime),'invalid current sysfs dev_t'
 runtime_pair=tuple(map(int,runtime.split(':')));assert runtime_pair[0]>0
 runtime_path=sh('readlink -f /sys/dev/block/'+runtime).strip()
 (o/'runtime-userdata-sysfs-path.txt').write_bytes(runtime_path+b'\n')
 assert runtime_path.endswith(b'/block/sda/sda22'),'current dev_t does not resolve to userdata'
 record['runtime_userdata_sysfs_path']=runtime_path.decode();save()
 oldref=json.loads((r/'research/polaris/uefi-ios-0078/existing-marker-export-0001/base-fiemap.json').read_text())
 newref=json.loads((r/'research/polaris/uefi-ios-0124/phone-root-tail-append-0001/new-root-fiemap.json').read_text())
 markerref=json.loads((r/'research/polaris/uefi-ios-0124/phone-root-tail-append-0001/after-marker-identity.json').read_text())
 def identify(path,name):
  v=json.loads(sh('/dev/polaris-file-extents --identity '+path));(o/(name+'-identity-before.json')).write_text(json.dumps(v,indent=2)+'\n');return v
 def persistent(actual,expected):
  assert {k:actual[k] for k in expected if k!='identity'}=={k:v for k,v in expected.items() if k!='identity'}
  a=json.loads(json.dumps(actual['identity']));a['device_minor']=expected['identity']['device_minor'];a['device_major']=expected['identity']['device_major']
  difference={k:dict(previous=expected['identity'].get(k),actual=v) for k,v in a.items() if expected['identity'].get(k)!=v}
  assert set(difference)<={'free_blocks','available_blocks'};return difference
 oldid=identify(base,'old-root');newid=identify(newroot,'new-root');markid=identify(marker,'marker')
 assert all((i['identity']['device_major'],i['identity']['device_minor'])==runtime_pair for i in (newid,oldid,markid)),'current userdata dev_t/file identity mismatch'
 assert {k:oldid[k] for k in oldref}==oldref and len(oldid['extents'])==182 and oldid['file_bytes']==16<<30
 assert newid['inode']==6193154 and newid['file_bytes']==16<<30 and newid['identity']['generation']==2167264735 and newid['identity']['flags']==0x80090 and len(newid['extents'])==142
 record['new_root_identity_differences']=persistent(newid,newref)
 assert markid['inode']==1720322 and markid['identity']['generation']==2693650061 and markid['identity']['flags']==0x80090 and markid['file_bytes']==8<<20
 record['marker_identity_differences']=persistent(markid,markerref)
 assert [(e['physical'],e['length']) for e in markid['extents']]==[(121634816,4194304),(184549376,4194304)]
 def no_overlap(a,b):return all(x['physical']+x['length']<=y['physical'] or y['physical']+y['length']<=x['physical'] for x in a for y in b)
 assert no_overlap(newid['extents'],oldid['extents']) and no_overlap(newid['extents'],markid['extents']) and no_overlap(oldid['extents'],markid['extents'])
 record.update(root_map_unchanged=True,new_root_map_unchanged=True,marker_persistent_identity_unchanged=True,marker_fiemap_unchanged=True,no_new_old_marker_alias=True)
 contents=raw(marker,0,2048);(o/'marker-whole.bin').write_bytes(contents);record['marker_whole_pattern_unchanged']=contents==bytes((i*37+0x76)&255 for i in range(4096))+bytes((8<<20)-4096);assert record['marker_whole_pattern_unchanged']
 for page in json.loads((r/'research/polaris/uefi-ios-0078/existing-marker-export-0001/ownership-proof.json').read_text())['metadata_pages']:
  block=page['block'];current=raw('/dev/block/sda22',block);(o/f'owner-metadata-{block}.bin').write_bytes(current)
  if block:record.setdefault('raw_owner_page_matches',{})[str(block)]=current==(r/'research/polaris/uefi-ios-0108/pre-XNU-only-audit-0002'/f'metadata-{block}.bin').read_bytes()
 for path,name,expected in [(newroot,'new-root','91515474f2f886e1508e2ef62f0d8dce6fe4188c0dd382e566ba819264d37c0f'),(base,'old-root','689a8cd1df0fc0093706272241a9ac77d5eddd7a62df5d340913ec6abcd7ce2b')]:
  record['state']='hashing_'+name;save();began=time.monotonic();value=sh('/dev/polaris-sha256 '+path+' 2>/dev/polaris-'+name+'-progress',90).strip().decode();seconds=time.monotonic()-began
  record[name.replace('-','_')+'_sha256']=value;record[name.replace('-','_')+'_hash_seconds']=seconds
  (o/(name+'-progress.txt')).write_bytes(sh('cat /dev/polaris-'+name+'-progress'));assert value==expected;save();print('Fresh strictRO whole '+name+' SHA matched, seconds='+str(round(seconds,3)),flush=True)
 for path,name,expected in [(newroot,'new-root',newid),(base,'old-root',oldid),(marker,'marker',markid)]:
  after=json.loads(sh('/dev/polaris-file-extents --identity '+path));(o/(name+'-identity-after.json')).write_text(json.dumps(after,indent=2)+'\n');assert after==expected
 assert sh('cat /sys/class/block/sda22/dev').strip().decode()==runtime and sh('readlink -f /sys/dev/block/'+runtime).strip()==runtime_path,'userdata device identity changed'
 record['runtime_userdata_namespace_before_after_same']=True;save()
 record.update(whole_new_root_matches_original=True,whole_root_matches_original=True,fresh_maps_before_after_match=True)
 record['unmount_attempt_once_utc']=now();mounted=None;save()
 try:sh('umount '+mount)
 except Exception as e:record['unmount_ACK_unknown_or_failed']=str(e).replace(serial,'<phone>');save()
 mounts=sh('cat /proc/mounts');(o/'mounts-after-unmount.txt').write_bytes(mounts);assert not any(x.startswith(b'/dev/block/') for x in mounts.splitlines()) and raw('/dev/block/sda22',0)==header;mounted=False
 record.update(state='full_RO_samples_collected_pending_review',outer_header_unchanged_this_session=True);save();print('Whole root/map/marker/raw-owner samples collected and unmounted; capturing journal RO',flush=True)
 record['journal']=journal_capture(header)
 for identity,prefix in [(newid,'new-root-raw'),(markid,'marker-raw'),(oldid,'old-root-raw')]:
  inode,loc=inode_capture(header,identity['inode'],prefix);fields=identity['identity']
  assert loc['raw_size']==identity['file_bytes']
  for rawkey,key in [('raw_generation','generation'),('raw_flags','flags'),('raw_mode','mode'),('raw_uid','uid'),('raw_gid','gid'),('raw_links','links'),('raw_allocated_512byte_blocks','allocated_512byte_blocks')]:assert loc[rawkey]==fields[key],prefix+' raw identity mismatch '+key
 record['all_three_raw_inodes_match_current_identity']=True
 record['old_root_historical_generation_not_available']=True

 # Independent whole-partition SHA after all root/map/journal reads; do not
 # retry a changing NV image or claim it current from matching GPT alone.
 for entry in nv:
  path='/dev/block/'+entry['disk']+str(entry['partition'])
  entry['sha256_after']=sh('sha256sum '+path,20).split()[0].decode()
  assert entry['sha256_before']==entry['local_sha256']==entry['sha256_after']
  assert sh('blockdev --getro '+path).strip()==b'1'
 assert sh('sha256sum /dev/block/sdf1',20).split()[0].decode()==record['fresh_FSC_SHA256']
 for disk in ('sde','sdf'):
  for edge,block in [('head',0),('tail',(layout[disk]['disk_bytes']-1048576)//4096)]:
   data=raw('/dev/block/'+disk,block,256);assert data==(o/(disk+'.'+edge+'.bin')).read_bytes()
   (o/(disk+'.'+edge+'.after.bin')).write_bytes(data)
 record['fresh_3NV_before_local_after_SHA_equal']=True;record['fresh_NV_GPT_before_after_equal']=True
 record['actual_NV_bytes']=sum(x['bytes'] for x in nv)
 assert record['actual_NV_bytes']==24<<20
 (o/'fresh-NV-inputs.json').write_text(json.dumps(dict(passed=True,actual_inputs=nv,all_original_data=True,FSC=dict(path='fsc.bin',bytes=262144,sha256=record['fresh_FSC_SHA256']),fresh_GPT_before_after_equal=True,phone_partition_writes=False,may_serve_NV_to_remote=False,MSS_started=False),indent=2)+'\n')
 after=raw('/dev/block/sda22',0);(o/'outer-header-after.bin').write_bytes(after);assert after==header and sh('blockdev --getro /dev/block/sda22').strip()==b'1';record.update(state='readonly_audit_complete_pending_independent_review',outer_header_unchanged_this_session=True,actual_unmount=True,block_readonly=True);save()
except Exception as e:
 record['failure_source_line']=sys.exc_info()[2].tb_lineno
 record.update(state='stopped_for_review',error=(type(e).__name__+': '+str(e)).replace(serial,'<phone>'),mounted_at_error=mounted);save();print('Audit stopped:',record['error'],flush=True)
finally:
 cleanup_phase=True
 if own:
  # A lost mount/umount ACK never establishes mount state. Read actual state
  # before cleanup; each state-changing command is issued at most once.
  if record.get('mount_attempt_once_utc'):
   try:
    mounts=sh('cat /proc/mounts',8);(o/'mounts-cleanup-readonly-status.txt').write_bytes(mounts)
    blockmounts=[x.split() for x in mounts.splitlines() if x.startswith(b'/dev/block/')]
    mounted=True if any(x[1]==b'/mnt/polaris-wifi-audit-0189-0001' for x in blockmounts) else (False if not blockmounts else None)
   except Exception as e:mounted=None;record['cleanup_mount_status_error']=str(e).replace(serial,'<phone>')
   if mounted is True and not record.get('unmount_attempt_once_utc'):
    record['unmount_attempt_once_utc']=now();mounted=None;save()
    try:sh('umount /mnt/polaris-wifi-audit-0189-0001',15)
    except Exception as e:record['unmount_ACK_unknown_or_failed']=str(e).replace(serial,'<phone>')
    try:
     mounts=sh('cat /proc/mounts',8);(o/'mounts-cleanup-after-unmount-status.txt').write_bytes(mounts)
     blockmounts=[x.split() for x in mounts.splitlines() if x.startswith(b'/dev/block/')]
     mounted=True if any(x[1]==b'/mnt/polaris-wifi-audit-0189-0001' for x in blockmounts) else (False if not blockmounts else None)
    except Exception as e:mounted=None;record['cleanup_mount_status_error']=str(e).replace(serial,'<phone>')
  if mounted is False:
   record['bootloader_request_once_utc']=now();save()
   try:
    result=subprocess.run(adb+['reboot','bootloader'],capture_output=True,timeout=10)
    record['bootloader_request_exit_code']=result.returncode
   except subprocess.TimeoutExpired:record['bootloader_ACK_unknown']=True
 if sent:
  until=start+335
  while time.monotonic()<until:
   try:
    if fastboot():record['actual_expected_FASTBOOT_after']=True;record['actual_FASTBOOT_utc']=now();break
   except subprocess.TimeoutExpired:pass
   time.sleep(1)
 record['mounted_at_end']=mounted;record['host_elapsed_seconds']=time.monotonic()-start if start is not None else None;save()
 print(json.dumps({k:record.get(k) for k in ['state','new_root_hash_seconds','old_root_hash_seconds','actual_expected_FASTBOOT_after','actual_FASTBOOT_utc','may_boot_iOS','may_write_userdata']},indent=2),flush=True)
 assert record.get('actual_expected_FASTBOOT_after'),'No actual FASTBOOT after bounded recovery; physical action may be necessary'
