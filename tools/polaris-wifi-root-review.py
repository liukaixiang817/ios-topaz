"""Review current native Wi-Fi strict-RO artifacts only; no device access or write admission."""
from pathlib import Path
import argparse,datetime,hashlib,json,struct
r=Path(__file__).resolve().parents[1]
ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--audit-directory',required=True,type=Path);args=ap.parse_args()
o=args.audit_directory.resolve();w=o.parent
assert o.is_relative_to(r/'research')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
read=lambda name:json.loads((o/name).read_text())
u16=lambda b,at:struct.unpack_from('<H',b,at)[0]
u32=lambda b,at:struct.unpack_from('<I',b,at)[0]
AUDIT_SHA='898720a851536b9c06f144642cbafa99858cafc947c039b198bd3c8aba128c14'
IMAGE_SHA='ecb73be4bd591f836ab1a9132e998a28fd4ef356624ba3dab1550b5a105f12ba'
NEW_SHA='91515474f2f886e1508e2ef62f0d8dce6fe4188c0dd382e566ba819264d37c0f'
OLD_SHA='689a8cd1df0fc0093706272241a9ac77d5eddd7a62df5d340913ec6abcd7ce2b'
ESP_SHA='7338692a4e42db7f53fac8fe2ff3bb3bf55bd5dec4bdc6d5c4243d8d49794ef3'
RAMTOOLS={'polaris-file-extents':'abdcb124d738b8146fbe785c03915476cc4b652081f138eb422513b065865999','polaris-sha256':'93fa02d44e7ad1081d18a6f42780d35c9437cf40ae1a6c24a19485c2efe607c0'}
rp=w/'fresh-20F66-readonly-root-review.json';pp=w/'fresh-20F66-readonly-preflight.json'
assert not rp.exists() and not pp.exists(),'never overwrite an earlier review/preflight'
assert o.is_dir() and (o/'result.json').is_file(),'NEW actual audit result required; historical results cannot substitute'
assert sha(r/'tools/polaris-wifi-root-audit.py')==AUDIT_SHA,'audit changed after independent review'
d=read('result.json');h=(o/'outer-header-before.bin').read_bytes();after=(o/'outer-header-after.bin').read_bytes();s=h[1024:2048]
assert len(h)==len(after)==4096
features=u32(s,96);fsblocks=u32(s,4)+(u32(s,336)<<32 if features&0x80 else 0)
checks={}
def check(name,value):checks[name]=bool(value)
def dt(value):
 t=datetime.datetime.fromisoformat(value);assert t.tzinfo is not None;return t
candidate=json.loads((w/'image-0001/manifest.json').read_text())
check('current_candidate_bound',d['candidate_image_sha256']==candidate['sha256']==sha(w/'image-0001'/candidate['artifact']) and d['candidate_driver_sha256']==candidate['driver_sha256'] and d['layout_source']=='backup/polaris-20261023-205328/layout.json')
check('actual_completed_new_case',d['state']=='readonly_audit_complete_pending_independent_review' and d['audit_only'] is True and d['new_install'] is False)
check('exact_reviewed_recovery_and_audit',d['script_sha256']==AUDIT_SHA and d['image_sha256']==IMAGE_SHA and d['watchdog_seconds']==300 and d['host_work_budget_seconds']==250)
check('RAM_tools_exact_pinned',d['RAM_tools']==RAMTOOLS)
check('no_partition_writes_replay_repair',all(d[k] is False for k in ['phone_partition_writes','journal_replayed','metadata_repaired','may_boot_iOS','may_write_userdata']))
check('actual_unmount_blockRO_FASTBOOT',d['actual_unmount'] is True and d['mounted_at_end'] is False and d['block_readonly'] is True and d['actual_expected_FASTBOOT_after'] is True)
check('actual_times_ordered',dt(d['boot_attempt_utc'])<dt(d['mount_attempt_once_utc'])<dt(d['unmount_attempt_once_utc'])<=dt(d['bootloader_request_once_utc'])<=dt(d['actual_FASTBOOT_utc']))
check('bounded_audit',0<d['new_root_hash_seconds']<90 and 0<d['old_root_hash_seconds']<90 and 0<d['host_elapsed_seconds']<=350)
check('stable_outer_header_bytes',h==after and sha(o/'outer-header-before.bin')==d['outer_header_sha256'] and d['outer_header_unchanged_this_session'] is True)
check('outer_geometry_clean_no_recovery_or_orphans',u16(s,56)==0xef53 and 1024<<u32(s,24)==4096 and 0<fsblocks<=115167178752//4096 and u16(s,58)==1 and not features&4 and u32(s,232)==0 and u32(s,404)==0)

def blockmounts(name):return [x.split() for x in (o/name).read_bytes().splitlines() if x.startswith(b'/dev/block/')]
initial=(o/'mounts-initial.txt').read_bytes().splitlines()
check('initial_and_final_actual_unmounted',not blockmounts('mounts-initial.txt') and not blockmounts('mounts-after-unmount.txt') and not blockmounts('mounts-cleanup-readonly-status.txt'))
check('RAM_dev_tmpfs',any(len(x.split())>2 and x.split()[1]==b'/dev' and x.split()[2] in (b'tmpfs',b'devtmpfs') for x in initial))
active=blockmounts('mounts-readonly.txt');flags=set(active[0][3].split(b',')) if len(active)==1 else set()
check('only_ro_noload_mount',len(active)==1 and active[0][0]==b'/dev/block/sda22' and active[0][2]==b'ext4' and active[0][1]==b'/mnt/polaris-wifi-audit-0189-0001' and {b'ro',b'nodev',b'nosuid',b'noexec'}<=flags and bool({b'noload',b'norecovery'}&flags))
check('actual_expected_FASTBOOT_before',read('fresh-actual-fastboot.json')['expected_polaris'] is True and read('fresh-actual-fastboot.json')['read_only'] is True)
old=r/'research/polaris/uefi-integration-0057/original-current'
check('all_six_GPT_exact_original',all((o/f'{disk}.{edge}.bin').read_bytes()==(old/f'{disk}.{edge}.bin').read_bytes() for disk in ('sda','sdb','sdc','sdd','sde','sdf') for edge in ('head','tail')))
expectedcritical={x['name']:(ESP_SHA if x['name']=='mindowsesp' else x['sha256']) for x in json.loads((old/'manifest.json').read_text())['files'] if x['name'] in ('boot','recovery','abl_a','abl_b','mindowsesp')}
check('critical_wholeSHA_exact',len(d['critical'])==5 and {x['name']:x['sha256'] for x in d['critical']}==expectedcritical)
esp=read('ESP-102file-rawhash-correspondence.json');plan=json.loads((r/'research/polaris/uefi-ios-0062/menu-additive-plan-0001/plan.json').read_text());side=json.loads((r/'research/polaris/uefi-ios-0062/menu-additive-physical-0001/result.json').read_text());inventory=plan['original_files']+side['new_files_written']
check('ESP_102files_whole_raw_correspondence',esp['passed'] is True and esp['actual_raw_partition_SHA256']==esp['known_raw_image_SHA256']==ESP_SHA==sha(r/'research/polaris/uefi-ios-0062/menu-additive-physical-0001/ESP-after.img') and esp['inventory']==inventory and len(inventory)==102 and len({x['path'] for x in inventory})==102 and esp['all102files_correspond_by_whole_raw_byte_hash'] is True and esp['ESP_mounted'] is False and esp['ESP_written'] is False and side['all_101_existing_files_byte_identical'] is True)

newid=read('new-root-identity-before.json');oldid=read('old-root-identity-before.json');markid=read('marker-identity-before.json')
newrefp=r/'research/polaris/uefi-ios-0124/phone-root-tail-append-0001/new-root-fiemap.json';markrefp=r/'research/polaris/uefi-ios-0124/phone-root-tail-append-0001/after-marker-identity.json';oldrefp=r/'research/polaris/uefi-ios-0078/existing-marker-export-0001/base-fiemap.json'
check('historical_maps_pinned',sha(newrefp)=='c543ddc6207fe4f53ecce452440296f37e0832de3e8630458817c4dc1335953d' and sha(markrefp)=='39f5c0748e80b401cc0ee99e622c323518702fc0bd11680a273f8fa7e39e4d6e' and sha(oldrefp)=='f8abe4398bace3dacba9ef4c7b7ebbe9a81529a64f09ce825e1a04c2536c1b55')
newref=json.loads(newrefp.read_text());markref=json.loads(markrefp.read_text());oldref=json.loads(oldrefp.read_text())
def persistent(actual,reference):
 if {k:v for k,v in actual.items() if k!='identity'}!={k:v for k,v in reference.items() if k!='identity'}:return False
 a=dict(actual['identity']);b=reference['identity'];a['device_minor']=b['device_minor'];a['device_major']=b['device_major']
 return set(a)==set(b) and all(a[k]==b[k] for k in b if k not in ('free_blocks','available_blocks'))
check('new_root_persistent_identity_and_142map',persistent(newid,newref) and newid['inode']==6193154 and newid['file_bytes']==16<<30 and len(newid['extents'])==142 and newid['identity']['generation']==2167264735 and newid['identity']['flags']==0x80090)
check('old_root_original_182map',all(oldid[k]==v for k,v in oldref.items()) and oldid['inode']==oldref['inode'] and oldid['file_bytes']==16<<30 and len(oldid['extents'])==182)
check('marker_original_identity_and_two_extents',persistent(markid,markref) and markid['inode']==1720322 and markid['identity']['generation']==2693650061 and markid['identity']['flags']==0x80090 and [(e['physical'],e['length']) for e in markid['extents']]==[(121634816,4194304),(184549376,4194304)])
check('all_current_identity_before_after_exact',all(read(name+'-identity-after.json')==identity for name,identity in [('new-root',newid),('old-root',oldid),('marker',markid)]))
runtime=d['runtime_userdata_device'];parts=runtime.split(':')
runtime_pair=tuple(map(int,parts)) if len(parts)==2 and all(x.isascii() and x.isdecimal() for x in parts) else ()
check('runtime_device_identity',len(runtime)<32 and len(runtime_pair)==2 and runtime_pair[0]>0 and
 d['runtime_userdata_sysfs_path'].endswith('/block/sda/sda22') and
 (o/'runtime-userdata-sysfs-path.txt').read_text().strip()==d['runtime_userdata_sysfs_path'] and
 d['runtime_userdata_namespace_before_after_same'] is True and
 all((i['identity']['device_major'],i['identity']['device_minor'])==runtime_pair for i in (newid,oldid,markid)))
def no_overlap(a,b):return all(x['physical']+x['length']<=y['physical'] or y['physical']+y['length']<=x['physical'] for x in a for y in b)
def valid_map(identity):
 position=0
 for e in identity['extents']:
  if not (e['logical']==position and e['length']>0 and all(e[k]%4096==0 for k in ('logical','physical','length')) and e['physical']>0 and e['physical']+e['length']<=fsblocks*4096):return False
  position+=e['length']
 return position==identity['file_bytes'] and all(no_overlap([e],identity['extents'][i+1:]) for i,e in enumerate(identity['extents']))
check('all_maps_bounded_and_no_alias',all(valid_map(i) for i in (newid,oldid,markid)) and no_overlap(newid['extents'],oldid['extents']) and no_overlap(newid['extents'],markid['extents']) and no_overlap(oldid['extents'],markid['extents']))
check('both_fresh_whole_16GiB_SHA',d['new_root_sha256']==NEW_SHA and d['old_root_sha256']==OLD_SHA and d['whole_new_root_matches_original'] is True and d['whole_root_matches_original'] is True and d['fresh_maps_before_after_match'] is True)
pattern=bytes((i*37+0x76)&255 for i in range(4096))+bytes((8<<20)-4096)
check('actual_whole_marker_pattern',(o/'marker-whole.bin').read_bytes()==pattern and d['marker_whole_pattern_unchanged'] is True)

def raw_inode(prefix,ino,identity=None):
 loc=read(prefix+'-raw-location.json');page=(o/(prefix+'-inode-page.bin')).read_bytes();inode=(o/(prefix+'-inode.bin')).read_bytes();gd=(o/(prefix+'-group-descriptor-page.bin')).read_bytes()
 per=u32(s,40);isz=u16(s,88);ds=u16(s,254) if features&0x80 else 32
 assert 1<=ino<=u32(s,0) and per>0 and isz in (128,256,512) and ds in (32,64)
 group=(ino-1)//per;gdat=group*ds;gdb=1+gdat//4096;gdo=gdat%4096
 assert len(gd)==len(page)==4096 and len(inode)==isz and 0<gdb<fsblocks and gdo+ds<=4096
 desc=gd[gdo:gdo+ds];table=u32(desc,8)+(u32(desc,40)<<32 if ds==64 else 0);at=((ino-1)%per)*isz;ipage=table+at//4096;offset=at%4096
 assert 0<table<fsblocks and ipage<fsblocks and offset+isz<=4096 and inode==page[offset:offset+isz]
 actual=dict(inode=ino,filesystem_raw_blocks=fsblocks,group=group,descriptor_block=gdb,descriptor_offset=gdo,descriptor_bytes=ds,inode_table=table,inode_page=ipage,inode_offset=offset,inode_bytes=isz,raw_generation=u32(inode,100),raw_flags=u32(inode,32),raw_mode=u16(inode,0),raw_uid=u16(inode,2)+(u16(inode,120)<<16),raw_gid=u16(inode,24)+(u16(inode,122)<<16),raw_size=u32(inode,4)+(u32(inode,108)<<32),raw_links=u16(inode,26),raw_allocated_512byte_blocks=u32(inode,28)+(u16(inode,116)<<32))
 assert loc==actual
 if identity:
  assert actual['raw_size']==identity['file_bytes']
  for rawkey,key in [('raw_generation','generation'),('raw_flags','flags'),('raw_mode','mode'),('raw_uid','uid'),('raw_gid','gid'),('raw_links','links'),('raw_allocated_512byte_blocks','allocated_512byte_blocks')]:assert actual[rawkey]==identity['identity'][key]
 return inode,actual,desc
newinode,newloc,_=raw_inode('new-root-raw',newid['inode'],newid)
oldinode,oldloc,_=raw_inode('old-root-raw',oldid['inode'],oldid)
markinode,markloc,markdesc=raw_inode('marker-raw',markid['inode'],markid)
check('three_raw_inodes_cross_bound_current_identity',d['all_three_raw_inodes_match_current_identity'] is True and d['old_root_historical_generation_not_available'] is True)
owner=r/'research/polaris/uefi-ios-0108/pre-XNU-only-audit-0002'
check('marker_raw_inode_page_exact_original',markloc['inode_page']==6881282 and (o/'marker-raw-inode-page.bin').read_bytes()==(owner/'metadata-6881282.bin').read_bytes()==(o/'owner-metadata-6881282.bin').read_bytes())
oldgd=(owner/f"metadata-{markloc['descriptor_block']}.bin").read_bytes();at=markloc['descriptor_offset']
historical_markdesc=oldgd[at:at+markloc['descriptor_bytes']]
#0124 allocated new-root data blocks in marker inode group210. Descriptor
#free counts/bitmap checksums can therefore differ; keep raw differences,
#bind ownership addresses/flags and current geometry, never admit writes.
ds=markloc['descriptor_bytes'];group=markloc['group'];per=u32(s,40);blocksper=u32(s,32);isz=u16(s,88)
groupblocks=min(blocksper,fsblocks-(u32(s,20)+group*blocksper))
freeblocks=u16(markdesc,12)+(u16(markdesc,44)<<16 if ds==64 else 0)
freeinodes=u16(markdesc,14)+(u16(markdesc,46)<<16 if ds==64 else 0)
useddirs=u16(markdesc,16)+(u16(markdesc,48)<<16 if ds==64 else 0)
unused=u16(markdesc,28)+(u16(markdesc,50)<<16 if ds==64 else 0)
bitmap=u32(markdesc,0)+(u32(markdesc,32)<<32 if ds==64 else 0)
ibitmap=u32(markdesc,4)+(u32(markdesc,36)<<32 if ds==64 else 0)
check('marker_descriptor_addresses_flags_and_geometry',len(historical_markdesc)==ds and markdesc[:12]==historical_markdesc[:12] and (ds==32 or markdesc[32:44]==historical_markdesc[32:44]) and markdesc[18:24]==historical_markdesc[18:24] and not u16(markdesc,18)&~7 and 0<groupblocks<=blocksper and 0<=freeblocks<=groupblocks and 0<=freeinodes<=per and 0<=useddirs<=per and 0<=unused<=per and 0<bitmap<fsblocks and 0<ibitmap<fsblocks and markloc['inode_table']+(per*isz+4095)//4096<=fsblocks)
marker_descriptor_differences=[i for i in range(ds) if markdesc[i]!=historical_markdesc[i]]

journal=read('journal-capture.json');ji,jloc,_=raw_inode('journal',u32(s,224));js=(o/'journal-superblock.bin').read_bytes();jwords=list(struct.unpack_from('>9I',js));jsize=u32(ji,4)+(u32(ji,108)<<32)
spans=[];nodes=[];seen=set()
def extents(b,maxdepth):
 magic,n,maximum,depth=struct.unpack_from('<4H',b);assert magic==0xf30a and 0<=depth<=maxdepth and 0<n<=maximum and 12+n*12<=len(b)
 for index in range(n):
  at=12+index*12
  if depth:
   logical,low,high,_=struct.unpack_from('<IIHH',b,at);block=low+(high<<32)
   assert 0<block<fsblocks and block not in seen and len(seen)<16;seen.add(block)
   child=(o/f'journal-index-{block}.bin').read_bytes();assert len(child)==4096;nodes.append(dict(block=block,sha256=hashlib.sha256(child).hexdigest()));extents(child,depth-1)
  else:
   logical,length,high,low=struct.unpack_from('<IHHI',b,at);assert 0<length<=0x8000;spans.append([logical,low+(high<<32),length])
extents(ji[40:100],1);position=0
for logical,physical,count in spans:
 assert logical==position and 0<physical and physical+count<=fsblocks;position+=count
assert position*4096==jsize and len(spans)<=64
assert all(a[1]+a[2]<=b[1] or b[1]+b[2]<=a[1] for i,a in enumerate(spans) for b in spans[i+1:])
assert all(not physical<=block<physical+count for _,physical,count in spans for block in seen)
jmap=[dict(physical=physical*4096,length=count*4096) for _,physical,count in spans]
check('journal_no_root_marker_alias',all(no_overlap(jmap,i['extents']) for i in (newid,oldid,markid)))
check('journal_metadata_actual_and_bounded',journal==d['journal'] and journal['inode']==u32(s,224)==8 and jsize==journal['size']==512<<20 and journal['extents']==spans and journal['index_nodes']==nodes and journal['raw_location']==jloc and journal['superblock_big_endian_words']==jwords and sha(o/'journal-superblock.bin')==journal['superblock_sha256'] and len(js)==4096 and u16(ji,0)&0xf000==0x8000 and u32(ji,32)&0x80000)
check('journal_superblock_no_pending_start_or_errno',jwords[0]==0xc03b3998 and jwords[1] in (3,4) and jwords[3]==4096 and jwords[4]*4096==jsize and jwords[7]==0 and jwords[8]==0)
check('journal_cap_is_explicit_not_corruption',journal['metadata_capture_complete'] is True and journal['whole_capture_complete'] is False and journal['whole_capture_cap_bytes']==256<<20 and journal['whole_capture_skipped'] is True and journal['cap_refusal_is_corruption'] is False and journal['replayed'] is False and journal['whole_journal_integrity_proven'] is False)

historical_review=r/'research/polaris/uefi-ios-0124/fresh-20F66-readonly-root-review.json';historical_preflight=r/'research/polaris/uefi-ios-0124/fresh-20F66-readonly-preflight.json'
check('historical_install_review_pinned',sha(historical_review)=='f9a7b665793149c4b08fa9e481140e9b8eb11b5a5b2ac7b502325c3c5d4f39bd' and sha(historical_preflight)=='52af9054ffe7f41d9767d08d7816d99a5e3d9247a30f39a2adbfa7ef1d2f4222')
hist=json.loads(historical_review.read_text());hp=json.loads(historical_preflight.read_text())
check('historical_install_only_not_current_writes',hist['passed'] is True and hist['build']=='20F66' and hist['new_file_install_preceded_readonly_review'] is True and hist['original_root_and_marker_preserved'] is True and hist['new_root_immutable'] is True and hp['root_review_sha256']==sha(historical_review) and hp['full_image_sha256']==NEW_SHA and dt(hp['updated_utc'])<dt(d['boot_attempt_utc']))
nv=read('fresh-NV-inputs.json');entries=nv['actual_inputs']
check('three_NV_exact_partitions_and_sizes',[(x['name'],x['disk'],x['partition'],x['first_lba'],x['last_lba'],x['bytes']) for x in entries]==[('modemst1','sdf',6,2048,4095,8<<20),('modemst2','sdf',7,4096,6143,8<<20),('fsg','sde',36,8192,10239,8<<20)])
check('three_NV_whole_before_local_after_SHA',all(x['sha256_before']==x['local_sha256']==x['sha256_after']==sha(o/x['path']) and (o/x['path']).stat().st_size==8<<20 and (o/x['path']).stat().st_mode&0o777==0o600 for x in entries) and d['fresh_3NV_before_local_after_SHA_equal'] is True and d['actual_NV_bytes']==24<<20)
fsc=nv['FSC']
check('fresh_entire_FSC_from_GPT_head',fsc['path']=='fsc.bin' and fsc['bytes']==262144 and fsc['sha256']==sha(o/'fsc.bin')==d['fresh_FSC_SHA256']=='8a39d2abd3999ab73c34db2476849cddf303ce389b35826850f9a700589b4a90' and (o/'fsc.bin').read_bytes()==(o/'sdf.head.bin').read_bytes()[6*4096:70*4096])
check('NV_GPT_before_after_byte_equal',d['fresh_NV_GPT_before_after_equal'] is True and nv['fresh_GPT_before_after_equal'] is True and all((o/(disk+'.'+edge+'.bin')).read_bytes()==(o/(disk+'.'+edge+'.after.bin')).read_bytes() for disk in ('sde','sdf') for edge in ('head','tail')))
check('NV_no_remote_or_storage_writes',nv['passed'] is True and nv['phone_partition_writes'] is False and nv['MSS_started'] is False and nv['may_serve_NV_to_remote'] is False)
assert all(checks.values()),[k for k,v in checks.items() if not v]
review=dict(passed=True,build='20F66',scope='ONLY immutable16GiB20F66 HFSX RO +512MiB RAMCOW/ufsrw0/noownedmarker; native UFS writes forbidden',checks=checks,
 post_unmount_RO_only=True,new_file_install_preceded_readonly_review=True,historical_install_basis_only=True,preceding_install_partition_writes=False,new_install=False,current_audit_partition_writes=False,
 historical_install_review_path=str(historical_review.relative_to(r)),historical_install_review_sha256=sha(historical_review),historical_install_preflight_path=str(historical_preflight.relative_to(r)),historical_install_preflight_sha256=sha(historical_preflight),
 original_root_and_marker_preserved=True,new_root_immutable=True,actual_FASTBOOT_utc=d['actual_FASTBOOT_utc'],current_outer_header_sha256=sha(o/'outer-header-after.bin'),historical_outer_header_sha256=hist['current_outer_header_sha256'],
 outer_header_changed_since_historical_install=sha(o/'outer-header-after.bin')!=hist['current_outer_header_sha256'],metadata_change_origin='If changed since0124: unknown unobserved interval; not attributed to Android, Windows, or this audit',
 current_fs_fields=dict(state=u16(s,58),incompat=features,last_orphan=u32(s,232),error_count=u32(s,404),raw_blocks=fsblocks),
 old_root_historical_generation_proven=False,old_root_current_raw_identity_and_fullSHA_map_proven=True,
 marker_group_descriptor_changed_byte_positions=marker_descriptor_differences,marker_group_descriptor_counters=dict(free_blocks=freeblocks,free_inodes=freeinodes,used_directories=useddirs,unused_inodes=unused),marker_descriptor_counter_checksum_changes='raw retained; includes historical0124 allocations or unknown interval; no write ownership inferred',
 journal=dict(metadata_superblock_only=True,size=jsize,whole_capture_cap_bytes=256<<20,whole_capture_complete=False,whole_capture_refusal_is_corruption=False,s_start=jwords[7],s_errno=jwords[8],sequence_observed=jwords[6],replayed=False),
 may_boot_iOS=True,may_write_userdata=False,may_replay_or_repair=False,may_change_write_ownership_baseline=False,whole_journal_integrity_or_general_filesystem_health_proven=False,
 audit_script_sha256=AUDIT_SHA,review_script_sha256=sha(Path(__file__)),files={str(p.relative_to(r)):sha(p) for p in o.iterdir() if p.is_file()})
with rp.open('x') as f:json.dump(review,f,indent=2);f.write('\n')
pre=dict(state='fresh_new20F66_root_readonly_preflight_passed',build='20F66',review_phase='fresh-uncontrolled-interval-post-unmount-readonly-only',updated_utc=d['actual_FASTBOOT_utc'],
 preceding_install_partition_writes=False,historical_install_basis_only=True,new_install=False,phone_partition_writes=False,journal_replayed=False,metadata_repaired=False,
 all_six_GPT_copies_match_original=True,fresh_maps_before_after_match=True,unmounted=True,block_readonly=True,outer_header_unchanged_during_readonly_check=True,outer_header_independently_reviewed=True,
 observed_root_sha256=NEW_SHA,full_image_sha256=NEW_SHA,extent_count=142,file_bytes=16<<30,hash_seconds=d['new_root_hash_seconds'],outer_header_sha256=sha(o/'outer-header-after.bin'),
 actual_expected_fastboot_after_verified=True,may_boot_iOS=True,may_write_userdata=False,permitted_boot_scope=review['scope'],root_review_sha256=sha(rp),journal_capture_complete=False,
 owned_write_or_persistence_admitted=False,outer_needs_journal_recovery=False,outer_state=1,critical_partitions_match_reviewed_baselines=True,fresh_extents_match_payload_baseline=True,
 permitted_boot_arguments={'ufsrw':0,'polarisramcow':1,'rootrw':1,'polarisrammb':512,'polarisownedmarker':0},write_ownership_baseline_update_permitted=False,
 whole_journal_integrity_or_general_filesystem_health_proven=False,historical_install_review_sha256=sha(historical_review))
with pp.open('x') as f:json.dump(pre,f,indent=2);f.write('\n')
print(json.dumps(dict(passed=True,checks=len(checks),actual_FASTBOOT_utc=d['actual_FASTBOOT_utc'],may_boot_iOS_immutable_RO_RAMCOW=True,may_write_userdata=False),indent=2))
