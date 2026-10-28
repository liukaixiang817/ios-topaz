#!/usr/bin/env python3
"""Package original UEFI plus a validated RAM-only resident iOS loader offline.

This does not relax the inventory packager's hold-only CLI. A physical trial
requires the matching new kernel's full CI and actual EFI/XNU QEMU handoff,
fresh immutable-root preflight and a separate final EDK2 decoder check.
No device access or installation commands are implemented here.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def admit(driver,qemu,ci,profile,preflight):
    if driver.get('physical_owned_marker_test') or qemu.get('physical_owned_marker_test'):
        raise ValueError('physical owned marker needs separate fresh new-file and owned-native-proof admission; RAM-only packaging cannot grant it')
    if (driver.get('isolated_QEMU_readonly_UFS_test') or qemu.get('isolated_QEMU_readonly_UFS_test') or
            driver.get('isolated_QEMU_owned_UFS_test') or qemu.get('isolated_QEMU_owned_UFS_test')):
        raise ValueError('isolated virtual UFS is not physical phone admission evidence')
    if (driver.get('RAM_only_XNU_loader') is not True or driver.get('QEMU_variant') is not False or
        driver.get('ready_to_boot_driver') is not True or driver.get('bounded_input') is not True or driver.get('kernel_CPU_affinity') not in (256,1792) or
        driver.get('storage_write_api') is not False or driver.get('NVRAM_write_api') is not False):
        raise ValueError('physical RAM-only loader required')
    if driver.get('kernel_CPU_affinity')==1792 and qemu.get('kernel_CPU_affinity')!=7:
        raise ValueError('big-core physical trial requires matching actual QEMU CPU7 execution')
    count=driver.get('kernel_CPU_count',1)
    if count not in (1,2,4) or (count>1 and (driver.get('kernel_CPU_affinity')!=1792 or
        qemu.get('kernel_CPU_count')!=count or
        not all(qemu.get('checks',{}).get(k) is True for k in ['both_kernel_CPUs_online','real_cross_core_callbacks']))):
        raise ValueError('multi-core RAM trial requires actual matching online/xcall proof')
    if count==4 and (driver.get('RAM_native_shutdown_bridge') is not True or qemu.get('checks',{}).get('four_core_affinities_and_xcalls') is not True):
        raise ValueError('four-core phone trial requires native shutdown bridge and four-core actual online/xcall proof')
    if bool(driver.get('CPU_OSM_readonly_inventory'))!=bool(qemu.get('CPU_OSM_readonly_inventory')):
        raise ValueError('physical and actual virtual OSM inventory intent must match exactly')
    if driver.get('CPU_OSM_readonly_inventory') and (count!=4 or
        qemu.get('CPU_OSM_readonly_inventory') is not True or
        qemu.get('checks',{}).get('native_OSM_probe_refused_before_virtual_MMIO') is not True):
        raise ValueError('OSM physical inventory requires actual virtual-platform refusal before MMIO')
    if bool(driver.get('CPU_OSM_stock_performance'))!=bool(qemu.get('CPU_OSM_stock_performance')):
        raise ValueError('physical and virtual stock performance intent must match')
    if driver.get('CPU_OSM_stock_performance'):
        inventory=driver.get('CPU_OSM_stock_inventory') or {}
        if (count!=4 or driver.get('CPU_OSM_readonly_inventory') or
            qemu.get('checks',{}).get('native_stock_OSM_refused_before_virtual_RW') is not True or
            inventory.get('passed') is not True or inventory.get('target_index')!=22 or
            inventory.get('target_requested_Hz')!=2649600000 or not inventory.get('actual_native_log_sha256')):
            raise ValueError('stock performance needs physical inventory and actual virtual guard refusal')
    gpu_mode=driver.get('GPU_stock_request',0)
    keys=driver.get('physical_buttons',False)
    if (type(keys) is not bool or type(qemu.get('physical_buttons',False)) is not bool or
        keys!=qemu.get('physical_buttons',False)):
        raise ValueError('physical and actual virtual three-key intent must match')
    if keys and (count not in (2,4) or driver.get('RAM_native_shutdown_bridge') is not True or
                 qemu.get('checks',{}).get('native_three_key_consumer') is not True or
                 qemu.get('checks',{}).get('explicit_three_key_payload') is not True):
        raise ValueError('physical keys require the actual native three-key and release consumer proof')
    wake=driver.get('framebuffer_arrival_wake',False)
    if (type(wake) is not bool or type(qemu.get('framebuffer_arrival_wake',False)) is not bool or
        wake!=qemu.get('framebuffer_arrival_wake',False)):
        raise ValueError('physical and virtual framebuffer wake intent must match')
    if wake and (count not in (2,4) or driver.get('RAM_native_shutdown_bridge') is not True or
                 qemu.get('checks',{}).get('native_framebuffer_workloop_probe') is not True or
                 qemu.get('checks',{}).get('explicit_framebuffer_wake_payload') is not True):
        raise ValueError('framebuffer wake requires the actual native workloop probe and exact payload')
    if gpu_mode!=qemu.get('GPU_stock_request',0):
        raise ValueError('physical and virtual GPU stock request intent must match')
    if gpu_mode:
        inventory=driver.get('GPU_stock_inventory') or {}
        if (type(gpu_mode) is not int or gpu_mode not in (1,2,3) or count!=4 or
            qemu.get('checks',{}).get('native_GPU_stock_refused_before_virtual_MMIO') is not True or
            inventory.get('passed') is not True or inventory.get('baseline_PERF')!=1 or inventory.get('baseline_BW')!=4 or
            not inventory.get('actual_log_sha256')):
            raise ValueError('GPU stock request requires physical baseline and actual virtual guard refusal')
    if (qemu.get('passed') is not True or qemu.get('release_handoff_admitted') is not True or
        qemu.get('diagnostic_legacy_only') is not False or not qemu.get('checks') or
        not all(v is True for v in qemu['checks'].values()) or qemu['checks'].get('bounded_input_handshake') is not True or
        qemu.get('kernel_sha256')!=driver.get('kernel_sha256') or qemu.get('inputs')!=driver.get('inputs')):
        raise ValueError('matching actual EFI/XNU handoff proof required; legacy refusal is insufficient')
    if driver.get('disk_payload_read_only') and (not qemu.get('disk_fixture') or
        not all(qemu['checks'].get(k) is True for k in ['unique_GPT_filesystem','disk_payload_exact_read',
                     'disk_files_closed_before_kernel','disk_read_success'])):
        raise ValueError('disk payload requires the actual GPT/FAT read and closed-handles proof')
    if driver.get('chain_app') and not all(qemu['checks'].get(k) is True for k in
         ['selected_disk_app_started','chain_file_handles_closed','chain_loaded_success','selected_app_did_not_return']):
        raise ValueError('chain trial requires actual selected EFI application handoff proof')
    if driver.get('RAM_native_shutdown_bridge'):
        if count>1 and qemu.get('checks',{}).get('native_peer_affinity_OFF') is not True:
            raise ValueError('multi-core native bridge requires actual scheduler shutdown and peer AFFINITY_OFF proof')
        status=qemu.get('native_shutdown_mailbox') or {}
        if (qemu.get('RAM_native_drain_test')!='success' or not all(qemu['checks'].get(k) is True for k in
                ['native_reboot_sync_path','real_zero_mounts_and_buffers','firmware_observed_RAM_drained','separate_RAM_result']) or
            not status.get('cookie') or status.get('cookie')!=status.get('request_cookie') or
            status.get('sequence')!=1 or status.get('mode')!=2 or status.get('phase')!=3 or
            status.get('error')!=0 or status.get('write_epoch')!=0 or status.get('flushed_epoch')!=0 or
            status.get('capabilities')!=0x80000003):
            raise ValueError('native RAM shutdown bridge requires actual successful native EFI/XNU drain proof')
    fields=dict(line.split('=',1) for line in profile.splitlines() if '=' in line)
    if (ci.get('status')!='completed' or ci.get('conclusion')!='success' or
        fields.get('target_platform')!='polaris' or fields.get('machine_config')!='SWEET' or
        fields.get('commit')!=ci.get('headSha') or not ci.get('databaseId')):
        raise ValueError('successful matching full Polaris CI/profile required')
    required=['all_six_GPT_copies_match_original','fresh_maps_before_after_match','unmounted','block_readonly',
              'outer_header_unchanged_during_readonly_check','outer_header_independently_reviewed']
    if (preflight.get('state')!='fresh_root_readonly_preflight_passed' or
        not all(preflight.get(k) is True for k in required) or preflight.get('phone_partition_writes') is not False or
        preflight.get('journal_replayed') is not False or preflight.get('metadata_repaired') is not False or
        preflight.get('observed_root_sha256')!=preflight.get('full_image_sha256') or
        len(preflight.get('full_image_sha256',''))!=64 or preflight.get('extent_count')!=182):
        raise ValueError('fresh immutable root and partition preflight required')


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--original',required=True,type=Path)
    ap.add_argument('--expected-original-sha256',required=True)
    ap.add_argument('--driver-manifest',required=True,type=Path)
    ap.add_argument('--qemu-proof',required=True,type=Path)
    ap.add_argument('--ci-proof',required=True,type=Path)
    ap.add_argument('--kernel',required=True,type=Path)
    ap.add_argument('--kernel-profile',required=True,type=Path)
    ap.add_argument('--preflight',required=True,type=Path)
    ap.add_argument('--payload',required=True,type=Path)
    ap.add_argument('--output',required=True,type=Path)
    a=ap.parse_args();root=Path(__file__).resolve().parents[1]
    driver=json.loads(a.driver_manifest.read_text());qemu=json.loads(a.qemu_proof.read_text())
    ci=json.loads(a.ci_proof.read_text());preflight=json.loads(a.preflight.read_text())
    admit(driver,qemu,ci,a.kernel_profile.read_text(),preflight)
    for name,digest in driver['inputs'].items():
        if sha(root/name)!=digest:raise ValueError('loader source changed: '+name)
    app=a.driver_manifest.parent/driver['artifact']
    if app.resolve().parent!=a.driver_manifest.parent.resolve():raise ValueError('invalid driver path')
    if (sha(a.original)!=a.expected_original_sha256 or sha(app)!=driver['sha256'] or
        sha(a.kernel)!=driver['kernel_sha256'] or sha(a.payload)!=driver['payload_sha256']):
        raise ValueError('firmware, driver, kernel or payload digest mismatch')
    # The CI artifact digest must be explicitly bound, not merely a success URL.
    sums=a.kernel_profile.parent/'SHA256SUMS'
    matches=[line.split()[0] for line in sums.read_text().splitlines()
             if len(line.split())==2 and line.split()[1].lstrip('*')==a.kernel.name]
    if matches!=[sha(a.kernel)]:raise ValueError('kernel does not match collected CI artifact digest')
    spec=importlib.util.spec_from_file_location('fv',root/'tools/polaris-uefi-firmware.py')
    fv=importlib.util.module_from_spec(spec);spec.loader.exec_module(fv)
    image,checks=fv.package(a.original.read_bytes(),app.read_bytes(),label='Polaris RAM resident iOS loader')
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    path=out/'polaris-original-uefi-xnu.img';path.write_bytes(image)
    record=dict(checks,artifact=path.name,sha256=sha(path),bytes=len(image),
                RAM_only_XNU_loader=True,kernel_handoff=True,holds_before_OS_start=False,
                holds_before_host_kernel_command=not driver.get('disk_payload_read_only',False),
                disk_payload_read_only=driver.get('disk_payload_read_only',False),
                RAM_native_shutdown_bridge=driver.get('RAM_native_shutdown_bridge',False),
                phone_writes=False,storage_write_api=False,NVRAM_write_api=False,
                original_sha256=sha(a.original),driver_sha256=sha(app),kernel_sha256=sha(a.kernel),
                payload_sha256=sha(a.payload),CI_run=ci['databaseId'],CI_head=ci['headSha'],
                qemu_proof_sha256=sha(a.qemu_proof),preflight_sha256=sha(a.preflight),
                original_codec_consumer_verified=False,device_execution_tested=False,
                packager_sha256=sha(Path(__file__)),FV_packager_sha256=sha(root/'tools/polaris-uefi-firmware.py'))
    (out/'manifest.json').write_text(json.dumps(record,indent=2)+'\n')
    print('RAM image packaged; final actual EDK2 decoder check still required before boot.')


if __name__=='__main__':main()
