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
    if (driver.get('RAM_only_XNU_loader') is not True or driver.get('QEMU_variant') is not False or
        driver.get('ready_to_boot_driver') is not True or driver.get('bounded_input') is not True or driver.get('kernel_CPU_affinity')!=256 or
        driver.get('storage_write_api') is not False or driver.get('NVRAM_write_api') is not False):
        raise ValueError('physical RAM-only loader required')
    if (qemu.get('passed') is not True or qemu.get('release_handoff_admitted') is not True or
        qemu.get('diagnostic_legacy_only') is not False or not qemu.get('checks') or
        not all(v is True for v in qemu['checks'].values()) or qemu['checks'].get('bounded_input_handshake') is not True or
        qemu.get('kernel_sha256')!=driver.get('kernel_sha256') or qemu.get('inputs')!=driver.get('inputs')):
        raise ValueError('matching actual EFI/XNU handoff proof required; legacy refusal is insufficient')
    if driver.get('disk_payload_read_only') and (not qemu.get('disk_fixture') or
        not all(qemu['checks'].get(k) is True for k in ['unique_GPT_filesystem','disk_payload_exact_read',
                     'disk_files_closed_before_kernel','disk_read_success'])):
        raise ValueError('disk payload requires the actual GPT/FAT read and closed-handles proof')
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
                phone_writes=False,storage_write_api=False,NVRAM_write_api=False,
                original_sha256=sha(a.original),driver_sha256=sha(app),kernel_sha256=sha(a.kernel),
                payload_sha256=sha(a.payload),CI_run=ci['databaseId'],CI_head=ci['headSha'],
                qemu_proof_sha256=sha(a.qemu_proof),preflight_sha256=sha(a.preflight),
                original_codec_consumer_verified=False,device_execution_tested=False,
                packager_sha256=sha(Path(__file__)),FV_packager_sha256=sha(root/'tools/polaris-uefi-firmware.py'))
    (out/'manifest.json').write_text(json.dumps(record,indent=2)+'\n')
    print('RAM image packaged; final actual EDK2 decoder check still required before boot.')


if __name__=='__main__':main()
