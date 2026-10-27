#!/usr/bin/env python3
"""Package a separately admitted, RAM-booted physical small-marker trial.

Does not access a device, install firmware, change a root write gate, or admit
a writable iOS root. Normal RAM packaging deliberately does not call this.
Actual original EDK2 decoding is still required after this offline packaging.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess

from polaris_marker_admission import (admit_manifest, base_audit, evidence, file_ownership,
                                    load, model_suite, require, sha, tree_binding)


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('original', 'driver-manifest', 'kernel', 'payload', 'ci-proof',
                 'model-suite', 'physical-readonly-proof', 'ownership-proof', 'output'):
        ap.add_argument('--' + name, type=Path, required=True)
    a = ap.parse_args(); root = Path(__file__).resolve().parents[1]
    driver = json.loads(a.driver_manifest.read_text()); admit_manifest(driver)
    for path, digest in driver['inputs'].items(): evidence(root, dict(path=path, sha256=digest))
    kernel_sha = sha(a.kernel)
    require(kernel_sha == driver['kernel_sha256'] and sha(a.payload) == driver['payload_sha256'], 'changed kernel/payload')
    sums = [line.split()[0] for line in (a.kernel.parent / 'SHA256SUMS').read_text().splitlines()
            if len(line.split()) == 2 and line.split()[1].lstrip('*') == a.kernel.name]
    require(sums == [kernel_sha], 'kernel differs from collected artifact SHA')
    ci = json.loads(a.ci_proof.read_text())
    profile = dict(line.split('=', 1) for line in (a.kernel.parent / 'build-profile.txt').read_text().splitlines() if '=' in line)
    require(ci.get('status') == 'completed' and ci.get('conclusion') == 'success' and
            profile.get('commit') == ci.get('headSha') and profile.get('target_platform') == 'polaris' and
            profile.get('machine_config') == 'SWEET' and ci.get('databaseId') and
            re.fullmatch('[0-9a-f]{40}', ci.get('headSha', '')), 'successful full exact-source CI required')
    tail_patch = 'xnu/profiles/polaris/0875-polaris-owned-filesystem-tail-bound.patch'
    require(subprocess.run(['git', 'show', ci['headSha'] + ':' + tail_patch], cwd=root,
                capture_output=True, check=True).stdout == (root / tail_patch).read_bytes(),
            'kernel CI source lacks exact reviewed physical filesystem tail bounds')
    suite = json.loads(a.model_suite.read_text())
    require(suite.get('CI') == ci['databaseId'] and suite.get('kernel_source') == ci['headSha'], 'model CI source changed')
    model_suite(root, suite, kernel_sha, driver['inputs'])
    physical = json.loads(a.physical_readonly_proof.read_text())
    require(physical.get('passed') is True and physical.get('physical_phone') is True and
            physical.get('CI') == ci['databaseId'] and physical.get('kernel_sha256') == kernel_sha and
            physical.get('storage_writes') is False and physical.get('native_queue_sealed') is True and
            physical.get('native_UFS_submitted') == physical.get('native_UFS_completed') and
            physical.get('native_UFS_completed', 0) > 0 and
            physical.get('actual_FASTBOOT', {}).get('expected_polaris') is True, 'same-kernel native physical readonly proof required')
    case_record = physical.get('case_directory')
    require(isinstance(case_record, str) and not Path(case_record).is_absolute() and
            '..' not in Path(case_record).parts, 'physical case directory required')
    physical_case = root / case_record
    require(physical_case.resolve().is_relative_to(root), 'physical case escaped checkout')
    ordinary = json.loads((physical_case / 'driver/manifest.json').read_text())
    old_image = json.loads((physical_case / 'image/manifest.json').read_text())
    old_boot = json.loads((physical_case / 'boot.json').read_text())
    require(ordinary['inputs'] == driver['inputs'] and ordinary['kernel_sha256'] == kernel_sha and
            ordinary['physical_owned_marker_test'] is False and ordinary['RAM_only_XNU_loader'] is True,
            'original readonly physical driver source mismatch')
    require(sha(physical_case / 'driver' / ordinary['artifact']) == ordinary['sha256'] == old_image['driver_sha256'] and
            sha(physical_case / 'image' / old_image['artifact']) == old_image['sha256'] == physical['image_sha256'] ==
            old_boot['image_sha256'], 'physical readonly image/driver evidence changed')
    for frame in physical['frames']:
        folder = physical_case / frame['capture']
        require(sha(folder / 'screen.png') == frame['PNG_sha256'] and sha(folder / 'kernel.log') == frame['log_sha256'] and
                sha(folder / 'result.json') == frame['record_sha256'], 'physical frame/log evidence changed')
    require(sha(physical_case / 'native-shutdown-0001/shutdown-kernel.log') == physical['shutdown_log_sha256'] and
            sha(physical_case / 'native-shutdown-0001/result.json') == physical['shutdown_result_sha256'], 'physical drain proof changed')
    ownership = json.loads(a.ownership_proof.read_text())
    packet, before, after = file_ownership(root, ownership)
    current = load(root, physical['preflight_record'])
    base_audit(current)
    require(current['updated_utc'] >= after['updated_utc'] and
            current.get('outer_header_sha256') == after.get('outer_header_sha256') and
            current.get('existing_marker_identity_and_zeros_unchanged') is True,
            'same-kernel readonly trial requires the reviewed post-allocation baseline')
    require(old_image.get('preflight_sha256') == physical['preflight_record']['sha256'],
            'physical readonly image used a different preflight')
    ram = module(root / 'tools/polaris-uefi-xnu-image.py', 'original_ram_admission')
    control = next(row for row in suite['cases'] if row['case'] == 'dual-RAM-control')
    qemu = json.loads((root / suite['case_root'] / ('dual-RAM-control-run-' + control['run']) / 'result.json').read_text())
    ram.admit(ordinary, qemu, ci, (a.kernel.parent / 'build-profile.txt').read_text(), current)
    base_map = load(root, ownership['base_fiemap'])
    payload = a.payload.read_bytes()
    old_path = evidence(root, physical['payload_record'])
    require(sha(old_path) == ordinary['payload_sha256'], 'physical readonly payload changed')
    old_payload = old_path.read_bytes()
    at, size = struct.unpack_from('<QQ', old_payload, 32)
    tree_binding(payload, old_payload[at:at + size], packet, base_map,
                 ownership['partition_start'], ownership['partition_blocks'])
    original_sha = '8588a9a5218d407dd3169ec1f340097db689b3d046f3d38189514e09f3944336'
    require(sha(a.original) == original_sha, 'original Mindows firmware changed')
    app = a.driver_manifest.parent / driver['artifact']
    require(app.resolve().parent == a.driver_manifest.parent.resolve() and sha(app) == driver['sha256'], 'driver artifact changed')
    fv = module(root / 'tools/polaris-uefi-firmware.py', 'marker_fv')
    image, checks = fv.package(a.original.read_bytes(), app.read_bytes(), label='Polaris RAM small owned marker trial')
    output = a.output.resolve(); output.mkdir(parents=True, exist_ok=False)
    target = output / 'polaris-original-uefi-marker.img'; target.write_bytes(image)
    bound = {name: dict(path=str(getattr(a, name).resolve().relative_to(root)), sha256=sha(getattr(a, name))) for name in
             ('driver_manifest', 'kernel', 'payload', 'ci_proof', 'model_suite', 'physical_readonly_proof', 'ownership_proof')}
    record = dict(checks, artifact=target.name, sha256=sha(target), bytes=len(image),
        RAM_only_XNU_loader=False, physical_owned_marker_trial=True, original_root_writes_volatile=True,
        writes_only_new_owned_marker=True, marker_bytes=8 << 20, marker_write_bytes=4096,
        raw_reset_requires_durable_SAFE=True, RAM_host_idle_recovery_seconds=None,
        storage_write_api=False, NVRAM_write_api=False, phone_writes=True,
        original_sha256=original_sha, driver_sha256=driver['sha256'], kernel_sha256=kernel_sha,
        payload_sha256=sha(a.payload), CI_run=ci['databaseId'], CI_head=ci['headSha'],
        before_preflight=ownership['before'], after_preflight=ownership['after'],
        evidence=bound, packager_sha256=sha(Path(__file__)),
        admission_sha256=sha(root / 'tools/polaris_marker_admission.py'),
        original_codec_consumer_verified=False, physical_owned_write_proven=False,
        full_iOS_persistence_proven=False, device_execution_tested=False)
    (output / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
    print('Small marker RAM image packaged; actual original EDK2 decoding remains required.')


if __name__ == '__main__': main()
