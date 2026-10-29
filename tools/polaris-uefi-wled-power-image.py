#!/usr/bin/env python3
"""Admit one pre-XNU WLED OFF/restore RAM trial, never an iOS installation.

Unlike the read-only inventory this contains a PMIC writer: only the original
module bit and its OVP notification mask/restore. Require actual read inventory,
own DT, isolated EFI success/uncertain cases and fresh read-only data audit.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

MODEL_CHECKS = {'firmware_EL1_admission','exact_payload_valid','kernel_prepared_not_executed',
                'no_PSCI_CPU_ON','mock_backend_explicit','preflight_succeeded','expected_final_error',
                'expected_final_uncertainty','writes_issued_exactly','writes_completed_exactly',
                'reset_gate','off_readback_and_reset','on_readback_after_two_seconds',
                'actual_AP_context_stage_zero','actual_kernel_log_total_zero','no_native_startup_log','no_panic'}


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def admit(d, models):
    required = dict(WLED_power_cycle_only=True,WLED_readonly_inventory_only=False,
                    PMIC_write_api=True,kernel_CPU_ON_compiled_out=True,kernel_handoff=False,
                    storage_write_api=False,NVRAM_write_api=False,probe_only=True,
                    holds_before_OS_start=True,physical_buttons=True,ready_to_boot_driver=True,
                    QEMU_variant=False,phone_compatible=True,kernel_CPU_affinity=1792,kernel_CPU_count=4,
                    controlled_WLED_write_timeout=False,controlled_WLED_read_refusal=False,
                    selected_application=False,disk_payload_read_only=False,physical_owned_marker_test=False,
                    RAM_host_idle_recovery_seconds=1800,payload_C_admission=True,rebased_kernel_bytes_match=True)
    for key, value in required.items():
        if type(d.get(key)) is not type(value) or d[key] != value:
            raise ValueError('not the explicit pre-XNU WLED cycle: '+key)
    if d.get('chain_app') is not None or not d.get('inputs') or len(models) != 2:
        raise ValueError('missing exact source-bound WLED cases or foreign chain')
    seen = set()
    for m in models:
        if (m.get('passed') is not True or m.get('inputs') != d['inputs'] or
                m.get('kernel_sha256') != d.get('kernel_sha256') or
                m.get('WLED_power_cycle_only') is not True or
                m.get('actual_phone_or_PMIC_emulated') is not False or
                m.get('kernel_CPU_started') is not False or
                m.get('release_handoff_admitted') is not False):
            raise ValueError('missing actual isolated EFI cycle evidence')
        if set(m.get('checks',{})) != MODEL_CHECKS or any(v is not True for v in m['checks'].values()):
            raise ValueError('incomplete reset/readback/actual guest AP-zero checks')
        bad = m.get('controlled_write_timeout')
        if type(bad) is not bool or bad in seen:
            raise ValueError('distinct success and uncertain-command cases required')
        seen.add(bad)
        raw = m.get('raw_fields',{})
        if (raw.get('WLED_POWER_MOCK_BACKEND') != 1 or raw.get('WLED_KERNEL_AP_STAGE') != 0 or
                raw.get('WLED_POWER_FINAL_ERROR') != (36 if bad else 0) or
                raw.get('WLED_POWER_FINAL_UNCERTAIN') != int(bad) or
                raw.get('WLED_POWER_WRITES_ISSUED') != (1 if bad else 4) or
                raw.get('WLED_POWER_WRITES_COMPLETED') != (0 if bad else 4) or
                raw.get('WLED_POWER_FINAL_RESET_ALLOWED') != int(not bad)):
            raise ValueError('actual command/reset outcome absent')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('original','driver-manifest','success','uncertain','power-core-model',
                 'physical-readonly-proof','own-dt-proof','preflight','output'):
        ap.add_argument('--'+name,required=True,type=Path)
    ap.add_argument('--expected-original-sha256',required=True)
    a = ap.parse_args();root = Path(__file__).resolve().parents[1]
    if a.output.exists():
        raise ValueError('refusing to overwrite a WLED power image')
    d = json.loads(a.driver_manifest.read_text())
    cases = [json.loads(p.read_text()) for p in (a.success,a.uncertain)]
    admit(d,cases)
    for name,digest in d['inputs'].items():
        p = (root/name).resolve()
        if root not in p.parents or sha(p) != digest:
            raise ValueError('cycle source changed: '+name)
    app = a.driver_manifest.parent/d['artifact']
    if app.resolve().parent != a.driver_manifest.parent.resolve() or sha(app) != d['sha256']:
        raise ValueError('physical cycle binary changed')
    for path,m in zip((a.success,a.uncertain),cases):
        parent = path.parent.parent/(path.parent.name.replace('-run-','-driver-'))
        md = json.loads((parent/'manifest.json').read_text())
        if (sha(parent/'manifest.json') != m['driver_manifest_sha256'] or
                sha(parent/md['artifact']) != m['driver_sha256'] or md['inputs'] != d['inputs'] or
                md['QEMU_variant'] is not True or not md['kernel_CPU_ON_compiled_out'] or
                md['kernel_handoff'] is not False):
            raise ValueError('actual EFI executable binding changed')
    core = json.loads(a.power_core_model.read_text())
    if (core.get('passed') is not True or core.get('actual_phone_or_PMIC_emulated') is not False or
            core.get('real_guest_clock_softstart') is not True or core.get('phone_compatible') is not False or
            core.get('raw_fields',{}).get('WLED_POWER_SOFTSTART_US',0)<10000):
        raise ValueError('actual guest-clock softstart model required')
    for name,digest in core['inputs'].items():
        if sha(root/name) != digest:
            raise ValueError('power core model source changed')
    ro = json.loads(a.physical_readonly_proof.read_text())
    if ro.get('passed') is not True or ro.get('PMIC_power_control_tested') is not False:
        raise ValueError('actual read-only physical inventory required')
    for name,digest in ro['evidence'].items():
        if sha(root/name) != digest:
            raise ValueError('frozen physical read inventory changed')
    dt = json.loads(a.own_dt_proof.read_text())
    if (dt.get('passed') is not True or sha(root/dt['source']) != dt['source_sha256'] or
            len(dt['nodes']) != 1 or dt['nodes'][0]['lcd_psm_ctrl_present'] is not False):
        raise ValueError('own DT without optional LCD PSM control required')
    pre = json.loads(a.preflight.read_text())
    if (pre.get('actual_expected_fastboot_after_verified') is not True or
            pre.get('phone_partition_writes') is not False or
            pre.get('full_image_sha256') != '689a8cd1df0fc0093706272241a9ac77d5eddd7a62df5d340913ec6abcd7ce2b'):
        raise ValueError('successful full read-only data preflight required')
    if pre.get('outer_metadata_changed_during_unobserved_interval') is True and (
            pre.get('pre_XNU_WLED_only_reviewed') is not True or
            pre.get('may_boot_iOS') is not False or pre.get('may_write_userdata') is not False):
        raise ValueError('changed outer filesystem may only admit the no-OS WLED scope')
    if sha(a.original) != a.expected_original_sha256:
        raise ValueError('original Mindows firmware changed')
    spec = importlib.util.spec_from_file_location('fw',root/'tools/polaris-uefi-firmware.py')
    fw = importlib.util.module_from_spec(spec);spec.loader.exec_module(fw)
    image, record = fw.package(a.original.read_bytes(),app.read_bytes())
    a.output.mkdir(parents=True)
    target = a.output/'polaris-original-uefi-wled-cycle.img';target.write_bytes(image)
    record.update(artifact=target.name,sha256=sha(target),bytes=len(image),
                  original_sha256=sha(a.original),driver_sha256=d['sha256'],driver_manifest_sha256=sha(a.driver_manifest),
                  WLED_power_cycle_only=True,WLED_readonly_inventory_only=False,PMIC_write_api=True,
                  kernel_CPU_ON_compiled_out=True,kernel_handoff=False,storage_write_api=False,NVRAM_write_api=False,
                  actual_backlight_control_proven=False,installer=False,packager_sha256=sha(Path(__file__)),
                  evidence_sha256={str(p.resolve().relative_to(root)):sha(p) for p in
                      (a.success,a.uncertain,a.power_core_model,a.physical_readonly_proof,a.own_dt_proof,a.preflight)})
    (a.output/'manifest.json').write_text(json.dumps(record,indent=2)+'\n')
    print('Source-bound WLED power cycle packaged; no OS start or storage write permitted')


if __name__ == '__main__':
    main()
