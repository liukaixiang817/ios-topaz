#!/usr/bin/env python3
"""Package ONE explicit no-OS WLED OEM cycle after the complete EFI fault matrix.

This writes a local RAM-boot image only. No device access, installation, journal
repair or OS/root admission. All original Mindows components must be retained.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
from polaris_wled_oem_admission import admit,vector,PHYSICAL_SCOPE
from polaris_wled_journal import parse_packet,parse_reset_receipt,parse_zero_write_receipt

ORIGINAL_SHA='8588a9a5218d407dd3169ec1f340097db689b3d046f3d38189514e09f3944336'
ROOT_SHA='689a8cd1df0fc0093706272241a9ac77d5eddd7a62df5d340913ec6abcd7ce2b'
DT_SHA='f7762357a86d484881bf637cba639f84bf2929840484c4d78faf3633f798f2c8'


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def checked_path(root,name):
    p=(root/name).resolve()
    if root not in p.parents or not p.is_file():raise ValueError('evidence outside project or missing')
    return p


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('original','driver-manifest','physical-inventory','physical-timeline','own-dt-proof',
                 'source-oracle','preflight','output'):
        ap.add_argument('--'+name,type=Path,required=True)
    ap.add_argument('--model',type=Path,action='append',required=True)
    a=ap.parse_args();root=Path(__file__).resolve().parents[1]
    if a.output.exists():raise ValueError('refusing to overwrite a phone trial image')
    d=json.loads(a.driver_manifest.read_text());models=[json.loads(p.read_text()) for p in a.model]
    admit(d,models);evidence={}
    def bind(p):
        p=checked_path(root,str(p.resolve().relative_to(root)));evidence[str(p.relative_to(root))]=sha(p);return p
    def check_map(mapping):
        if not mapping:raise ValueError('missing frozen evidence/source map')
        for name,digest in mapping.items():
            p=checked_path(root,name)
            if sha(p)!=digest:raise ValueError('changed evidence/source: '+name)
            bind(p)
    check_map(d['inputs']);app=a.driver_manifest.parent/d['artifact']
    if app.resolve().parent!=a.driver_manifest.parent.resolve() or sha(app)!=d['sha256']:
        raise ValueError('physical OEM driver changed')
    bind(app);bind(a.driver_manifest)
    for path,m in zip(a.model,models):
        bind(path);mdp=checked_path(root,m['driver_manifest_path']);md=json.loads(mdp.read_text())
        model_app=mdp.parent/md['artifact']
        if (model_app.resolve().parent!=mdp.parent.resolve() or
            sha(mdp)!=m['driver_manifest_sha256'] or sha(model_app)!=m['driver_sha256'] or
            md.get('inputs')!=d['inputs'] or md.get('QEMU_variant') is not True or
            md.get('WLED_OEM_physical_cycle') is not False or md.get('kernel_CPU_ON_compiled_out') is not True or
            md.get('kernel_CPU_affinity')!=7 or md.get('kernel_CPU_count')!=4 or
            md.get('controlled_WLED_prepare_refusal')!=m['controlled_prepare_refusal'] or
            md.get('controlled_WLED_prepare_kind')!=m['controlled_prepare_kind'] or
            md.get('controlled_WLED_write_timeout')!=m['controlled_write_timeout'] or
            md.get('controlled_WLED_status_after_issue')!=m['controlled_status_after_issue']):
            raise ValueError('actual EFI executable/vector/source binding changed')
        check_map(m['observer_inputs']);bind(mdp);bind(model_app)
        if m.get('runner_sha256')!=sha(root/'tools/qemu-polaris-wled-power-cycle.py'):
            raise ValueError('actual EFI observer changed')
        log=path.parent/'serial.log';bind(log);text=log.read_text()
        raw={k:int(v,16) for k,v in re.findall(r'([A-Z_0-9]+)=0x([0-9a-f]{16})',text)}
        if raw!=m['raw_fields'] or 'Darwin Kernel Version' in text or 'KERNEL_PSCI_STATUS=' in text:
            raise ValueError('raw EFI log changed or native CPU executed')
        packet_path=path.parent/'actual-journal.bin';bind(packet_path);packet=packet_path.read_bytes()
        if parse_packet(packet)!=m['binary_journal_evidence']['journal']:
            raise ValueError('actual firmware journal changed')
        timeout,prepare,status=vector(m)
        if prepare:
            receipt=path.parent/'actual-zero-write-receipt.bin';bind(receipt)
            if parse_zero_write_receipt(receipt.read_bytes(),packet)!=m['binary_journal_evidence']['zero_write_receipt']:
                raise ValueError('actual zero-write receipt changed')
        elif not(timeout or status):
            receipt=path.parent/'actual-final-receipt.bin';bind(receipt)
            if parse_reset_receipt(receipt.read_bytes(),packet)!=m['binary_journal_evidence']['final_receipt']:
                raise ValueError('actual final-read receipt changed')
        elif (path.parent/'actual-final-receipt.bin').exists():
            raise ValueError('failed case contains a false final receipt')
    inventory=json.loads(a.physical_inventory.read_text());timeline=json.loads(a.physical_timeline.read_text())
    if inventory.get('passed') is not True or inventory.get('PMIC_power_control_tested') is not False:
        raise ValueError('missing actual expanded physical inventory')
    if (timeline.get('passed') is not True or timeline.get('physical_fault_timeline_complete') is not True or
        timeline.get('PMIC_WLED_power_writes') is not False or timeline.get('XNU_started') is not False or
        timeline.get('count')!=32 or timeline.get('observer_reads')!=128 or
        timeline.get('module_enable_always')!=0x80 or timeline.get('fault_or')!=1 or timeline.get('rt_or')!=1):
        raise ValueError('missing actual retained ILIM-only physical timeline')
    check_map(inventory['evidence']);check_map(timeline['evidence'])
    dt=json.loads(a.own_dt_proof.read_text());oracle=json.loads(a.source_oracle.read_text())
    if (dt.get('passed') is not True or dt.get('source_sha256')!=DT_SHA or
        sha(checked_path(root,dt['source']))!=DT_SHA or len(dt.get('nodes',[]))!=1 or
        dt['nodes'][0].get('lcd_psm_ctrl_present') is not False):
        raise ValueError('own DT/preserved PSM correspondence absent')
    if (oracle.get('passed') is not True or oracle.get('enum_preserved_verbatim') is not True or
        oracle.get('function_preserved_verbatim') is not True or oracle.get('checks')!=768 or
        tuple(oracle.get(k) for k in ('IRQ_RT_ILIM_bit','IRQ_RT_OVP_bit','IRQ_RT_SC_bit','own_RT_offset'))!=(0,1,2,16)):
        raise ValueError('exact original IRQ/status semantics not verified')
    check_map(oracle['inputs']);bind(checked_path(root,dt['source']))
    pre=json.loads(a.preflight.read_text())
    if (pre.get('actual_expected_fastboot_after_verified') is not True or pre.get('phone_partition_writes') is not False or
        pre.get('full_image_sha256')!=ROOT_SHA):raise ValueError('missing reviewed no-write original data audit')
    if pre.get('outer_metadata_changed_during_unobserved_interval') is True and (
        pre.get('pre_XNU_WLED_only_reviewed') is not True or pre.get('may_boot_iOS') is not False or pre.get('may_write_userdata') is not False):
        raise ValueError('pending outer filesystem is not reviewed for pre-XNU scope')
    for p in (a.physical_inventory,a.physical_timeline,a.own_dt_proof,a.source_oracle,a.preflight):bind(p)
    if sha(a.original)!=ORIGINAL_SHA:raise ValueError('wrong original Mindows UEFI')
    spec=importlib.util.spec_from_file_location('fw',root/'tools/polaris-uefi-firmware.py')
    fw=importlib.util.module_from_spec(spec);spec.loader.exec_module(fw)
    image,record=fw.package(a.original.read_bytes(),app.read_bytes())
    if record.get('original_inner_files')!=81 or record.get('unchanged_inner_files')!=81:
        raise ValueError('original firmware file preservation failed')
    a.output.mkdir(parents=True);target=a.output/'polaris-original-uefi-wled-oem-cycle.img';target.write_bytes(image)
    record.update(PHYSICAL_SCOPE)
    record.update(artifact=target.name,sha256=sha(target),bytes=len(image),inputs=d['inputs'],
        original_sha256=sha(a.original),driver_sha256=d['sha256'],driver_manifest_sha256=sha(a.driver_manifest),
        payload_bytes=d['payload_bytes'],payload_sha256=d['payload_sha256'],installer=False,
        actual_backlight_control_proven=False,physical_darkness_proven=False,root_access_permitted=False,
        requires_new_root_audit_before_iOS=True,final_reset_receipt_required=True,
        packager_sha256=sha(Path(__file__)),admission_sha256=sha(root/'tools/polaris_wled_oem_admission.py'),
        controller_sha256=sha(root/'tools/polaris-uefi-wled-oem.py'),
        wire_parser_sha256=sha(root/'tools/polaris_wled_journal.py'),
        transport_sha256=sha(root/'tools/polaris_uefi_usb_transport.py'),
        evidence_sha256=evidence)
    (a.output/'manifest.json').write_text(json.dumps(record,indent=2)+'\n')
    print('Independent OEM WLED RAM image prepared; no OS/root/storage admission')


if __name__=='__main__':main()
