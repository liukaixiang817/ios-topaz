#!/usr/bin/env python3
"""Build a read-only AArch64 EFI inventory app; never package/flash firmware."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import importlib.util


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--zig',required=True,type=Path)
    ap.add_argument('--output',required=True,type=Path)
    ap.add_argument('--hold',action='store_true',help='stop before the original firmware menu; RAM compatibility trial only')
    ap.add_argument('--ready-to-boot',action='store_true',help='boot-service driver; hold at the pre-OS event, preserve the original menu')
    ap.add_argument('--usb-diag',action='store_true',help='enable RAM-only USB log/map/screenshot commands; no XNU or disk writes')
    ap.add_argument('--apps-watchdog-readonly',action='store_true',help='read only four own-DT watchdog registers if already mapped Device MMIO; never pet or disable')
    ap.add_argument('--native-fault-witness',type=Path,help='private descriptor: only the nonce and fixed record of one spent diagnostic; no old RAM writes')
    ap.add_argument('--bootloader-reset',action='store_true',help='only an explicit host reboot-bootloader command may set volatile boot markers and call original ResetSystem; no idle timer')
    a=ap.parse_args();root=Path(__file__).resolve().parents[1]
    if a.ready_to_boot and not a.hold:ap.error('--ready-to-boot requires --hold')
    if a.usb_diag and not a.ready_to_boot:ap.error('--usb-diag requires --ready-to-boot and --hold')
    if a.apps_watchdog_readonly and not (a.usb_diag and a.ready_to_boot and a.hold):
        ap.error('--apps-watchdog-readonly requires --hold --ready-to-boot --usb-diag')
    if a.native_fault_witness and not (a.usb_diag and a.ready_to_boot and a.hold):
        ap.error('--native-fault-witness requires --hold --ready-to-boot --usb-diag')
    if a.bootloader_reset and not (a.usb_diag and a.ready_to_boot and a.hold):
        ap.error('--bootloader-reset requires --hold --ready-to-boot --usb-diag')
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
    witness=None
    if a.native_fault_witness:
        spec=importlib.util.spec_from_file_location('fault_witness',root/'tools/polaris-native-fault-witness.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        witness=module.prepare(root,a.native_fault_witness,out)
    obj=out/'probe.obj';image=out/('PolarisProbeDxe.efi' if a.ready_to_boot else 'PolarisProbe.efi')
    env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(out/'zig-global'),ZIG_LOCAL_CACHE_DIR=str(out/'zig-local'))
    jobs=[['/usr/bin/clang','--target=aarch64-unknown-windows','-std=c11',
           '-ffreestanding','-fno-builtin','-fno-stack-protector','-fshort-wchar',
           '-mgeneral-regs-only','-O2','-Wall','-Wextra','-Werror',
           '-DPOLARIS_EFI_HOLD='+str(int(a.hold)),'-c',
           str(root/'shim/polaris/uefi-probe.c'),'-o',str(obj)],
          [str(a.zig.resolve()),'build-exe',str(obj),'-target','aarch64-uefi',
           '--subsystem','efi_boot_service_driver' if a.ready_to_boot else 'efi_application',
           '-O','ReleaseSmall','-femit-bin='+str(image)]]
    if a.ready_to_boot:jobs[0].insert(-4,'-DPOLARIS_EFI_READY_TO_BOOT=1')
    if a.usb_diag:jobs[0].insert(-4,'-DPOLARIS_EFI_USB_DIAG=1')
    if a.apps_watchdog_readonly:jobs[0].insert(-4,'-DPOLARIS_EFI_APPS_WATCHDOG_READONLY=1')
    if witness:
        jobs[0][1:1]=['-DPOLARIS_EFI_NATIVE_FAULT_WITNESS=1','-I'+str(out)]
    if a.bootloader_reset:jobs[0].insert(1,'-DPOLARIS_EFI_PROBE_BOOTLOADER_RESET=1')
    extra_inputs=[]
    if a.usb_diag:
        extra_inputs=['shim/polaris/uefi-usb.h','shim/polaris/uefi-usb.c','shim/polaris/uefi-usb-command.c','shim/polaris/uefi-usb-control.c']
        for n in extra_inputs[1:]:
            objfile=out/(Path(n).stem+'.obj');cmd=jobs[0].copy()
            cmd[cmd.index(str(root/'shim/polaris/uefi-probe.c'))]=str(root/n);cmd[-1]=str(objfile)
            run=subprocess.run(cmd,capture_output=True,env=env)
            (out/(Path(n).stem+'-build.log')).write_bytes(run.stdout+run.stderr)
            if run.returncode:raise RuntimeError('USB module compile failed: '+n)
            jobs[1].insert(3,str(objfile))
    for i,cmd in enumerate(jobs):
        p=subprocess.run(cmd,capture_output=True,env=env)
        (out/('build-'+str(i)+'.log')).write_bytes(p.stdout+p.stderr)
        if p.returncode:raise RuntimeError('Build failed; see '+str(out/('build-'+str(i)+'.log')))
    b=image.read_bytes();pe=struct.unpack_from('<I',b,60)[0]
    assert b[:2]==b'MZ' and b[pe:pe+4]==b'PE\0\0'
    assert struct.unpack_from('<H',b,pe+4)[0]==0xaa64
    assert struct.unpack_from('<H',b,pe+24)[0]==0x20b
    assert struct.unpack_from('<H',b,pe+24+68)[0]==(11 if a.ready_to_boot else 10)
    assert len(b)<1024*1024
    assert b'USB_MOCK_PASS' not in b and b'USB_MOCK_FAIL' not in b
    manifest=dict(artifact=image.name,bytes=len(b),sha256=hashlib.sha256(b).hexdigest(),
                  architecture='AArch64',subsystem='EFI boot service driver' if a.ready_to_boot else 'EFI application',
                  PE_image_base=struct.unpack_from('<Q',b,pe+24+24)[0],
                  probe_only=True,storage_write_api=False,NVRAM_write_api=False,
                  kernel_handoff=False,phone_boot_packaged=False,
                  holds_before_original_boot_manager=a.hold,
                  ready_to_boot_driver=a.ready_to_boot,
                  RAM_only_USB_diagnostics=a.usb_diag,
                  apps_watchdog_readonly=a.apps_watchdog_readonly,
                  apps_watchdog_register_writes=False,
                  native_fault_witness=witness,
                  diagnostic_bootloader_reset=a.bootloader_reset,
                  explicit_command_volatile_boot_marker_writes=a.bootloader_reset,
                  inactivity_reset=False,
                  inputs={n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in
                          ['shim/polaris/uefi.h','shim/polaris/uefi-memory.h','shim/polaris/uefi-probe.c','tools/build-polaris-uefi-probe.py']})
    for n in extra_inputs:manifest['inputs'][n]=hashlib.sha256((root/n).read_bytes()).hexdigest()
    if a.apps_watchdog_readonly:
        n='shim/polaris/uefi-apps-watchdog-readonly.h'
        manifest['inputs'][n]=hashlib.sha256((root/n).read_bytes()).hexdigest()
    if witness:
        manifest['inputs'].update(witness['inputs'])
        for n in ('shim/polaris/uefi-native-fault-witness.h','shim/polaris/uefi-apps-watchdog-readonly.h',
                  'shim/polaris/uefi-wifi-native-fault.h','tools/polaris-native-fault-witness.py',
                  'tools/polaris-scalar-sha256.h'):
            manifest['inputs'][n]=hashlib.sha256((root/n).read_bytes()).hexdigest()
        manifest['witness_configuration_sha256']=hashlib.sha256((out/'native-fault-witness-config.h').read_bytes()).hexdigest()
    if a.bootloader_reset:
        for n in ('shim/polaris/uefi-apps-watchdog-readonly.h','shim/polaris/uefi-probe-reset.h','shim/polaris/uefi-reset.h'):
            manifest['inputs'][n]=hashlib.sha256((root/n).read_bytes()).hexdigest()
    if a.usb_diag:
        n='tools/polaris-uefi-input.h';manifest['inputs'][n]=hashlib.sha256((root/n).read_bytes()).hexdigest()
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    if a.ready_to_boot:
        manifest['holds_before_original_boot_manager']=False
        manifest['holds_before_OS_start']=True
        (out/'probe-driver.inc').write_text('static const unsigned char driver_bytes[]={'+','.join(str(x) for x in b)+'};\n')
        cmds=[jobs[0].copy(),jobs[1].copy()]
        cmds[0]=[x for x in cmds[0] if x!='-DPOLARIS_EFI_READY_TO_BOOT=1']
        cmds[0]=[x for x in cmds[0] if x!='-DPOLARIS_EFI_USB_DIAG=1']
        cmds[0][cmds[0].index(str(root/'shim/polaris/uefi-probe.c'))]=str(root/'shim/polaris/uefi-probe-harness.c')
        cmds[0][-1]=str(out/'harness.obj');cmds[0].insert(1,'-I'+str(out))
        cmds[1][2]=str(out/'harness.obj');cmds[1][cmds[1].index('efi_boot_service_driver')]='efi_application'
        cmds[1][-1]='-femit-bin='+str(out/'PolarisProbeHarness.efi')
        for i,cmd in enumerate(cmds):
            run=subprocess.run(cmd,capture_output=True,env=env)
            (out/('harness-build-'+str(i)+'.log')).write_bytes(run.stdout+run.stderr)
            if run.returncode:raise RuntimeError('Harness build failed')
        manifest['harness_artifact']='PolarisProbeHarness.efi'
        manifest['harness_sha256']=hashlib.sha256((out/'PolarisProbeHarness.efi').read_bytes()).hexdigest()
        manifest['inputs']['shim/polaris/uefi-probe-harness.c']=hashlib.sha256((root/'shim/polaris/uefi-probe-harness.c').read_bytes()).hexdigest()
        if a.usb_diag:
            mockcmds=[cmds[0].copy(),cmds[1].copy()]
            mockcmds[0].insert(1,'-DPOLARIS_EFI_USB_MOCK=1');mockcmds[0][-1]=str(out/'usb-mock-harness.obj')
            mockcmds[1][2]=str(out/'usb-mock-harness.obj')
            mockcmds[1][-1]='-femit-bin='+str(out/'PolarisUSBMockHarness.efi')
            for i,cmd in enumerate(mockcmds):
                run=subprocess.run(cmd,capture_output=True,env=env)
                (out/('usb-mock-build-'+str(i)+'.log')).write_bytes(run.stdout+run.stderr)
                if run.returncode:raise RuntimeError('USB mock harness build failed')
            manifest['USB_mock_harness_artifact']='PolarisUSBMockHarness.efi'
            manifest['USB_mock_harness_sha256']=hashlib.sha256((out/'PolarisUSBMockHarness.efi').read_bytes()).hexdigest()
            n='shim/polaris/uefi-usb-mock.inc';manifest['inputs'][n]=hashlib.sha256((root/n).read_bytes()).hexdigest()
        (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps(manifest,indent=2))


if __name__=='__main__':main()
