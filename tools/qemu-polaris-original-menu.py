#!/usr/bin/env python3
"""Exercise the extracted original SimpleInit menu and selected EFI in QEMU.

All writable disks/variables are newly created ordinary fixture files. No
phone, host block device, network, firmware replacement or boot-variable
installation is involved. This does not emulate SDM845/PM8998 volume keys.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import select
import shutil
import subprocess
import time

import polaris_efi_disk_fixture
from polaris_uefi_menu import menu_include

ORIGINAL_MENU_SHA = '39d387b73879beae0876614f1c8de33cba803c3d14e3fcc2ec9781e051ebc244'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('qemu', 'code', 'vars', 'menu-app', 'original-config',
                 'child-manifest', 'payload', 'mtools', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--case', choices=('default', 'select'), default='select')
    parser.add_argument('--seconds', type=int, default=120)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if not 30 <= args.seconds <= 300:
        parser.error('deadline must be30..300seconds')
    if sha(args.menu_app) != ORIGINAL_MENU_SHA:
        raise ValueError('the inventoried original SimpleInit PE is required')
    manifest = json.loads(args.child_manifest.read_text())
    child = args.child_manifest.parent / manifest['artifact']
    if (not manifest.get('QEMU_variant') or not manifest.get('selected_application') or
            manifest.get('kernel_CPU_affinity') != 1 or
            manifest.get('sha256') != sha(child) or
            manifest.get('payload_sha256') != sha(args.payload)):
        raise ValueError('exact QEMU selected-application build and payload required')
    for name, digest in manifest['inputs'].items():
        if sha(root / name) != digest:
            raise ValueError('selected application source changed: ' + name)
    original = args.original_config.read_bytes()
    if not re.search(rb'boot\.default\s*=\s*"continue"', original):
        raise ValueError('original Continue Boot default required for this fixture')
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    fixture = polaris_efi_disk_fixture.create(
        out / 'fixture.raw', args.menu_app, args.payload,
        manifest['disk_guid'], manifest['disk_start_lba'], manifest['disk_blocks'],
        manifest['disk_payload_path'], args.mtools, child, partition_name='esp')
    sidecar = out / 'simpleinit.static.uefi.cfg'
    sidecar.write_text(menu_include(manifest['disk_guid'], manifest['disk_payload_path']))
    config = out / 'simpleinit.uefi.cfg'
    # Only the offline selection fixture pauses autoboot. The physical menu's
    # default/timeout are never changed by this tool or its generated sidecar.
    config.write_bytes(original + (b'\nboot.timeout = -1\n' if args.case == 'select' else b''))
    target = str(out / 'fixture.raw') + '@@1048576'
    for source in (sidecar, config):
        subprocess.run([str(args.mtools / 'mcopy'), '-i', target, str(source),
                        '::/' + source.name], check=True, capture_output=True)
    shutil.copyfile(args.vars, out / 'vars.fd')
    cmd = [str(args.qemu.resolve()), '-M', 'virt,gic-version=3,virtualization=off',
           '-cpu', 'cortex-a55', '-smp', '2', '-m', '8G', '-display', 'none',
           '-monitor', 'none', '-nic', 'none', '-serial', 'file:' + str(out / 'serial.log'),
           '-qmp', 'stdio', '-no-reboot',
           '-drive', 'if=pflash,format=raw,readonly=on,file=' + str(args.code.resolve()),
           '-drive', 'if=pflash,format=raw,file=' + str(out / 'vars.fd'),
           '-drive', 'if=none,id=esp,format=raw,file=' + str(out / 'fixture.raw'),
           '-device', 'virtio-blk-pci,drive=esp', '-device', 'virtio-gpu-pci',
           '-device', 'qemu-xhci', '-device', 'usb-kbd']
    record = dict(case=args.case, passed=False, command=cmd, physical_device_access=False,
                  SDM845_emulated=False, physical_volume_keys_proven=False,
                  original_menu_sha256=sha(args.menu_app), child_sha256=sha(child),
                  fixture_only_autoboot_disabled=args.case == 'select',
                  original_config_sha256=sha(args.original_config),
                  sidecar_sha256=sha(sidecar), fixture=fixture, commands=[])
    (out / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    began = time.monotonic()
    error = None
    serial = ''
    with (out / 'qemu.log').open('wb') as err:
        process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=err, bufsize=0)
        def response():
            line = bytearray()
            until = time.monotonic() + 10
            while time.monotonic() < until:
                if not select.select([process.stdout], [], [], .2)[0]:
                    continue
                part = process.stdout.read(1)
                if not part:
                    raise RuntimeError('QMP closed')
                if part == b'\n':
                    return json.loads(line)
                line.extend(part)
            raise TimeoutError('bounded QMP response timed out')
        def q(name, arguments=None):
            request = {'execute': name}
            if arguments is not None:
                request['arguments'] = arguments
            process.stdin.write(json.dumps(request).encode() + b'\n')
            process.stdin.flush()
            while True:
                result = response()
                if 'event' in result:
                    continue
                if 'error' in result:
                    raise RuntimeError(str(result['error']))
                return result['return']
        try:
            if 'QMP' not in response():
                raise RuntimeError('QMP greeting absent')
            q('qmp_capabilities')
            sent_keys = False
            while time.monotonic() - began < args.seconds and process.poll() is None:
                serial = (out / 'serial.log').read_text(errors='replace')
                if args.case == 'select' and not sent_keys and 'uefigop: use uefigop resolution' in serial:
                    time.sleep(1)
                    q('screendump', {'filename': str(out / 'menu-visible.ppm')})
                    for key in ('up', 'up', 'ret'):
                        q('send-key', {'keys': [{'type': 'qcode', 'data': key}], 'hold-time': 150})
                        record['commands'].append(key)
                        time.sleep(.8)
                    q('screendump', {'filename': str(out / 'menu-selected.ppm')})
                    q('send-key', {'keys': [{'type': 'qcode', 'data': 'ret'}], 'hold-time': 150})
                    record['commands'].append('ret')
                    sent_keys = True
                if (args.case == 'default' and 'boot: try to execute boot config continue' in serial or
                        args.case == 'select' and 'SMP STRESS all4 PASS' in serial and 'QEMU_INPUT_BRIDGE=1' in serial):
                    break
                if 'panic(cpu ' in serial or 'efi file not found' in serial:
                    break
                time.sleep(.2)
            q('screendump', {'filename': str(out / 'final.ppm')})
            q('quit')
            process.wait(timeout=5)
        except Exception as exc:
            error = str(exc)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
    serial = (out / 'serial.log').read_text(errors='replace')
    after = subprocess.run([str(args.mtools / 'mtype'), '-i', target, '::/simpleinit.uefi.cfg'],
                           check=True, capture_output=True).stdout
    (out / 'config-after.cfg').write_bytes(after)
    checks = dict(original_menu_executed='main: initialize simple-init' in serial,
                  static_include_loaded='loaded \\simpleinit.static.uefi.cfg' in serial,
                  regular_config_loaded='loaded \\simpleinit.uefi.cfg' in serial,
                  default_preserved=bool(re.search(rb'boot\.default\s*=\s*"continue"', after)),
                  no_panic='panic(cpu ' not in serial)
    if args.case == 'default':
        checks.update(original_default_executed='boot: try to execute boot config continue' in serial,
                      no_trial_started='POLARIS UEFI XNU:' not in serial)
    else:
        checks.update(trial_selected='try to execute boot config polaris_ios(iOS 16 (trial))' in serial,
                      GPT_target_found='found locate PciRoot' in serial,
                      actual_StartImage='efi: start image' in serial and 'EFI_IMAGE_BASE=' in serial,
                      bank_admitted='XNU_ADMISSION=0x0000000000000000' in serial,
                      disk_read=f'DISK_READ_BYTES=0x{manifest["payload_bytes"]:016x}' in serial,
                      files_closed='DISK_FILES_CLOSED=0x0000000000000002' in serial,
                      secondary_core_started='KERNEL_PSCI_STATUS=0x0000000000000000' in serial,
                      actual_PID1='init running as PID 1' in serial,
                      four_VM_children='SMP STRESS all4 PASS' in serial,
                      bounded_input_ack='QEMU_INPUT_BRIDGE=1' in serial,
                      no_path_refusal='efi file not found' not in serial)
    record.update(passed=all(checks.values()) and error is None, checks=checks, error=error,
                  seconds=time.monotonic()-began, serial_sha256=sha(out / 'serial.log'),
                  config_after_sha256=sha(out / 'config-after.cfg'))
    (out / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({k: record[k] for k in ('passed', 'checks', 'error', 'seconds')}, indent=2))
    return 0 if record['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
