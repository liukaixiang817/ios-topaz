#!/usr/bin/env python3
"""Prepare an additive SimpleInit menu include; never touch a phone or NVRAM.

The extracted original SimpleInit consumes by_file with EFI_FILE_PROTOCOL,
which requires backslashes. Its efi_file URL uses POSIX separators instead.
Both paths were exercised through the original PE, LoadImage and real XNU
in generic EDK2/QEMU. Hardware key support remains a separate device test.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import uuid


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def menu_include(guid, payload_path):
    guid = str(uuid.UUID(str(guid)))
    match = re.fullmatch(r'\\EFI\\Polaris\\(V[0-9]{4})\\PAYLOAD\.BIN', payload_path)
    if not match:
        raise ValueError('versioned Polaris payload path required')
    version = match[1]
    native = f'\\EFI\\Polaris\\{version}\\PolarisIos.efi'
    url = f'@polaris_ios_esp:/EFI/Polaris/{version}/PolarisIos.efi'
    # JSON string escaping also matches the original cfg str_unescape parser.
    rows = [
        '# Additional trial entry; original default and second option untouched.',
        'locates.polaris_ios_esp.by_gpt_guid = ' + json.dumps(guid),
        'locates.polaris_ios_esp.by_file = ' + json.dumps(native),
        'boot.configs.polaris_ios.mode = 9',
        'boot.configs.polaris_ios.desc = "iOS 16 (trial)"',
        'boot.configs.polaris_ios.show = true',
        'boot.configs.polaris_ios.enabled = true',
        'boot.configs.polaris_ios.extra.efi_file = ' + json.dumps(url),
    ]
    return '\n'.join(rows) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app-manifest', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    manifest = json.loads(args.app_manifest.read_text())
    app = args.app_manifest.parent / manifest['artifact']
    if (not manifest.get('selected_application') or
            not manifest.get('disk_payload_read_only') or
            not manifest.get('RAM_only_XNU_loader') or
            manifest.get('storage_write_api') or manifest.get('NVRAM_write_api') or
            sha(app) != manifest.get('sha256')):
        raise ValueError('verified read-only selected EFI application required')
    content = menu_include(manifest['disk_guid'], manifest['disk_payload_path'])
    args.output.mkdir(parents=True, exist_ok=False)
    sidecar = args.output / 'simpleinit.static.uefi.cfg'
    sidecar.write_text(content)
    record = dict(state='offline_only_not_installed',
                  new_file='/simpleinit.static.uefi.cfg',
                  original_default_changed=False, original_config_replaced=False,
                  BootOrder_changed=False, NVRAM_API=False, device_access=False,
                  root_writes='volatile RAMCOW; trial entry only',
                  sidecar_sha256=sha(sidecar), app_sha256=sha(app),
                  app_manifest_sha256=sha(args.app_manifest),
                  partition_guid=manifest['disk_guid'],
                  emulator_only=bool(manifest.get('QEMU_variant')),
                  physical_menu_or_volume_keys_proven=False)
    (args.output / 'plan.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    main()
