#!/usr/bin/env python3
"""Rebuild only PID1's RAM-overlay binary with an explicit native Wi-Fi probe.

The five graphics binaries are byte-identical to the verified current bundle.
Wallpaper/timezone code and embedded assets remain pinned. No device access,
installation, kernel admission or successful networking is implied.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BASE = 'f790512548bfb9d46911590bedf5ec3962e9c3dc566b10f219d618131ae65353'
ASSET = '2377b197c84246719fd7828a0e47cca918bed63b712be3813baaeef940b859c7'
NAMES = ('libPolarisMesa.dylib', 'libPolarisGL.dylib', 'libPolarisInject.dylib',
         'polaris-bbd-wrapper', 'polaris-gl-test', 'polaris-init')
PRESERVED_SOURCES = {
    'userland/gpu/polaris-poster-assets.c': '101125aead92269b6d1f752be8f62d7458440e928dbec068c847113813fba72b',
    'userland/gpu/polaris-poster-assets.h': '363a8839de9cb255069bcefbad03c7b66a95d9e9d48a5c761661c1478bf7d5f2',
    'userland/gpu/polaris-timezone.c': '14dd829b4b6a81cbce556840883b8968a8da958816dec66938b2ea68195b0b7c',
    'userland/gpu/polaris-timezone.h': '15329ec696fc1254faa14fa7cf6e6c3aed457de0df82514c1a9ca54938561690',
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unpack(data):
    if len(data) < 304 or data[:8] != b'PGPU0047' or struct.unpack_from('<II', data, 8) != (6, len(data)):
        raise ValueError('not the exact six-file overlay format')
    result = []
    end = 304
    for i in range(6):
        kind, size, offset = struct.unpack_from('<IIQ', data, 16 + i * 48)
        if kind != i or not size or offset != (end + 15) & ~15 or offset + size > len(data):
            raise ValueError('invalid overlay file extent')
        blob = data[offset:offset + size]
        if hashlib.sha256(blob).digest() != data[32 + i * 48:64 + i * 48]:
            raise ValueError('overlay file digest mismatch')
        result.append(blob)
        end = offset + size
    if end != len(data):
        raise ValueError('trailing overlay bytes')
    return result


def pack(files):
    data = bytearray(304)
    struct.pack_into('<8sII', data, 0, b'PGPU0047', 6, 0)
    for i, blob in enumerate(files):
        data.extend(b'\0' * (-len(data) % 16))
        struct.pack_into('<IIQ', data, 16 + i * 48, i, len(blob), len(data))
        data[32 + i * 48:64 + i * 48] = hashlib.sha256(blob).digest()
        data.extend(blob)
    struct.pack_into('<I', data, 12, len(data))
    if len(data) > 32 << 20:
        raise ValueError('overlay exceeds existing bound')
    return bytes(data)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('baseline-bundle', 'poster-header', 'sdk', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    base = a.baseline_bundle.read_bytes()
    if sha(base) != BASE or sha(a.poster_header.read_bytes()) != ASSET:
        raise ValueError('exact current graphics bundle and wallpaper header required')
    for name, digest in PRESERVED_SOURCES.items():
        if sha((ROOT / name).read_bytes()) != digest:
            raise ValueError('unchanged wallpaper/timezone source differs: ' + name)
    files = unpack(base)
    if sha(files[5]) != '43ea84788cbad7a5346a7804e3bd4e6127d6dbc55fca3791ccfd436ec98619b0':
        raise ValueError('unexpected current init')
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    sdk = a.sdk.resolve(strict=True)
    subprocess.run([sys.executable, str(ROOT / 'tools/build-polaris-wifi-control.py'),
                    '--sdk', str(sdk), '--output', str(out / 'control')], check=True)
    source = ROOT / 'userland'
    command = ['/usr/bin/clang', '-target', 'arm64-apple-ios16.0', '-isysroot', str(sdk),
        '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
        '-DPGPU_USERLAND_20F66=1', '-DPOLARIS_WIFI_BOOT_PROBE=1',
        '-DPOLARIS_WIFI_CONTROL_ENTRY=polaris_wifi_control_main',
        '-DPOLARIS_POSTER_ASSETS=1', '-DPOLARIS_MELBOURNE_TIMEZONE=1',
        '-DPOLARIS_POSTER_ASSET_HEADER="' + str(a.poster_header.resolve()) + '"',
        '-I' + str(out / 'control'), '-I' + str(source / 'wifi'),
        *map(str, [source / 'gpu/polaris-init.c', source / 'gpu/polaris-poster-assets.c',
                   source / 'gpu/polaris-timezone.c', source / 'wifi/polaris-wifi-ctl.c',
                   source / 'wifi/polaris-wifi-ip.c', out / 'control/polaris-ipconfig.c']),
        '-framework', 'CoreFoundation', '-o', str(out / 'polaris-init')]
    (out / 'command.json').write_text(json.dumps(command, indent=2) + '\n')
    with (out / 'init-build.log').open('w') as log:
        subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
    binary = out / 'polaris-init'
    subprocess.run(['codesign', '--force', '--sign', '-', '--timestamp=none',
                    '--identifier', 'local.polaris.polaris-init', str(binary)], check=True)
    subprocess.run(['codesign', '--verify', '--strict', str(binary)], check=True)
    raw = binary.read_bytes()
    if struct.unpack_from('<II', raw) != (0xfeedfacf, 0x100000c):
        raise ValueError('not ARM64 Mach-O')
    dependencies = subprocess.check_output(['otool', '-L', str(binary)], text=True)
    if '@rpath/' in dependencies or '/Versions/' in dependencies:
        raise ValueError('unsupported iOS dependency')
    (out / 'dependencies.txt').write_text(dependencies)
    files[5] = raw
    bundle = pack(files)
    assert unpack(bundle) == files and unpack(base)[:5] == files[:5]
    (out / 'polaris-gpu.bundle').write_bytes(bundle)
    source_names = [*PRESERVED_SOURCES, 'userland/gpu/polaris-init.c',
        'userland/wifi/polaris-wifi-launch.h', 'userland/wifi/polaris-wifi-ctl.c',
        'userland/wifi/polaris-wifi-ip.c', 'userland/wifi/polaris-wifi-ip.h',
        'tools/build-polaris-wifi-userland.py']
    manifest = dict(format=1, build='20F66', baseline_bundle_sha256=BASE,
        bundle_sha256=sha(bundle), bundle_bytes=len(bundle), unchanged_file_indices=list(range(5)),
        files=[dict(name=name, bytes=len(blob), sha256=sha(blob)) for name, blob in zip(NAMES, files)],
        poster_header_sha256=ASSET, source_inputs={name: sha((ROOT / name).read_bytes()) for name in source_names},
        control_manifest_sha256=sha((out / 'control/manifest.json').read_bytes()),
        boot_probe=dict(launchd=True, root=True, automatic_restarts=False, timeout_seconds=120,
                        command='one scan followed by returned entries', join=False),
        installed=False, kernel_admission=False, physical_networking_verified=False)
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({key: manifest[key] for key in ('bundle_sha256', 'bundle_bytes', 'installed')}))


if __name__ == '__main__':
    main()
