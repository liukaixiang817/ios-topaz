#!/usr/bin/env python3
"""Pinned Mesa25.0.7 iOS/A630 build in a NEW directory, no phone/root writes.

Requires clang, ar/ranlib, Meson, Ninja, Bison>=2.7, Flex and Python Mako,
PyYAML/packaging on PATH. Pass a locally obtained iOS SDK and Mesa archive.
No SDK, Apple files, firmware or built libraries are added to the repository.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
SHA256 = '592272df3cf01e85e7db300c449df5061092574d099da275d19e97ef0510f8a6'


def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def build(args):
    if digest(args.archive) != SHA256:
        raise ValueError('Mesa25.0.7 official archive SHA256 mismatch')
    sdk = args.sdk.resolve()
    if not (sdk / 'SDKSettings.plist').is_file():
        raise ValueError('expected an iOS SDK directory')
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=False)
    with tarfile.open(args.archive) as archive:
        archive.extractall(work, filter='data')
    source = work / 'mesa-25.0.7'
    patches = [ROOT / 'userland/mesa' / name for name in
               ('freedreno-darwin.patch', 'osmesa-es-profile.patch')]
    for patch in patches:
        with patch.open('rb') as inp, (work / (patch.name + '.log')).open('wb') as log:
            subprocess.run(['patch', '--batch', '--fuzz=0', '-p1'], cwd=source, stdin=inp,
                           stdout=log, stderr=subprocess.STDOUT, check=True)
    shutil.copytree(ROOT / 'userland/mesa/redwood-drm', source / 'src/redwood-drm')
    cross = work / 'cross.ini'
    cross.write_text(f'''[binaries]
c = ['/usr/bin/clang', '-target', 'arm64-apple-ios16.0', '-isysroot', '{sdk}']
cpp = ['/usr/bin/clang++', '-target', 'arm64-apple-ios16.0', '-isysroot', '{sdk}']
objc = ['/usr/bin/clang', '-target', 'arm64-apple-ios16.0', '-isysroot', '{sdk}']
ar = '/usr/bin/ar'
ranlib = '/usr/bin/ranlib'
strip = '/usr/bin/strip'
pkg-config = 'false'
[host_machine]
system = 'darwin'
subsystem = 'ios'
cpu_family = 'aarch64'
cpu = 'arm64'
endian = 'little'
[properties]
needs_exe_wrapper = true
[built-in options]
c_args = ['-DREDWOOD_GPU_SERVICE="PolarisGPU"']
cpp_args = ['-DREDWOOD_GPU_SERVICE="PolarisGPU"']
''')
    options = dict(platforms='', **{'gallium-drivers': 'softpipe,freedreno', 'freedreno-kmds': 'msm',
                                  'vulkan-drivers': '', 'glx': 'disabled', 'egl': 'disabled',
                                  'gbm': 'disabled', 'osmesa': 'true', 'llvm': 'disabled',
                                  'shared-glapi': 'enabled', 'gles1': 'disabled', 'gles2': 'enabled',
                                  'opengl': 'true', 'zstd': 'disabled', 'xmlconfig': 'disabled',
                                  'expat': 'disabled', 'shader-cache': 'disabled', 'valgrind': 'disabled',
                                  'libunwind': 'disabled', 'glvnd': 'disabled', 'video-codecs': '',
                                  'tools': '', 'gallium-vdpau': 'disabled', 'gallium-va': 'disabled',
                                  'gallium-xa': 'disabled', 'lmsensors': 'disabled', 'build-tests': 'false'})
    command = ['meson', 'setup', str(work / 'build'), str(source), '--cross-file', str(cross),
               '--wrap-mode=nofallback', '--prefix=/polaris', '--libdir=lib', '--buildtype=release',
               '-Db_ndebug=true', *[f'-D{k}={v}' for k, v in options.items()]]
    for name, cmd in [('setup', command), ('ninja', ['ninja', '-C', str(work / 'build'), '-j', str(args.jobs)])]:
        with (work / (name + '.log')).open('w') as log:
            subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, check=True, env=os.environ.copy())
    library = work / 'build/src/gallium/targets/osmesa/libOSMesa.8.dylib'
    report = dict(version='25.0.7', archive_sha256=SHA256, options=options,
                  patches={str(p.relative_to(ROOT)): digest(p) for p in patches},
                  drm={str(p.relative_to(ROOT)): digest(p) for p in
                       sorted((ROOT / 'userland/mesa/redwood-drm').glob('*')) if p.is_file()},
                  compiler=subprocess.check_output(['/usr/bin/clang', '--version'], text=True),
                  output_sha256=digest(library), hardware_tested=False)
    (work / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    print(library)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--sdk', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=4, choices=range(1, 33))
    build(parser.parse_args())
