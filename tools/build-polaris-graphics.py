#!/usr/bin/env python3
"""Build a NEW local iOS20H392 GPU bundle; never edits a mounted/phone root.

Inputs: pinned, patched Mesa25.0.7 iOS ARM64 library and its gl.xml, iOS SDK.
Mesa's Darwin service name must be compiled as PolarisGPU. SDK/Apple files
and all binaries stay outside Git. Kernel admission is RAM COW only.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / 'userland/gpu'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(args):
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    sdk = args.sdk.resolve()
    mesa_input = args.mesa_library.read_bytes()
    if b'PolarisGPU\0' not in mesa_input or b'POLARIS_GPU_CONNECTION\0' not in mesa_input:
        raise ValueError('Mesa does not contain the matching Polaris service/acceptance connection adapter')
    mesa = out / 'libPolarisMesa.dylib'
    shutil.copyfile(args.mesa_library, mesa)
    subprocess.run(['install_name_tool', '-id', '/usr/lib/libPolarisMesa.dylib', str(mesa)], check=True)
    # Theos's IOKit link stub uses the macOS Versions/A spelling. The real
    # iOS cache image has the unversioned install name; do not ship that typo.
    subprocess.run(['install_name_tool', '-change',
                    '/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit',
                    '/System/Library/Frameworks/IOKit.framework/IOKit', str(mesa)], check=True)
    exports = subprocess.check_output(['nm', '-gU', str(mesa)], text=True)
    (out / 'exported-gl.txt').write_text('\n'.join(line.split()[-1][1:] for line in exports.splitlines()
                                                if line.split() and line.split()[-1].startswith('_gl')) + '\n')
    with (out / 'eagl_gen.h').open('w') as target:
        subprocess.run([sys.executable, str(SOURCES / 'mkeagl.py'), str(SOURCES / 'eagl_slots_20H392.txt'),
                        str(args.gl_xml), str(out / 'exported-gl.txt'), str(SOURCES / 'eagl.c')],
                       stdout=target, check=True)
    common = ['/usr/bin/clang', '-target', 'arm64-apple-ios16.0', '-isysroot', str(sdk), '-O2',
              '-I', str(out), '-I', str(SOURCES)]
    cf = ['-framework', 'CoreFoundation']
    io = ['-framework', 'IOKit']
    surface = ['-framework', 'IOSurface']
    jobs = [
        ('libPolarisGL.dylib', ['-dynamiclib', '-Wl,-install_name,/usr/lib/libPolarisGL.dylib',
                               str(SOURCES / 'eagl.c'), str(SOURCES / 'gl_osmesa.c'), str(mesa),
                               *cf, *io, *surface, '-lobjc']),
        ('libPolarisInject.dylib', ['-dynamiclib', '-Wl,-install_name,/usr/lib/libPolarisInject.dylib',
                                   str(SOURCES / 'polaris-inject.c'), *cf, *io, '-framework', 'OpenGLES', '-lobjc']),
        ('polaris-bbd-wrapper', [str(SOURCES / 'polaris-bbd-wrapper.c'), *cf, *io]),
        ('polaris-gl-test', [str(SOURCES / 'polaris-gl-test.c'), str(mesa), *cf, *surface, *io, '-lobjc']),
        ('polaris-init', [str(SOURCES / 'polaris-init.c')]),
    ]
    for name, options in jobs:
        with (out / (name + '.build.log')).open('w') as log:
            p = subprocess.run([*common, *options, '-o', str(out / name)], stdout=log, stderr=subprocess.STDOUT)
        if p.returncode:
            raise RuntimeError((out / (name + '.build.log')).read_text())
        # Normalize the same SDK stub spelling in these images as well.
        for framework in ('IOKit', 'IOSurface'):
            subprocess.run(['install_name_tool', '-change',
                            f'/System/Library/Frameworks/{framework}.framework/Versions/A/{framework}',
                            f'/System/Library/Frameworks/{framework}.framework/{framework}',
                            str(out / name)], check=True)
    names = ['libPolarisMesa.dylib', 'libPolarisGL.dylib', 'libPolarisInject.dylib',
             'polaris-bbd-wrapper', 'polaris-gl-test', 'polaris-init']
    manifests = []
    for name in names:
        path = out / name
        subprocess.run(['strip', '-x', str(path)], check=True)
        subprocess.run(['codesign', '--force', '--sign', '-', '--timestamp=none',
                        '--identifier', 'local.polaris.' + name, str(path)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        subprocess.run(['codesign', '--verify', '--strict', str(path)], check=True)
        data = path.read_bytes()
        assert struct.unpack_from('<II', data) == (0xfeedfacf, 0x100000c), name
        dependencies = subprocess.check_output(['otool', '-L', str(path)], text=True)
        assert '@rpath/' not in dependencies and '/Versions/' not in dependencies, dependencies
        (out / (name + '.dependencies.txt')).write_text(dependencies)
        manifests.append(dict(name=name, bytes=len(data), sha256=sha(path)))
    # No paths in the wire input: the kernel maps each of six enum IDs to
    # its own constant path. Contiguous aligned spans, one digest per file.
    bundle = bytearray(304)
    struct.pack_into('<8sII', bundle, 0, b'PGPU0047', 6, 0)
    for kind, name in enumerate(names):
        bundle.extend(b'\0' * (-len(bundle) & 15))
        data = (out / name).read_bytes()
        struct.pack_into('<IIQ32s', bundle, 16 + 48 * kind, kind, len(data), len(bundle),
                         hashlib.sha256(data).digest())
        bundle.extend(data)
    assert len(bundle) <= 32 * 1024 * 1024
    struct.pack_into('<I', bundle, 12, len(bundle))
    (out / 'polaris-gpu.bundle').write_bytes(bundle)
    manifest = dict(build='20H392', arch='arm64', files=manifests,
                    bundle_sha256=sha(out / 'polaris-gpu.bundle'),
                    source_inputs={str(p.relative_to(ROOT)): sha(p) for p in [
                        SOURCES / 'eagl.c', SOURCES / 'gl_osmesa.c', SOURCES / 'mkeagl.py',
                        SOURCES / 'eagl_slots_20H392.txt', *[SOURCES / n for n in
                            ('polaris-inject.c', 'polaris-bbd-wrapper.c', 'polaris-gl-test.c', 'polaris-init.c')],
                        ROOT / 'tools/polaris-gl-status.h',ROOT / 'tools/polaris-performance.h',
                        ROOT / 'tools/polaris-frame-tail.h',ROOT / 'tools/polaris-compositor-clock.h']},
                    compositor_clock_trial=dict(default_enabled=False,token='ca_vbl=0|1',
                        scope='tested backboardd child environment only; runtime read-only choice observer',
                        hardware_refresh_rate_changed=False),
                    frame_tail_diagnostic=dict(default_enabled=False,full_trace_token='touch_lat=2',
                        aggregate_trace_token='touch_lat=3',paired_frame_window=64,
                        GPU_submission_semantics_changed=False),
                    mesa_input_sha256=sha(args.mesa_library), gl_xml_sha256=sha(args.gl_xml),
                    builder_sha256=sha(Path(__file__).resolve()),
                    hardware_test_passed=False, desktop_GPU_proven=False, writes_phone=False)
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--sdk', type=Path, required=True)
    p.add_argument('--mesa-library', type=Path, required=True)
    p.add_argument('--gl-xml', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    build(p.parse_args())
