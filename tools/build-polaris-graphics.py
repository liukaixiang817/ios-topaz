#!/usr/bin/env python3
"""Build a NEW local version-matched GPU bundle; never edits a mounted/phone root.

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
    abi = None
    preserved = {}
    if args.rebuild_init and args.preserve_common_from is None:
        raise ValueError('rebuild-init requires the verified current common binaries')
    if args.build == '20F66':
        if args.abi_proof is None:
            raise ValueError('20F66 requires the separately verified actual-library ABI proof')
        abi = json.loads(args.abi_proof.read_text())
        expected = {
            'QuartzCore': '9d60b1dd6347efd3edd66d173746dd26a5e0bf6629fd8a07b52c190a4297cb58',
            'OpenGLES': 'b84d0dc21490d1f89c0dd93d02ae855d0ee9801e277b2fc84fd58f9f65a3ddc8',
            'IOSurface': 'a875c9124ebb5279a63f5137402f3bc1a64c462e281000c78291aa7180e8904e',
        }
        if not abi.get('passed') or abi.get('build') != '20F66' or abi.get('EAGL_names_checked') != 457:
            raise ValueError('incomplete or foreign graphics ABI proof')
        for name, digest in expected.items():
            entry = abi['images'][name]
            path = (ROOT / entry['path']).resolve()
            if not path.is_relative_to(ROOT / 'research') or entry['sha256'] != digest or sha(path) != digest:
                raise ValueError('actual20F66 analysis image changed: ' + name)
        for name, digest in abi['evidence_sha256'].items():
            path = (ROOT / name).resolve()
            if not path.is_relative_to(ROOT / 'research') or sha(path) != digest:
                raise ValueError('actual20F66 ABI evidence changed: ' + name)
        correspondence = json.loads((ROOT / 'research/polaris/uefi-ios-0124/OpenGLES-all-slot-correspondence.json').read_text())
        actual = {row['name']: row['slot'] for row in correspondence['rows'] if row['passed'] is True}
        table = {}
        for line in (SOURCES / 'eagl_slots_20H392.txt').read_text().splitlines():
            fields = line.split('#')[0].split()
            if fields:
                slot, _, *names = fields
                for name in names:
                    if name in table:
                        raise ValueError('duplicate EAGL dispatch name')
                    table[name] = int(slot, 16)
        if len(actual) != 457 or table != actual:
            raise ValueError('current EAGL dispatch table differs from actual20F66')
    elif args.abi_proof is not None:
        raise ValueError('the 20F66 proof cannot admit the default20H392 bundle')
    if args.preserve_common_from is not None:
        if args.build != '20F66':
            raise ValueError('common-file preservation is only for the new20F66 candidate')
        base = args.preserve_common_from.resolve()
        previous = json.loads((base / 'manifest.json').read_text())
        known = '865407ee5b402fe690c04f5888ee6758a29f6ef3eca639019ac89dfba0f3371f'
        if previous.get('build') != '20H392' or previous.get('bundle_sha256') != known or sha(base / 'polaris-gpu.bundle') != known:
            raise ValueError('preserve only the current physically verified graphics bundle')
        if sha(args.gl_xml) != previous['gl_xml_sha256']:
            raise ValueError('common graphics registry changed')
        for name in ('eagl.c', 'gl_osmesa.c', 'mkeagl.py', 'eagl_slots_20H392.txt',
                     'polaris-gl-test.c', 'polaris-init.c'):
            if name == 'polaris-init.c' and args.rebuild_init:
                continue
            path = SOURCES / name
            if previous['source_inputs'].get(str(path.relative_to(ROOT))) != sha(path):
                raise ValueError('common graphics source changed: ' + name)
        for name in ('polaris-gl-status.h', 'polaris-performance.h', 'polaris-frame-tail.h'):
            path = ROOT / 'tools' / name
            if previous['source_inputs'].get(str(path.relative_to(ROOT))) != sha(path):
                raise ValueError('common graphics interface changed: ' + name)
        for item in previous['files']:
            if item['name'] in ('libPolarisMesa.dylib', 'libPolarisGL.dylib', 'polaris-gl-test', 'polaris-init'):
                path = base / item['name']
                if sha(path) != item['sha256']:
                    raise ValueError('physically verified common binary changed')
                if item['name'] != 'polaris-init' or not args.rebuild_init:
                    preserved[item['name']] = path
        if len(preserved) != (3 if args.rebuild_init else 4) or sha(args.mesa_library) != sha(preserved['libPolarisMesa.dylib']):
            raise ValueError('exact current Mesa and all unchanged common files required')
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
    if args.build == '20F66':
        common.append('-DPGPU_USERLAND_20F66=1')
    cf = ['-framework', 'CoreFoundation']
    io = ['-framework', 'IOKit']
    surface = ['-framework', 'IOSurface']
    jobs = [
        ('libPolarisGL.dylib', ['-dynamiclib', '-Wl,-install_name,/usr/lib/libPolarisGL.dylib',
                               str(SOURCES / 'eagl.c'), str(SOURCES / 'gl_osmesa.c'), str(mesa),
                               *cf, *io, *surface, '-lobjc']),
        ('libPolarisInject.dylib', ['-dynamiclib', '-Wl,-install_name,/usr/lib/libPolarisInject.dylib',
                                   str(SOURCES / 'polaris-inject.c'),
                                   *([str(SOURCES / 'polaris-poster-preview.c'),
                                      str(SOURCES / 'polaris-media-compat.c')] if args.build == '20F66' else []),
                                   *cf, *io, '-framework', 'OpenGLES', '-lobjc']),
        ('polaris-bbd-wrapper', [str(SOURCES / 'polaris-bbd-wrapper.c'), *cf, *io]),
        ('polaris-gl-test', [str(SOURCES / 'polaris-gl-test.c'), str(mesa), *cf, *surface, *io, '-lobjc']),
        ('polaris-init', [str(SOURCES / 'polaris-init.c'), *(cf if args.build == '20F66' else [])]),
    ]
    for name, options in jobs:
        if name in preserved:
            shutil.copyfile(preserved[name], out / name)
            continue
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
        if name in preserved:
            shutil.copyfile(preserved[name], path)
        else:
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
    manifest = dict(build=args.build, arch='arm64', files=manifests,
                    preserved_current_common_files={name: sha(path) for name, path in preserved.items()},
                    actual_userland_ABI_proof_sha256=sha(args.abi_proof) if abi else None,
                    bundle_sha256=sha(out / 'polaris-gpu.bundle'),
                    source_inputs={str(p.relative_to(ROOT)): sha(p) for p in [
                        SOURCES / 'eagl.c', SOURCES / 'gl_osmesa.c', SOURCES / 'mkeagl.py',
                        SOURCES / 'eagl_slots_20H392.txt', *[SOURCES / n for n in
                            ('polaris-inject.c', 'polaris-bbd-wrapper.c', 'polaris-gl-test.c', 'polaris-init.c')],
                        ROOT / 'tools/polaris-gl-status.h',ROOT / 'tools/polaris-performance.h',
                        ROOT / 'tools/polaris-frame-tail.h',ROOT / 'tools/polaris-compositor-clock.h',
                        ROOT / 'tools/polaris-graphics-abi.h']},
                    compositor_clock_trial=dict(default_enabled=False,token='ca_vbl=0|1',
                        scope='tested backboardd child environment only; runtime read-only choice observer',
                        hardware_refresh_rate_changed=False),
                    frame_tail_diagnostic=dict(default_enabled=False,full_trace_token='touch_lat=2',
                        aggregate_trace_token='touch_lat=3',paired_frame_window=64,
                        GPU_submission_semantics_changed=False),
                    mesa_input_sha256=sha(args.mesa_library), gl_xml_sha256=sha(args.gl_xml),
                    builder_sha256=sha(Path(__file__).resolve()),
                    hardware_test_passed=False, desktop_GPU_proven=False, writes_phone=False)
    if args.build == '20F66':
        for p in (SOURCES / 'polaris-poster-preview.c', ROOT / 'tools/polaris-poster-preview.h',
                  SOURCES / 'polaris-media-compat.c', ROOT / 'tools/polaris-media-compat.h',
                  ROOT / 'tools/polaris-media-status.h'):
            manifest['source_inputs'][str(p.relative_to(ROOT))] = sha(p)
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--sdk', type=Path, required=True)
    p.add_argument('--mesa-library', type=Path, required=True)
    p.add_argument('--gl-xml', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--build', choices=('20H392', '20F66'), default='20H392')
    p.add_argument('--abi-proof', type=Path)
    p.add_argument('--preserve-common-from', type=Path,
                   help='keep four exact binaries from the current verified20H392 bundle')
    p.add_argument('--rebuild-init', action='store_true',
                   help='rebuild only the changed20F66 init among the four common binaries')
    build(p.parse_args())
