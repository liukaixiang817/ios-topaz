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
    poster = None
    timezone = None
    retained = None
    if args.retained_cache_trial_from is not None:
        if args.build != '20F66' or args.rebuild_init or args.preserve_common_from is not None or \
           args.poster_assets_header is not None or args.melbourne_timezone_source_root is not None:
            raise ValueError('retained-cache trial is a separate20F66 Mesa+wrapper build; no init/resource rebuild or mixed preservation mode')
        base = args.retained_cache_trial_from.resolve()
        expected_base = ROOT / 'research/polaris/uefi-ios-0138/graphics-melbourne-default-0002'
        if base != expected_base or sha(base / 'manifest.json') != 'b682d17ef03876c052b85c0cd7b7d4c28bc034b377d1489e5942d823a2b87c1a' or \
           sha(base / 'polaris-gpu.bundle') != '4fe2b903efcdfabddc7b84c16284c4ab4b7c5fc851b090e531b95c57658fc770':
            raise ValueError('retained-cache trial requires the exact complete0138 wallpaper/Melbourne baseline')
        if sha(args.mesa_library) != 'd283234ba4bbe7294b533f101a9ac0d9306aac7930b33396c214b4f413f4a7bc':
            raise ValueError('only the independently linked/signed0139 retention-query Mesa is admitted')
        old = json.loads((base / 'manifest.json').read_text())
        mesa_proof = ROOT / 'research/polaris/uefi-ios-0139/performance/mesa-retained-trial-0001/proof.json'
        fixture_proof = ROOT / 'research/polaris/uefi-ios-0139/performance/retained-madvise-final-0002/proof.json'
        if sha(mesa_proof) != 'ea52b126e3495f55f87fe3798d383c6ad458f7d6eac847e2d676ab6127516793' or \
           sha(fixture_proof) != '407d4c70c6dcdb786d4ed3eed3a86ba3c0bce017f6937d80ec2175fb99084e2f':
            raise ValueError('exact real-shim lifetime/concurrency and complete Mesa link proofs required')
        for proof in (mesa_proof, fixture_proof):
            for name, digest in json.loads(proof.read_text())['source_sha256'].items():
                if sha(ROOT / name) != digest:
                    raise ValueError('retention-query source changed since its actual tests/link: ' + name)
        if sha(args.gl_xml) != old['gl_xml_sha256']:
            raise ValueError('retained-cache trial cannot change the current GL registry')
        # Preserve the already tested init, including its exact private PNG,
        # state/package contracts, time zone and rollback. Only the wrapper's
        # source is intentionally rebuilt in this scope.
        for name, digest in old['source_inputs'].items():
            if name != 'userland/gpu/polaris-bbd-wrapper.c' and sha(ROOT / name) != digest:
                raise ValueError('retained-cache trial changed a baseline graphics/resource source: ' + name)
        for item in old['files']:
            path = base / item['name']
            if sha(path) != item['sha256']:
                raise ValueError('retained-cache baseline signed file changed: ' + item['name'])
            if item['name'] not in ('libPolarisMesa.dylib', 'polaris-bbd-wrapper'):
                preserved[item['name']] = path
        if len(preserved) != 4:
            raise ValueError('retained-cache trial must preserve exactly four current signed graphics files')
        retained = dict(base=base, previous=old, mesa_proof=mesa_proof, fixture_proof=fixture_proof)
    if args.rebuild_init and args.preserve_common_from is None:
        raise ValueError('rebuild-init requires the verified current common binaries')
    if args.poster_assets_header is not None:
        if args.build != '20F66' or not args.rebuild_init:
            raise ValueError('poster assets require20F66 and explicit rebuild-init')
        header = args.poster_assets_header.resolve()
        prepared = header.parent / 'manifest.json'
        baseline = ROOT / 'research/polaris/uefi-ios-0133/graphics-poster-hierarchy-0001'
        if not header.is_relative_to(ROOT / 'research') or \
           sha(header) != '2377b197c84246719fd7828a0e47cca918bed63b712be3813baaeef940b859c7' or \
           sha(prepared) != 'df8b340f9a50f88aed8f9045ca331c8bccf387872855670a5e4c2180cb4f9420':
            raise ValueError('only exact prepared-static-states-0002 private official default7400 assets are admitted')
        if sha(baseline / 'manifest.json') != '858230c94aa282bd683b953a5ee1e4637d1419e33fd440818699f110818aa49e' or \
           sha(baseline / 'polaris-gpu.bundle') != 'bf8a704411fae01abeb23578b19f0c6c1738f90cedaeedb7b394930187069b70':
            raise ValueError('the exact current0133 graphics baseline is required')
        previous = json.loads((baseline / 'manifest.json').read_text())
        for name, digest in previous['source_inputs'].items():
            if name != 'userland/gpu/polaris-init.c' and sha(ROOT / name) != digest:
                raise ValueError('unchanged0133 graphics source changed: ' + name)
        poster = dict(header=header, prepared=prepared, baseline=baseline, previous=previous)
    if args.melbourne_timezone_source_root is not None:
        if args.build != '20F66' or not args.rebuild_init or poster is None:
            raise ValueError('Melbourne timezone requires20F66, rebuild-init and the exact five-binary-preserving poster baseline')
        source = args.melbourne_timezone_source_root.resolve()
        tzif = source / 'usr/share/zoneinfo.default/Australia/Melbourne'
        version = source / 'System/Library/CoreServices/SystemVersion.plist'
        metadata = ROOT / 'research/polaris/uefi-ios-0138/melbourne-source-raw-HFS-metadata.json'
        if tzif.is_symlink() or sha(tzif) != '9c49d5cfe497359dcda1753005435d9cdc9eb49a06345cf4d73558e5411465d9' or \
           tzif.stat().st_size != 2195 or sha(version) != '46457f81a04a81f462bfa0ab24693eff2140ce81a254e64354e43bd0b996dd22' or \
           sha(metadata) != '042c9af96b0d36f5407255c8b317f8d588ebf1eb1575e162e3eef42d414af464':
            raise ValueError('exact original20F66 Melbourne TZif/SystemVersion and raw HFS metadata proof required')
        # lstat/readlink rather than resolve: original absolute links must
        # never escape the read-only source root into host /var.
        for path, target in [('usr/share/zoneinfo', '/var/db/timezone/zoneinfo'),
                             ('private/var/db/timezone/localtime', '/var/db/timezone/zoneinfo/US/Pacific')]:
            link = source / path
            if not link.is_symlink() or str(link.readlink()) != target:
                raise ValueError('original20F66 timezone link differs: ' + path)
        link = source / 'private/var/db/timezone/zoneinfo'
        if link.exists() or link.is_symlink():
            raise ValueError('original20F66 zoneinfo node must be absent')
        timezone = dict(source=source, metadata=metadata, tzif=tzif)
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
    if poster:
        # Asset installation changes only PID1. Retain all five current0133
        # signed binaries, including the existing preview/media injector.
        for item in poster['previous']['files']:
            if item['name'] == 'polaris-init':
                continue
            path = poster['baseline'] / item['name']
            if sha(path) != item['sha256']:
                raise ValueError('current0133 graphics binary changed: ' + item['name'])
            if item['name'] in preserved and sha(preserved[item['name']]) != item['sha256']:
                raise ValueError('original common baseline differs from current0133')
            preserved[item['name']] = path
        if len(preserved) != 5:
            raise ValueError('poster assets may rebuild only init')
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
        ('polaris-bbd-wrapper', [str(SOURCES / 'polaris-bbd-wrapper.c'),
                                 *(['-DPOLARIS_BBD_RETAIN_CACHE_TRIAL=1', '-Wall', '-Wextra', '-Werror'] if retained else []),
                                 *cf, *io]),
        ('polaris-gl-test', [str(SOURCES / 'polaris-gl-test.c'), str(mesa), *cf, *surface, *io, '-lobjc']),
        ('polaris-init', [str(SOURCES / 'polaris-init.c'),
                          *(['-DPOLARIS_POSTER_ASSETS=1',
                             '-DPOLARIS_POSTER_ASSET_HEADER="' + str(poster['header']) + '"',
                             '-Wall', '-Wextra', '-Werror',
                             str(SOURCES / 'polaris-poster-assets.c')] if poster else []),
                          *(['-DPOLARIS_MELBOURNE_TIMEZONE=1',
                             '-Wall', '-Wextra', '-Werror',
                             str(SOURCES / 'polaris-timezone.c')] if timezone else []),
                          *(cf if args.build == '20F66' else [])]),
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
    if poster:
        for p in (SOURCES / 'polaris-poster-assets.c', SOURCES / 'polaris-poster-assets.h',
                  poster['header'], poster['prepared'], poster['baseline'] / 'manifest.json',
                  ROOT / 'research/polaris/uefi-ios-0136/default-wallpaper/render-official-default.m',
                  ROOT / 'research/polaris/uefi-ios-0136/default-wallpaper/default-identity-raw-metadata.json',
                  ROOT / 'research/polaris/uefi-ios-0138/prepare-static-states.py',
                  poster['header'].parent.parent / 'check-static-states.m',
                  poster['header'].parent.parent / 'state-contract-render-proof.json',
                  poster['header'].parent.parent / 'original-package-index-raw-HFS-metadata.json',
                  ROOT / 'research/polaris/uefi-ios-0134/wallpaper-assets/original-source-catalog-BSDInfo-readonly.json'):
            manifest['source_inputs'][str(p.relative_to(ROOT))] = sha(p)
        manifest['poster_assets'] = dict(enabled=True, destination='verified512MiB RAM COW only',
            private_header_sha256=sha(poster['header']), prepared_manifest_sha256=sha(poster['prepared']),
            official_default_wallpaper_identifier=7400, source='original3CAML+5HEIC; full staticRGBA8, no generated image',
            package_contract=dict(states=['Locked', 'Unlock', 'Sleep'], static_empty_elements=True,
                original_published_scene_ids=['Background', 'Floating', 'Foreground'],
                original_index_and_asset_manifest_retained=True,
                actual_CAMLParser_CAPackage_CAStateController_and_CPU_Metal_pixel_proof=True),
            baseline_bundle_sha256=poster['previous']['bundle_sha256'],
            target='PID1 after console, before poster jobs/app publication/launchd',
            source_failure='original CAMLs retained; original UI continues without retry',
            incomplete_rollback='PID1 hold; Apple launchd prohibited',
            actual_bundle_bytes=len(bundle), cap_bytes=32 * 1024 * 1024,
            physical_wallpaper_fixed=False)
    if timezone:
        for p in (SOURCES / 'polaris-timezone.c', SOURCES / 'polaris-timezone.h', timezone['metadata'],
                  ROOT / 'research/reference-repos/hackios-xnu-userland/userland/build.sh',
                  ROOT / 'research/polaris/uefi-ios-0138/tzinit-localtime-prefix-proof.txt'):
            manifest['source_inputs'][str(p.relative_to(ROOT))] = sha(p)
        manifest['default_timezone'] = dict(zone='Australia/Melbourne',
            source_tzif_sha256=sha(timezone['tzif']), source_tzif_bytes=timezone['tzif'].stat().st_size,
            source='unmodified original20F66 TZif; DST rules read by CoreFoundation',
            scope='exact PID1/root_device/devfs identity/immutable-base512MiB RAM COW before launchd',
            changes=['RAM-only zoneinfo symlink', 'RAM-only localtime symlink'],
            original_localtime='same inode retained as .polaris-0138-localtime.original',
            source_failure='original timezone retained; no retry', incomplete_rollback='PID1 hold',
            kernel_UTC_changed=False, fixed_offset_used=False, physical_timezone_verified=False)
    if retained:
        original = retained['previous']
        current_inputs = manifest['source_inputs']
        manifest['source_inputs'] = dict(original['source_inputs'])
        manifest['source_inputs'].update(current_inputs)
        for path in (retained['base'] / 'manifest.json', retained['mesa_proof'], retained['fixture_proof'],
                     ROOT / 'tools/polaris-drm-retained-environment.h',
                     ROOT / 'tools/polaris-drm-retained-environment-test.c',
                     ROOT / 'tools/polaris-drm-retained-environment-check.py',
                     ROOT / 'userland/mesa/redwood-drm/redwood_drm.c',
                     ROOT / 'userland/mesa/redwood-drm/polaris-retained-cache.h'):
            manifest['source_inputs'][str(path.relative_to(ROOT))] = sha(path)
        manifest['poster_assets'] = dict(original['poster_assets'])
        manifest['poster_assets']['actual_bundle_bytes'] = len(bundle)
        manifest['default_timezone'] = original['default_timezone']
        manifest['retained_madvise_trial'] = dict(enabled_in_this_candidate=True,
            compile_default_OFF=True, runtime_environment='POLARIS_DRM_RETAIN_CACHE=1',
            scope='only accepted genuine backboardd child, canonical polarisgl=1, own new PolarisGPU connection',
            acceptance_child_cache_enabled=False, inherited_GPU_port_cleared=True,
            fallback_restart_and_environment_failure='cache cleared; ambiguous mutation denies exec',
            only_native_successful_WILLNEED_retained1_reused=True,
            native_SUBMIT_fence_cache_DSB_auth_lifetime_thermal_unchanged=True,
            changed_signed_files=['libPolarisMesa.dylib', 'polaris-bbd-wrapper'],
            preserved_signed_files=sorted(preserved), baseline_bundle_sha256=original['bundle_sha256'],
            source_and_link_proof_sha256=sha(retained['mesa_proof']),
            actual_shim_fixture_proof_sha256=sha(retained['fixture_proof']),
            actual_target_cache_hits_observed=False, physical_performance_improved=False)
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
    p.add_argument('--poster-assets-header', type=Path,
                   help='exact private prepared-static-states-0002 default7400 header;20F66/rebuild-init only, preserves five0133 binaries')
    p.add_argument('--melbourne-timezone-source-root', type=Path,
                   help='read-only exact20F66 original root for the PID1 RAM-only Australia/Melbourne default; preserves five current graphics files')
    p.add_argument('--retained-cache-trial-from', type=Path,
                   help='explicit separate20F66 trial: exact0138 baseline, reviewed Mesa+scoped wrapper only; preserve four signed files and all recovered resources')
    build(p.parse_args())
