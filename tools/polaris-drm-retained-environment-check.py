#!/usr/bin/env python3
"""Actual scoped-wrapper activation checks and optional private trial bundle.

No phone, USB, kernel build, root installation or native pin is performed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

R = Path(__file__).resolve().parents[1]
WRAPPER = R / 'userland/gpu/polaris-bbd-wrapper.c'
HEADER = R / 'tools/polaris-drm-retained-environment.h'
FIXTURE = R / 'tools/polaris-drm-retained-environment-test.c'
BUILDER = R / 'tools/build-polaris-graphics.py'
BASE_SOURCE = Path('/private/tmp/polaris-runtime-0138-frozen-0001/userland/gpu/polaris-bbd-wrapper.c')
BASE_SOURCE_SHA = '24f9c54a5a3d17cbdbe192d8eed8081607d4196b97666b6fcb0eb6f70ee4830d'
BASE = R / 'research/polaris/uefi-ios-0138/graphics-melbourne-default-0002'
MESA = R / 'research/polaris/uefi-ios-0139/performance/mesa-retained-trial-0001/libPolarisMesa.dylib'
GL_XML = R / 'research/polaris/continuation-0047/mesa-public-v1/mesa-25.0.7/src/mapi/glapi/registry/gl.xml'
ABI = R / 'research/polaris/uefi-ios-0124/20F66-graphics-ABI-proof.json'
CASES = ('good', 'fallback', 'restart', 'no-service', 'duplicate', 'conflict',
         'substring', 'wrong-value', 'missing', 'entry-clear-failure',
         'false-clear-success', 'port-clear-failure', 'launch-clear-failure',
         'set-failure', 'partial-set-failure', 'wrong-readback', 'port-after-set',
         'clock-failure', 'exec-failure')


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def run(command, log, expected_success=True):
    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    log.write_text(result.stdout + result.stderr)
    if (result.returncode == 0) is not expected_success:
        raise RuntimeError('Unexpected result; inspect ' + str(log))
    return result


def main(a):
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    sdk = a.sdk.resolve()
    assert sha(BASE_SOURCE) == BASE_SOURCE_SHA
    common = ['/usr/bin/clang', '-target', 'arm64-apple-ios16.0', '-isysroot', str(sdk),
              '-std=c11', '-D_DARWIN_C_SOURCE', '-DPGPU_USERLAND_20F66=1', '-O2',
              '-Wall', '-Wextra', '-Werror']
    objects, preprocessed = {}, []
    for name, source, flags in [('baseline', BASE_SOURCE, []), ('off', WRAPPER, []),
                                ('on', WRAPPER, ['-DPOLARIS_BBD_RETAIN_CACHE_TRIAL=1'])]:
        p = out / (name + '.o')
        run(common + flags + ['-c', str(source), '-o', str(p)], out / (name + '.build.log'))
        objects[name] = dict(bytes=p.stat().st_size, sha256=sha(p))
        if name != 'on':
            raw = subprocess.check_output(common + ['-E', '-P', str(source)])
            normalized = b'\n'.join(line.rstrip() for line in raw.splitlines() if line.strip())
            (out / (name + '.i')).write_bytes(normalized)
            preprocessed.append(normalized)
    assert preprocessed[0] == preprocessed[1]
    assert (out / 'baseline.o').read_bytes() == (out / 'off.o').read_bytes()
    fixture = out / 'wrapper-fixture'
    run(['/usr/bin/clang', '-std=c11', '-O1', '-g', '-D_DARWIN_C_SOURCE',
         '-DPOLARIS_BBD_RETAIN_CACHE_TRIAL=1', '-fsanitize=address,undefined',
         '-fno-omit-frame-pointer', '-Wall', '-Wextra', '-Werror', str(FIXTURE),
         '-framework', 'CoreFoundation', '-o', str(fixture)], out / 'fixture.build.log')
    for case in CASES:
        run([str(fixture), case], out / (case + '.log'))
    command = [sys.executable, str(BUILDER), '--build', '20F66', '--sdk', str(sdk),
               '--mesa-library', str(MESA), '--gl-xml', str(GL_XML), '--abi-proof', str(ABI),
               '--retained-cache-trial-from', str(BASE)]
    negatives = (
        ('foreign-build', ['--build', '20H392']),
        ('mixed-init', ['--rebuild-init']),
        ('foreign-baseline', ['--retained-cache-trial-from', str(BASE.parent / 'graphics-melbourne-default-0001')]),
        ('old-Mesa', ['--mesa-library', str(BASE / 'libPolarisMesa.dylib')]),
    )
    for name, extra in negatives:
        destination = out / ('rejected-' + name)
        run(command + ['--output', str(destination), *extra], out / (name + '.log'), False)
        assert not destination.exists()
    bundle = None
    if a.build_trial_bundle:
        destination = out / 'graphics-retained-trial'
        run(command + ['--output', str(destination)], out / 'trial-bundle.build.log')
        m = json.loads((destination / 'manifest.json').read_text())
        original = json.loads((BASE / 'manifest.json').read_text())
        changed = [x['name'] for x, y in zip(m['files'], original['files']) if x != y]
        assert changed == ['libPolarisMesa.dylib', 'polaris-bbd-wrapper']
        expected_poster = dict(original['poster_assets'])
        expected_poster['actual_bundle_bytes'] = (destination / 'polaris-gpu.bundle').stat().st_size
        assert m['poster_assets'] == expected_poster
        assert m['default_timezone'] == original['default_timezone']
        assert m['retained_madvise_trial']['actual_target_cache_hits_observed'] is False
        for item in m['files']:
            assert sha(destination / item['name']) == item['sha256']
        for name, digest in m['source_inputs'].items():
            assert sha(R / name) == digest, name
        assert m['builder_sha256'] == sha(BUILDER)
        bundle = dict(path=str(destination.relative_to(R)), bytes=(destination / 'polaris-gpu.bundle').stat().st_size,
                      sha256=sha(destination / 'polaris-gpu.bundle'), files=m['files'],
                      only_Mesa_and_wrapper_changed=True, other_four_byte_identical=True,
                      baseline_wallpaper_and_Melbourne_contracts_retained=True)
    proof = dict(passed=True, source_sha256={str(p.relative_to(R)): sha(p) for p in
        (WRAPPER, HEADER, FIXTURE, BUILDER, Path(__file__).resolve())},
        default_OFF_preprocessed_whole_bytes=len(preprocessed[0]),
        default_OFF_preprocessed_byte_identical=True, default_OFF_ARM64_object_byte_identical=True,
        actual_SDK16_5_ARM64_objects=objects, real_wrapper_fixture_count=len(CASES),
        actual_builder_rejections=len(negatives), acceptance_child_intent_and_port_cleared=True,
        only_accepted_canonical_gl_own_connection_may_enable=True,
        fallback_restart_or_environment_failure_does_not_enable=True,
        trial_bundle=bundle, physical_performance_improved=False, phone_action=False)
    (out / 'proof.json').write_text(json.dumps(proof, indent=2) + '\n')
    print(json.dumps(dict(passed=True, fixture_count=len(CASES), builder_negative_count=len(negatives),
                         default_OFF_exact=True, trial_bundle=bundle,
                         proof_sha256=sha(out / 'proof.json')), indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--sdk', type=Path, default=R / 'research/polaris/continuation-0047/sdk-source/sdks-0222fd5413cf4b9af096f37b4621afa2688572f7/iPhoneOS16.5.sdk')
    p.add_argument('--build-trial-bundle', action='store_true')
    main(p.parse_args())
