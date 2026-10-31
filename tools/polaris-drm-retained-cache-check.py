#!/usr/bin/env python3
"""Real-shim retention/lifetime and nonblocking-WAIT checks; no physical GPU."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time

R = Path(__file__).resolve().parents[1]
SOURCE = R / 'userland/mesa/redwood-drm/redwood_drm.c'
HEADER = SOURCE.with_name('polaris-retained-cache.h')
FIXTURE = R / 'tools/polaris-drm-retained-cache-test.c'
BASE = R / 'research/polaris/continuation-0047/mesa-public-v1/mesa-25.0.7/src/redwood-drm/redwood_drm.c'
BASE_SHA = '080b9a4a6de6344a6bd57ae8d666eacbaae6a31134a692e490834059e3d234df'
CASES = ('warm', 'unknown', 'retained-zero', 'dontneed', 'unknown-advice',
         'malformed-size', 'null-data', 'new', 'map-failure', 'unmap-failure', 'close-failure', 'unknown-selector',
         'surface-import', 'failure', 'short-return', 'changed-response', 'full',
         'wait-submit', 'close-race', 'reconnect', 'reconnect-inflight', 'fork',
         'fork-during-wait', 'no-intent', 'bad-intent', 'inherited')


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def run(cmd, log, timeout=30):
    began = time.monotonic()
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    log.write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError('Check failed; inspect ' + str(log))
    return round(time.monotonic() - began, 6)


def main(a):
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    sdk, includes = a.sdk.resolve(), a.mesa_includes.resolve()
    assert sha(BASE) == BASE_SHA
    assert (sdk / 'SDKSettings.plist').is_file() and (includes / 'drm-uapi/drm.h').is_file()
    ios = ['/usr/bin/clang', '-target', 'arm64-apple-ios16.5', '-isysroot', str(sdk),
           '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
           '-DREDWOOD_GPU_SERVICE="PolarisGPU"', '-I', str(includes)]
    compiled = {}
    preprocessed = []
    for name, source, flags in [('ios-baseline', BASE, []), ('ios-off', SOURCE, []),
                                ('ios-on', SOURCE, ['-DPOLARIS_DRM_RETAIN_CACHE_TRIAL=1'])]:
        obj = out / (name + '.o')
        run(ios + flags + ['-c', str(source), '-o', str(obj)], out / (name + '.log'))
        compiled[name] = dict(bytes=obj.stat().st_size, sha256=sha(obj))
        if name != 'ios-on':
            data = subprocess.check_output(ios + ['-E', '-P', str(source)])
            data = b'\n'.join(line.rstrip() for line in data.splitlines() if line.strip())
            (out / (name + '.i')).write_bytes(data)
            preprocessed.append(data)
    assert preprocessed[0] == preprocessed[1]
    assert (out / 'ios-baseline.o').read_bytes() == (out / 'ios-off.o').read_bytes()
    host = ['/usr/bin/clang', '-std=c11', '-O1', '-g', '-fsanitize=address,undefined',
            '-fno-omit-frame-pointer', '-Wall', '-Wextra', '-Werror',
            '-Wno-unused-function', '-I', str(includes)]
    fixtures = []
    for name, flags, cases in [
        ('host-on', ['-DREDWOOD_GPU_SERVICE="PolarisGPU"', '-DPOLARIS_DRM_RETAIN_CACHE_TRIAL=1'], CASES),
        ('host-off', ['-DREDWOOD_GPU_SERVICE="PolarisGPU"'], ('off',)),
        ('host-nonpolaris', ['-DREDWOOD_GPU_SERVICE="RedwoodGPU"', '-DPOLARIS_DRM_RETAIN_CACHE_TRIAL=1'], ('nonpolaris',))]:
        exe = out / name
        run(host + flags + [str(FIXTURE), '-o', str(exe)], out / (name + '.build.log'))
        for case in cases:
            duration = run([str(exe), case], out / (name + '.' + case + '.log'), timeout=6)
            fixtures.append(dict(binary=name, case=case, passed=True, seconds=duration))
    proof = dict(passed=True,
        scope='real shim with independent mocked native-client oracle; no physical GPU/IOKit service',
        source_sha256={str(p.relative_to(R)): sha(p) for p in (SOURCE, HEADER, FIXTURE, Path(__file__).resolve())},
        exact_original_baseline_sha256=BASE_SHA, actual_SDK16_5_ARM64=compiled,
        default_OFF_preprocessed_whole_bytes=len(preprocessed[0]),
        default_OFF_preprocessed_sha256=hashlib.sha256(preprocessed[0]).hexdigest(),
        default_OFF_preprocessed_byte_identical=True, default_OFF_ARM64_object_byte_identical=True,
        fixtures=fixtures, fixture_count=len(fixtures),
        WAIT_needs_another_thread_SUBMIT=True, no_cache_mutex_across_any_IOKit_call=True,
        lifetime_invalidated_before_and_after_native_completion=True,
        unknown_handles_and_full_table_call_native=True, native_errors_sticky=True,
        inherited_connection_and_fork_child_cache_disabled=True,
        synthetic_warm_sequence=dict(handles=37, rounds=64, native_WILLNEED=37, cached=37*63,
                                     physical_roundtrip_saving_proven=False),
        physical_GPU_execution=False, physical_performance_improved=False, phone_action=False)
    (out / 'proof.json').write_text(json.dumps(proof, indent=2) + '\n')
    print(json.dumps(dict(passed=True, fixture_count=len(fixtures), default_OFF_exact=True,
                         proof=str(out / 'proof.json'), proof_sha256=sha(out / 'proof.json')), indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--sdk', type=Path, default=R / 'research/polaris/continuation-0047/sdk-source/sdks-0222fd5413cf4b9af096f37b4621afa2688572f7/iPhoneOS16.5.sdk')
    p.add_argument('--mesa-includes', type=Path, default=R / 'research/polaris/continuation-0047/mesa-25.0.7/include')
    main(p.parse_args())
