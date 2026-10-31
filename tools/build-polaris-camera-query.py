#!/usr/bin/env python3
"""Build a standalone iOS16.5 camera-capability observer; never install/run it."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SDK = ROOT / 'research/polaris/continuation-0047/sdk-source/sdks-0222fd5413cf4b9af096f37b4621afa2688572f7/iPhoneOS16.5.sdk'
CLANG = Path('/Applications/Xcode-beta.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang')


def build(output):
    output = output.resolve()
    if not output.is_relative_to(ROOT / 'research'):
        raise ValueError('Only a private research output directory is accepted')
    output.mkdir(parents=True, exist_ok=False)
    source = ROOT / 'userland/camera/polaris-camera-query.m'
    binary = output / 'polaris-camera-query'
    command = [str(CLANG), '-target', 'arm64-apple-ios16.5', '-isysroot', str(SDK),
               '-O2', '-fobjc-arc', '-Wall', '-Wextra', '-Werror', str(source),
               '-framework', 'Foundation', '-framework', 'AVFoundation', '-framework', 'CoreMedia',
               '-o', str(binary)]
    commands = [command, ['/usr/bin/codesign', '--force', '--sign', '-', '--timestamp=none', str(binary)],
                ['/usr/bin/codesign', '--verify', '--strict', str(binary)]]
    logs = []
    for cmd in commands:
        done = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        logs.append(dict(command=cmd, returncode=done.returncode, stdout=done.stdout, stderr=done.stderr))
        (output / 'build-log.json').write_text(json.dumps(logs, indent=2) + '\n')
        if done.returncode:
            raise RuntimeError('Camera observer build failed; see private build-log.json')
    proof = dict(passed=True, source=str(source.relative_to(ROOT)),
                 source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                 binary_bytes=binary.stat().st_size, binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                 SDK=str(SDK.relative_to(ROOT)), target='arm64-apple-ios16.5', strict_codesign=True,
                 installation_performed=False, binary_executed=False, native_transport_implemented=False,
                 physical_frame_verified=False,
                 scope='Published software capabilities; discovery can contact mediaserverd, whose side effects are not asserted absent')
    (output / 'proof.json').write_text(json.dumps(proof, indent=2) + '\n')
    print(json.dumps(proof, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    build(parser.parse_args().output)
