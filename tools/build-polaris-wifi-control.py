#!/usr/bin/env python3
"""Build the private iOS16 arm64 Wi-Fi client; does not install or boot it."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

ROOT=Path(__file__).resolve().parents[1]
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--sdk',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();sdk=a.sdk.resolve(strict=True);out=a.output.resolve()
    out.mkdir(parents=True,exist_ok=False)
    target=out/'polaris-wifi-ctl';source=ROOT/'userland/wifi/polaris-wifi-ctl.c'
    command=['/usr/bin/clang','-target','arm64-apple-ios16.0','-isysroot',str(sdk),
             '-std=c11','-O2','-Wall','-Wextra','-Werror',str(source),'-o',str(target)]
    with (out/'build.log').open('w') as log:
        subprocess.run(command,check=True,stdout=log,stderr=subprocess.STDOUT)
    subprocess.run(['codesign','--force','--sign','-','--timestamp=none',
                    '--identifier','local.polaris.wifi-control',str(target)],check=True)
    subprocess.run(['codesign','--verify','--strict',str(target)],check=True)
    raw=target.read_bytes()
    if struct.unpack_from('<II',raw)!=(0xfeedfacf,0x100000c):raise ValueError('not ARM64 Mach-O')
    dependencies=subprocess.check_output(['otool','-L',str(target)],text=True)
    if '@rpath/' in dependencies or '/Versions/' in dependencies:raise ValueError('unsupported runtime dependency')
    (out/'dependencies.txt').write_text(dependencies)
    inputs=['userland/wifi/polaris-wifi-ctl.c','tools/polaris-wifi-interface.h',
            'tools/polaris-wifi-mailbox.h','tools/polaris-wifi-control-wire.h',
            'tools/build-polaris-wifi-control.py']
    manifest=dict(format=1,target='arm64-apple-ios16.0',command=command,
                  binary_sha256=sha(target),binary_bytes=len(raw),
                  sources={n:sha(ROOT/n) for n in inputs},
                  installed=False,physical_wifi_verified=False)
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(target)
if __name__=='__main__':main()
