#!/usr/bin/env python3
"""Build a read-only AArch64 EFI inventory app; never package/flash firmware."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--zig',required=True,type=Path)
    ap.add_argument('--output',required=True,type=Path)
    a=ap.parse_args();root=Path(__file__).resolve().parents[1]
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=True)
    obj=out/'probe.obj';image=out/'PolarisProbe.efi'
    env=dict(os.environ,ZIG_GLOBAL_CACHE_DIR=str(out/'zig-global'),ZIG_LOCAL_CACHE_DIR=str(out/'zig-local'))
    jobs=[['/usr/bin/clang','--target=aarch64-unknown-windows','-std=c11',
           '-ffreestanding','-fno-builtin','-fno-stack-protector','-fshort-wchar',
           '-mgeneral-regs-only','-O2','-Wall','-Wextra','-Werror','-c',
           str(root/'shim/polaris/uefi-probe.c'),'-o',str(obj)],
          [str(a.zig.resolve()),'build-exe',str(obj),'-target','aarch64-uefi',
           '--subsystem','efi_application',
           '-O','ReleaseSmall','-femit-bin='+str(image)]]
    for i,cmd in enumerate(jobs):
        p=subprocess.run(cmd,capture_output=True,env=env)
        (out/('build-'+str(i)+'.log')).write_bytes(p.stdout+p.stderr)
        if p.returncode:raise RuntimeError('Build failed; see '+str(out/('build-'+str(i)+'.log')))
    b=image.read_bytes();pe=struct.unpack_from('<I',b,60)[0]
    assert b[:2]==b'MZ' and b[pe:pe+4]==b'PE\0\0'
    assert struct.unpack_from('<H',b,pe+4)[0]==0xaa64
    assert struct.unpack_from('<H',b,pe+24)[0]==0x20b
    assert struct.unpack_from('<H',b,pe+24+68)[0]==10
    assert len(b)<1024*1024
    manifest=dict(artifact=image.name,bytes=len(b),sha256=hashlib.sha256(b).hexdigest(),
                  architecture='AArch64',subsystem='EFI application',
                  PE_image_base=struct.unpack_from('<Q',b,pe+24+24)[0],
                  probe_only=True,storage_write_api=False,NVRAM_write_api=False,
                  kernel_handoff=False,phone_boot_packaged=False,
                  inputs={n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in
                          ['shim/polaris/uefi.h','shim/polaris/uefi-memory.h','shim/polaris/uefi-probe.c','tools/build-polaris-uefi-probe.py']})
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps(manifest,indent=2))


if __name__=='__main__':main()
