#!/usr/bin/env python3
"""Check the exact0909 RAM-only discard/reuse implementation. No device I/O."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
PATCH=ROOT/'xnu/profiles/polaris/0909-polaris-RAM-only-discard-reuse-and-HFS-budget.patch'

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',required=True,type=Path)
    args=parser.parse_args();args.out.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='polaris-discard-') as tmp:
        tmp=Path(tmp);dev=tmp/'bsd/dev';dev.mkdir(parents=True)
        for source,target in [('polaris-ram-cow.h','polaris_ram_cow.h'),('polaris-ram-io.h','polaris_ram_io.h')]:
            (dev/target).write_bytes((ROOT/'tools'/source).read_bytes())
        subprocess.run(['git','apply','--include=bsd/dev/polaris_ram_cow.h',
                        '--include=bsd/dev/polaris_ram_io.h','--include=bsd/dev/polaris_ram_discard.h',str(PATCH)],cwd=tmp,check=True)
        for native,local in [('polaris_ram_cow.h','polaris-ram-cow.h'),('polaris_ram_io.h','polaris-ram-io.h'),('polaris_ram_discard.h','polaris-ram-discard.h')]:
            (tmp/local).write_bytes((dev/native).read_bytes())
        assert (tmp/'polaris-ram-discard.h').read_bytes()==(ROOT/'tools/polaris-ram-discard.h').read_bytes()
        for source in ['polaris-ram-discard-test.c','polaris-ram-transaction.h','polaris-cow-arena.h']:
            (tmp/source).write_bytes((ROOT/'tools'/source).read_bytes())
        command=['/usr/bin/clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',
                 '-I'+str(tmp),str(tmp/'polaris-ram-discard-test.c'),'-o',str(tmp/'test')]
        build=subprocess.run(command,capture_output=True,text=True)
        (args.out/'host-build.log').write_text(build.stdout+build.stderr)
        if build.returncode:raise RuntimeError('Host integration compile failed')
        run=subprocess.run([str(tmp/'test')],capture_output=True,text=True,timeout=30)
        (args.out/'host-run.log').write_text(run.stdout+run.stderr)
        (tmp/'arm.c').write_text('#include "polaris-ram-cow.h"\n'
            'bool run(struct polaris_cow*c,unsigned n,const struct polaris_ram_trim_extent*e)'
            '{return polaris_cow_discard(c,n,e);}\n')
        arm=subprocess.run(['/usr/bin/clang','-target','aarch64-none-elf','-ffreestanding','-std=c11','-O2',
            '-Wall','-Wextra','-Werror','-Wframe-larger-than=1024','-I'+str(tmp),'-c',str(tmp/'arm.c'),'-o',str(tmp/'arm.o')],capture_output=True,text=True)
        (args.out/'arm-build.log').write_text(arm.stdout+arm.stderr)
        passed=not run.returncode and not arm.returncode
        proof={'passed':passed,'scope':'Exact0909 patched headers +0907 preparation; software RAM allocator only; no storage/device interface',
               'host_compile_exit':build.returncode,'ASAN_UBSAN_run_exit':run.returncode,'output':run.stdout.strip(),
               'arm64_freestanding_exit':arm.returncode,'patch_sha256':hashlib.sha256(PATCH.read_bytes()).hexdigest(),
               'source_sha256':hashlib.sha256((ROOT/'tools/polaris-ram-discard-test.c').read_bytes()).hexdigest()}
        (args.out/'result.json').write_text(json.dumps(proof,indent=2)+'\n')
        print(json.dumps(proof))
        return 0 if passed else 1
if __name__=='__main__':raise SystemExit(main())
