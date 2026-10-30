#!/usr/bin/env python3
"""Reuse verified DriverKit-286 generated sources with modern Xcode hosts.

XNU8796's IORPC layout predates current iig's kernelContent ABI. Replaying
the previous successful build's identical interface sources preserves that
layout; it never modifies the kernel ABI or postprocesses new generator code.
Every original source header/IDL is checked, and changed interfaces fail.
The cache is private build data, never committed to the source repository.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys
import tarfile

BASELINE_RUN=40210874806
TARBALL_SHA='a8cfdb9aa97043e887233ac072f3676790a484b34786a4462eac467db89a5d1e'
# Set from the deterministic manifest of the pinned successful source archive.
MANIFEST_SHA='d04b50c8a13850c71d1679c2d180582b8f294b116da1a7534ce2c0c74adc7d65'
EXTRA_PRIVATE_HEADERS={'iokit/Kernel/arm/polaris_uefi_cpu.h','bsd/dev/polaris_uefi_input.h'}
# Private shutdown, GPU policy and display-queue implementation headers are
# outside DriverKit's interface include graph. Bind their reviewed bytes; adding them
# must not weaken the original IDL/header checks or admit arbitrary headers.
EXTRA_PRIVATE_HEADER_SHA={'bsd/dev/polaris_uefi_buttons.h':
    '06bab9e8a1de3057de220d952da56ccb20c5c35e9db130e00308868ccd71fe8d',
    # Native WLED wire/adapter are private SweetFramebuffer.cpp-only includes;
    # no IDL/interface type or generator option changes. Exact reviewed bytes.
    'iokit/Kernel/arm/polaris_wled_mailbox.h':
    '6353b5848b8adb84b5ce76a18ee0c26365c6740bca6d38c5f6f8a065a4a9a472',
    'iokit/Kernel/arm/polaris_wled_native.h':
    '68c0d10ee06240b835f0325232b968fab90a883ddd80a1201a520be2ac67bc42',
    'iokit/Kernel/arm/polaris_display_queue.h':
    '8f58213606c7dad756a492ec8858170b5aecded769f5f730dc34c3d344043a39',
    'bsd/dev/polaris_a630_performance.h':
    'c38f2397d7d5d179d8701707104d0b6af411d76aecd8325401d3fc6742c75d6a',
    'bsd/dev/polaris_runtime_quiesce.h':
    '184aa7ad4d296c407e061082fa1f83d46278489e0252ed142136c3718d778757'}
# These existing headers are implementation includes of polaris_a630.c
# only; no header/IDL includes them. Profiles0876/0877 change internal timing
# and page attributes;0886 adds saved timings;0887 adds fixed read-only clock
# observations under the existing successful-submission lock;0888 adds the
# default-OFF original HFI request experiment under that same lock. These are not
# IIG types/interfaces. Profiles0894/0896 embed the bounded thermal planner and explicit duration here,
# still included ONLY by polaris_a630.c. Bind original and replacement
# bytes. Every other original header and all 17 IDLs still require identity.
PRIVATE_IMPLEMENTATION_REPLACEMENTS={
    'bsd/dev/polaris_a630_runtime.h':(
        'ac96ec731d4a49a5a1de5edf734f3382a971e881d1d5878167d55701d94b36aa',
        '8113b553ebbbccfdd6d89f87d6214e41d91950da336d93e86bb83cac0089fbd8'),
    'bsd/dev/polaris_a630_mmu.h':(
        '427145f067d7ddff349eff15f0bfca95566b802fbcfd249cfa9ec118f520b3b3',
        'a1513183cfe4647f3f31a59754b85bb7bbb2e9362e38f6451b8bb4405407c388'),
    'bsd/dev/polaris_a630_submit.h':(
        'c91f3ff1adafe9e13370a30305b2bdd7e44b4f0f5fd3ceffab77d4d800b8f835',
        'f8219e19f05246531b49a8bfdfa42c4eff2e58d46b71f21c9a035608f0951151')}
# Stage scripts0019/0026 copy these host SDK files into private pthread/HFS
# scratch directories. Neither directory is on the IIG include search path;
# these two host-dependent copies do not define the DriverKit interfaces.
HOST_SDK_COPIES={'bsd/pthread/sweet_libpthread/TargetConditionals.h','bsd/sweet_hfs/TargetConditionals.h'}


def digest(b):return hashlib.sha256(b).hexdigest()
def sha(p):return digest(p.read_bytes())
def header_matches(name,want,path):
    got=sha(path)
    return got==want or PRIVATE_IMPLEMENTATION_REPLACEMENTS.get(name)==(want,got)
def safe(name):
    p=PurePosixPath(name)
    if p.is_absolute() or '..' in p.parts:raise ValueError('unsafe cache member')
    return p


def prepare(archive,out):
    if sha(archive)!=TARBALL_SHA:raise ValueError('wrong baseline buildtree archive')
    out.mkdir(parents=True,exist_ok=False);inputs={};outputs={}
    with tarfile.open(archive) as tar:
        members={m.name:m for m in tar if m.isfile()}
        for name,m in members.items():
            if name.startswith('xnu/') and name.endswith(('.h','.iig')):
                relative=name[4:];safe(relative);inputs[relative]=digest(tar.extractfile(m).read())
        defs=sorted(n for n in inputs if n.endswith('.iig'))
        if len(defs)!=17 or any(not n.startswith('iokit/DriverKit/') for n in defs):raise ValueError('unexpected baseline IDL set')
        for name in defs:
            stem=Path(name).stem
            for suffix in ['.h','.iig.cpp']:
                path='build/xnu.obj/DEVELOPMENT_ARM64_SWEET/iokit/DriverKit/'+stem+suffix
                raw=tar.extractfile(members[path]).read()
                if b'iig(DriverKit-286' not in raw or b'kernelContent' in raw:raise ValueError('wrong generated interface ABI')
                target=stem+suffix;(out/target).write_bytes(raw);outputs[target]=digest(raw)
    record=dict(format=1,baseline_run=BASELINE_RUN,baseline_archive_sha256=TARBALL_SHA,
                generator='DriverKit-286',source_inputs=inputs,outputs=outputs)
    raw=(json.dumps(record,sort_keys=True,indent=2)+'\n').encode();(out/'manifest.json').write_bytes(raw)
    print('Prepared verified legacy interface cache:',digest(raw))


def verify_cache(cache):
    raw=(cache/'manifest.json').read_bytes()
    if digest(raw)!=MANIFEST_SHA:raise ValueError('unbound or modified interface cache manifest')
    manifest=json.loads(raw)
    if manifest['baseline_archive_sha256']!=TARBALL_SHA:raise ValueError('baseline mismatch')
    for name,want in manifest['outputs'].items():
        safe(name)
        if sha(cache/name)!=want:raise ValueError('generated file cache corruption')
    return manifest


def replay(cache,args):
    manifest=verify_cache(cache)
    options={};at=0
    while at<len(args) and args[at]!='--':
        if args[at] not in ['--def','--header','--impl','--framework-name'] or at+1>=len(args):raise ValueError('unsupported iig options')
        if args[at] in options:raise ValueError('duplicate iig option')
        options[args[at]]=args[at+1];at+=2
    if at==len(args) or set(options)!={'--def','--header','--impl','--framework-name'} or options['--framework-name']!='DriverKit':raise ValueError('unsupported interface generator invocation')
    flags=args[at+1:]
    for flag in ['-D__IIG=1','-DDRIVERKIT_PRIVATE=1','-DPRIVATE_WIFI_ONLY=1','-DXNU_PLATFORM_MacOSX']:
        if flags.count(flag)!=1:raise ValueError('interface preprocessing mode changed')
    if any(f.startswith('-D') and f not in ['-D__IIG=1','-DDRIVERKIT_PRIVATE=1','-DPRIVATE_WIFI_ONLY=1','-DXNU_PLATFORM_MacOSX'] for f in flags):raise ValueError('new interface preprocessor definition')
    source=Path(options['--def']).resolve(strict=True)
    if source.parent.name!='DriverKit' or source.parent.parent.name!='iokit':raise ValueError('unknown source definition directory')
    root=source.parents[2]
    present={str(p.relative_to(root)):p for p in root.rglob('*') if p.is_file() and p.suffix in ['.h','.iig']}
    expected=manifest['source_inputs']
    if set(present)-set(expected)-EXTRA_PRIVATE_HEADERS-set(EXTRA_PRIVATE_HEADER_SHA):
        raise ValueError('unreviewed added source headers/IDL')
    for name,want in EXTRA_PRIVATE_HEADER_SHA.items():
        if name in present and sha(present[name])!=want:
            raise ValueError('reviewed private header changed: '+name)
    changed=[name for name,want in expected.items() if name not in HOST_SDK_COPIES and
             (name not in present or not header_matches(name,want,present[name]))]
    if changed:raise ValueError('source header/IDL changed: '+', '.join(changed))
    relative=str(source.relative_to(root))
    if relative not in expected or not relative.endswith('.iig'):raise ValueError('definition absent from baseline')
    for option,suffix in [('--header','.h'),('--impl','.iig.cpp')]:
        target=Path(options[option]);name=source.stem+suffix
        if target.name!=name or name not in manifest['outputs']:raise ValueError('unexpected generated output path')
        target.write_bytes((cache/name).read_bytes())
    print('IIG286 verified source replay:',source.name)


def main():
    if len(sys.argv)>=2 and sys.argv[1]=='replay':
        if len(sys.argv)<4:raise ValueError('replay requires cache and original iig arguments')
        replay(Path(sys.argv[2]).resolve(strict=True),sys.argv[3:]);return
    ap=argparse.ArgumentParser(description=__doc__);sub=ap.add_subparsers(dest='mode',required=True)
    p=sub.add_parser('prepare');p.add_argument('--archive',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p=sub.add_parser('verify');p.add_argument('--cache',type=Path,required=True)
    a=ap.parse_args()
    if a.mode=='prepare':prepare(a.archive,a.output)
    else:verify_cache(a.cache);print('Verified pinned interface cache')


if __name__=='__main__':main()
