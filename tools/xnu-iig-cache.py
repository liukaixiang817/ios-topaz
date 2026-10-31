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
EXTRA_PRIVATE_HEADER_SHA={
    # Exact private battery/calendar and Wi-Fi implementation headers.
    'bsd/dev/polaris-glink-inventory.h':
    '707c9515d7b51af9c8690eebcd8f07f2e5d80905f329eebda4e975946818fa15',
    'bsd/dev/polaris-smem-inventory.h':
    '162530742a13c965d0e16091ae5fa8386ea353b41e06969350a95dc22cb96f94',
    'bsd/dev/polaris-wifi-cap.h':
    'b477bc967cdb422f2ffb059ff9e0240b84ac74b7abbc3e79769adde6dc118b56',
    'bsd/dev/polaris-wifi-glink.h':
    '5855169795bfd51db520126cd70404f761bc183d612e317c3f526e950e116cfe',
    'bsd/dev/polaris-wifi-native-policy.h':
    '5f0af976649a8bfb88e5d1c01d59e149f943a34110e77c959f750c9f6a08c812',
    'bsd/dev/polaris-wifi-smem-probe.h':
    '7d06018efcaf61a48773608232372d7ef7c7714765da4dbc9e033fed8c370495',
    'bsd/dev/polaris-wlfw.h':
    '671333fc2ebbe3ba25f959709aec07dcf13d82551abdfa85fdeea89c0b6754f2',
    'bsd/dev/polaris_clock.h':
    'fc34ea97a6cdf5d1a1850257147db6a13fac79463d78ad3fd9761e20231de16c',
    'bsd/dev/polaris_clock_wire.h':
    'f82b864530564ec92d45390590dc34c8c15c53cd3afc833021117f5c29f95e1d',
    'iokit/Kernel/arm/polaris-battery-shared.h':
    'e11a3ff135c92a13c2b8f2dab908c8a70c25e9f595228ac49efd49f960f88ce0',
    'bsd/dev/polaris_ram_discard.h':
    '9065973132524411f2c4046c0ff4d2952a7d1441949c4ed4dcdf4732a9987fa9',
    # RAM-only root write preflight, included only by sweet_ufs.c.
    'bsd/dev/polaris_ram_transaction.h':
    'e6345921bdcbd61e63d887303c50d94b9af77c8b71135d920fdf433b3948575b',
    # Media-only implementation includes, outside DriverKit/IDL include graph.
    'bsd/dev/polaris-media-status.h':
    '36546b9a6bc92a3efc0af9f22aace2235fe5da1a6bac93d1868247744155f71d',
    'bsd/dev/polaris-media-admission.h':
    'abf19217aa86034767c0988540a901ff78bde0158f3796d76e2baa464bb5d613',
    'bsd/dev/polaris_uefi_buttons.h':
    '06bab9e8a1de3057de220d952da56ccb20c5c35e9db130e00308868ccd71fe8d',
    # Native WLED wire/adapter are private SweetFramebuffer.cpp-only includes;
    # no IDL/interface type or generator option changes. Exact reviewed bytes.
    'iokit/Kernel/arm/polaris_wled_mailbox.h':
    'de8b2fbc39e6ec406e7786ca4741ae76f76ecae01f311017ad127e2629715215',
    'iokit/Kernel/arm/polaris_wled_native.h':
    '929933fec9083e88698f445ff22e8a2f2afef57b16c27d370546e40327af9bc7',
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
    # Private volatile-root implementation; no DriverKit interface includes.
    'bsd/dev/polaris_ram_cow.h':(
        '869ffecdda69188c2faee2fd9a3e8d4a7c422bc8161a3eda76463811cd87929c',
        '5eecfdf7d7bfd5f607269f30d5c09827530082822a6b61c01fa7dcb3b784e4a3'),
    'bsd/dev/polaris_ram_io.h':(
        '1c4275456fc473533307e5108019bcf8b8d298b4758b8733fd68bb3c97302b48',
        '62d398e32e3ca2ba4e2834378f5d5a0db1d50e97fc32336f855acf836fa4abad'),
    # Private HFS journal bookkeeping appends its first asynchronous error.
    # It is outside the DriverKit interface graph; retain exact input binding.
    'bsd/sweet_hfs/core/hfs_journal.h':(
        '1de7e23acb743775d99970ce83ddad68d2f56200ab52f5dfd7aafa8038b4aa40',
        'ea32f0b153ebbda79e0245ab460dade52b8d3660330c6e5d322a2c6bd8905f56'),
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
