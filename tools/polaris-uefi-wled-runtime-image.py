#!/usr/bin/env python3
"""Package only the independent native-WLED RO/RAMCOW RAM trial. No device access."""
import argparse,hashlib,importlib.util,json,re,struct,subprocess
from pathlib import Path
from polaris_wled_runtime_admission import admit,ORIGINAL_SHA,GPU_SHA,target_profile,original_gcd_policy
from polaris_wled_runtime_journal import journal,exit_footer,exit_receipt


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for n in ('original','driver-manifest','kernel','payload','kernel-profile','ci-proof','preflight','root-review','optical-proof','output'):
        ap.add_argument('--'+n,type=Path,required=True)
    ap.add_argument('--model',type=Path,action='append',required=True)
    ap.add_argument('--model-driver',type=Path,action='append',required=True)
    ap.add_argument('--build',choices=('20H392','20F66'),default='20H392')
    a=ap.parse_args();root=Path(__file__).resolve().parents[1];d=json.loads(a.driver_manifest.read_text());models=[json.loads(p.read_text()) for p in a.model]
    ci,pre,review=(json.loads(p.read_text()) for p in (a.ci_proof,a.preflight,a.root_review));admit(d,models,ci,pre,review,a.build)
    profile=target_profile(a.build)
    if a.output.exists():raise ValueError('exclusive new image output required')
    evidence={};historical={}
    def bind(p):
        p=p.resolve()
        if root not in p.parents or not p.is_file():raise ValueError('evidence outside project')
        evidence[str(p.relative_to(root))]=sha(p);return p
    def checked(mapping,commit=None):
        if not mapping:raise ValueError('empty evidence map')
        for name,digest in mapping.items():
            p=(root/name).resolve()
            if root not in p.parents:raise ValueError('evidence path escaped project')
            if p.is_file() and sha(p)==digest:bind(p);continue
            if commit:
                original=subprocess.run(['git','show',commit+':'+name],cwd=root,capture_output=True)
                if original.returncode==0 and hashlib.sha256(original.stdout).hexdigest()==digest:
                    historical[commit+':'+name]=digest;continue
            raise ValueError('changed evidence/source '+name)
    policy=original_gcd_policy(d)
    if policy and policy.get('power_scope_review'):
        checked(policy['power_scope_review'])
    checked(d['inputs']);app=a.driver_manifest.parent/d['artifact']
    if app.resolve().parent!=a.driver_manifest.parent.resolve() or sha(app)!=d['sha256']:
        raise ValueError('changed actual physical driver')
    if sha(a.kernel)!=d['kernel_sha256'] or sha(a.payload)!=d['payload_sha256'] or a.payload.stat().st_size!=d['payload_bytes']:
        raise ValueError('kernel/payload binding changed')
    if 'target_platform=polaris' not in a.kernel_profile.read_text() or 'commit='+profile['source'] not in a.kernel_profile.read_text():
        raise ValueError('wrong native profile')
    baseline=root/'research/polaris/uefi-ios-0106/phone-clock-vbl-0106-0001-payload.json';b=json.loads(baseline.read_text());bind(baseline)
    tokens=a.payload.read_bytes()[0x48:0x2a8].split(b'\0',1)[0]
    expected=' '.join('polariswled=1' if t=='polarisperf=1' else t for t in b['cmdline'].split()).encode()
    if tokens!=expected or len(tokens)!=602 or b['GPU_bundle_sha256']!=GPU_SHA:
        raise ValueError('only the reviewed equal-length diagnostic substitution is permitted')
    if a.build=='20F66':
        # Verify the actual embedded build, digest and new root mapping rather
        # than admitting a re-labelled20H392 payload or stale old182 extents.
        import sys
        sys.path.insert(0,str(root/'tools'))
        import adt,polaris_file_root
        raw=a.payload.read_bytes();at,size=struct.unpack_from('<QQ',raw,0x20)
        tree,consumed=adt.parse(raw[at:at+size])
        if consumed!=size:raise ValueError('new payload tree has trailing bytes')
        gpu=next(n for n in tree.children if n.name=='polaris-gpu-userland')
        disk=next(n for n in tree.children if n.name=='polaris-file-root')
        if gpu.prop('ios-build')!=b'20F66\0' or gpu.prop('sha256')!=bytes.fromhex(profile['GPU']):
            raise ValueError('actual new graphics build/digest missing')
        physical,bytes_=struct.unpack('<QQ',gpu.prop('reg'))
        virtual,=struct.unpack_from('<Q',raw,0x10);base,=struct.unpack_from('<Q',raw,0x38)
        count,=struct.unpack_from('<I',raw,12)
        spans=[struct.unpack_from('<4Q',raw,0x2a8+32*n) for n in range(count)]
        span=next(s for s in spans if s[0]-virtual+base==physical and s[3]==bytes_)
        if hashlib.sha256(raw[span[2]:span[2]+span[3]]).hexdigest()!=profile['GPU']:
            raise ValueError('embedded actual20F66 bundle bytes changed')
        folder=root/'research/polaris/uefi-ios-0124'
        abi=json.loads(bind(folder/'20F66-graphics-ABI-proof.json').read_text())
        if abi.get('passed') is not True or abi.get('build')!='20F66' or abi.get('EAGL_names_checked')!=457:
            raise ValueError('actual20F66 graphics correspondence absent')
        checked(abi['evidence_sha256'])
        for entry in abi['images'].values():checked({entry['path']:entry['sha256']})
        graphics_manifest=root/profile['graphics_manifest']
        gfx=json.loads(bind(graphics_manifest).read_text())
        if gfx.get('build')!='20F66' or gfx.get('bundle_sha256')!=profile['GPU']:
            raise ValueError('new graphics provenance mismatch')
        checked(gfx['source_inputs'])
        for entry in gfx['files']:
            if sha(bind(graphics_manifest.parent/entry['name']))!=entry['sha256']:
                raise ValueError('new actual graphics binary changed')
        wire=json.loads(bind(folder/'20F66-IOSurface-native-wire-correspondence.json').read_text())
        if wire.get('passed') is not True or wire.get('build')!='20F66':
            raise ValueError('actual20F66 native surface correspondence absent')
        checked(wire['evidence_sha256'])
        path=root/'research/polaris/uefi-ios-0124/new-20F66-file-root-manifest.json'
        mapping=polaris_file_root.validate(json.loads(bind(path).read_text()))
        if (mapping['image_sha256']!=profile['root'] or
            disk.prop('layout')!=struct.pack('<3Q',*mapping['layout']) or
            disk.prop('crc32')!=struct.pack('<3I',*mapping['crc32']) or
            disk.prop('extents')!=b''.join(struct.pack('<3Q',*e) for e in mapping['extents'])):
            raise ValueError('new immutable root map differs from actual payload')
    # The payload builder independently validated the actual rebased kernel and
    # own CPU tree. Bind the exact embedded bytes and source, not a claimed FPS.
    if len(a.model_driver)!=2:raise ValueError('two exact actual model executables required')
    for mp,mdp,m in zip(a.model,a.model_driver,models):
        bind(mp);bind(mdp);md=json.loads(mdp.read_text());model_app=mdp.parent/md['artifact'];bind(model_app)
        if (model_app.resolve().parent!=mdp.parent.resolve() or sha(mdp)!=m['driver_manifest_sha256'] or
            sha(model_app)!=m['driver_sha256'] or md['sha256']!=m['driver_sha256'] or
            md['inputs']!=d['inputs'] or md['kernel_sha256']!=d['kernel_sha256'] or
            md.get('QEMU_variant') is not True or md.get('WLED_native_runtime_test') is not True or
            md.get('WLED_native_runtime_physical') is not False or md.get('kernel_CPU_affinity')!=7 or
            md.get('kernel_CPU_count')!=4 or md.get('controlled_WLED_native_exit')!=m['controlled_exit'] or
            m['runner_sha256']!=sha(root/'tools/qemu-polaris-wled-runtime-exit.py')):
            raise ValueError('actual current-source native fixture executable mismatch')
        directory=mp.parent
        text=(directory/'serial.log').read_text(errors='replace')
        if {k:int(v,16) for k,v in re.findall(r'([A-Z_0-9]+)=0x([0-9a-f]{16})',text)}!=m['raw_fields']:
            raise ValueError('actual serial observations changed')
        for p in directory.iterdir():
            if p.is_file() and p.suffix in ('.bin','.json','.log','.txt'):bind(p)
        attempts=m['attempts'];previous=None
        native=(directory/'shutdown.bin').read_bytes();nc,ns,mode,phase,error,epoch,flushed,caps=struct.unpack_from('<QIIIIQQI',native,128)
        if not nc or (ns,mode,phase,error,epoch,flushed,caps)!=(1,2,3,0,0,0,0x80000003):raise ValueError('actual native drain absent')
        for at,record in enumerate(attempts):
            prefix=journal([(directory/f'prefix-{at}-{n}.bin').read_bytes() for n in range(3)])
            if previous and any(prefix[k]!=previous[k] for k in ('records','cookie','total','prefix_crc')):raise ValueError('missing failure-recovery prefix')
            footer=exit_footer((directory/f'footer-{at}.bin').read_bytes(),prefix,native_cookie=nc,native_sequence=ns,recover=bool(at))
            reply=(directory/f'reply-{at}.bin').read_bytes()
            if len(reply)!=64 or reply[:4]!=b'OKAY':raise ValueError('actual terminal reply missing')
            previous=exit_receipt(reply[4:],footer)
            if previous!=record['final']:raise ValueError('actual whole history changed')
    if sha(a.root_review)!=pre['root_review_sha256']:raise ValueError('fresh root review binding changed')
    checked(review['files'])
    optical=json.loads(a.optical_proof.read_text())
    if (optical.get('passed') is not True or optical.get('physical_darkness_proven') is not True or
        optical.get('human_feedback')!='有，真的关闭了2秒背光' or optical.get('writes_issued')!=4 or
        optical.get('writes_completed')!=4 or optical.get('actual_expected_FASTBOOT_verified') is not True):
        raise ValueError('completed original physical/optical WLED proof required')
    checked(optical['evidence'],'15bbd77')
    old=root/'research/polaris/uefi-ios-0119/actual-native-WLED-lifecycle-and-lease-continuation-proof.json';oldj=json.loads(old.read_text());bind(old)
    if oldj.get('passed') is not True or oldj.get('source_commit')!='8b7c62cabc213a3edfdc59867e10e8f348c086fa':raise ValueError('native fault/lifecycle foundation missing')
    checked(oldj['files'],'8b7c62c')
    if sha(a.original)!=ORIGINAL_SHA:raise ValueError('wrong original Mindows firmware')
    for p in (a.original,a.driver_manifest,app,a.kernel,a.payload,a.kernel_profile,a.ci_proof,a.preflight,a.root_review,a.optical_proof):bind(p)
    for name in ('polaris_wled_runtime_admission.py','polaris_wled_runtime_control.py','polaris_wled_runtime_journal.py','polaris-uefi-wled-runtime.py','polaris_uefi_usb_transport.py'):bind(root/'tools'/name)
    spec=importlib.util.spec_from_file_location('fw',root/'tools/polaris-uefi-firmware.py');fw=importlib.util.module_from_spec(spec);spec.loader.exec_module(fw)
    image,record=fw.package(a.original.read_bytes(),app.read_bytes())
    if record['original_inner_files']!=81 or record['unchanged_inner_files']!=81:raise ValueError('original81 FW preservation failed')
    a.output.mkdir();target=a.output/'polaris-original-uefi-wled-runtime.img';target.write_bytes(image)
    record.update(d);record.update(artifact=target.name,sha256=sha(target),bytes=len(image),scope='independent_native_WLED_RO_RAMCOW_runtime',
        userland_build=a.build,
        driver_sha256=sha(app),driver_manifest_sha256=sha(a.driver_manifest),installer=False,may_write_userdata=False,
        immutable_root_RAMCOW_only=True,physical_iOS_lockscreen_proven=False,atomic_exit_required=True,
        packager_sha256=sha(Path(__file__)),controller_sha256=sha(root/'tools/polaris-uefi-wled-runtime.py'),
        evidence_sha256=evidence,historical_source_sha256=historical)
    (a.output/'manifest.json').write_text(json.dumps(record,indent=2)+'\n')
    print('Independent native WLED RO/RAMCOW RAM image packaged; no device action')


if __name__=='__main__':main()
