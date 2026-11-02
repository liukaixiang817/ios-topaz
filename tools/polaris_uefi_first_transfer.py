#!/usr/bin/env python3
"""First image transfer for the unchanged, never-sent frozen0188 candidate.

A returned product timeout did not consume boot.json. The original launcher
and its HEAD-bound publication proof stay immutable. This current host
handoff independently requires the same complete frozen qualification, a
published current source closure, actual new connection facts, and ONE fresh
product query before the original shared record can be created. No refreeze,
firmware variant, payload command, partition write, reset, or replay exists.
"""
import argparse
import datetime
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
FROZEN=Path('/private/tmp/polaris-runtime-0188-frozen-0001')
CASE=ROOT/'research/polaris/uefi-ios-0188/phone-four-VRM-roundtrip-runtime-0001'
FREEZE='research/polaris/uefi-ios-0188/four-VRM-roundtrip-freeze-manifest-0001.json'
FREEZE_SHA='60ec95a1cb2440912c07ec68db3838aeb1bccd702ddb96938a4d674480e780e3'
IMAGE_SHA='0b656760be6b51b29da4232d686ae3c0c889ff7bc683c67bc30bd7deb68466af'
KERNEL_AUTH_SHA='df995cae2d0989f029a79808b284657dc8b9c33d6302dd5524b2d15bf3c0db12'
PUBLIC_AUTH_SHA='873635fcf90da43ff0a4fc102f9ee7d53526a29149e8b02ff68423825b1b9032'
PRIOR_PUBLIC_SHA='d5b7d82487a9ea704f9803acffe69260f4365c252f97c5321b6035a75841140e'
GUARD_PATH='tools/polaris_uefi_first_transfer.py'
TEST_PATH='tools/tests/test_polaris_uefi_first_transfer.py'
CURRENT_FREEZE_SHA='b7e610e6cf2088d332cc4f58264088bc01a34f1e6e56dc44c4cffa73e11ff4c0'
TIMEOUT_SHA='1ff8acf1e92727e41b7aecc798e7d91bfbb9a2dd904320bdb29d538ab9e4d6bd'
PRIOR_GATE_SHA='8db452df55c06a95c8c9579d840bfaacb23e8d0e3ba469b862ec60351305797e'


def load(p):return json.loads(p.read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def need(value,why):
    if not value:raise ValueError(why)


def bound_path(name):
    need(type(name) is str and not Path(name).is_absolute(),'relative evidence path required')
    value=ROOT/name
    need('..' not in Path(name).parts and value.resolve()==value and value.is_file(),'invalid evidence path')
    return value


def check_publication(p,*,head,source_sha,test_sha,facts_sha):
    """Pure current-publication check; no supplied boolean grants device I/O."""
    expected=dict(repository='liukaixiang817/ios-topaz',branch='codex/polaris-preflight',remote_HEAD=head,local_HEAD=head,
        firmware_source='270052fb02e9b2e1455d8cd064e01b642d3fa315',
        host_profile_source='15e830b76b761b4570d9505e64f751bd885855bc',
        candidate_image_SHA256=IMAGE_SHA,freeze_manifest_SHA256=FREEZE_SHA,
        human_publication_authorization_SHA256=PUBLIC_AUTH_SHA,
        original_preboot_publication_proof_SHA256=PRIOR_PUBLIC_SHA,
        current_first_transfer_guard_path=GUARD_PATH,
        current_first_transfer_guard_SHA256=source_sha,
        current_first_transfer_test_path=TEST_PATH,
        current_first_transfer_test_SHA256=test_sha,
        actual_new_connection_facts_SHA256=facts_sha)
    for key,value in expected.items():
        need(type(p.get(key)) is type(value) and p[key]==value,'current publication mismatch: '+key)
    for key in ('passed','independent_ls_remote_matched',
                'public_NEW0188_source_and_handoff_within_actual_future_like_approval'):
        need(p.get(key) is True,'current publication missing: '+key)


def check_facts(facts):
    need(facts.get('source')=='actual_user_replies_in_current_chat','human provenance required')
    need(facts.get('FASTBOOT_question_item')=='call_33df349d214043518ccc0abce9ea4ce5/0' and
         facts.get('FASTBOOT_answer')=='已到FASTBOOT','actual connection reply required')
    need(facts.get('OS_question_item')=='call_d5408edb02e94178b7a22f1101066427/0' and
         facts.get('OS_answer')=='没有，只检查连接或进入 FASTBOOT','actual no-other-OS reply required')


def committed(root,revision,names):
    need(all('\n' not in n for n in names),'invalid source path')
    p=subprocess.run(['git','cat-file','--batch'],cwd=root,
        input=('\n'.join(revision+':'+n for n in names)+'\n').encode(),capture_output=True)
    need(p.returncode==0,'source lookup failed');stream=io.BytesIO(p.stdout);result={}
    for name in names:
        header=stream.readline().split();need(len(header)==3 and header[1]==b'blob','missing committed source: '+name)
        count=int(header[2]);data=stream.read(count)
        need(len(data)==count and stream.read(1)==b'\n','partial committed source')
        result[name]=hashlib.sha256(data).hexdigest()
    need(not stream.read(1),'unexpected committed source tail');return result


def current(h):
    """Original frozen qualification plus current immutable host evidence."""
    need(sys.flags.optimize==0,'original asserted admission requires normal Python')
    need(not os.path.lexists(CASE/'boot.json'),'original shared record already consumed')
    need(sha(FROZEN/FREEZE)==FREEZE_SHA==sha(ROOT/FREEZE),'original freeze changed')
    facts_path=bound_path(h['actual_new_connection_facts_path']);facts_sha=sha(facts_path)
    need(facts_sha==h['actual_new_connection_facts_SHA256'],'connection facts changed');check_facts(load(facts_path))
    head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    own_sha=sha(Path(__file__));test_sha=sha(bound_path(TEST_PATH))
    pub_path=bound_path(h['current_publication_proof_path']);p=load(pub_path)
    check_publication(p,head=head,source_sha=own_sha,test_sha=test_sha,facts_sha=facts_sha)
    need(sha(pub_path)==h['current_publication_proof_SHA256'],'publication file changed')
    need(committed(ROOT,'HEAD',[GUARD_PATH,TEST_PATH])=={GUARD_PATH:own_sha,TEST_PATH:test_sha},'current host sources are not committed')
    pinned=bound_path('research/polaris/uefi-ios-0188/current-runtime-source-freeze-0001.json')
    need(sha(pinned)==CURRENT_FREEZE_SHA,'original current freeze changed')
    timeout=CASE/'actual-preboot-product.json';timeout_copy=CASE/'actual-preboot-product-timeout-0001.json'
    gate=bound_path('research/polaris/uefi-ios-0188/wifi/physical-preboot-product-timeout-no-image-sent-proof-0001.json')
    need(sha(timeout)==sha(timeout_copy)==TIMEOUT_SHA and sha(gate)==PRIOR_GATE_SHA,'original no-image observation changed')
    # Import only the existing immutable qualified helper. freeze() performs
    # its original complete source/model/codec/root/authorization checks; its
    # old main/publication/product/boot path is never called or changed.
    sys.dont_write_bytecode=True
    helper=FROZEN/'research/polaris/uefi-ios-0188/boot-four-VRM-roundtrip-once-0001.py'
    f=load(FROZEN/FREEZE);need(sha(helper)==f['files'][str(helper.relative_to(FROZEN))],'original helper changed')
    spec=importlib.util.spec_from_file_location('original_frozen_first_image',helper)
    original=importlib.util.module_from_spec(spec);spec.loader.exec_module(original)
    f,image,ip,dp,i,review=original.freeze()
    need(sha(image)==IMAGE_SHA,'original image changed')
    need(sha(ROOT/'research/polaris/uefi-ios-0188/wifi/four-VRM-source-and-physical-handoff-push-proof-0001.json')==PRIOR_PUBLIC_SHA,'original publication overwritten')
    need(sha(ROOT/f['kernel_reuse_authorization_path'])==KERNEL_AUTH_SHA and
         sha(ROOT/f['publication_authorization_path'])==PUBLIC_AUTH_SHA,'standing authorization changed')
    pub=load(ROOT/f['publication_authorization_path'])
    need(pub.get('repository')=='liukaixiang817/ios-topaz' and
         pub.get('actual_human_answer')=='批准0180及后续同类公开推送' and
         pub.get('future_same_project_same_repository_source_and_text_handoffs_approved') is True,'standing publication scope changed')
    for revision in (f['firmware_source'],f['exact_host_profile_source']):
        need(subprocess.run(['git','merge-base','--is-ancestor',revision,head],cwd=ROOT).returncode==0,'source ancestry changed')
    values=committed(ROOT,'HEAD',list(f['active_sources']))
    for name,value in f['active_sources'].items():
        need(values[name]==value==sha(ROOT/name),'current original source changed: '+name)
    for name,value in review['evidence_sha256'].items():need(sha(ROOT/name)==value,'current integrity evidence changed: '+name)
    bindings={path:sha(path) for path in (facts_path,pub_path,Path(__file__),bound_path(TEST_PATH),
        pinned,timeout,timeout_copy,gate,ROOT/FREEZE,FROZEN/FREEZE,ip,dp)}
    return head,original,f,image,ip,dp,i,bindings


def first_transfer(handoff):
    handoff=bound_path(str(handoff.relative_to(ROOT)))
    handoff_sha=sha(handoff);h=load(handoff)
    head,original,f,image,ip,dp,i,bindings=current(h)
    # Immutable result directory, separate from the original timed-out query.
    attempt=CASE/'preboot-connection-return-0001';attempt.mkdir(mode=0o700,exist_ok=False)
    match=re.search(r'androidboot.serialno=(\S+)',(ROOT/'backup/polaris-20261023-193109/cmdline.txt').read_text())
    need(match is not None,'missing private expected device identity');serial=match.group(1)
    fb=[str(ROOT/'research/host-tools/platform-tools/fastboot'),'-s',serial]
    product=dict(utc=now(),readonly=True,expected_product='polaris',bound_seconds=8)
    try:
        p=subprocess.run(fb+['getvar','product'],capture_output=True,text=True,timeout=8)
        value=(p.stdout+p.stderr).replace(serial,'<redacted>')
        product.update(exit_code=p.returncode,output=value,expected_present=original.expected_polaris_fastboot(p.returncode,value))
    except subprocess.TimeoutExpired:product.update(expected_present=False,error='expected-product timeout')
    (attempt/'actual-product.json').write_text(json.dumps(product,indent=2)+'\n')
    if not product['expected_present']:print('No verified Polaris FASTBOOT; no image sent');raise SystemExit(2)
    # No second product query. No background worker. Recheck current host
    # binding and the exact image before atomically consuming boot.json.
    need(subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()==head,'HEAD changed during product query')
    need(sha(handoff)==handoff_sha,'handoff changed')
    for path,value in bindings.items():need(sha(path)==value,'evidence changed during product query')
    need(sha(image)==IMAGE_SHA,'image changed during product query')
    record=dict(state='sending_unique_native_WLED_runtime_RAM_boot',sent_utc=now(),source_commit=head,
        explicit_same_SHA_future_NEW_session_authorization_SHA256=KERNEL_AUTH_SHA,
        explicit_publication_authorization_SHA256=PUBLIC_AUTH_SHA,native_source=f['native_source'],native_CI=f['native_CI'],
        image_sha256=i['sha256'],image_manifest_sha256=sha(ip),driver_manifest_sha256=sha(dp),
        first_transfer_after_actual_connection_reply=True,current_host_handoff_SHA256=handoff_sha,
        phone_partition_writes=False,NVRAM_writes=False,immutable_root_RAMCOW_only=True)
    with (CASE/'boot.json').open('x') as out:
        os.chmod(CASE/'boot.json',0o600)
        out.write(json.dumps(record,indent=2)+'\n');out.flush();os.fsync(out.fileno())
    def save():record['updated_utc']=now();(CASE/'boot.json').write_text(json.dumps(record,indent=2)+'\n')
    try:
        p=subprocess.run(fb+['boot',str(image)],capture_output=True,text=True,timeout=120)
        value=(p.stdout+p.stderr).replace(serial,'<redacted>');(attempt/'image-transfer-sanitized.log').write_text(value)
        need(p.returncode==0 and 'OKAY' in value,'image ACK unknown/refused; no replay')
        record['state']='temporary_native_WLED_runtime_RAM_boot_succeeded';save()
        print('ONE0188 FIRST four-VRM RAM image sent; native payload not yet requested')
    except Exception as error:
        record.update(state='stopped_for_review',error=type(error).__name__+': '+str(error).replace(serial,'<redacted>'));save()
        raise RuntimeError(record['error']) from None


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--handoff',type=Path,required=True)
    ap.add_argument('--boot-once',action='store_true',required=True);args=ap.parse_args()
    first_transfer(args.handoff.absolute())

if __name__=='__main__':main()
