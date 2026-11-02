"""Host-only first-transfer gates; simulated subprocesses never contact USB."""
import contextlib
import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import polaris_uefi_first_transfer as guard


class Evidence(unittest.TestCase):
    def facts(self):
        return dict(source='actual_user_replies_in_current_chat',
            FASTBOOT_question_item='call_33df349d214043518ccc0abce9ea4ce5/0',FASTBOOT_answer='已到FASTBOOT',
            OS_question_item='call_d5408edb02e94178b7a22f1101066427/0',OS_answer='没有，只检查连接或进入 FASTBOOT')

    def publication(self):
        return dict(repository='liukaixiang817/ios-topaz',branch='codex/polaris-preflight',remote_HEAD='current',local_HEAD='current',
            firmware_source='270052fb02e9b2e1455d8cd064e01b642d3fa315',host_profile_source='15e830b76b761b4570d9505e64f751bd885855bc',
            candidate_image_SHA256=guard.IMAGE_SHA,freeze_manifest_SHA256=guard.FREEZE_SHA,
            human_publication_authorization_SHA256=guard.PUBLIC_AUTH_SHA,original_preboot_publication_proof_SHA256=guard.PRIOR_PUBLIC_SHA,
            current_first_transfer_guard_path=guard.GUARD_PATH,current_first_transfer_guard_SHA256='guard',
            current_first_transfer_test_path=guard.TEST_PATH,current_first_transfer_test_SHA256='test',actual_new_connection_facts_SHA256='facts',
            passed=True,independent_ls_remote_matched=True,public_NEW0188_source_and_handoff_within_actual_future_like_approval=True)

    def test_new_facts_do_not_accept_missing_or_other_OS_history(self):
        guard.check_facts(self.facts())
        for key in self.facts():
            for value in (None,True,'entered Android'):
                with self.subTest(key=key,value=value),self.assertRaises(ValueError):
                    facts=self.facts();facts[key]=value;guard.check_facts(facts)

    def test_publication_requires_current_HEAD_scope_sources_and_exact_types(self):
        valid=self.publication()
        def check(p):guard.check_publication(p,head='current',source_sha='guard',test_sha='test',facts_sha='facts')
        check(valid)
        for key in valid:
            for value in (None,False,1,'stale'):
                with self.subTest(key=key,value=value),self.assertRaises(ValueError):
                    p=copy.deepcopy(valid);p[key]=value;check(p)

    def test_evidence_paths_cannot_escape_or_follow_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();(root/'valid').write_text('ok');(root/'link').symlink_to(root/'valid')
            with patch.object(guard,'ROOT',root):
                self.assertEqual(guard.bound_path('valid'),root/'valid')
                for name in ('../valid',str(root/'valid'),'link','missing'):
                    with self.subTest(name=name),self.assertRaises(ValueError):guard.bound_path(name)

    def test_existing_original_record_refuses_before_any_subprocess(self):
        with tempfile.TemporaryDirectory() as tmp:
            case=Path(tmp);(case/'boot.json').write_text('{}')
            with patch.object(guard,'CASE',case),patch.object(guard.subprocess,'run') as run:
                with self.assertRaisesRegex(ValueError,'consumed'):guard.current({})
                run.assert_not_called()


class Transfer(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve();self.case=self.root/'case';self.case.mkdir()
        self.handoff=self.root/'handoff.json';self.handoff.write_text('{}')
        self.image=self.root/'image';self.image.write_bytes(b'unchanged simulated image')
        self.ip=self.root/'image.json';self.ip.write_text('{}');self.dp=self.root/'driver.json';self.dp.write_text('{}')
        private=self.root/'backup/polaris-20261023-193109';private.mkdir(parents=True)
        (private/'cmdline.txt').write_text('androidboot.serialno=test-private-identity')
        self.calls=[]
        original=SimpleNamespace(expected_polaris_fastboot=lambda code,output:code==0 and output=='product: polaris\nOKAY\n')
        self.qualified=('current',original,dict(native_source='same-native',native_CI='same-CI'),self.image,self.ip,self.dp,
                        dict(sha256=guard.sha(self.image)),{self.ip:guard.sha(self.ip)})
        for name,value in (('ROOT',self.root),('CASE',self.case),('IMAGE_SHA',guard.sha(self.image))):
            p=patch.object(guard,name,value);p.start();self.addCleanup(p.stop)
        p=patch.object(guard,'current',return_value=self.qualified);p.start();self.addCleanup(p.stop)
        p=patch.object(guard.subprocess,'check_output',return_value='current\n');p.start();self.addCleanup(p.stop)

    def run_transfer(self,product=None,boot=None,mutate=None):
        def run(command,**kw):
            self.calls.append((command,kw))
            if command[-2:]==['getvar','product']:
                if mutate:mutate()
                if isinstance(product,Exception):raise product
                return product or SimpleNamespace(returncode=0,stdout='product: polaris\nOKAY\n',stderr='')
            self.assertEqual(command[-2], 'boot')
            self.assertTrue((self.case/'boot.json').is_file(),'record must exist before FIRST image')
            if isinstance(boot,Exception):raise boot
            return boot or SimpleNamespace(returncode=0,stdout='OKAY\n',stderr='')
        with patch.object(guard.subprocess,'run',side_effect=run),contextlib.redirect_stdout(io.StringIO()):
            guard.first_transfer(self.handoff)

    def test_product_timeout_creates_no_boot_record_and_cannot_auto_repeat(self):
        with self.assertRaises(SystemExit):self.run_transfer(product=subprocess.TimeoutExpired('private',8))
        self.assertFalse((self.case/'boot.json').exists());self.assertEqual(len(self.calls),1)
        with self.assertRaises(FileExistsError):self.run_transfer()
        self.assertEqual(len(self.calls),1)

    def test_wrong_product_or_nonzero_status_cannot_send_image(self):
        for product in (SimpleNamespace(returncode=0,stdout='product: other\nOKAY\n',stderr=''),
                        SimpleNamespace(returncode=1,stdout='product: polaris\nOKAY\n',stderr='')):
            with self.subTest(product=product),self.assertRaises(SystemExit):self.run_transfer(product=product)
            self.assertFalse((self.case/'boot.json').exists())
            attempt=self.case/'preboot-connection-return-0001'
            (attempt/'actual-product.json').unlink();attempt.rmdir() # isolated simulated case only
        self.assertEqual(len(self.calls),2)

    def test_tampered_evidence_after_product_prevents_first_image(self):
        with self.assertRaisesRegex(ValueError,'evidence changed'):
            self.run_transfer(mutate=lambda:self.ip.write_text('changed'))
        self.assertFalse((self.case/'boot.json').exists());self.assertEqual(len(self.calls),1)

    def test_handoff_change_after_product_prevents_first_image(self):
        with self.assertRaisesRegex(ValueError,'handoff changed'):
            self.run_transfer(mutate=lambda:self.handoff.write_text('{"changed":true}'))
        self.assertFalse((self.case/'boot.json').exists());self.assertEqual(len(self.calls),1)

    def test_one_product_then_atomic_record_then_one_image(self):
        self.run_transfer();self.assertEqual(len(self.calls),2)
        self.assertEqual([call[1]['timeout'] for call in self.calls],[8,120])
        record=json.loads((self.case/'boot.json').read_text())
        self.assertEqual(record['state'],'temporary_native_WLED_runtime_RAM_boot_succeeded')
        self.assertEqual((self.case/'boot.json').stat().st_mode&0o777,0o600)
        self.assertFalse(record['phone_partition_writes']);self.assertFalse(record['NVRAM_writes'])
        self.assertFalse(any('test-private-identity' in p.read_text() for p in self.case.rglob('*') if p.is_file()))

    def test_image_timeout_is_consumed_and_private_exception_is_sanitized(self):
        with self.assertRaises(RuntimeError) as error:
            self.run_transfer(boot=subprocess.TimeoutExpired('test-private-identity',120))
        self.assertNotIn('test-private-identity',str(error.exception))
        self.assertEqual(json.loads((self.case/'boot.json').read_text())['state'],'stopped_for_review')
        self.assertEqual(len(self.calls),2)
        with self.assertRaises(FileExistsError):self.run_transfer()
        self.assertEqual(len(self.calls),2)


if __name__=='__main__':unittest.main()
