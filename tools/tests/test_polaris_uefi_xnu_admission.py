"""A prototype panic or unrelated successful CI must never admit a phone trial."""
import importlib.util
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('packer',ROOT/'tools/polaris-uefi-xnu-image.py')
packer=importlib.util.module_from_spec(spec);spec.loader.exec_module(packer)


class XnuAdmissionTests(unittest.TestCase):
    def fixtures(self):
        driver=dict(RAM_only_XNU_loader=True,QEMU_variant=False,ready_to_boot_driver=True,bounded_input=True,
                    kernel_CPU_affinity=256,storage_write_api=False,NVRAM_write_api=False,
                    kernel_sha256='a'*64,inputs={'one.c':'b'*64})
        qemu=dict(passed=True,release_handoff_admitted=True,diagnostic_legacy_only=False,
                  checks={'PSCI_success':True,'four_process_VM_stress':True,'bounded_input_handshake':True},
                  kernel_sha256='a'*64,inputs=driver['inputs'])
        ci=dict(status='completed',conclusion='success',headSha='c'*40,databaseId=123)
        profile='target_platform=polaris\nmachine_config=SWEET\ncommit='+('c'*40)+'\n'
        pre=dict(state='fresh_root_readonly_preflight_passed',phone_partition_writes=False,
                 journal_replayed=False,metadata_repaired=False,observed_root_sha256='d'*64,
                 full_image_sha256='d'*64,extent_count=182)
        for k in ['all_six_GPT_copies_match_original','fresh_maps_before_after_match','unmounted',
                  'block_readonly','outer_header_unchanged_during_readonly_check','outer_header_independently_reviewed']:pre[k]=True
        return driver,qemu,ci,profile,pre

    def test_matching_full_proofs_admitted(self):packer.admit(*self.fixtures())

    def test_prototype_stale_source_queued_CI_and_root_change_refused(self):
        changes=[(1,'diagnostic_legacy_only',True),(1,'release_handoff_admitted',False),
                 (1,'kernel_sha256','e'*64),(1,'checks',{}),(1,'inputs',{}),
                 (2,'status','queued'),(2,'headSha','e'*40),
                 (4,'phone_partition_writes',True),(4,'fresh_maps_before_after_match',False),
                 (4,'observed_root_sha256','e'*64),(0,'QEMU_variant',True),(0,'storage_write_api',True)]
        for index,key,value in changes:
            with self.subTest(key=key):
                fixtures=list(self.fixtures());fixtures[index][key]=value
                with self.assertRaises(ValueError):packer.admit(*fixtures)

    def test_chain_requires_actual_selected_application_execution(self):
        f=list(self.fixtures());f[0].update(chain_app={'sha256':'e'*64},disk_payload_read_only=True)
        f[1]['disk_fixture']={'regular_file_only':True}
        needed=['unique_GPT_filesystem','disk_payload_exact_read','disk_files_closed_before_kernel',
                'disk_read_success','selected_disk_app_started','chain_file_handles_closed',
                'chain_loaded_success','selected_app_did_not_return']
        f[1]['checks'].update({k:True for k in needed});packer.admit(*f)
        for key in needed:
            with self.subTest(key=key):
                f[1]['checks'][key]=False
                with self.assertRaises(ValueError):packer.admit(*f)
                f[1]['checks'][key]=True


if __name__=='__main__':unittest.main()
