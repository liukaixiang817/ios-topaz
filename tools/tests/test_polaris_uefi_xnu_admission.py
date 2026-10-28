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

    def test_virtual_UFS_proof_never_admits_phone_even_if_other_fields_look_valid(self):
        for field in ('isolated_QEMU_readonly_UFS_test','isolated_QEMU_owned_UFS_test','physical_owned_marker_test'):
            for index in (0, 1):
                fixtures=list(self.fixtures())
                fixtures[index][field]=True
                with self.subTest(field=field,index=index),self.assertRaises(ValueError):packer.admit(*fixtures)

    def test_big_core_requires_actual_matching_generic_core_execution(self):
        f=list(self.fixtures());f[0]['kernel_CPU_affinity']=1792
        with self.assertRaises(ValueError):packer.admit(*f)
        f[1]['kernel_CPU_affinity']=1
        with self.assertRaises(ValueError):packer.admit(*f)
        f[1]['kernel_CPU_affinity']=7;packer.admit(*f)
        f[0]['kernel_CPU_affinity']=0
        with self.assertRaises(ValueError):packer.admit(*f)

    def test_two_core_requires_online_and_xcall_proof_and_refuses_native_drain(self):
        f=list(self.fixtures());f[0].update(kernel_CPU_affinity=1792,kernel_CPU_count=2)
        f[1].update(kernel_CPU_affinity=7,kernel_CPU_count=2)
        with self.assertRaises(ValueError):packer.admit(*f)
        f[1]['checks'].update(both_kernel_CPUs_online=True,real_cross_core_callbacks=True)
        packer.admit(*f)
        f[0]['RAM_native_shutdown_bridge']=True
        with self.assertRaises(ValueError):packer.admit(*f)

    def test_stock_CPU_clock_request_needs_exact_mode_inventory_and_virtual_refusal(self):
        f=list(self.fixtures());d,q=f[:2]
        d.update(kernel_CPU_affinity=1792,kernel_CPU_count=4,RAM_native_shutdown_bridge=True)
        q.update(kernel_CPU_affinity=7,kernel_CPU_count=4,RAM_native_drain_test='success')
        q['checks'].update({k:True for k in ['both_kernel_CPUs_online','real_cross_core_callbacks',
            'four_core_affinities_and_xcalls','native_peer_affinity_OFF','native_reboot_sync_path',
            'real_zero_mounts_and_buffers','firmware_observed_RAM_drained','separate_RAM_result']})
        q['native_shutdown_mailbox']=dict(cookie=123,request_cookie=123,sequence=1,mode=2,phase=3,
            error=0,write_epoch=0,flushed_epoch=0,capabilities=0x80000003)
        d['CPU_OSM_stock_performance']=True
        with self.assertRaises(ValueError):packer.admit(*f)
        q['CPU_OSM_stock_performance']=True
        with self.assertRaises(ValueError):packer.admit(*f)
        q['checks']['native_stock_OSM_refused_before_virtual_RW']=True
        with self.assertRaises(ValueError):packer.admit(*f)
        inventory=dict(passed=True,target_index=22,target_requested_Hz=2649600000,
                       actual_native_log_sha256='e'*64)
        d['CPU_OSM_stock_inventory']=inventory;packer.admit(*f)
        for field,bad in [('passed',False),('target_index',26),('target_requested_Hz',2803200000),
                          ('actual_native_log_sha256','')]:
            old=inventory[field];inventory[field]=bad
            with self.subTest(field=field),self.assertRaises(ValueError):packer.admit(*f)
            inventory[field]=old
        d['CPU_OSM_readonly_inventory']=True
        with self.assertRaises(ValueError):packer.admit(*f)

    def test_four_core_cannot_reuse_pair_or_incomplete_shutdown_evidence(self):
        f=list(self.fixtures());d,q=f[:2]
        d.update(kernel_CPU_affinity=1792,kernel_CPU_count=4,RAM_native_shutdown_bridge=True)
        q.update(kernel_CPU_affinity=7,kernel_CPU_count=4,RAM_native_drain_test='success')
        keys=['both_kernel_CPUs_online','real_cross_core_callbacks','four_core_affinities_and_xcalls',
              'native_peer_affinity_OFF','native_reboot_sync_path','real_zero_mounts_and_buffers',
              'firmware_observed_RAM_drained','separate_RAM_result']
        q['checks'].update({k:True for k in keys})
        q['native_shutdown_mailbox']=dict(cookie=123,request_cookie=123,sequence=1,mode=2,phase=3,
                                         error=0,write_epoch=0,flushed_epoch=0,capabilities=0x80000003)
        packer.admit(*f)
        d['CPU_OSM_readonly_inventory']=True
        with self.assertRaises(ValueError):packer.admit(*f)
        q['CPU_OSM_readonly_inventory']=True
        with self.assertRaises(ValueError):packer.admit(*f)
        q['checks']['native_OSM_probe_refused_before_virtual_MMIO']=True
        packer.admit(*f)
        q['CPU_OSM_readonly_inventory']=False
        with self.assertRaises(ValueError):packer.admit(*f)
        q['CPU_OSM_readonly_inventory']=True
        q['kernel_CPU_count']=2
        with self.assertRaises(ValueError):packer.admit(*f)
        q['kernel_CPU_count']=4
        for key in keys:
            q['checks'][key]=False
            with self.subTest(key=key),self.assertRaises(ValueError):packer.admit(*f)
            q['checks'][key]=True
        d['CPU_OSM_readonly_inventory']=False
        with self.assertRaises(ValueError):packer.admit(*f)
        d['CPU_OSM_readonly_inventory']=True
        d['RAM_native_shutdown_bridge']=False
        with self.assertRaises(ValueError):packer.admit(*f)

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

    def test_native_RAM_bridge_requires_more_than_VM_boot_or_stale_refusal(self):
        f=list(self.fixtures());f[0]['RAM_native_shutdown_bridge']=True
        with self.assertRaises(ValueError):packer.admit(*f)
        f[1]['RAM_native_drain_test']='success'
        f[1]['checks'].update({k:True for k in ['native_reboot_sync_path','real_zero_mounts_and_buffers',
            'firmware_observed_RAM_drained','separate_RAM_result']})
        f[1]['native_shutdown_mailbox']=dict(cookie=123,request_cookie=123,sequence=1,mode=2,phase=3,
                                           error=0,write_epoch=0,flushed_epoch=0,capabilities=0x80000003)
        packer.admit(*f)
        for key,value in [('phase',5),('capabilities',0x1f),('error',5),('cookie',124),('write_epoch',1)]:
            before=f[1]['native_shutdown_mailbox'][key];f[1]['native_shutdown_mailbox'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):packer.admit(*f)
            f[1]['native_shutdown_mailbox'][key]=before

    def test_two_core_native_bridge_requires_actual_peer_OFF_and_successful_drain(self):
        f=list(self.fixtures())
        f[0].update(kernel_CPU_affinity=1792,kernel_CPU_count=2,RAM_native_shutdown_bridge=True)
        f[1].update(kernel_CPU_affinity=7,kernel_CPU_count=2,RAM_native_drain_test='success')
        f[1]['checks'].update({k:True for k in ['both_kernel_CPUs_online','real_cross_core_callbacks',
            'native_reboot_sync_path','real_zero_mounts_and_buffers','firmware_observed_RAM_drained','separate_RAM_result']})
        f[1]['native_shutdown_mailbox']=dict(cookie=123,request_cookie=123,sequence=1,mode=2,phase=3,
                                           error=0,write_epoch=0,flushed_epoch=0,capabilities=0x80000003)
        with self.assertRaises(ValueError):packer.admit(*f)
        f[1]['checks']['native_peer_affinity_OFF']=True;packer.admit(*f)
        for key,value in [('RAM_native_drain_test','peer-refused'),('release_handoff_admitted',False)]:
            before=f[1][key];f[1][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):packer.admit(*f)
            f[1][key]=before
        f[1]['checks']['native_peer_affinity_OFF']=False
        with self.assertRaises(ValueError):packer.admit(*f)


if __name__=='__main__':unittest.main()
