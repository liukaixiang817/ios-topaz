"""Independent physical native-WLED RAM scope, never owned/persistent writes."""
import hashlib
import struct

KERNEL_SHA='dd4bd7571c00278d3b5dc116fc63639da8271254ecb59d55cfd754f822b7a50f'
NATIVE_SOURCE='2d55a4e6da5c73edc0d72cd3c17203a00fa6a7bb'
ORIGINAL_SHA='8588a9a5218d407dd3169ec1f340097db689b3d046f3d38189514e09f3944336'
ROOT_SHA='689a8cd1df0fc0093706272241a9ac77d5eddd7a62df5d340913ec6abcd7ce2b'
GPU_SHA='865407ee5b402fe690c04f5888ee6758a29f6ef3eca639019ac89dfba0f3371f'
# The new profile stays closed until the exact successful-CI artifact is bound.
TARGETS={
    '20H392':dict(kernel=KERNEL_SHA,source=NATIVE_SOURCE,CI=41056172330,root=ROOT_SHA,GPU=GPU_SHA,extents=182),
    '20F66':dict(kernel='82b3fef383365efdfbf3c8fd72c4a98cab15589d96dbaf006c5af5cd96ab5802',
        source='41e9a87f7b18efb3029803a41b18ee1984bf66ed',CI=41205803135,
        root='91515474f2f886e1508e2ef62f0d8dce6fe4188c0dd382e566ba819264d37c0f',
        GPU='f790512548bfb9d46911590bedf5ec3962e9c3dc566b10f219d618131ae65353',extents=142,
        runtime_services=True,
        graphics_manifest='research/polaris/uefi-ios-0139/performance/bbd-activation-final-0002/graphics-retained-trial/manifest.json')}

def target_profile(build):
    if build not in TARGETS or TARGETS[build]['kernel'] is None or TARGETS[build]['extents'] is None:
        raise ValueError('unverified native target profile')
    return TARGETS[build]
PHYSICAL=dict(RAM_only_XNU_loader=True,kernel_handoff=True,PMIC_write_api=True,
    WLED_native_runtime_physical=True,WLED_native_runtime_test=False,WLED_native_SOFTWARE_PMIC=False,
    WLED_readonly_inventory_only=False,WLED_readonly_fault_watch=False,WLED_power_cycle_only=False,
    WLED_OEM_status_policy=False,WLED_OEM_physical_cycle=False,kernel_CPU_ON_compiled_out=False,
    storage_write_api=False,NVRAM_write_api=False,thermal_configuration_write_api=False,
    kernel_CPU_affinity=1792,kernel_CPU_count=4,QEMU_variant=False,phone_compatible=True,
    ready_to_boot_driver=True,bounded_input=True,physical_buttons=True,framebuffer_arrival_wake=True,
    RAM_native_shutdown_bridge=True,RAM_host_idle_recovery_seconds=1800,
    CPU_OSM_readonly_inventory=False,CPU_OSM_stock_performance=True,TSENS_readonly_inventory=True,
    GPU_stock_request=3,GPU_thermal_lease_trial=True,GPU_thermal_extended_trial=True,TSENS_pair_witness_trial=True,
    physical_owned_marker_test=False,physical_small_file_write_test=False,selected_application=False,
    disk_payload_read_only=False,isolated_QEMU_owned_UFS_test=False,isolated_QEMU_readonly_UFS_test=False,
    probe_only=False,holds_before_OS_start=False,payload_C_admission=True,rebased_kernel_bytes_match=True,
    WLED_runtime_journal_version=3,WLED_runtime_archive_capacity=8192,WLED_runtime_archive_storage_capacity=8192,
    raw_reset_requires_native_and_WLED_restore=True,WLED_native_zero_write_receipt_bytes=40,
    WLED_atomic_exit_footer_max=212,WLED_atomic_exit_receipt_bytes=60,
    WLED_reset_prepared_before_terminal_reads=True,WLED_reset_arm_SOFTWARE_delay_us=0)
THERMAL=dict(experimental_limits_mC=[75000,70000,60000,55000],max_observation_age_us=500000,
    hard_high_ns=600000000000,confirmed_low_ns=10000000000,idle_ns=250000000)
PAIR=dict(max_physical_reads=72,max_words_per_sensor=4,max_span_us=1000,max_pair_delta_mC=2000,
          hottest_word_required=1,actual_words_only=1)
RUNTIME_SERVICES=dict(host_UTC_sync=True,host_UTC_source='host-realtime-plus-monotonic-RTT',
    calendar_RAM_only=True,RTC_write_api=False,monotonic_counter_write_api=False,
    battery_readonly=True,battery_UI_span_limit_us=500000,battery_PMIC_write_api=False,
    battery_physical_PMIC_reads_compiled_out=False,wifi_readonly=True,
    wifi_EFI_SMEM_read_api=False,wifi_EFI_transmit_api=False,RAM_bytes=0xfc8a0000)
RUNTIME_DT=dict(version=1,battery_readonly=True,wifi_readonly=True,
    path='/polaris-runtime-services',boot_argument_tokens_changed=False)
CLOCK_INITIAL_SHA=hashlib.sha256(struct.pack('<Q',0x50434c4f434b3031)+bytes(248)).hexdigest()
BASE_TERMINAL_CHECKS=frozenset(('actual_EL1','actual_payload','actual_native_started',
    'native_workloop_three_actual_RAM_copies','actual_native_RAM_drain','actual_final_archive',
    'no_additional_PMIC_WRITE','original_errors_zero','footer_actual_delay_over_original_freshness',
    'actual_reset_observer_only_after_final_pair','reset_arm_actual_guest_delay',
    'reset_checked_after_new_pair','bounded_attempts','expected_first_delivery',
    'failed_delivery_no_reset','explicit_readonly_recovery','complete_literal_raw_prefix_footer_receipt','no_panic'))

# A fixed early CPU0 read is a distinct physical scope, even though it exposes
# no USB read command. Existing cache-only profiles must not silently admit it.
FIRSTREAD_PREFIX='wifi_CPU0_firstread_'
FIRSTREAD_DISABLED=dict(readonly=False,default_OFF=True,new_SMEM_read_body=False,
    compiled_target_LDR32_max=0,actual_target_reads_observed=False,bytes_each=None,
    passes_max=None,target_LDR32_max=None,addresses=None,fresh_limit_ticks=None,
    frequency=None,before_CPU_ON=None,before_console_and_PON=None,
    no_runtime_or_USB_command=True,retrospective_constructor_admission=None,
    hardware_MPU_or_VMID_query=False,external_SError_recoverable=False,
    native_permission=False,FIFO_or_TX=False,physical_SMEM_reads_compiled_out=False)


# Reviewed fixed-reader0139 scope is separate from the cache-only profile.
# Bind every compiled/private input and the unchanged native payload; a flag
# alone cannot admit a new reader or a modified implementation.
FIRSTREAD_0139={'firmware_source': '828389d56970ef97104e77f50f3e2d497f330d7d',
 'inputs': {'research/polaris/uefi-integration-0057/firmware-files/f541d663-4a48-40aa-aabf-ff158ccae34c.efi': '9e366873287fbde6452bb8990ee233f7e53513454befb48df01378d88a072ea8',
            'shim/polaris/payload.c': 'd5a3901b87692b5e0776713a8dd7c163ac18b40984b684524103514922e6bd5d',
            'shim/polaris/payload.h': '268b7f90c6c5076aeaf28421848fa82ee435f4c57f48b444d02cc15f0dd31cd6',
            'shim/polaris/runtime-marker.h': '23ae6c2ea5c43520cf29e59a9dbbe1f0bcdc0653464c8e052aaebfc83fc3bd8e',
            'shim/polaris/runtime-quiesce.h': '184aa7ad4d296c407e061082fa1f83d46278489e0252ed142136c3718d778757',
            'shim/polaris/uefi-battery-native.h': 'b07ff3fe03732565fd2a7b34935a771250e1a6c6d5f1966bedf7a24d687edd1d',
            'shim/polaris/uefi-boot-options.h': 'e6162e260155ac0ddc29d30a72589e39f20bb4e1137e2f44144d5cef7635f1dc',
            'shim/polaris/uefi-buttons-spmi.h': '3010dfb293f4cef33d44a28754090752a77f22fee04930487b54e5114f60a8e8',
            'shim/polaris/uefi-buttons.h': 'ce7872c28a560b7ae09131f85b460b9b9766dc1ddf3e93287a800d1c7d95bd2f',
            'shim/polaris/uefi-file.h': '8c0745612a3965ef24d3a220ace186eef0c84ec24f9f606f4abbc851ef02a3b8',
            'shim/polaris/uefi-memory.h': '6b7927260bcf2492bf6d5ae037d541bddcce58f3f8134a716b0d728f31651753',
            'shim/polaris/uefi-ram-lease.h': '75b256a7b3da6f64f9be04f2930485b53b9dad4dbbda9d617f550a5db88693c3',
            'shim/polaris/uefi-reset.h': '594cbe372e810162982a71e3c8a2ec4f9812df33807a03f6aa86f82bef65c3f2',
            'shim/polaris/uefi-usb-command.c': '46a85fd86c752ba3ed327862f74b107bb08c28d94f9a6f2bde1202260155e46a',
            'shim/polaris/uefi-usb-control.c': '74cb9fe5c4709ed89b70ea5a70fa22e21d8cf5deb3d4076827a68d10618cf44f',
            'shim/polaris/uefi-usb.c': 'cb2573ab5ca7c4bd7629bd4d1c0e5964d10bd9b0bd184cfce1b51241d1954b1a',
            'shim/polaris/uefi-usb.h': '8ad0adef34e90e929da8fc14e552dab6abad7e51951038badba1c35289cf7c6d',
            'shim/polaris/uefi-wifi-cache-readonly.h': 'b4dd9cf918a5511d83b66660e01c504ce73c8e7a85146f2b9a9d1764cd4366dc',
            'shim/polaris/uefi-wifi-firstread.h': 'e1bbda38b341a3a96c70e24b237915734b3322df9169c710e52c2a7d29542952',
            'shim/polaris/uefi-wled-journal.h': '599e5244c2c90407fcf6e45a23c5375dd1f3cb66a99389128058cf6742eed93e',
            'shim/polaris/uefi-wled-native.h': 'a8353fd083fd561b6158621d92299ed0621fd3b84b173e2a73b23be8d359831d',
            'shim/polaris/uefi-wled-power.h': '6f411cf7c9a819f51eddb7317cb285954a15da3043f3488a910bbadce2dba88d',
            'shim/polaris/uefi-wled-readonly.h': '6784dd380e56cb5b94601ad52cd0e165c1df3632338c188495f3d72a7787a9b6',
            'shim/polaris/uefi-wled-runtime.h': 'c4aab671375b5e0f5b29e8529bd48d489f6504c30dd5957aa1680135be8bf111',
            'shim/polaris/uefi-wled-status.h': '7f1e988b1a27904d4b021ee4dd43ea88a330c9e87fad64816154e7bbbc457db5',
            'shim/polaris/uefi-xnu-ap.S': '060f146b68ddc1f98beeaefc2ff42899791149e8ce37a9cc22830039f872e2cb',
            'shim/polaris/uefi-xnu-crc.c': '1de4bdaede7864c861aa78d7845da9a2bf1dae023a49efc896804ae0c648b2cb',
            'shim/polaris/uefi-xnu.c': '5dcffbfc7cef34bc633b55afcd8b9034434c08f7f6995fb42ceb45b7aaaf4ea6',
            'shim/polaris/uefi-xnu.h': '8d394e618d92fc3188550b8b94da279bfe8a2334b88a14f45b87ce45d9b87b8f',
            'shim/polaris/uefi.h': '4c704e68dafbf36c59eddd9623275c2c51168d9ed6353106c9900b0c5894e2c6',
            'tools/adt.py': 'ebb7a858835fc7acf5da1e543a05b9561e70c6fd4f9328f4d52c009465573bdd',
            'tools/build-polaris-uefi-xnu.py': 'aebc413e90f56c0aecdabb6dcb539b305591deb588bdd31c39ad65356f3444f2',
            'tools/mkpayload.py': '26d49a3ee8b34dae9a4f56f53b6ae619787a502926e5f3db38468ed809d2dd9f',
            'tools/polaris-battery-native.cpp': '22e0fee9b66ee82d524dfb90c285230590f7037abfeac2fa05722dafbf9309b5',
            'tools/polaris-battery-producer.h': '5834a761cc1c5c618efca4ccf5b604afd4a44f68cbfd612e47c259496278411c',
            'tools/polaris-battery-readonly.h': '4763209498244fedb95d5e7edec97994fb4d2d5e8f9521d4d4f94278fb2c0e21',
            'tools/polaris-battery-shared.h': 'e11a3ff135c92a13c2b8f2dab908c8a70c25e9f595228ac49efd49f960f88ce0',
            'tools/polaris-buttons.h': 'f31cfb945680007f8b100f01d2680c2822e035bcf6a1888e28581603fe56913d',
            'tools/polaris-clock-host.py': 'a2219a00329d16a8e01992d83bc89a41205a809470a79668110a3fb7a3c6e39a',
            'tools/polaris-clock-native.h': 'fc34ea97a6cdf5d1a1850257147db6a13fac79463d78ad3fd9761e20231de16c',
            'tools/polaris-clock-sync.h': 'f82b864530564ec92d45390590dc34c8c15c53cd3afc833021117f5c29f95e1d',
            'tools/polaris-clock-uefi.h': '537d558904b27c2118c5b6263cc2a4c22704c1a61ee48d75283ef24bed297ef3',
            'tools/polaris-uefi-buttons.h': '06bab9e8a1de3057de220d952da56ccb20c5c35e9db130e00308868ccd71fe8d',
            'tools/polaris-uefi-input.h': '2f81d45cdfcf400eb924f299ab44458092aabb10530bb4acf374d56f612c14dc',
            'tools/polaris-wifi-firmware-identity.h': '35af76a7a754d481980c51750382fd006786abba093ea635ec92863c67af4b50',
            'tools/polaris-wifi-firmware-identity.py': '35a5c7e18113f8f1a9d9e529ffce22de98085fe88981e904ffa8e3ce19d6abac',
            'tools/polaris-wled-mailbox.h': 'de8b2fbc39e6ec406e7786ca4741ae76f76ecae01f311017ad127e2629715215',
            'tools/polaris_uefi_cpu_tree.py': '7cc6c14bcb907ff3e6141e1102b8c7e6105996c669a89692caf6f34318f6372a'},
 'kernel': '009c8a0fe66a0374670b57831c92741cea70e8dc34a0f514c8c4fe8ba5566655',
 'payload': 'f7d50f840d01f039ccbcef434747e3b7375ab26b3ac5f5dc6df725227df10708'}
FIRSTREAD_0139_FIELDS={'FIFO_or_TX': False,
 'actual_target_reads_observed': False,
 'addresses': [2248147036,
               2248147136,
               2250240000,
               2250240004,
               2250240008,
               2248904704,
               2248904712,
               2248904716,
               2248904720],
 'before_CPU_ON': True,
 'before_console_and_PON': True,
 'bytes_each': 36,
 'compiled_target_LDR32_max': 18,
 'default_OFF': True,
 'external_SError_recoverable': False,
 'frequency': 19200000,
 'fresh_limit_ticks': 3840000,
 'hardware_MPU_or_VMID_query': False,
 'native_permission': False,
 'new_SMEM_read_body': True,
 'no_runtime_or_USB_command': True,
 'passes_max': 2,
 'physical_SMEM_reads_compiled_out': False,
 'readonly': True,
 'retrospective_constructor_admission': True,
 'target_LDR32_max': 18}

def _exact(actual,expected):
    if type(actual) is not type(expected):return False
    if type(expected) is dict:
        return actual.keys()==expected.keys() and all(_exact(actual[k],v) for k,v in expected.items())
    if type(expected) is list:return len(actual)==len(expected) and all(_exact(a,b) for a,b in zip(actual,expected))
    return actual==expected


#Independent NormalNC scope. None means NOT admitted; populate only after
#committed-source/actual-f790-kernel/payload and full compiled input review.
NORMAL_NC_0141=None
NORMAL_NC_PREFIX='wifi_CPU0_normal_nc_firstread_'
NORMAL_NC_DISABLED={'FIFO_or_TX': False,
 'MAIR_expected': None,
 'PAR_attributes': None,
 'PAR_exact_low12': None,
 'PAR_nonsecure': None,
 'PAR_shareability': None,
 'actual_architectural_target_reads_observed': False,
 'addresses': None,
 'all3pages_required_before_target_LDR': None,
 'architectural_bytes_each': None,
 'architectural_target_LDR32_max': None,
 'before_CPU_ON': None,
 'before_console_and_PON': None,
 'compiled_architectural_target_LDR32_max': 0,
 'default_OFF': True,
 'external_SError_recoverable': False,
 'frequency': None,
 'fresh_limit_ticks': None,
 'hardware_MPU_or_VMID_query': False,
 'mutually_exclusive_with_Device_firstread': True,
 'native_permission': False,
 'new_SMEM_read_body': False,
 'no_runtime_or_USB_command': True,
 'normal_speculative_repeated_coalesced_bus_reads_possible': None,
 'original_Device_policy_unchanged': True,
 'passes_max': None,
 'physical_SMEM_reads_compiled_out': False,
 'physical_bus_transaction_cap': False,
 'policy_version': None,
 'readonly': False,
 'retrospective_constructor_admission': None,
 'translation_pages': None,
 'whole_raw_PAR_stable': None}
NORMAL_NC_PHYSICAL_FIELDS={'FIFO_or_TX': False,
 'MAIR_expected': 4290462720,
 'PAR_attributes': 68,
 'PAR_exact_low12': 2816,
 'PAR_nonsecure': True,
 'PAR_shareability': 2,
 'actual_architectural_target_reads_observed': False,
 'addresses': [2248147036,
               2248147136,
               2250240000,
               2250240004,
               2250240008,
               2248904704,
               2248904712,
               2248904716,
               2248904720],
 'all3pages_required_before_target_LDR': True,
 'architectural_bytes_each': 36,
 'architectural_target_LDR32_max': 18,
 'before_CPU_ON': True,
 'before_console_and_PON': True,
 'compiled_architectural_target_LDR32_max': 18,
 'default_OFF': True,
 'external_SError_recoverable': False,
 'frequency': 19200000,
 'fresh_limit_ticks': 3840000,
 'hardware_MPU_or_VMID_query': False,
 'mutually_exclusive_with_Device_firstread': True,
 'native_permission': False,
 'new_SMEM_read_body': True,
 'no_runtime_or_USB_command': True,
 'normal_speculative_repeated_coalesced_bus_reads_possible': True,
 'original_Device_policy_unchanged': True,
 'passes_max': 2,
 'physical_SMEM_reads_compiled_out': False,
 'physical_bus_transaction_cap': False,
 'policy_version': 'exact-NormalNC44-NS-OuterShareable-v1',
 'readonly': True,
 'retrospective_constructor_admission': True,
 'translation_pages': [2248146944, 2248904704, 2250240000],
 'whole_raw_PAR_stable': True}

#Independent I2CDxe original-imageRAM witness, never a deviceI2C permission.
AUDIO_I2C_0141=None
AUDIO_I2C_PREFIX='audio_I2C_cache_'
AUDIO_I2C_DISABLED={'DIR64_relocations': None,
 'MMIO_reads': False,
 'PCM_completion_proven': False,
 'SE5_owner_proven': False,
 'TAS_identity_proven': False,
 'actual_cache_observed': False,
 'after_complete_WiFi_collect_read_report': None,
 'before_PON_and_mask': None,
 'binding_SHA256': None,
 'bytes_per_snapshot': None,
 'cache_RVA': None,
 'cached_pointer_follow': False,
 'calls_I2C_DAL_methods': False,
 'calls_original_firmware': False,
 'default_OFF': True,
 'image_bytes': None,
 'immutable_hashes': None,
 'map_calls_max': None,
 'map_keys_before_FreePool_only': None,
 'native_permission': False,
 'new_original_image_RAM_read_body': False,
 'no_runtime_or_USB_command': True,
 'original_PE': None,
 'original_PE_whole_SHA256': None,
 'physical_image_inspection_compiled_out': False,
 'prepare_stage': None,
 'raw_report_bytes': None,
 'raw_report_endianness': None,
 'raw_report_format': None,
 'raw_report_lines': None,
 'raw_report_max_text_units': None,
 'readonly': False,
 'snapshot_count': None}
AUDIO_I2C_PHYSICAL_FIELDS={'DIR64_relocations': 43,
 'MMIO_reads': False,
 'PCM_completion_proven': False,
 'SE5_owner_proven': False,
 'TAS_identity_proven': False,
 'actual_cache_observed': False,
 'after_complete_WiFi_collect_read_report': True,
 'before_PON_and_mask': True,
 'binding_SHA256': '897f0d6bde76b50f645ba0567ae75f293f80eb0bb8a58ddf84fb20fdb66a0aa5',
 'bytes_per_snapshot': 120,
 'cache_RVA': 28000,
 'cached_pointer_follow': False,
 'calls_I2C_DAL_methods': False,
 'calls_original_firmware': False,
 'default_OFF': True,
 'image_bytes': 32768,
 'immutable_hashes': 4,
 'map_calls_max': 3,
 'map_keys_before_FreePool_only': True,
 'native_permission': False,
 'new_original_image_RAM_read_body': True,
 'no_runtime_or_USB_command': True,
 'original_PE': 'research/polaris/uefi-integration-0057/firmware-files/04de8591-d2b3-4077-bbbe-b12070094eb6.efi',
 'original_PE_whole_SHA256': '5eb6c9ddd3449ef3f74feb3644448c279fcc619dc95812b16ad2fb616d738332',
 'physical_image_inspection_compiled_out': False,
 'prepare_stage': 2,
 'raw_report_bytes': 5096,
 'raw_report_endianness': 'little',
 'raw_report_format': 'RAW_V1',
 'raw_report_lines': 8,
 'raw_report_max_text_units': 126,
 'readonly': True,
 'snapshot_count': 2}

def audio_i2c_cache_scope(d):
    actual={k[len(AUDIO_I2C_PREFIX):]:v for k,v in d.items() if k.startswith(AUDIO_I2C_PREFIX)}
    if not actual or _exact(actual,AUDIO_I2C_DISABLED):
        if 'shim/polaris/uefi-audio-i2c-cache.h' in d.get('inputs',{}):
            raise ValueError('audio I2C image read cannot hide behind absent/disabled metadata')
        return False
    policy=AUDIO_I2C_0141
    if (type(policy) is not dict or not policy.get('firmware_source') or
        not _exact(actual,AUDIO_I2C_PHYSICAL_FIELDS) or not _exact(d.get('inputs'),policy.get('inputs')) or
        d.get('kernel_sha256')!=policy.get('kernel') or d.get('payload_sha256')!=policy.get('payload') or
        'shim/polaris/uefi-audio-i2c-cache.h' not in d.get('inputs',{})):
        raise ValueError('audio I2C cache requires its exact separately committed-source0141 scope')
    return True


def normal_nc_firstread_scope(d):
    actual={k[len(NORMAL_NC_PREFIX):]:v for k,v in d.items() if k.startswith(NORMAL_NC_PREFIX)}
    if not actual or _exact(actual,NORMAL_NC_DISABLED):
        if 'shim/polaris/uefi-wifi-firstread-normal-nc.h' in d.get('inputs',{}):
            raise ValueError('NormalNC firstread source cannot hide behind absent/disabled metadata')
        return False
    policy=NORMAL_NC_0141
    if (type(policy) is not dict or not policy.get('firmware_source') or
        not _exact(actual,NORMAL_NC_PHYSICAL_FIELDS) or
        not _exact(d.get('inputs'),policy.get('inputs')) or
        d.get('kernel_sha256')!=policy.get('kernel') or d.get('payload_sha256')!=policy.get('payload') or
        'shim/polaris/uefi-wifi-firstread-normal-nc.h' not in d.get('inputs',{}) or
        'shim/polaris/uefi-wifi-firstread.h' in d.get('inputs',{}) or
        d.get('wifi_CPU0_firstread_readonly') is not False):
        raise ValueError('NormalNC firstread requires its exact separately committed-source0141 scope')
    return True


def firstread_scope(d):
    actual={k[len(FIRSTREAD_PREFIX):]:v for k,v in d.items() if k.startswith(FIRSTREAD_PREFIX)}
    if not actual or _exact(actual,FIRSTREAD_DISABLED):
        if 'shim/polaris/uefi-wifi-firstread.h' in d.get('inputs',{}):
            raise ValueError('firstread source cannot hide behind absent/disabled metadata')
        return False
    policy=FIRSTREAD_0139
    if (not _exact(actual,FIRSTREAD_0139_FIELDS) or
        not _exact(d.get('inputs'),policy['inputs']) or
        d.get('kernel_sha256')!=policy['kernel'] or d.get('payload_sha256')!=policy['payload']):
        raise ValueError('CPU0 SMEM firstread requires the exact separately reviewed0139 physical scope')
    return True


def runtime_services_scope(d):
    for key,value in RUNTIME_SERVICES.items():
        if not _exact(d.get(key),value):raise ValueError('runtime service physical scope changed: '+key)
    if not _exact(d.get('runtime_services_DT'),RUNTIME_DT):
        raise ValueError('runtime services require exact canonical payload DT opt-ins')
    spans=[]
    for key,symbol,bss,sections in (('host_UTC_mailbox','_polaris_uefi_clock',False,('__data',)),
                                  ('battery_mailbox','_polaris_uefi_battery',True,('__bss','__common'))):
        box=d.get(key)
        fixed=dict(symbol=symbol,bytes=256,alignment=128,segment='__DATA',BSS=bss)
        keys=set(fixed)|{'offset','section'}|({'pre_CPU_ON_publish'} if bss else {'file_offset','initial_sha256'})
        if (type(box) is not dict or set(box)!=keys or
            any(not _exact(box.get(k),v) for k,v in fixed.items()) or box.get('section') not in sections or
            type(box.get('offset')) is not int or box['offset']%128 or
            not 0<=box['offset']<=d['RAM_bytes']-256):
            raise ValueError('runtime service requires its exact independent native mailbox: '+key)
        if bss:
            if box['pre_CPU_ON_publish'] is not False:raise ValueError('battery cannot publish before native BSS init')
        elif (type(box['file_offset']) is not int or box['file_offset']<0 or box['file_offset']%128 or
              type(d.get('payload_bytes')) is not int or box['file_offset']>d['payload_bytes']-256 or
              box['initial_sha256']!=CLOCK_INITIAL_SHA):
            raise ValueError('clock requires the exact file-backed DATA initializer')
        spans.append((box['offset'],256))
    for key in ('input_offset','buttons_offset','shutdown_offset'):
        offset=d.get(key)
        if type(offset) is not int or offset%128 or not 0<=offset<=d['RAM_bytes']-256:
            raise ValueError('runtime mailbox must exclude existing native channel: '+key)
        spans.append((offset,256))
    for i,(start,size) in enumerate(spans):
        if any(start<other+length and other<start+size for other,length in spans[i+1:]):
            raise ValueError('runtime/native mailbox ranges overlap')


def runtime_model_scope(m):
    command=m.get('QEMU_command')
    if (type(command) is not list or not all(type(x) is str for x in command) or
        command.count('-cpu')!=1 or command.count('-accel')!=1):
        raise ValueError('clock model requires its explicit SOFTWARE CPU/counter command')
    cpu,accel=command.index('-cpu'),command.index('-accel')
    if (cpu+1>=len(command) or command[cpu+1]!='cortex-a55,cntfrq=19200000' or
        accel+1>=len(command) or command[accel+1]!='tcg' or
        type(m.get('SOFTWARE_CNTFRQ_hz')) is not int or m['SOFTWARE_CNTFRQ_hz']!=19200000 or
        m.get('host_UTC_SET_sent') is not False or m.get('host_UTC_sync_applied_proven') is not False or
        m.get('battery_physical_PMIC_reads_compiled_out') is not True or
        m.get('battery_SOFTWARE_disabled_observed') is not True or
        m.get('physical_USB_or_PMIC_emulation') is not False or m.get('actual_guest_reset_proven') is not False):
        raise ValueError('runtime model must retain SOFTWARE battery disable and no calendar/physical proof')


def exact_scope(d,build=None):
    profile=target_profile(build or d.get('userland_build','20H392'))
    firstread_scope(d)
    normal_nc_firstread_scope(d)
    audio_i2c_cache_scope(d)
    for k,v in PHYSICAL.items():
        if type(d.get(k)) is not type(v) or d[k]!=v:raise ValueError('not the independent physical runtime scope: '+k)
    if d.get('chain_app') is not None or d.get('disk_guid') is not None or d.get('RAM_native_drain_test') is not None:
        raise ValueError('foreign chain/disk/VM drain fixture')
    if any(v for k,v in d.items() if k.startswith('controlled_')):
        raise ValueError('physical runtime cannot carry fault fixtures')
    if d.get('kernel_sha256')!=profile['kernel'] or not _exact(d.get('GPU_thermal_policy'),THERMAL) or not _exact(d.get('TSENS_pair_policy'),PAIR):
        raise ValueError('verified native kernel/protection policy changed')
    if not d.get('inputs'):raise ValueError('missing exact source inputs')
    if profile.get('runtime_services') is True:runtime_services_scope(d)


def admit(d,models,ci,pre,review,build='20H392'):
    profile=target_profile(build)
    exact_scope(d,build)
    if build=='20F66' and (review.get('build')!='20F66' or pre.get('build')!='20F66' or
        review.get('post_unmount_RO_only') is not True or
        review.get('new_file_install_preceded_readonly_review') is not True or
        review.get('original_root_and_marker_preserved') is not True or
        review.get('new_root_immutable') is not True):
        raise ValueError('new16.5 root requires its independent post-unmount RO review')
    if (ci.get('conclusion')!='success' or ci.get('status')!='completed' or
        ci.get('databaseId')!=profile['CI'] or ci.get('headSha')!=profile['source']):
        raise ValueError('exact successful macOS27 native CI required')
    if len(models)!=2 or {m.get('controlled_exit') for m in models}!={'delayed-footer','lost-receipt-recovery'}:
        raise ValueError('both current actual terminal EFI-XNU paths required')
    for m in models:
        runtime=profile.get('runtime_services') is True
        if runtime and type(m.get('checks')) is not dict:
            raise ValueError('runtime terminal checks must be an exact dictionary')
        if (m.get('passed') is not True or m.get('inputs')!=d['inputs'] or
            m.get('SOFTWARE_PMIC') is not True or m.get('RAM_USB_sink') is not True or
            m.get('physical_admission') is not False or len(m.get('checks',{}))!=(19 if runtime else 18) or
            any(v is not True for v in m['checks'].values())):
            raise ValueError('stale/incomplete actual terminal model')
        if runtime:
            if set(m['checks'])!=BASE_TERMINAL_CHECKS|{'actual_clock_firmware_slot_prepared'}:
                raise ValueError('runtime terminal model requires its additional actual clock slot check')
            runtime_model_scope(m)
            if firstread_scope(d):
                raw=m.get('raw_fields',{})
                flag=raw.get('WIFI_FIRSTREAD_SOFTWARE_PHYSICAL_SMEM_READ_COMPILED_OUT')
                if type(flag) is not int or flag!=1:
                    raise ValueError('reviewed firstread model must compile out all physical SMEM loads')
            if normal_nc_firstread_scope(d):
                flag=m.get('raw_fields',{}).get('WIFI_NORMAL_NC_FIRSTREAD_SOFTWARE_PHYSICAL_SMEM_READ_COMPILED_OUT')
                if type(flag) is not int or flag!=1:
                    raise ValueError('reviewed NormalNC model must compile out all physical SMEM loads')
            if audio_i2c_cache_scope(d):
                flag=m.get('raw_fields',{}).get('AUDIO_I2C_CACHE_SOFTWARE_PHYSICAL_IMAGE_INSPECTION_COMPILED_OUT')
                if type(flag) is not int or flag!=1:
                    raise ValueError('reviewed audio model must compile out all physical image inspection')
    if (review.get('passed') is not True or review.get('may_boot_iOS') is not True or
        review.get('may_write_userdata') is not False or pre.get('may_boot_iOS') is not True or
        pre.get('may_write_userdata') is not False or pre.get('full_image_sha256')!=profile['root'] or
        pre.get('extent_count')!=profile['extents'] or pre.get('phone_partition_writes') is not False or
        pre.get('outer_needs_journal_recovery') is not False or pre.get('outer_state')!=1 or
        pre.get('write_ownership_baseline_update_permitted') is not False or
        pre.get('permitted_boot_arguments')!={'ufsrw':0,'polarisramcow':1,'rootrw':1,'polarisrammb':512,'polarisownedmarker':0}):
        raise ValueError('fresh immutable-root RO/RAMCOW review required')
    for k in ('all_six_GPT_copies_match_original','fresh_maps_before_after_match','unmounted','block_readonly',
              'outer_header_unchanged_during_readonly_check','outer_header_independently_reviewed',
              'actual_expected_fastboot_after_verified','critical_partitions_match_reviewed_baselines'):
        if pre.get(k) is not True:raise ValueError('root review incomplete: '+k)
