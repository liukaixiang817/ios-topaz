"""Independent physical native-WLED RAM scope, never owned/persistent writes."""
KERNEL_SHA='dd4bd7571c00278d3b5dc116fc63639da8271254ecb59d55cfd754f822b7a50f'
NATIVE_SOURCE='2d55a4e6da5c73edc0d72cd3c17203a00fa6a7bb'
ORIGINAL_SHA='8588a9a5218d407dd3169ec1f340097db689b3d046f3d38189514e09f3944336'
ROOT_SHA='689a8cd1df0fc0093706272241a9ac77d5eddd7a62df5d340913ec6abcd7ce2b'
GPU_SHA='865407ee5b402fe690c04f5888ee6758a29f6ef3eca639019ac89dfba0f3371f'
# The new profile stays closed until the exact successful-CI artifact is bound.
TARGETS={
    '20H392':dict(kernel=KERNEL_SHA,source=NATIVE_SOURCE,CI=41056172330,root=ROOT_SHA,GPU=GPU_SHA,extents=182),
    '20F66':dict(kernel='d51ad260df5002ffa46a16e2125365cac6663c153462e892a3eedd8114d3862a',
        source='a55026075fe59255b02bb7c8652ce16965b68aeb',CI=41174275124,
        root='91515474f2f886e1508e2ef62f0d8dce6fe4188c0dd382e566ba819264d37c0f',
        GPU='6ab8e26039824073356156923be7cca267713359f90a3bd3ad63488647771b3b',extents=142,
        graphics_manifest='research/polaris/uefi-ios-0131/graphics-media-original-job-0001/manifest.json')}

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


def _exact(actual,expected):
    if type(actual) is not type(expected):return False
    if type(expected) is dict:
        return actual.keys()==expected.keys() and all(_exact(actual[k],v) for k,v in expected.items())
    if type(expected) is list:return len(actual)==len(expected) and all(_exact(a,b) for a,b in zip(actual,expected))
    return actual==expected


def exact_scope(d,build=None):
    profile=target_profile(build or d.get('userland_build','20H392'))
    for k,v in PHYSICAL.items():
        if type(d.get(k)) is not type(v) or d[k]!=v:raise ValueError('not the independent physical runtime scope: '+k)
    if d.get('chain_app') is not None or d.get('disk_guid') is not None or d.get('RAM_native_drain_test') is not None:
        raise ValueError('foreign chain/disk/VM drain fixture')
    if any(v for k,v in d.items() if k.startswith('controlled_')):
        raise ValueError('physical runtime cannot carry fault fixtures')
    if d.get('kernel_sha256')!=profile['kernel'] or not _exact(d.get('GPU_thermal_policy'),THERMAL) or not _exact(d.get('TSENS_pair_policy'),PAIR):
        raise ValueError('verified native kernel/protection policy changed')
    if not d.get('inputs'):raise ValueError('missing exact source inputs')


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
        if (m.get('passed') is not True or m.get('inputs')!=d['inputs'] or
            m.get('SOFTWARE_PMIC') is not True or m.get('RAM_USB_sink') is not True or
            m.get('physical_admission') is not False or len(m.get('checks',{}))!=18 or
            any(v is not True for v in m['checks'].values())):
            raise ValueError('stale/incomplete actual terminal model')
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
