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
    '20F66':dict(kernel='c901a66ec7972c8aacf1471f93b7a7f16e4be8e1ef95030577a28eca003b9ccb',
        source='9138b0c0c23d15d0a9f332f71a295d8ea7932142',CI=41181883387,
        root='91515474f2f886e1508e2ef62f0d8dce6fe4188c0dd382e566ba819264d37c0f',
        GPU='bf8a704411fae01abeb23578b19f0c6c1738f90cedaeedb7b394930187069b70',extents=142,
        graphics_manifest='research/polaris/uefi-ios-0133/graphics-poster-hierarchy-0001/manifest.json')}

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


def _exact(actual,expected):
    if type(actual) is not type(expected):return False
    if type(expected) is dict:
        return actual.keys()==expected.keys() and all(_exact(actual[k],v) for k,v in expected.items())
    if type(expected) is list:return len(actual)==len(expected) and all(_exact(a,b) for a,b in zip(actual,expected))
    return actual==expected


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
