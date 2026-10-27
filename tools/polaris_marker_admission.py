"""Offline admission for ONE physical 8MiB owned marker, never a writable root.

Every evidence path is relative to this checkout and SHA-bound. Live native
ownership and reset checks remain mandatory; this inventory cannot grant a
generic UFS write command or substitute for physical persistence readback.
"""
import hashlib
import json
from pathlib import Path
import struct

import adt
import polaris_runtime_owner as owner
from polaris_owned_marker_protocol import admit_manifest

BASE_SHA = '689a8cd1df0fc0093706272241a9ac77d5eddd7a62df5d340913ec6abcd7ce2b'
ESP_SHA = '7338692a4e42db7f53fac8fe2ff3bb3bf55bd5dec4bdc6d5c4243d8d49794ef3'
MARKER_PATH = 'polaris-owned-v0077-0001/marker.bin'
CASES = ('owned-success', 'owned-missing-live-guard', 'owned-flush-EIO',
         'owned-write-unknown-DMA', 'owned-response-short', 'owned-stale-cookie',
         'owned-HCE-loss', 'dual-RAM-control')
COMMON_CHECKS = ('both_kernel_CPUs_online', 'real_cross_core_callbacks', 'native_mailbox_captured',
                 'four_process_VM_stress', 'each_child_passed', 'bounded_input_handshake', 'no_panic')
CASE_CHECKS = {
    'owned-success': ('live_firmware_guard_observed_by_kernel', 'owner_verified_through_native_UFS',
        'protected_base_descriptor_refused', 'actual_owned_WRITE_submitted', 'actual_owned_READ_back',
        'real_native_final_SYNC_completed', 'native_zero_mounts_busy', 'native_peer_actual_OFF',
        'firmware_observed_durable_SAFE', 'exact_safe_mailbox', 'actual_backend_flush_completed'),
    'owned-missing-live-guard': ('native_refused_before_PCI_MMIO', 'no_PCI_or_owned_data_claim',
        'firmware_no_guard_reset_refused', 'no_write_or_SAFE_cookie', 'actual_native_queue_never_submitted'),
    'owned-flush-EIO': ('real_native_final_SYNC_refused', 'actual_backend_failed_flush_recorded'),
    'owned-write-unknown-DMA': ('actual_native_WRITE_timeout', 'actual_doorbell_still_pending',
        'no_completed_write_or_readback_claim', 'native_unknown_DMA_retained'),
    'owned-response-short': ('controlled_completed_response_residual_refused',),
    'owned-stale-cookie': ('native_stale_cookie_refused',),
    'owned-HCE-loss': ('actual_HCE_loss_observed',),
    'dual-RAM-control': ('native_reboot_sync_path', 'real_zero_mounts_and_buffers',
        'firmware_observed_RAM_drained', 'separate_RAM_result', 'native_peer_affinity_OFF'),
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def evidence(root, record):
    require(isinstance(record, dict) and set(record) == {'path', 'sha256'}, 'unbound evidence')
    relative = Path(record['path'])
    require(not relative.is_absolute() and '..' not in relative.parts, 'evidence path escapes checkout')
    path = root / relative
    require(path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(root.resolve()),
            'ordinary evidence file in checkout required')
    require(sha(path) == record['sha256'], 'evidence SHA changed: ' + str(relative))
    return path


def load(root, record):
    return json.loads(evidence(root, record).read_text())


def base_audit(audit, after=False):
    required = ('all_six_GPT_copies_match_original', 'fresh_maps_before_after_match',
                'unmounted', 'block_readonly', 'outer_header_unchanged_during_readonly_check',
                'outer_header_independently_reviewed', 'fresh_extents_match_payload_baseline',
                'actual_expected_fastboot_after_verified')
    require(all(audit.get(k) is True for k in required), 'complete physical base audit required')
    require(audit.get('state') == ('fresh_owned_marker_preflight_passed' if after else
                                'fresh_root_readonly_preflight_passed'), 'wrong audit stage')
    require(audit.get('phone_partition_writes') is after and audit.get('journal_replayed') is False and
            audit.get('metadata_repaired') is False, 'unexpected filesystem mutation or replay')
    require(audit.get('observed_root_sha256') == audit.get('full_image_sha256') == BASE_SHA and
            audit.get('file_bytes') == 16 << 30 and audit.get('extent_count') == 182 and
            audit.get('ESP_approved_addition_baseline') == ESP_SHA and
            audit.get('outer_state') == 1 and audit.get('outer_needs_journal_recovery') is False and
            set(audit.get('critical_partitions_match_reviewed_baselines', [])) ==
            {'recovery', 'mindowsesp', 'abl_a', 'abl_b', 'boot'}, 'baseline, GPT or journal audit incomplete')


def model_suite(root, suite, kernel_sha, inputs):
    require(suite.get('actual_EFI_XNU_native_owned_file_tests_passed') is True and
            suite.get('kernel_sha256') == kernel_sha and
            suite.get('actual_live_guard_required_before_PCI_MMIO') is True, 'native owned model suite absent')
    observer_sha = sha(root / 'tools/qemu-polaris-uefi-xnu.py')
    require(suite.get('observer_sha256') == observer_sha, 'native observer source changed')
    rows = suite.get('cases', [])
    require(len(rows) == len(CASES) and {r.get('case') for r in rows} == set(CASES), 'missing native failure case')
    for row in rows:
        require(row.get('run') and row.get('passed') is True, 'failed model selected')
        folder = Path('research/polaris/uefi-ios-0077') / (row['case'] + '-run-' + row['run'])
        for name, digest in row.get('files', {}).items():
            evidence(root, dict(path=str(folder / name), sha256=digest))
        require('result.json' in row.get('files', {}), 'model result unbound')
        result = load(root, dict(path=str(folder / 'result.json'), sha256=row['files']['result.json']))
        require(result.get('passed') is True and result.get('checks') and
                all(v is True for v in result['checks'].values()) and result.get('kernel_sha256') == kernel_sha and
                result.get('inputs') == inputs and result.get('release_handoff_admitted') is
                (row['case'] == 'dual-RAM-control'), 'model source, kernel or admission mismatch')
        checks = COMMON_CHECKS + CASE_CHECKS[row['case']]
        if row['case'] != 'dual-RAM-control':
            checks += ('raw_and_lease_disabled_before_reset_permission', 'full_backend_reopened_and_matched',
                       'protected_base_byte_identical', 'original_fixture_source_unchanged',
                       'no_unexpected_LUN_block_changes', 'exact_owned_backend_stats_captured')
        if row['case'] in CASES[2:7]:
            checks += ('firmware_refused_both_reset_modes', 'no_durable_SAFE')
        require(all(result['checks'].get(k) is True for k in checks) and result.get('runner_sha256') == observer_sha,
                'specific native proof condition absent or observer changed')


def file_ownership(root, proof):
    require(proof.get('state') == 'new_physical_marker_owned_readonly' and
            proof.get('physical_phone') is True and proof.get('only_new_exclusive_namespace') is True and
            proof.get('original_files_overwritten') is False and proof.get('native_write_performed') is False,
            'fresh physical new-file inventory required; model evidence is insufficient')
    helper = evidence(root, proof['creator_binary'])
    source = evidence(root, proof['creator_source'])
    linux = load(root, proof['Linux_creation_proof'])
    require(linux.get('passed') is True and linux.get('physical_phone_touched') is False and
            linux.get('source_sha256') == sha(source) and linux.get('creation_binary_sha256') == sha(helper) and
            proof.get('remote_creator_sha256') == sha(helper), 'production creator differs from tested and uploaded binary')
    creation = load(root, proof['creation'])
    require(creation.get('test_build') is False and creation.get('relative_path') == MARKER_PATH and
            creation.get('file_bytes') == 8 << 20 and creation.get('flags') == 0x80090 and
            creation.get('links') == 1 and creation.get('uid') == creation.get('gid') == 0 and
            creation.get('mode') == 0o600 and creation.get('raw_device_write_api') is False,
            'production exclusive pinned marker identity required')
    require(all(creation.get(k) is True for k in ('created_namespace_exclusive', 'created_file_exclusive',
            'fully_written', 'initial_zero_readback', 'file_fsync', 'directory_fsync', 'syncfs')),
            'allocation or synchronization incomplete')
    before, after = load(root, proof['before']), load(root, proof['after'])
    base_audit(before); base_audit(after, True)
    require(before['updated_utc'] < proof['created_utc'] < after['updated_utc'], 'stale or reordered ownership audit')
    fiemap = load(root, proof['fiemap'])
    require(fiemap.get('backing_device_bytes') == 115167178752 and
            fiemap.get('identity_inventory_only') is True and fiemap.get('identity', {}).get('device_major') == 8 and
            fiemap['identity'].get('device_minor') == 22 and
            fiemap['identity'].get('generation') == creation.get('generation') and
            fiemap['identity'].get('flags') == 0x80090 and fiemap['identity'].get('links') == 1 and
            fiemap['identity'].get('uid') == fiemap['identity'].get('gid') == 0 and
            fiemap['identity'].get('mode') == 0x8180,
            'independent physical readonly FIEMAP identity mismatch')
    zero = evidence(root, proof['initial_whole_file'])
    require(zero.stat().st_size == 8 << 20 and sha(zero) == hashlib.sha256(bytes(8 << 20)).hexdigest(),
            'whole new marker must independently read back as zero')
    pages = {}
    for row in proof['metadata_pages']:
        block = row['block']; data = evidence(root, row['file']).read_bytes()
        require(type(block) is int and block >= 0 and block not in pages and len(data) == 4096,
                'invalid or duplicate raw metadata page')
        pages[block] = data
    packet, decoded = owner.snapshot(lambda block: pages[block], proof['partition_start'],
            proof['partition_blocks'], creation['inode'], fiemap)
    require(packet == evidence(root, proof['owner_packet']).read_bytes() and
            decoded['independently_matched_FIEMAP'] is True, 'packet differs from raw inode/CRC/FIEMAP')
    return packet, before, after


def tree_binding(payload, readonly_tree, packet, base_fiemap, partition_start, partition_blocks):
    require(payload[:8] == b'SWEETXNU', 'wrong payload')
    at, size = struct.unpack_from('<QQ', payload, 32)
    require(at <= len(payload) and 8 <= size <= len(payload) - at, 'tree outside payload')
    tree, consumed = adt.parse(payload[at:at + size]); old, old_consumed = adt.parse(readonly_tree)
    require(consumed == size and old_consumed == len(readonly_tree), 'noncanonical device tree')
    marker = [n for n in tree.children if n.name == 'polaris-owned-marker']
    require(len(marker) == 1, 'one physical marker node required')
    tree.children = [n for n in tree.children if n.name != 'polaris-owned-marker']
    require(adt.serialize(tree) == adt.serialize(old), 'original physical board/base/graphics tree changed')
    base = next(n for n in tree.children if n.name == 'polaris-file-root')
    start, blocks, base_blocks = struct.unpack('<QQQ', base.prop('layout'))
    require((start, blocks, base_blocks) == (partition_start, partition_blocks, 4194304), 'wrong base partition')
    require(base_fiemap.get('readonly_snapshot') is True and base_fiemap.get('raw_write_allowed') is False and
            base_fiemap.get('file_bytes') == 16 << 30 and len(base_fiemap['extents']) == 182, 'complete base map required')
    triples = []
    for e in base_fiemap['extents']:
        require(all(type(e[k]) is int and e[k] % 4096 == 0 for k in ('logical', 'physical', 'length')),
                'unaligned base extent')
        triples.append((e['logical'] // 4096, start + e['physical'] // 4096, e['length'] // 4096))
    protected = b''.join(struct.pack('<QQQ', *e) for e in triples)
    require(protected == base.prop('extents'), 'base map differs from physical readonly inventory')
    node = marker[0]
    require(not node.children and len(node.props) == 6 and all(flags == 0 for _, flags, _ in node.props) and
            {name for name, _, _ in node.props} == {'name', 'version', 'layout', 'owner-packet',
                                                     'protected-map', 'protected-blocks'}, 'unexpected marker node fields')
    require(node.prop('version') == struct.pack('<I', 1) and
            node.prop('layout') == struct.pack('<QQQ', start, blocks, 2048) and
            node.prop('owner-packet') == packet and node.prop('protected-map') == protected and
            node.prop('protected-blocks') == struct.pack('<Q', base_blocks), 'marker or complete protected map changed')
    # Packet extents are relative to ext4; protected file-root extents are absolute.
    nodes, count = struct.unpack_from('<II', packet, 72)
    offset = owner.HEADER + nodes * 4104
    require(offset + count * 24 == len(packet), 'invalid owner extent packet length')
    for i in range(count):
        logical, relative, length = struct.unpack_from('<QQQ', packet, offset + i * 24)
        physical = start + relative
        require(all(physical + length <= p or p + n <= physical for _, p, n in triples), 'marker overlaps original root')
    return True
