"""Offline admission mutations, not native execution or phone write evidence."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import adt
import polaris_marker_admission as m


def node(name, **properties):
    n = adt.Node(); n.props = [('name', 0, name.encode() + b'\0')]
    n.props += [(key, 0, value) for key, value in properties.items()]
    return n


def tree_fixture(overlap=False):
    start, blocks = 0x1fa0000, 28116987
    extents = []; logical = 0
    for i in range(182):
        length = 4194304 // 182 if i < 181 else 4194304 - logical
        extents.append(dict(logical=logical * 4096, physical=(5000000 + logical) * 4096, length=length * 4096))
        logical += length
    triples = [(e['logical'] // 4096, start + e['physical'] // 4096, e['length'] // 4096) for e in extents]
    protected = b''.join(struct.pack('<QQQ', *row) for row in triples)
    base = node('polaris-file-root', layout=struct.pack('<QQQ', start, blocks, 4194304), extents=protected)
    old = node('root'); old.children = [base]; old_bytes = adt.serialize(old)
    packet = bytearray(408); packet[:8] = b'PROWN001'
    struct.pack_into('<II', packet, 72, 0, 1)
    struct.pack_into('<QQQ', packet, 384, 0, 5000000 if overlap else 256, 2048)
    marker = node('polaris-owned-marker', version=struct.pack('<I', 1),
                  layout=struct.pack('<QQQ', start, blocks, 2048),
                  **{'owner-packet': bytes(packet), 'protected-map': protected,
                     'protected-blocks': struct.pack('<Q', 4194304)})
    old.children.append(marker)
    mapping = dict(readonly_snapshot=True, raw_write_allowed=False, file_bytes=16 << 30, extents=extents)
    return old, old_bytes, bytes(packet), mapping, start, blocks


def payload(tree):
    raw = bytearray(720); raw[:8] = b'SWEETXNU'; blob = adt.serialize(tree)
    struct.pack_into('<QQ', raw, 32, len(raw), len(blob)); raw.extend(blob); return bytes(raw)


def audit(after=False):
    keys = ('all_six_GPT_copies_match_original', 'fresh_maps_before_after_match', 'unmounted',
            'block_readonly', 'outer_header_unchanged_during_readonly_check',
            'outer_header_independently_reviewed', 'fresh_extents_match_payload_baseline',
            'actual_expected_fastboot_after_verified')
    return dict.fromkeys(keys, True) | dict(
        state='fresh_owned_marker_preflight_passed' if after else 'fresh_root_readonly_preflight_passed',
        phone_partition_writes=after, journal_replayed=False, metadata_repaired=False,
        observed_root_sha256=m.BASE_SHA, full_image_sha256=m.BASE_SHA, file_bytes=16 << 30,
        extent_count=182, ESP_approved_addition_baseline=m.ESP_SHA, outer_state=1,
        outer_needs_journal_recovery=False,
        critical_partitions_match_reviewed_baselines=['recovery', 'mindowsesp', 'abl_a', 'abl_b', 'boot'])


class AdmissionTests(unittest.TestCase):
    def test_complete_original_map_and_exact_marker_positive(self):
        tree, old, packet, mapping, start, blocks = tree_fixture()
        self.assertTrue(m.tree_binding(payload(tree), old, packet, mapping, start, blocks))

    def test_root_tree_marker_map_packet_and_geometry_changes_refused(self):
        for kind in ('old-board', 'protected', 'packet', 'version', 'size', 'duplicate', 'extra', 'map', 'partition'):
            tree, old, packet, mapping, start, blocks = tree_fixture(); marker = tree.children[-1]
            if kind == 'old-board': tree.props.append(('foreign-reg', 0, b'x'))
            elif kind == 'duplicate': tree.children.append(copy.deepcopy(marker))
            elif kind == 'extra': marker.props.append(('unreviewed', 0, b'x'))
            elif kind == 'map': mapping['extents'][80]['physical'] += 4096
            elif kind == 'partition': start += 1
            else:
                field = dict(protected='protected-map', packet='owner-packet', version='version', size='layout')[kind]
                marker.props = [(key, flags, (bytes([data[0] ^ 1]) + data[1:]) if key == field else data)
                                for key, flags, data in marker.props]
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                m.tree_binding(payload(tree), old, packet, mapping, start, blocks)

    def test_marker_cannot_alias_protected_base(self):
        tree, old, packet, mapping, start, blocks = tree_fixture(overlap=True)
        with self.assertRaisesRegex(ValueError, 'overlaps'):
            m.tree_binding(payload(tree), old, packet, mapping, start, blocks)

    def test_all_baseline_conditions_and_mutation_stage_are_required(self):
        for after in (False, True):
            original = audit(after); m.base_audit(original, after)
            for key, value in original.items():
                changed = copy.deepcopy(original)
                changed[key] = (not value if type(value) is bool else value + 1 if type(value) is int else
                                [] if type(value) is list else 'changed')
                with self.subTest(after=after, key=key), self.assertRaises(ValueError): m.base_audit(changed, after)

    def test_model_inventory_cannot_become_physical_file_admission(self):
        with tempfile.TemporaryDirectory() as d:
            for proof in ({}, dict(state='new_physical_marker_owned_readonly', physical_phone=False,
                    only_new_exclusive_namespace=True, original_files_overwritten=False, native_write_performed=False)):
                with self.assertRaises(ValueError): m.file_ownership(Path(d), proof)

    def test_evidence_changed_symlink_or_escape_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); path = root / 'file'; path.write_bytes(b'original')
            record = dict(path='file', sha256=m.sha(path)); self.assertEqual(m.evidence(root, record), path)
            path.write_bytes(b'changed')
            with self.assertRaises(ValueError): m.evidence(root, record)
            (root / 'link').symlink_to(path)
            for name in ('link', '../file', str(path)):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    m.evidence(root, dict(path=name, sha256=m.sha(path)))

    def test_model_requires_every_specific_failure_and_frozen_observer(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); (root / 'tools').mkdir(); observer = root / 'tools/qemu-polaris-uefi-xnu.py'
            observer.write_bytes(b'offline test observer'); inputs = {'example-source': 'a' * 64}
            suite = dict(actual_EFI_XNU_native_owned_file_tests_passed=True, kernel_sha256='b' * 64,
                actual_live_guard_required_before_PCI_MMIO=True, observer_sha256=m.sha(observer), cases=[])
            for case in m.CASES:
                checks = set(m.COMMON_CHECKS + m.CASE_CHECKS[case])
                if case != 'dual-RAM-control': checks.update(('raw_and_lease_disabled_before_reset_permission',
                    'full_backend_reopened_and_matched', 'protected_base_byte_identical', 'original_fixture_source_unchanged',
                    'no_unexpected_LUN_block_changes', 'exact_owned_backend_stats_captured'))
                if case in m.CASES[2:7]: checks.update(('firmware_refused_both_reset_modes', 'no_durable_SAFE'))
                result = dict(passed=True, checks=dict.fromkeys(checks, True), kernel_sha256='b' * 64,
                    inputs=inputs, release_handoff_admitted=case == 'dual-RAM-control', runner_sha256=m.sha(observer))
                path = root / 'research/polaris/uefi-ios-0077' / (case + '-run-test') / 'result.json'
                path.parent.mkdir(parents=True); path.write_text(json.dumps(result))
                suite['cases'].append(dict(case=case, run='test', passed=True, files={'result.json': m.sha(path)}))
            m.model_suite(root, suite, 'b' * 64, inputs)
            path = root / 'research/polaris/uefi-ios-0077/owned-write-unknown-DMA-run-test/result.json'
            result = json.loads(path.read_text()); del result['checks']['actual_doorbell_still_pending']
            path.write_text(json.dumps(result)); suite['cases'][3]['files']['result.json'] = m.sha(path)
            with self.assertRaisesRegex(ValueError, 'specific native'): m.model_suite(root, suite, 'b' * 64, inputs)


if __name__ == '__main__': unittest.main()
