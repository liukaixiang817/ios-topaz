#!/usr/bin/env python3
"""Package a native Wi-Fi RAM image offline; never authorize or send a boot.

The persistent CPU0 runtime has different shutdown/USB semantics from the old
WLED-only trial. Preserve that trial's admission policy and package this scope
separately. Source/model review, current device/root preflight and one-use nonce
consumption remain mandatory before any device command.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = '8588a9a5218d407dd3169ec1f340097db689b3d046f3d38189514e09f3944336'
DECODER = 'd5d093974957a376e6fcc83ac3e42f7364c14d94001e88a7728f7c261eb26bc0'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT/'tools'/f'{name}.py')
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('original', 'driver-manifest', 'kernel', 'payload', 'codec-directory', 'output'):
        parser.add_argument('--'+name, required=True, type=Path)
    parser.add_argument('--firmware-diagnostic-only', action='store_true',
                        help='package only the separate terminal firmware diagnostic; XNU execution forbidden')
    args = parser.parse_args()
    output = args.output.resolve()
    require(output.is_relative_to(ROOT/'research') and not output.exists(),
            'new private research output required')
    manifest = json.loads(args.driver_manifest.read_text())
    for key, expected in {
        'wifi_native_runtime_enabled': True, 'wifi_native_display_input_integrated': True,
        'RAM_only_XNU_loader': True, 'payload_C_admission': True,
        'rebased_kernel_bytes_match': True, 'kernel_handoff': not args.firmware_diagnostic_only,
        'storage_write_api': False, 'NVRAM_write_api': False, 'QEMU_variant': False,
        'physical_owned_marker_test': False, 'RAM_native_shutdown_bridge': True,
        'kernel_CPU_affinity': 0x700, 'kernel_CPU_count': 4,
        'mss_firmware_in_payload': True, 'wifi_host_nonce_native_enabled': True,
        'wifi_native_boot_admission': False,
    }.items():
        require(type(manifest.get(key)) is type(expected) and manifest[key] == expected,
                'wrong native runtime scope: '+key)
    require(manifest.get('wifi_firmware_diagnostic_only', False) is args.firmware_diagnostic_only,
            'firmware diagnostic scope mismatch')
    require(manifest.get('wifi_native_auth_metadata_checkpoint_phase') != 'native-ready' or
            args.firmware_diagnostic_only, 'native-ready requires firmware-only scope')
    fault_hold=manifest.get('wifi_native_fault_hold',False)
    require(type(fault_hold) is bool and (not fault_hold or
            (args.firmware_diagnostic_only and manifest.get('wifi_native_auth_metadata_checkpoint_phase')=='native-ready' and
             manifest.get('wifi_native_fault_stack_bytes')==16384 and
             manifest.get('wifi_native_fault_exception_return') is False and
             manifest.get('wifi_native_fault_foreign_calls') is False)),
            'native fault hold requires its terminal firmware-only scope')
    marker=manifest.get('wifi_native_bootloader_marker',False)
    fast_sha=manifest.get('wifi_scalar_sha256_fast',False)
    require(type(fast_sha) is bool and (not fast_sha or fault_hold) and
            manifest.get('scalar_sha256_uses_SIMD',False) is False,
            'fast scalar SHA256 requires the explicit terminal diagnostic without SIMD')
    trace_first=manifest.get('wifi_native_copy_trace_first',0)
    require(type(trace_first) is int and 0<=trace_first<=30464 and (not trace_first or fault_hold),
            'fine copy trace must be a bounded fault diagnostic window')
    watchdog=manifest.get('wifi_native_watchdog_readonly',False)
    require(type(watchdog) is bool and (not watchdog or (fault_hold and manifest.get('wifi_native_bootloader_marker') is True)) and
            manifest.get('native_apps_watchdog_register_writes',False) is False,
            'native watchdog inventory requires marker/fault diagnostic and no writes')
    require(type(marker) is bool and (not marker or fault_hold) and
            manifest.get('pre_native_volatile_boot_reason_writes',False) is marker,
            'pre-native marker requires the explicit fault diagnostic')
    if args.firmware_diagnostic_only:
        require(manifest.get('XNU_execution_forbidden') is True and
                manifest.get('userdata_access_api') is False and
                manifest.get('disk_payload_path') is None and
                manifest.get('wifi_native_auth_metadata_checkpoint_phase') in
                ('assigned', 'returned', 'copied', 'copy-ready', 'first-copy', 'first-rmb', 'copy-prefix', 'idle-hold', 'copy-page', 'native-ready'), 'firmware diagnostic is not terminal RAM-only')
        events = manifest.get('wifi_native_first_rmb_events')
        require((type(events) is int and 1 <= events <= 6) if
                manifest['wifi_native_auth_metadata_checkpoint_phase'] == 'first-rmb' else events is None,
                'first RMB count/profile mismatch')
        segments = manifest.get('wifi_native_copy_segments')
        require((type(segments) is int and 1 <= segments <= 28) if
                manifest['wifi_native_auth_metadata_checkpoint_phase'] == 'copy-prefix' else segments is None,
                'copy prefix count/profile mismatch')
        page = manifest.get('wifi_native_copy_page_before')
        require((type(page) is int and 1 <= page < 30720) if
                manifest['wifi_native_auth_metadata_checkpoint_phase'] == 'copy-page' else page is None,
                'copy page/profile mismatch')
        probe = manifest.get('wifi_native_copy_page_probe', False)
        require(type(probe) is bool and (not probe or
                manifest['wifi_native_auth_metadata_checkpoint_phase'] == 'copy-page'),
                'copy page probe/profile mismatch')
        after_write = manifest.get('wifi_native_copy_page_after_write', False)
        require(type(after_write) is bool and (not after_write or
                (manifest['wifi_native_auth_metadata_checkpoint_phase'] == 'copy-page' and not probe)),
                'copy page after-write/profile mismatch')
    artifact = manifest['artifact']
    require(Path(artifact).name == artifact and artifact not in ('', '.', '..'), 'driver path')
    driver = args.driver_manifest.parent/artifact
    require(sha(driver) == manifest['sha256'] and driver.stat().st_size == manifest['bytes'],
            'driver changed')
    require(sha(args.kernel) == manifest['kernel_sha256'], 'kernel changed')
    require(sha(args.payload) == manifest['payload_sha256'] and
            args.payload.stat().st_size == manifest['payload_bytes'], 'payload changed')
    require(sha(args.original) == ORIGINAL, 'wrong original firmware')
    evidence = {}
    for name, digest in manifest['inputs'].items():
        path = (ROOT/name).resolve()
        require(path.is_relative_to(ROOT) and sha(path) == digest, 'source/input changed: '+name)
        evidence[name] = digest
    module('polaris-wifi-nonce-candidate').verify(args.driver_manifest, sha(args.driver_manifest))
    binding = manifest['wifi_native_runtime_binding']
    require(binding['country'] == 'AU' and binding['country_code'] == 36 and
            binding['terminal_exit'] == 'retained whole-system SYSTEM_OFF' and
            binding['per_device_DMA_retirement'] is False, 'native terminal/country scope changed')
    # Exact unique protection tokens, independently of descriptive manifest flags.
    payload = args.payload.read_bytes()
    require(payload[:8] == b'SWEETXNU', 'payload header')
    tokens = payload[0x48:0x2a8].split(b'\0', 1)[0].split()
    for token in (b'polariswifi=1', b'polarisramcow=1', b'ufsrw=0',
                  b'polarisfileroot=1', b'polarisquiesce=1', b'polariswled=1', b'cpus=4'):
        prefix = token.split(b'=')[0]+b'='
        require([x for x in tokens if x.startswith(prefix)] == [token], 'payload protection token')
    codec = args.codec_directory.resolve()
    require(sha(codec/'verify') == DECODER, 'original decoder executable changed')
    for item in json.loads((codec/'sources.json').read_text()):
        path = (codec/item['path']).resolve()
        require(path.is_relative_to(codec) and sha(path) == item['sha256'], 'original codec source changed')
    firmware = module('polaris-uefi-firmware')
    image, record = firmware.package(args.original.read_bytes(), driver.read_bytes(),
                                    label='Polaris RAM resident iOS loader')
    require(record['original_inner_files'] == record['unchanged_inner_files'] == 81,
            'original firmware preservation')
    _, decoded, _, _ = firmware.unpack_android(image)
    _, _, files = firmware.files(decoded[0x8000:])
    encoded = []
    for _, raw in files:
        if raw[18] == 0x0b:
            sections = list(firmware.sections(raw[24:]))
            require(len(sections) == 1 and sections[0][0] == 2, 'compressed section layout')
            encoded.append(sections[0][2][24:])
    require(len(encoded) == 1, 'one compressed firmware volume required')
    output.mkdir()
    (output/'whole.lzma').write_bytes(encoded[0])
    process = subprocess.run([str(codec/'verify'), str(output/'whole.lzma'),
                              str(output/'whole.decoded')], capture_output=True, timeout=30)
    (output/'codec.log').write_bytes(process.stdout+process.stderr)
    require(process.returncode == 0 and
            (output/'whole.decoded').read_bytes() == firmware.decode_edk2_lzma(encoded[0]),
            'actual original decoder round trip failed')
    target = output/'polaris-native-wifi.img'
    target.write_bytes(image)
    scope = 'native_WiFi_firmware_diagnostic_RAM_only' if args.firmware_diagnostic_only else 'native_WiFi_retained_CPU0_RO_RAMCOW'
    record.update(scope=scope, artifact=target.name,
        sha256=sha(target), bytes=len(image), driver_sha256=sha(driver),
        driver_manifest_sha256=sha(args.driver_manifest), kernel_sha256=sha(args.kernel),
        payload_sha256=sha(args.payload), kernel_handoff=not args.firmware_diagnostic_only,
        wifi_scalar_sha256_fast=fast_sha,scalar_sha256_uses_SIMD=False,
        wifi_native_copy_trace_first=trace_first,
        wifi_native_watchdog_readonly=watchdog,native_apps_watchdog_register_writes=False,
        wifi_native_bootloader_marker=marker,pre_native_volatile_boot_reason_writes=marker,
        original_decoder_sha256=DECODER, original_codec_round_trip=True,
        source_inputs=evidence, packager_sha256=sha(Path(__file__)),
        boot_admission=False, physical_networking_verified=False,
        may_write_userdata=False, immutable_root_RAMCOW_only=not args.firmware_diagnostic_only,
        post_start_USB_service=False, nonce_consumed=False,
        terminal_exit=binding['terminal_exit'], device_command_executed=False)
    if args.firmware_diagnostic_only:
        record.update(wifi_firmware_diagnostic_only=True, XNU_execution_forbidden=True,
            userdata_access_api=False, terminal_exit='RAM terminal hold before XNU')
    (output/'manifest.json').write_text(json.dumps(record, indent=2)+'\n')
    print('Native Wi-Fi image packaged and original codec verified; no boot admission or device action')


if __name__ == '__main__':
    main()
