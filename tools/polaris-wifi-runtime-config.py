#!/usr/bin/env python3
"""Bind native runtime build inputs to this linked kernel; never grant boot.

The single build option includes the complete producer chain. Display/input,
full candidate evidence and physical admission remain separate requirements.
"""
import importlib.util
from pathlib import Path


FEATURES = (
    'WIFI_SYSTEM_OFF_NATIVE', 'WIFI_NATIVE_RUNTIME', 'WIFI_WORKER_NATIVE',
    'WIFI_MAILBOX_NATIVE', 'WIFI_RUNTIME_HANDOFF', 'WIFI_NATIVE_MEMORY',
    'WIFI_NONCE_NATIVE', 'WIFI_STARTUP_PARENT', 'WIFI_NETWORK_NATIVE',
    'WIFI_KEYS_NATIVE', 'WIFI_STATION_NATIVE', 'WIFI_SCAN_NATIVE',
    'WIFI_HTT_DATA', 'WIFI_HTT_NATIVE', 'WIFI_WMI_NATIVE', 'WIFI_HTC_NATIVE',
    'WIFI_CE_TRANSPORT', 'WIFI_CE_MEMORY', 'WIFI_CE_NATIVE', 'WIFI_SMMU_NATIVE',
    'WIFI_WLFW_NATIVE', 'MSS_RMTFS_SERVICE', 'WIFI_NV_NATIVE', 'MSS_RMTFS_NATIVE',
    'MSS_GLINK_NATIVE', 'MSS_SMP2P_NATIVE', 'MSS_CHANNEL_NATIVE', 'MSS_SMEM_NATIVE',
    'MSS_SFPB_IO', 'MSS_AUTH_NATIVE', 'MSS_MODEM_COPY', 'MSS_MODEM_IO',
    'MSS_BOOT_NATIVE', 'MSS_AOP_NATIVE', 'MSS_AOP_IO', 'MSS_CLOCK_NATIVE',
    'MSS_PROXY_IO', 'MSS_CMDDB', 'MSS_POWER_NATIVE', 'MSS_RSC_STATE',
    'MSS_NATIVE_IO', 'MSS_RAIL_IO', 'MSS_RPMH_STATE', 'MSS_CPU_OWNER',
    'MSS_IMAGE_LEDGER', 'MSS_RESOURCE_MAP',
)
SOURCES = ('polaris-wifi-glink.c', 'polaris-wifi-cap.c',
           'polaris-wifi-rmtfs.c', 'polaris-wifi-wlfw.c')


def binding(kernel, base, span, other_spans, country):
    if country != 'AU':
        raise ValueError('native runtime requires the explicitly selected AU profile')
    path = Path(__file__).with_name('polaris-wifi-kernel-binding.py')
    spec = importlib.util.spec_from_file_location('polaris_wifi_kernel_binding', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    mailbox = module.binding(kernel, base, span, other_spans)
    shutdown = module.shutdown_binding(kernel, base, span,
        [*other_spans, (mailbox['offset'], mailbox['bytes'])])
    lines = ['/* Generated from the exact linked kernel; not boot admission. */']
    lines += ['#define EFI_XNU_'+name+'_AVAILABLE 1' for name in FEATURES]
    lines += [f'#define EFI_XNU_WIFI_MAILBOX_VA 0x{base+mailbox["offset"]:x}ULL',
              f'#define EFI_XNU_WIFI_SHUTDOWN_VA 0x{base+shutdown["offset"]:x}ULL',
              '#define EFI_XNU_WIFI_COUNTRY 36u']
    return '\n'.join(lines)+'\n', dict(mailbox=mailbox, shutdown=shutdown,
        country='AU', country_code=36, features=list(FEATURES),
        terminal_exit='retained whole-system SYSTEM_OFF',
        per_device_DMA_retirement=False, display_input_integrated=False,
        physical_networking_verified=False, boot_admission=False)
