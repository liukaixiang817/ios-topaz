#!/usr/bin/env python3
"""Parse a physical, read-only PMI8998 WLED inventory, never an off/on proof."""
import re


def parse(text):
    fields, strings, current = {}, [], None
    for line in text.splitlines():
        if not line.startswith('WLED_'):
            continue
        if line == 'WLED_INVENTORY_HOLD: NO_CPU_ON NO_PMIC_WRITE':
            if 'hold' in fields:
                raise ValueError('repeated WLED hold')
            fields['hold'] = True
            continue
        m = re.fullmatch(r'(WLED_[A-Z_]+)=0x([0-9a-f]{16})', line)
        if not m:
            raise ValueError('truncated/interleaved WLED field')
        key, value = m[1], int(m[2], 16)
        if key == 'WLED_STRING_INDEX':
            if value != len(strings) or value >= 4 or (current is not None and len(current) != 3):
                raise ValueError('WLED string order/inventory incomplete')
            current = dict(index=value); strings.append(current)
        elif key in ('WLED_STRING_CONFIG', 'WLED_STRING_LEVEL'):
            if current is None or key in current:
                raise ValueError('missing/repeated WLED string')
            current[key] = value
        else:
            if key in fields:
                raise ValueError('duplicate WLED field')
            fields[key] = value
    if (not fields.get('hold') or fields.get('WLED_KERNEL_AP_STAGE') != 0 or
            'WLED_MOCK_BACKEND' in fields or 'KERNEL_PSCI_STATUS=' in text or
            'Darwin Kernel Version' in text or 'POLARIS SMP CHECK:' in text or
            'WLED_READONLY_RESULT' not in fields):
        raise ValueError('not a physical pre-XNU readonly WLED hold')
    result = dict(readonly_result=fields['WLED_READONLY_RESULT'], fields=fields,
                  firmware_reported_AP_stage=0, PMIC_writes=False,
                  backlight_off_or_on_proven=False)
    if fields['WLED_READONLY_RESULT']:
        result['complete_inventory'] = False
        return result
    required = ['WLED_READONLY_VERSION', 'WLED_CTRL_APID_OWNER', 'WLED_SINK_APID_OWNER',
                'WLED_CTRL_MAPPING', 'WLED_SINK_MAPPING', 'WLED_READ_COMMANDS',
                'WLED_CTRL_REVISION', 'WLED_SINK_REVISION', 'WLED_DISPLAY_READY_ENABLE',
                'WLED_FAULT_RT', 'WLED_SINK_CONFIG']
    if (any(k not in fields for k in required) or len(strings) != 4 or
            any(len(s) != 3 for s in strings) or fields['WLED_READ_COMMANDS'] != 28 or
            not 0x50000000 <= fields['WLED_READONLY_VERSION'] < 0x60000000):
        raise ValueError('incomplete WLED double snapshot')
    for bank, ppid in [('CTRL', 0x3d8), ('SINK', 0x3d9)]:
        owned = fields['WLED_' + bank + '_APID_OWNER']
        if owned >> 32 >= 512 or owned & 0xffffffff > 7 or (fields['WLED_' + bank + '_MAPPING'] >> 8) & 0xfff != ppid:
            raise ValueError('foreign WLED channel/owner/map')
    if (fields['WLED_CTRL_REVISION'] >= 2**64 or fields['WLED_SINK_REVISION'] >= 2**64 or
            fields['WLED_DISPLAY_READY_ENABLE'] >= 2**24 or fields['WLED_FAULT_RT'] >= 2**16 or
            fields['WLED_SINK_CONFIG'] >= 2**48 or
            any(s['WLED_STRING_CONFIG'] >= 2**56 or s['WLED_STRING_LEVEL'] >= 2**16 for s in strings)):
        raise ValueError('WLED register width overflow')
    result.update(complete_inventory=True, strings=strings,
                  optimistic_snapshot_not_remote_lock=True,
                  writer_permission_or_identity_admitted=False)
    return result
