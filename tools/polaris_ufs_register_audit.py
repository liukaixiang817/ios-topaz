#!/usr/bin/env python3
"""Compare native UFSHCI offsets with a pinned, independently read QEMU layout.

Source audit only: this neither runs the controller nor proves I/O/durability.
The upstream header is a local reference input, never vendored or executed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

QEMU_HEADER_SHA = '6f91fa2a259021e37a17d649e8be94174bbe485537771912a9eebf7921f507b1'
FIELDS = {'REG_CAP': 'cap', 'REG_IS': 'is', 'REG_IE': 'ie', 'REG_HCS': 'hcs',
          'REG_HCE': 'hce', 'REG_UTRLBA': 'utrlba', 'REG_UTRLBAU': 'utrlbau',
          'REG_UTRLDBR': 'utrldbr', 'REG_UTRLCLR': 'utrlclr', 'REG_UTRLRSR': 'utrlrsr',
          'REG_UTMRLDBR': 'utmrldbr', 'REG_UTMRLRSR': 'utmrlrsr',
          'REG_UICCMD': 'uiccmd', 'REG_UCMDARG1': 'ucmdarg1',
          'REG_UCMDARG2': 'ucmdarg2', 'REG_UCMDARG3': 'ucmdarg3'}


def audit(native, upstream):
    if hashlib.sha256(upstream).hexdigest() != QEMU_HEADER_SHA:
        raise ValueError('requires exact independently pinned qemu v11.0.1 header')
    reference = upstream.decode()
    body = re.search(r'typedef struct QEMU_PACKED UfsReg \{(.*?)\} UfsReg;',
                     reference, re.S)
    if not body:
        raise ValueError('upstream register layout missing')
    declaration = r'\s*uint32_t\s+(\w+)(?:\[(\d+)\])?;'
    if re.sub(declaration, '', body[1]).strip():
        raise ValueError('unreviewed upstream register type/layout')
    offsets = {}
    offset = 0
    for name, count in re.findall(declaration, body[1]):
        if name in offsets:
            raise ValueError('duplicate register field')
        offsets[name] = offset
        offset += 4 * (int(count) if count else 1)
    source = native.decode()
    definitions = re.findall(r'^#define\s+(REG_\w+|UIC_DME_LINK_STARTUP)\s+(0x[0-9a-fA-F]+)\b',
                             source, re.M)
    if len(definitions) != len(dict(definitions)):
        raise ValueError('duplicate native register constant')
    actual = {name: int(value, 16) for name, value in definitions}
    for name, field in FIELDS.items():
        if actual.get(name) != offsets[field]:
            raise ValueError(f'{name}: native={actual.get(name)!r}, upstream={offsets[field]:#x}')
    command = re.search(r'\bUFS_UIC_CMD_DME_LINK_STARTUP\s*=\s*(0x[0-9a-fA-F]+)', reference)
    if not command or actual.get('UIC_DME_LINK_STARTUP') != int(command[1], 16):
        raise ValueError('native LinkStartup opcode mismatch')
    if ('FIELD(HCS, UCRDY, 3, 1)' not in reference or
            not re.search(r'^#define\s+HCS_UCRDY\s+\(1u\s*<<\s*3\)', source, re.M)):
        raise ValueError('native UIC-ready bit mismatch')
    for name in ('REG_UCMDARG1', 'REG_UCMDARG2', 'REG_UCMDARG3'):
        if not re.search(r'ufs_wr\(\s*' + name + r'\s*,\s*0\s*\)', source):
            raise ValueError('native LinkStartup argument setup missing: ' + name)
    if (not re.search(r'ufs_wr\(\s*REG_UICCMD\s*,\s*UIC_DME_LINK_STARTUP\s*\)', source) or
            not re.search(r'ufs_rd\(\s*REG_UCMDARG2\s*\)', source) or
            re.search(r'ufs_wr\(\s*0x[0-9a-fA-F]+\s*,', source)):
        raise ValueError('native LinkStartup bypasses the audited register constants')
    return dict(passed=True,source_audit_only=True,native_IO_or_durability_proven=False,
                qemu_header_sha256=QEMU_HEADER_SHA,native_source_sha256=hashlib.sha256(native).hexdigest(),
                offsets={name:offsets[field] for name,field in FIELDS.items()},
                LinkStartup=int(command[1],16),UIC_ready_bit=3,audited_native_command_calls=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-source', required=True, type=Path)
    parser.add_argument('--qemu-header', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = audit(args.native_source.read_bytes(), args.qemu_header.read_bytes())
    with args.output.open('x') as out:
        out.write(json.dumps(result, indent=2) + '\n')
    print('Pinned source audit passed:16 register offsets, LinkStartup and UCRDY; not an I/O proof')


if __name__ == '__main__':
    main()
