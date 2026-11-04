"""Check the exact own Core opcodes used by the read-only image ledger.

No firmware execution, exported firmware bytes, provider or physical access.
The runtime reader already requires this Core's immutable text SHA identity.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import struct


def binding(path):
    spec = importlib.util.spec_from_file_location(
        'own_core', Path(__file__).with_name('polaris-uefi-gcd-identity.py'))
    original = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(original)
    _, core = original.binding(Path(path))
    raw = Path(path).read_bytes()
    # CoreFindProtocolEntry: global head,72B allocation, signature, GUID,
    # instance-list/notify-list heads and containing-record adjustment.
    # CoreInstallProtocolInterface:88B interface,56B handle, signatures,
    # key, handle/entry/interface fields and the two separate list links.
    # CoreGetNextLocateByProtocol: ByProtocol-32, Handle+24, Interface+56.
    instructions = {
        0x18a0: 0xf00000c0, 0x18a8: 0x91084016, 0x18ac: 0xf9410814,
        0x18c4: 0xd2800900, 0x18d4: 0xd28e4e01, 0x18d8: 0xf2acae81,
        0x18dc: 0xf8018401, 0x18e8: 0x9100a260, 0x18f0: 0x9100e260,
        0x18f8: 0x91002261, 0x191c: 0xd1002293, 0x1924: 0x91004280,
        0x2650: 0x910fe000, 0x265c: 0x910fe000,
        0x6c00: 0xd2800b00, 0x6c18: 0xd2800700,
        0x6c28: 0xd28dcd01, 0x6c2c: 0xf2ad8c81, 0x6c30: 0xf8018401,
        0x6c38: 0xd00000a1, 0x6c3c: 0xf9459420, 0x6c44: 0xf9001aa0,
        0x6c48: 0xf9059420, 0x6c5c: 0xd28d2e00, 0x6c60: 0xf9000e95,
        0x6c64: 0xf2ac6cc0, 0x6c68: 0xf9000280, 0x6c6c: 0xa9036296,
        0x6c7c: 0x91002281, 0x6c80: 0x910062a0, 0x6c88: 0x91008281,
        0x6c8c: 0x9100a2c0, 0x11f8: 0xd1008042,
        0x11fc: 0xf9400c40, 0x1200: 0xf9401c42, 0x11d8: 0xf945e804,
    }
    for at, word in instructions.items():
        if struct.unpack_from('<I', raw, at)[0] != word:
            raise ValueError(f'own Core layout opcode mismatch at {at:#x}')
    if struct.unpack_from('<3Q', raw, 0x1b3f8) != (16, 4, 1):
        raise ValueError('own protocol database lock layout mismatch')
    if struct.unpack_from('<2Q', raw, 0x1c210) != (0x1c210, 0x1c210):
        raise ValueError('own protocol database list head mismatch')
    return dict(source_whole_SHA256=core['whole_SHA256'],
                protocol_head_RVA=0x1c210, protocol_lock_RVA=0x1b3f8,
                handle_key_RVA=0x1cb28, locate_key_RVA=0x1cbd0,
                protocol_bytes=72, interface_bytes=88, handle_bytes=56,
                checked_original_opcodes=instructions,
                original_firmware_executed=False, current_graph_captured=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('core', type=Path)
    print(json.dumps(binding(parser.parse_args().core), indent=2))
