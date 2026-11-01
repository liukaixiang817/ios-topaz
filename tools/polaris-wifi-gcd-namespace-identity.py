"""Digest-only layout binding for the own original Core's GCD RAM namespace."""
import hashlib
import importlib.util
from pathlib import Path
import struct


def binding(path):
    spec = importlib.util.spec_from_file_location('original_gcd', Path(__file__).with_name('polaris-uefi-gcd-identity.py'))
    original = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(original)
    _, core = original.binding(Path(path))
    raw = Path(path).read_bytes()
    assert raw[0x1bd70:0x1bd78] == b'gcdm\0\0\0\0'
    assert not any(raw[0x1bd78:0x1bdc0])
    assert struct.unpack_from('<3Q', raw, 0x1bd48) == (16, 4, 1)
    assert struct.unpack_from('<2Q', raw, 0x1bd60) == (0x1bd60, 0x1bd60)
    assert not any(0x1bd70 <= at < 0x1bdc0 for at in core['relocations'])
    # Original allocator requests80B; descriptor getter follows Link+8 and
    # loads Base/End/Capabilities/Attributes/Type/ImageHandle/DeviceHandle.
    instructions = {0x7f64:0xd2800a00, 0x7f84:0xd2800a00,
        0x2ca8:0x91358084, 0x2cbc:0xf9400822, 0x2cc4:0xf9400c20,
        0x2cd4:0xf9401020, 0x2cdc:0xf9401420, 0x2ce4:0xb9403020,
        0x2cec:0xf9401c20, 0x2cf4:0xf9402020}
    for at, word in instructions.items():
        assert struct.unpack_from('<I', raw, at)[0] == word
    digest = hashlib.sha256(raw[0x1bd70:0x1bdc0]).digest()
    text = '#ifndef PGNS_ORIGINAL_NAMESPACE_BINDING_H\n#define PGNS_ORIGINAL_NAMESPACE_BINDING_H\n'
    text += '#define PGNS_HEAD_RVA 0x1bd60u\n#define PGNS_LOCK_RVA 0x1bd48u\n#define PGNS_TEMPLATE_RVA 0x1bd70u\n'
    text += '#define PGNS_NODE_BYTES 80u\n#define PGNS_SIGNATURE UINT64_C(0x6d646367)\n'
    text += 'static const uint8_t pgns_template_SHA256[32]={'+','.join(hex(x) for x in digest)+'};\n#endif\n'
    return text, dict(source_whole_SHA256=core['whole_SHA256'], node_bytes=80,
        head_RVA=0x1bd60, lock_RVA=0x1bd48, template_RVA=0x1bd70,
        template_SHA256=digest.hex(), checked_original_opcodes=instructions,
        original_firmware_executed=False, current_namespace_captured=False)
